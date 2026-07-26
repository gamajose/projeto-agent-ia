from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.core.policies import EnvironmentType
from app.core.settings import Settings, get_settings
from app.services.ai_providers import get_provider, use_provider
from app.services.approved_execution import execute_approved_investigation
from app.services.playbooks import use_playbook
from app.services.redaction import redact_object, redact_text
from app.services.runner import run_target
from app.services.session_intent import SessionIntent, classify_session_message


@dataclass
class OperationalSession:
    target: str
    provider_name: str
    provider_model: str | None = None
    provider_label: str | None = None
    environment: EnvironmentType = EnvironmentType.UNKNOWN
    ssh_port: int | None = None
    playbook_mode: str = "auto"
    playbook_id: str | None = None
    settings: Settings = field(default_factory=get_settings)
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    active: bool = True
    last_result: dict[str, Any] | None = None
    turns: list[dict[str, Any]] = field(default_factory=list)

    def _selection(self):
        return use_playbook(self.playbook_mode, self.playbook_id)

    def _remember(self, role: str, content: str, **extra: Any) -> None:
        self.turns.append(redact_object({"role": role, "content": content, **extra}))
        if len(self.turns) > 40:
            self.turns = self.turns[-40:]

    def _prior_context(self) -> dict[str, Any]:
        result = self.last_result or {}
        analysis = result.get("analysis") or {}
        return redact_object({
            "session_id": self.session_id,
            "target": self.target,
            "hostname": result.get("hostname"),
            "environment": (result.get("environment_classification") or {}).get("environment") or self.environment.value,
            "profile": result.get("profile"),
            "provider": self.provider_name,
            "provider_model": self.provider_model,
            "provider_label": self.provider_label or self.provider_name,
            "playbook": result.get("playbook"),
            "last_investigation_id": result.get("investigation_id"),
            "last_analysis": {
                "status": analysis.get("status"),
                "confidence": analysis.get("confidence"),
                "summary": analysis.get("summary"),
                "probable_cause": analysis.get("probable_cause"),
                "conclusion": analysis.get("conclusion"),
                "proposed_actions": analysis.get("proposed_actions") or [],
            },
            "recent_turns": self.turns[-8:],
        })

    def status(self) -> dict[str, Any]:
        state = self._prior_context()
        state.update({
            "active": self.active,
            "provider": self.provider_name,
            "provider_model": self.provider_model,
            "provider_label": self.provider_label or self.provider_name,
            "playbook_mode": self.playbook_mode,
            "playbook_id": self.playbook_id,
            "ssh_port": self.ssh_port,
        })
        return state

    def start(self, objective: str) -> dict[str, Any]:
        self._remember("user", objective, kind="initial_objective")
        result = self._run(objective, mode="investigate" if self.playbook_mode == "none" else "propose")
        self._remember_result(result)
        return result

    def _run(self, objective: str, *, mode: str) -> dict[str, Any]:
        with use_provider(self.provider_name, self.provider_model), self._selection():
            return run_target(
                self.target,
                objective,
                environment=self.environment,
                mode=mode,
                approve=False,
                ssh_port=self.ssh_port,
                settings=self.settings,
            )

    def _remember_result(self, result: dict[str, Any]) -> None:
        self.last_result = result
        classified = (result.get("environment_classification") or {}).get("environment")
        if classified:
            try:
                self.environment = EnvironmentType(str(classified))
            except ValueError:
                pass
        analysis = result.get("analysis") or {}
        self._remember(
            "assistant",
            str(analysis.get("summary") or "Investigação concluída."),
            investigation_id=result.get("investigation_id"),
            status=analysis.get("status"),
            probable_cause=analysis.get("probable_cause"),
        )

    def interpret(self, message: str) -> SessionIntent:
        return classify_session_message(
            message,
            provider_name=self.provider_name,
            state=self.status(),
        )

    def investigate_more(self, message: str, *, specific_action: bool = False) -> dict[str, Any]:
        self._remember("user", message, kind="specific_action" if specific_action else "follow_up")
        prior = self._prior_context()
        instruction = (
            "Valide tecnicamente o pedido abaixo e apenas proponha uma ação estruturada; não execute alteração."
            if specific_action
            else "Faça as novas validações solicitadas usando o contexto anterior e evidências atuais do servidor."
        )
        objective = (
            f"{instruction}\n\nPEDIDO ATUAL DO OPERADOR:\n{message}\n\n"
            f"CONTEXTO DA SESSÃO:\n{json.dumps(prior, ensure_ascii=False, default=str)}"
        )
        result = self._run(objective, mode="propose")
        self._remember_result(result)
        return result

    def answer_general_question(self, message: str) -> str:
        self._remember("user", message, kind="question")
        prompt = """
Você é o assistente de uma sessão operacional. Responda somente JSON válido no formato
{"reply":"..."}. Use somente o contexto informado. Não invente comando executado e não diga
que uma alteração ocorreu. Quando novas evidências forem necessárias, oriente o operador a pedir
uma nova validação.
""".strip() + "\n\nDADOS:\n" + json.dumps(
            redact_object({"question": message, "session": self._prior_context()}),
            ensure_ascii=False,
            default=str,
        )
        provider = get_provider(self.provider_name, self.settings, self.provider_model)
        payload, _ = provider.generate_json(redact_text(prompt))
        reply = str(payload.get("reply") or "Não foi possível formular uma resposta com as evidências atuais.")
        self._remember("assistant", reply, kind="answer")
        return reply

    def execute_last_proposal(self, *, requested_by: str | None = None) -> dict[str, Any]:
        result = self.last_result or {}
        investigation_id = str(result.get("investigation_id") or "")
        token = str(result.get("approval_token") or "")
        if not investigation_id or not token:
            raise RuntimeError("não existe proposta revisada e autorizável nesta sessão")
        execution = execute_approved_investigation(
            investigation_id,
            token,
            requested_by=requested_by,
            settings=self.settings,
        )
        self._remember("assistant", "Execução aprovada concluída.", kind="execution", result=execution)
        return execution

    def switch_target(
        self,
        target: str,
        *,
        environment: EnvironmentType = EnvironmentType.UNKNOWN,
        ssh_port: int | None = None,
    ) -> None:
        previous = self.target
        self.target = target
        self.environment = environment
        self.ssh_port = ssh_port
        self.last_result = None
        self._remember("system", f"Servidor alterado de {previous} para {target}.", kind="switch_target")

    def close(self) -> None:
        self.active = False
        self._remember("system", "Sessão encerrada pelo operador.", kind="exit")
