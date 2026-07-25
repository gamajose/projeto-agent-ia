from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from app.services.ai_providers import get_provider
from app.services.redaction import redact_object, redact_text


@dataclass(frozen=True)
class SessionIntent:
    name: str
    target: str | None = None
    reply: str | None = None
    reason: str = ""


_EXIT_RE = re.compile(r"^\s*(?:/)?(?:exit|quit|sair|encerrar|finalizar|desconectar)(?:\s+(?:sess[aã]o|servidor))?[.!]?\s*$", re.I)
_STATUS_RE = re.compile(r"^\s*/?(?:status|estado|resumo)\s*$", re.I)
_EVIDENCE_RE = re.compile(r"^\s*/?(?:evid[eê]ncias?|evidence|coletas?|resultados?)\s*$", re.I)
_PROPOSAL_RE = re.compile(r"^\s*/?(?:proposta|a[cç][aã]o|corre[cç][aã]o)\s*$", re.I)
_HELP_RE = re.compile(r"^\s*/?(?:ajuda|help|comandos)\s*$", re.I)
_EXECUTE_RE = re.compile(r"\b(?:arrume|corrija|corrigir|execute|aplique|fa[cç]a\s+a\s+corre[cç][aã]o|pode\s+resolver)\b", re.I)
_SWITCH_RE = re.compile(r"\b(?:trocar|mudar|conectar|conecte|acesse|ir)\b.*\b(?:servidor|srv|host|ip)\b", re.I)
_RESTART_RE = re.compile(r"\b(?:restart|reinicie|reiniciar|recupere|suba|inicie)\b.*\b(?:servi[cç]o|service|socket|omd)\b", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HOST_AFTER_RE = re.compile(r"\b(?:servidor|srv|host|ip)\s+([A-Za-z0-9_.:-]+)", re.I)


def _extract_target(message: str) -> str | None:
    match = _IP_RE.search(message)
    if match:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    match = _HOST_AFTER_RE.search(message)
    if match:
        return match.group(1).rstrip(".,;:")
    return None


def detect_local_intent(message: str) -> SessionIntent | None:
    text = (message or "").strip()
    if not text:
        return SessionIntent("empty", reason="mensagem vazia")
    if _EXIT_RE.fullmatch(text):
        return SessionIntent("exit", reason="comando de encerramento reconhecido")
    if _STATUS_RE.fullmatch(text):
        return SessionIntent("show_status", reason="consulta de status")
    if _EVIDENCE_RE.fullmatch(text):
        return SessionIntent("show_evidence", reason="consulta de evidências")
    if _PROPOSAL_RE.fullmatch(text):
        return SessionIntent("show_proposal", reason="consulta de proposta")
    if _HELP_RE.fullmatch(text):
        return SessionIntent("help", reason="consulta de ajuda")
    if _SWITCH_RE.search(text):
        return SessionIntent("switch_target", target=_extract_target(text), reason="troca de servidor solicitada")
    if _EXECUTE_RE.search(text):
        return SessionIntent("execute_proposal", reason="execução da proposta atual solicitada")
    if _RESTART_RE.search(text):
        return SessionIntent("propose_specific_action", reason="ação específica precisa ser validada e proposta antes da execução")
    return None


_INTENT_RULES = """
Você classifica mensagens de uma sessão operacional AIOps. Responda somente JSON válido.
Nunca autorize execução direta. Pedido de restart, recuperação ou alteração específica deve ser
classificado como propose_specific_action para que o agente valide e proponha antes.
Intenções permitidas:
- investigate_more: novas validações ou coleta no servidor atual
- propose_specific_action: pedido de ação específica que ainda precisa ser validado
- execute_proposal: executar a última proposta já revisada
- switch_target: trocar de servidor
- show_status: mostrar resumo atual
- show_evidence: mostrar coletas
- show_proposal: mostrar proposta
- general_question: responder usando o contexto, sem executar ferramenta
- exit: encerrar a sessão
Formato:
{"intent":"...","target":null,"reply":"...","reason":"..."}
""".strip()


def classify_session_message(
    message: str,
    *,
    provider_name: str,
    state: dict[str, Any],
) -> SessionIntent:
    local = detect_local_intent(message)
    if local is not None:
        return local

    prompt = _INTENT_RULES + "\n\nDADOS:\n" + json.dumps(
        redact_object({"message": message, "session_state": state}),
        ensure_ascii=False,
        default=str,
    )
    try:
        provider = get_provider(provider_name)
        payload, _ = provider.generate_json(redact_text(prompt))
    except Exception as exc:
        return SessionIntent(
            "investigate_more",
            reason=f"classificador indisponível; mensagem tratada como nova validação ({type(exc).__name__})",
        )

    allowed = {
        "investigate_more",
        "propose_specific_action",
        "execute_proposal",
        "switch_target",
        "show_status",
        "show_evidence",
        "show_proposal",
        "general_question",
        "exit",
    }
    name = str(payload.get("intent") or "investigate_more")
    if name not in allowed:
        name = "investigate_more"
    target = str(payload.get("target") or "").strip() or _extract_target(message)
    return SessionIntent(
        name,
        target=target or None,
        reply=str(payload.get("reply") or "").strip() or None,
        reason=str(payload.get("reason") or "").strip(),
    )
