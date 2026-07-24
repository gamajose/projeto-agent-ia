from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict
from typing import Any

from app.core.policies import EnvironmentType
from app.services.ai_providers import get_provider
from app.services.discovery import _clean, discover_host
from app.services.persistence import recurrence_history, save_incident, upsert_host
from app.services.ssh import SSHExecutor


FILESYSTEM_RULES = """
Você é um analista AIOps especializado em filesystem Linux.
Responda exclusivamente em JSON válido.
Use somente as evidências fornecidas e cite os comandos que sustentam cada conclusão.
Não invente falha de DNS, aplicação, banco de dados ou rede sem evidência direta.
Nunca recomende reboot, remoção de arquivos, rm, truncate, limpeza automática, formatação,
redimensionamento, desmontagem, fsck online ou qualquer ação destrutiva.
O fluxo é de diagnóstico seguro: identifique utilização de blocos, inodes, tipo do filesystem,
montagem, maiores diretórios, arquivos abertos removidos, erros de I/O, estado de LVM e fstab.
Quando houver filesystem cheio, diferencie: consumo real de arquivos, inodes esgotados,
arquivos removidos ainda abertos, erro de montagem, filesystem somente leitura ou indício de I/O.
Campos obrigatórios: summary, classification, probable_cause, confidence, evidence_used,
recommended_read_only_checks, remediation, validation_steps, ticket_report.
classification deve ser: identical_recurrence, similar_recurrence, new_behavior ou inconclusive.
remediation deve ser uma lista. Como este módulo não remove arquivos automaticamente,
use command vazio e descreva a ação manual recomendada quando houver risco.
Toda evidência deve mencionar o comando e o retorno relevante.
""".strip()


def _run(executor: SSHExecutor, command: str, environment: EnvironmentType, sudo: bool = False) -> dict[str, Any]:
    try:
        result = executor.run_sudo(command, environment) if sudo else executor.run(command, environment)
        return {
            "command": command,
            "exit_code": result.exit_code,
            "stdout": _clean(result.stdout),
            "stderr": _clean(result.stderr),
            "sudo": sudo,
        }
    except Exception as exc:
        return {"command": command, "exit_code": 255, "stdout": "", "stderr": str(exc), "sudo": sudo}


def _run_with_sudo_fallback(executor: SSHExecutor, command: str, environment: EnvironmentType) -> dict[str, Any]:
    result = _run(executor, command, environment)
    combined = (result["stdout"] + result["stderr"]).lower()
    denied = any(token in combined for token in (
        "permission denied", "operation not permitted", "access denied", "not permitted"
    ))
    return _run(executor, command, environment, sudo=True) if denied else result


def _filesystem_state(df_output: str, inode_output: str) -> tuple[str, int, int]:
    block_pct = 0
    inode_pct = 0
    for text, target in ((df_output, "block"), (inode_output, "inode")):
        matches = re.findall(r"(?:^|\s)(\d{1,3})%(?:\s|$)", text)
        value = max((int(item) for item in matches), default=0)
        if target == "block":
            block_pct = value
        else:
            inode_pct = value
    peak = max(block_pct, inode_pct)
    if peak >= 90:
        return "CRIT", block_pct, inode_pct
    if peak >= 80:
        return "WARN", block_pct, inode_pct
    return "OK", block_pct, inode_pct


def _deterministic_analysis(payload: dict[str, Any], ai_error: str = "") -> dict[str, Any]:
    checks = payload.get("checks", {})
    state = payload.get("state", "UNKNOWN")
    block_pct = int(payload.get("block_usage_percent") or 0)
    inode_pct = int(payload.get("inode_usage_percent") or 0)
    mountpoint = str(payload.get("mountpoint") or "/")

    deleted_text = str((checks.get("deleted_open_files") or {}).get("stdout") or "").strip()
    errors_text = (
        str((checks.get("kernel_filesystem_errors") or {}).get("stdout") or "")
        + "\n"
        + str((checks.get("journal_filesystem_errors") or {}).get("stdout") or "")
    ).lower()
    readonly_text = str((checks.get("findmnt") or {}).get("stdout") or "").lower()

    evidence: list[str] = []
    probable = "Não foi possível determinar uma causa única com segurança."
    confidence = 55

    if inode_pct >= 90:
        probable = f"O filesystem {mountpoint} apresenta esgotamento de inodes ({inode_pct}%)."
        confidence = 95
        evidence.append(f"df -iP {mountpoint}: uso de inodes em {inode_pct}%.")
    elif block_pct >= 90:
        probable = f"O filesystem {mountpoint} apresenta utilização crítica de blocos ({block_pct}%)."
        confidence = 92
        evidence.append(f"df -hTP {mountpoint}: utilização em {block_pct}%.")
    elif block_pct >= 80 or inode_pct >= 80:
        probable = f"O filesystem {mountpoint} está próximo do limite operacional."
        confidence = 88
        evidence.append(f"df/df -i: blocos {block_pct}% e inodes {inode_pct}%.")
    else:
        probable = f"Não foi identificado consumo crítico de blocos ou inodes em {mountpoint}."
        confidence = 85
        evidence.append(f"df/df -i: blocos {block_pct}% e inodes {inode_pct}%.")

    if deleted_text:
        probable += " Há arquivos removidos ainda mantidos abertos por processos, que podem continuar ocupando espaço."
        confidence = max(confidence, 96)
        evidence.append("lsof +L1 retornou arquivos removidos ainda abertos.")
    if any(token in errors_text for token in ("i/o error", "buffer i/o", "ext4-fs error", "xfs.*error", "read-only file system")):
        probable += " Também existem mensagens de kernel/journal compatíveis com erro de filesystem ou I/O."
        confidence = max(confidence, 93)
        evidence.append("dmesg/journalctl retornaram mensagens relacionadas a filesystem ou I/O.")
    if " ro," in readonly_text or " ro " in readonly_text:
        probable += " A montagem aparenta estar em modo somente leitura."
        confidence = max(confidence, 95)
        evidence.append("findmnt indicou opção de montagem ro.")

    return {
        "summary": f"Diagnóstico de filesystem concluído para {mountpoint}: estado {state}.",
        "classification": "new_behavior" if state in {"WARN", "CRIT"} else "inconclusive",
        "probable_cause": probable,
        "confidence": confidence,
        "evidence_used": evidence,
        "recommended_read_only_checks": [
            f"df -hTP {shlex.quote(mountpoint)}",
            f"df -iP {shlex.quote(mountpoint)}",
            f"du -x -h --max-depth=1 {shlex.quote(mountpoint)} | sort -h",
            "lsof +L1",
        ],
        "remediation": [],
        "validation_steps": [
            f"Reexecutar df -hTP {mountpoint} e df -iP {mountpoint} após a tratativa manual.",
            "Confirmar ausência de novos erros de I/O no journal e no dmesg.",
        ],
        "ticket_report": (
            f"Foi realizada análise detalhada do filesystem {mountpoint}. "
            f"A utilização observada foi de {block_pct}% em blocos e {inode_pct}% em inodes. "
            f"Conclusão: {probable} Nenhuma remoção automática de arquivos foi executada."
        ),
        "analysis_source": "deterministic_fallback",
        "ai_error": ai_error,
    }


def _analyze_with_ai(payload: dict[str, Any]) -> dict[str, Any]:
    prompt = FILESYSTEM_RULES + "\n\nEVIDÊNCIAS:\n" + json.dumps(payload, ensure_ascii=False, default=str)
    try:
        provider = get_provider()
        result, _ = provider.generate_json(prompt)
        result["ai_model"] = provider.model
        result["ai_provider"] = provider.name
        result["analysis_source"] = provider.name
        return result
    except Exception as exc:
        return _deterministic_analysis(payload, f"{type(exc).__name__}: {exc}")

def run_filesystem_diagnosis(
    *,
    executor: SSHExecutor,
    vpn_ip: str,
    ssh_port: int,
    host_type: str,
    environment: EnvironmentType,
    mountpoint: str,
) -> dict[str, Any]:
    info = discover_host(executor, environment)
    quoted_mount = shlex.quote(mountpoint)

    checks: dict[str, dict[str, Any]] = {
        "df_blocks": _run(executor, f"df -hTP {quoted_mount}", environment),
        "df_inodes": _run(executor, f"df -iP {quoted_mount}", environment),
        "findmnt": _run(executor, f"findmnt -T {quoted_mount} -o TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,USED,AVAIL,USE%", environment),
        "lsblk": _run(executor, "lsblk -o NAME,TYPE,FSTYPE,SIZE,FSAVAIL,FSUSE%,MOUNTPOINTS,UUID", environment),
        "top_directories": _run_with_sudo_fallback(
            executor,
            f"timeout 90 du -x -h --max-depth=1 {quoted_mount} 2>/dev/null | sort -h | tail -n 30",
            environment,
        ),
        "top_files": _run_with_sudo_fallback(
            executor,
            f"timeout 90 find {quoted_mount} -xdev -type f -printf '%s %p\\n' 2>/dev/null | sort -nr | head -n 30",
            environment,
        ),
        "deleted_open_files": _run_with_sudo_fallback(
            executor,
            "timeout 45 lsof -nP +L1 2>/dev/null | head -n 80 || true",
            environment,
        ),
        "kernel_filesystem_errors": _run_with_sudo_fallback(
            executor,
            "dmesg -T 2>/dev/null | grep -Ei 'I/O error|buffer I/O|EXT[234]-fs error|XFS.*error|read-only file system|filesystem.*error' | tail -n 120 || true",
            environment,
        ),
        "journal_filesystem_errors": _run_with_sudo_fallback(
            executor,
            "journalctl --no-pager -k --since '-24 hours' 2>/dev/null | grep -Ei 'I/O error|buffer I/O|EXT[234]-fs error|XFS.*error|read-only file system|filesystem.*error' | tail -n 120 || true",
            environment,
        ),
        "fstab": _run(executor, "grep -Ev '^\\s*(#|$)' /etc/fstab 2>/dev/null || true", environment),
        "lvm": _run_with_sudo_fallback(
            executor,
            "pvs --units g 2>/dev/null; echo '--- VGS ---'; vgs --units g 2>/dev/null; echo '--- LVS ---'; lvs -a -o lv_name,vg_name,lv_size,data_percent,metadata_percent,devices --units g 2>/dev/null || true",
            environment,
        ),
    }

    state, block_pct, inode_pct = _filesystem_state(
        checks["df_blocks"]["stdout"], checks["df_inodes"]["stdout"]
    )
    host_row = upsert_host(
        host_type=host_type,
        vpn_ip=vpn_ip,
        ssh_port=ssh_port,
        hostname=info.hostname,
        os_name=info.os_name,
        environment=environment.value,
        internal_ips=info.ip_brief.splitlines(),
    )

    history = recurrence_history(checkmk_host=info.hostname, service_name=f"Filesystem {mountpoint}")
    evidence = {
        "module": "filesystem",
        "identity": asdict(info),
        "mountpoint": mountpoint,
        "state": state,
        "block_usage_percent": block_pct,
        "inode_usage_percent": inode_pct,
        "checks": checks,
        "history": history,
        "security_policy": {
            "read_only_diagnostics": "allowed",
            "automatic_file_deletion": "always_denied",
            "filesystem_format_resize_unmount": "always_denied",
            "host_reboot": "always_denied",
        },
    }
    analysis = _analyze_with_ai(evidence)
    incident_id = save_incident(
        affected_host_id=host_row.id,
        site_name=None,
        checkmk_host=info.hostname,
        service_name=f"Filesystem {mountpoint}",
        state=state,
        normalized_output=json.dumps(
            {"block_usage_percent": block_pct, "inode_usage_percent": inode_pct},
            ensure_ascii=False,
        ),
        evidence=evidence,
        analysis=analysis,
    )

    return {
        "incident_id": incident_id,
        "hostname": info.hostname,
        "mountpoint": mountpoint,
        "state": state,
        "block_usage_percent": block_pct,
        "inode_usage_percent": inode_pct,
        "recurrences": len(history),
        "analysis": analysis,
        "checks": checks,
        "evidence": evidence,
    }
