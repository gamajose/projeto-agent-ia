from __future__ import annotations

import re
from collections import Counter
from typing import Any

from sqlalchemy import select

from app.db.base import SessionLocal
from app.db.models import InvestigationORM


STOP_WORDS = {
    "para", "com", "uma", "uns", "das", "dos", "que", "por", "sem", "nos", "nas",
    "servidor", "server", "srv", "host", "validar", "verificar", "problema", "erro",
    "esta", "está", "esse", "essa", "isso", "aqui", "como", "mais", "entre", "sobre",
}


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9_.:-]{3,}", (value or "").casefold())
        if token not in STOP_WORDS
    }


def _playbook_id(plans: list[dict[str, Any]] | None) -> str | None:
    for plan in plans or []:
        playbook = plan.get("playbook") or {}
        if isinstance(playbook, dict) and playbook.get("id"):
            return str(playbook["id"])
    return None


def _infer_category_component(text: str, profile: str | None) -> tuple[str, str]:
    lowered = (text or "").casefold()
    if any(token in lowered for token in ("snmp", "oid", "porta 161", "sysdescr")):
        if "idrac" in lowered or "racadm" in lowered:
            return "monitoring", "idrac"
        if "ilo" in lowered:
            return "monitoring", "ilo"
        if "ipmi" in lowered:
            return "monitoring", "ipmi"
        if "fortigate" in lowered:
            return "monitoring", "fortigate-snmp"
        if "pfsense" in lowered or "bsnmpd" in lowered:
            return "monitoring", "pfsense-snmp"
        return "monitoring", "snmp"
    if any(token in lowered for token in ("checkmk", "check mk", "omd", "cmk ")):
        return "monitoring", "checkmk"
    if any(token in lowered for token in ("filesystem", "inode", "disco", "partição", "particao")):
        return "filesystem", "linux-filesystem"
    if any(token in lowered for token in ("swap", "memória", "memoria", "ram")):
        return "resources", "memory"
    if any(token in lowered for token in ("ssh", "reset by peer", "permission denied")):
        return "network", "ssh"
    if any(token in lowered for token in ("vpn", "túnel", "tunel", "openvpn", "ipsec")):
        return "network", "vpn"
    return "other", profile or "generic"


def _successful_tools(evidence: list[dict[str, Any]], corrections: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for item in [*(evidence or []), *(corrections or [])]:
        status = str(item.get("status") or "")
        exit_code = item.get("exit_code")
        if status not in {"executed", "validated"} or exit_code not in {0, None}:
            continue
        name = str(item.get("tool") or item.get("command") or "").strip()
        if name and name not in names:
            names.append(name[:300])
    return names[:20]


def build_operational_memory(
    *,
    objective: str,
    profile: str | None,
    playbook_id: str | None,
    analysis: dict[str, Any],
    evidence: list[dict[str, Any]],
    corrections: list[dict[str, Any]] | None = None,
    target: str | None = None,
    hostname: str | None = None,
) -> dict[str, Any]:
    corrections = corrections or []
    status = str(analysis.get("status") or "inconclusive")
    confidence = int(analysis.get("confidence") or 0)
    probable_cause = str(analysis.get("probable_cause") or "").strip()
    conclusion = str(analysis.get("conclusion") or analysis.get("summary") or "").strip()
    combined = " ".join((objective, probable_cause, conclusion, profile or ""))
    category, component = _infer_category_component(combined, profile)
    correction_validated = any(str(item.get("status") or "") == "validated" for item in corrections)

    if correction_validated or (status == "healthy" and confidence >= 80):
        validation_state = "verified"
    elif status in {"healthy", "attention", "critical"} and confidence >= 70:
        validation_state = "useful"
    elif status != "inconclusive" and confidence >= 40:
        validation_state = "candidate"
    else:
        validation_state = "inconclusive"

    tags = sorted(_tokens(combined))[:60]
    return {
        "version": 1,
        "category": category,
        "component": component,
        "profile": profile,
        "playbook_id": playbook_id,
        "target": target,
        "hostname": hostname,
        "symptom": objective[:2000],
        "probable_cause": probable_cause[:2000],
        "resolution_summary": conclusion[:2000],
        "outcome_status": status,
        "confidence": confidence,
        "validation_state": validation_state,
        "resolved": correction_validated or status == "healthy",
        "successful_tools": _successful_tools(evidence, corrections),
        "tags": tags,
    }


def _memory_from_row(row: InvestigationORM) -> dict[str, Any]:
    analysis = dict(row.analysis or {})
    memory = analysis.get("operational_memory")
    if isinstance(memory, dict) and memory:
        return dict(memory)
    return build_operational_memory(
        objective=row.objective,
        profile=row.profile,
        playbook_id=_playbook_id(row.plans),
        analysis=analysis,
        evidence=list(row.evidence or []),
        corrections=[],
        target=row.target,
        hostname=row.hostname,
    )


def _case_score(
    *,
    objective: str,
    profile: str | None,
    playbook_id: str | None,
    target: str | None,
    memory: dict[str, Any],
) -> float:
    wanted = _tokens(objective)
    current = _tokens(
        " ".join(
            (
                str(memory.get("symptom") or ""),
                str(memory.get("probable_cause") or ""),
                str(memory.get("resolution_summary") or ""),
                " ".join(str(item) for item in memory.get("tags") or []),
            )
        )
    )
    overlap = len(wanted & current) / max(1, len(wanted | current))
    score = overlap

    current_category, current_component = _infer_category_component(objective, profile)
    if memory.get("category") == current_category:
        score += 0.12
    if memory.get("component") == current_component:
        score += 0.12
    if profile and memory.get("profile") == profile:
        score += 0.12
    if playbook_id and memory.get("playbook_id") == playbook_id:
        score += 0.18
    if target and memory.get("target") == target:
        score += 0.10
    if memory.get("validation_state") == "verified":
        score += 0.12
    elif memory.get("validation_state") == "useful":
        score += 0.06
    score += min(int(memory.get("confidence") or 0), 100) / 1000
    return min(score, 1.0)


def search_operational_cases(
    *,
    objective: str,
    profile: str | None,
    playbook_id: str | None = None,
    target: str | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    try:
        with SessionLocal() as session:
            rows = session.scalars(
                select(InvestigationORM)
                .order_by(InvestigationORM.created_at.desc())
                .limit(500)
            ).all()
    except Exception:
        return []

    scored: list[tuple[float, InvestigationORM, dict[str, Any]]] = []
    for row in rows:
        memory = _memory_from_row(row)
        if memory.get("validation_state") not in {"verified", "useful"}:
            continue
        score = _case_score(
            objective=objective,
            profile=profile,
            playbook_id=playbook_id,
            target=target,
            memory=memory,
        )
        if score >= 0.25:
            scored.append((score, row, memory))

    scored.sort(key=lambda item: item[0], reverse=True)
    result: list[dict[str, Any]] = []
    for score, row, memory in scored[:limit]:
        result.append(
            {
                "id": str(row.id),
                "similarity": round(score, 3),
                "created_at": row.created_at.isoformat() if row.created_at else None,
                **memory,
            }
        )
    return result


def playbook_learning_summary(playbook_id: str | None, profile: str | None = None) -> dict[str, Any]:
    if not playbook_id:
        return {
            "playbook_id": None,
            "runs": 0,
            "conclusive_runs": 0,
            "verified_runs": 0,
            "conclusive_rate": 0.0,
            "common_causes": [],
            "successful_tools": [],
        }
    try:
        with SessionLocal() as session:
            rows = session.scalars(
                select(InvestigationORM)
                .order_by(InvestigationORM.created_at.desc())
                .limit(1000)
            ).all()
    except Exception:
        rows = []

    selected: list[dict[str, Any]] = []
    for row in rows:
        memory = _memory_from_row(row)
        if memory.get("playbook_id") != playbook_id:
            continue
        if profile and memory.get("profile") not in {profile, None, "any"}:
            continue
        selected.append(memory)

    runs = len(selected)
    conclusive = [item for item in selected if item.get("validation_state") in {"candidate", "useful", "verified"}]
    verified = [item for item in selected if item.get("validation_state") == "verified"]
    causes = Counter(
        str(item.get("probable_cause") or "").strip()
        for item in selected
        if str(item.get("probable_cause") or "").strip()
    )
    tools = Counter(
        str(tool)
        for item in selected
        if item.get("validation_state") in {"useful", "verified"}
        for tool in item.get("successful_tools") or []
    )
    return {
        "playbook_id": playbook_id,
        "runs": runs,
        "conclusive_runs": len(conclusive),
        "verified_runs": len(verified),
        "conclusive_rate": round(len(conclusive) / runs, 3) if runs else 0.0,
        "common_causes": [
            {"cause": cause, "count": count}
            for cause, count in causes.most_common(5)
        ],
        "successful_tools": [
            {"tool": tool, "count": count}
            for tool, count in tools.most_common(10)
        ],
    }


def recommended_playbook_id(objective: str, profile: str | None) -> str | None:
    cases = search_operational_cases(
        objective=objective,
        profile=profile,
        playbook_id=None,
        target=None,
        limit=3,
    )
    for case in cases:
        if float(case.get("similarity") or 0) >= 0.45 and case.get("playbook_id"):
            return str(case["playbook_id"])
    return None


def playbook_effectiveness_bonus(playbook_id: str, profile: str | None) -> int:
    summary = playbook_learning_summary(playbook_id, profile)
    runs = int(summary.get("runs") or 0)
    if runs < 2:
        return 0
    conclusive_rate = float(summary.get("conclusive_rate") or 0)
    verified_rate = int(summary.get("verified_runs") or 0) / max(1, runs)
    bonus = round(conclusive_rate * 15 + verified_rate * 5)
    return max(-10, min(20, bonus))
