from __future__ import annotations

import re
from typing import Any

VALID_STATES = {"OK", "WARN", "WARNING", "CRIT", "CRITICAL", "UNKNOWN", "PENDING"}
STATE_NORMALIZATION = {"WARNING": "WARN", "CRITICAL": "CRIT"}


def _normalize_state(value: str) -> str:
    state = value.strip().upper()
    return STATE_NORMALIZATION.get(state, state)


def _service_key(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip()).casefold()


def _upsert(target: dict[str, dict[str, Any]], name: str, state: str, output: str, source: str) -> None:
    normalized = _normalize_state(state)
    if normalized not in {"OK", "WARN", "CRIT", "UNKNOWN", "PENDING"}:
        return
    clean_name = re.sub(r"\s+", " ", name.strip(" ;:\t"))
    if not clean_name:
        return
    key = _service_key(clean_name)
    target[key] = {
        "service": clean_name,
        "state": normalized,
        "output": output.strip(),
        "source": source,
    }


def _parse_nagios(text: str, target: dict[str, dict[str, Any]]) -> None:
    # SERVICE ALERT: host;service;STATE;HARD;attempt;output
    alert_re = re.compile(
        r"(?:SERVICE ALERT|CURRENT SERVICE STATE|INITIAL SERVICE STATE):\s*"
        r"[^;]+;(?P<service>[^;]+);(?P<state>OK|WARNING|WARN|CRITICAL|CRIT|UNKNOWN|PENDING);"
        r"[^;]*;[^;]*;(?P<output>.*)$",
        re.I,
    )
    for line in text.splitlines():
        match = alert_re.search(line)
        if match:
            _upsert(target, match.group("service"), match.group("state"), match.group("output"), "nagios.log")


def _parse_cmk_vvn(text: str, target: dict[str, dict[str, Any]]) -> None:
    patterns = [
        # Common verbose formats: "Service name OK - output" or "Service name: CRIT - output"
        re.compile(
            r"^(?P<service>.+?)\s*[:|]\s*(?P<state>OK|WARNING|WARN|CRITICAL|CRIT|UNKNOWN|PENDING)\b\s*[-:]?\s*(?P<output>.*)$",
            re.I,
        ),
        re.compile(
            r"^(?P<service>.+?)\s{2,}(?P<state>OK|WARNING|WARN|CRITICAL|CRIT|UNKNOWN|PENDING)\b\s*[-:]?\s*(?P<output>.*)$",
            re.I,
        ),
        re.compile(
            r"^\s*(?P<state>OK|WARNING|WARN|CRITICAL|CRIT|UNKNOWN|PENDING)\s*[-:]\s*(?P<service>[^:]+?)(?:\s*[-:]\s*(?P<output>.*))?$",
            re.I,
        ),
    ]
    ignored = ("executing", "trying", "successfully", "cached", "piggyback", "checking host")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(ignored):
            continue
        for pattern in patterns:
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                _upsert(
                    target,
                    groups.get("service") or "",
                    groups.get("state") or "",
                    groups.get("output") or "",
                    "cmk -vvn",
                )
                break


def extract_services(checkmk_data: dict[str, Any]) -> list[dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}
    for finding in checkmk_data.get("findings") or []:
        if not finding.get("found"):
            continue
        nagios = finding.get("nagios_logs") or {}
        _parse_nagios(str(nagios.get("stdout") or "") + "\n" + str(nagios.get("stderr") or ""), services)
        cmk = finding.get("cmk_vvn") or {}
        _parse_cmk_vvn(str(cmk.get("stdout") or "") + "\n" + str(cmk.get("stderr") or ""), services)
    return sorted(services.values(), key=lambda item: (item["state"] == "OK", item["service"].casefold()))


def compare_services(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    before_map = {_service_key(item["service"]): item for item in before}
    after_map = {_service_key(item["service"]): item for item in after}
    keys = sorted(set(before_map) | set(after_map))

    normalized: list[dict[str, Any]] = []
    still_affected: list[dict[str, Any]] = []
    new_issues: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for key in keys:
        old = before_map.get(key)
        new = after_map.get(key)
        old_state = old["state"] if old else "NOT_SEEN"
        new_state = new["state"] if new else "NOT_SEEN"
        record = {
            "service": (new or old or {}).get("service", key),
            "before": old_state,
            "after": new_state,
            "before_output": (old or {}).get("output", ""),
            "after_output": (new or {}).get("output", ""),
        }
        if old_state != "OK" and new_state == "OK":
            normalized.append(record)
        elif old_state in {"OK", "NOT_SEEN"} and new_state not in {"OK", "NOT_SEEN"}:
            new_issues.append(record)
        elif new_state not in {"OK", "NOT_SEEN"}:
            still_affected.append(record)
        elif old_state == new_state:
            unchanged.append(record)

    if new_issues or still_affected:
        resolution = "partially_resolved" if normalized else "not_resolved"
    elif normalized:
        resolution = "resolved"
    elif before or after:
        resolution = "resolved" if all(item["state"] == "OK" for item in after) else "inconclusive"
    else:
        resolution = "inconclusive"

    return {
        "resolution": resolution,
        "before": before,
        "after": after,
        "normalized": normalized,
        "still_affected": still_affected,
        "new_issues": new_issues,
        "unchanged": unchanged,
    }


def build_service_state_report(evidence: dict[str, Any]) -> dict[str, Any]:
    before = extract_services(evidence.get("checkmk") or {})
    post = evidence.get("post_validation") or {}
    after_data = post.get("checkmk")
    after = extract_services(after_data or {}) if after_data else before
    return compare_services(before, after)
