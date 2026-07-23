from __future__ import annotations

import re
from typing import Any


def _number(value: str) -> float | None:
    try:
        return float(value.replace(",", "."))
    except (TypeError, ValueError):
        return None


def parse_free(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0].rstrip(":").lower() == "mem" and len(parts) >= 7:
            result["memory"] = dict(zip(("total", "used", "free", "shared", "buff_cache", "available"), parts[1:7]))
        elif parts[0].rstrip(":").lower() == "swap" and len(parts) >= 4:
            result["swap"] = dict(zip(("total", "used", "free"), parts[1:4]))
    return result


def parse_df(text: str) -> dict[str, Any]:
    filesystems: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip() or line.lower().startswith("filesystem") or line.lower().startswith("sist. arq"):
            continue
        parts = line.split()
        percent_index = next((i for i, value in enumerate(parts) if re.fullmatch(r"\d+%", value)), None)
        if percent_index is None or len(parts) <= percent_index + 1:
            continue
        filesystems.append({
            "filesystem": parts[0],
            "size": parts[1] if len(parts) > 1 else None,
            "used": parts[2] if len(parts) > 2 else None,
            "available": parts[3] if len(parts) > 3 else None,
            "used_percent": int(parts[percent_index].rstrip("%")),
            "mount": parts[-1],
        })
    return {"filesystems": filesystems}


def parse_uptime(text: str) -> dict[str, Any]:
    match = re.search(r"load average[s]?:\s*([\d.,]+)[, ]+([\d.,]+)[, ]+([\d.,]+)", text, re.IGNORECASE)
    if not match:
        return {}
    return {"load_1m": _number(match.group(1)), "load_5m": _number(match.group(2)), "load_15m": _number(match.group(3))}


def parse_nproc(text: str) -> dict[str, Any]:
    match = re.search(r"^\s*(\d+)\s*$", text, re.MULTILINE)
    return {"cpu_count": int(match.group(1))} if match else {}


def parse_vmstat(text: str) -> dict[str, Any]:
    rows: list[dict[str, float]] = []
    headers: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if "swpd" in parts and "free" in parts and "id" in parts:
            headers = parts
            continue
        if headers and len(parts) == len(headers) and all(re.fullmatch(r"-?\d+(?:\.\d+)?", value) for value in parts):
            rows.append({key: float(value) for key, value in zip(headers, parts)})
    sample_rows = rows[1:] if len(rows) > 1 else rows
    if not sample_rows:
        return {}
    averages = {key: round(sum(row[key] for row in sample_rows) / len(sample_rows), 2) for key in headers}
    return {"samples": len(sample_rows), "averages": averages}


def parse_iostat(text: str) -> dict[str, Any]:
    devices: list[dict[str, Any]] = []
    headers: list[str] = []
    in_devices = False
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0].lower().startswith("device"):
            headers = [value.rstrip(":") for value in parts]
            in_devices = True
            continue
        if in_devices and headers and len(parts) == len(headers):
            row: dict[str, Any] = {headers[0]: parts[0]}
            for key, value in zip(headers[1:], parts[1:]):
                row[key] = _number(value)
            devices.append(row)
    return {"devices": devices}


def normalize_evidence(command: str, stdout: str) -> dict[str, Any]:
    first = command.strip().split()[0] if command.strip() else ""
    if first == "free":
        return parse_free(stdout)
    if first == "df":
        return parse_df(stdout)
    if first == "uptime":
        return parse_uptime(stdout)
    if first == "nproc":
        return parse_nproc(stdout)
    if first == "vmstat":
        return parse_vmstat(stdout)
    if first == "iostat":
        return parse_iostat(stdout)
    return {}


def deterministic_signals(normalized_items: list[dict[str, Any]], thresholds: dict[str, int]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for item in normalized_items:
        command = item.get("command", "")
        data = item.get("normalized") or {}
        for fs in data.get("filesystems", []):
            used = fs.get("used_percent")
            if used is None:
                continue
            status = "critical" if used >= thresholds["filesystem_critical"] else "attention" if used >= thresholds["filesystem_warning"] else "healthy"
            signals.append({"area": "disk", "status": status, "statement": f"Filesystem {fs.get('mount')} com {used}% de uso.", "command": command, "value": used})
        uptime = data.get("load_1m")
        cpu_count = data.get("cpu_count")
        if uptime is not None and cpu_count:
            ratio = round(float(uptime) / max(int(cpu_count), 1), 2)
            status = "critical" if ratio >= thresholds["load_critical_ratio"] else "attention" if ratio >= thresholds["load_warning_ratio"] else "healthy"
            signals.append({"area": "cpu", "status": status, "statement": f"Load de 1 minuto por CPU: {ratio}.", "command": command, "value": ratio})
    return signals
