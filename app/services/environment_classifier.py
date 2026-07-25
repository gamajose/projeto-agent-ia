from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.policies import EnvironmentType


@dataclass(frozen=True)
class EnvironmentClassification:
    environment: EnvironmentType
    source: str
    confidence: int
    reason: str

    @property
    def trusted_for_changes(self) -> bool:
        return self.confidence >= 90 and self.environment in {
            EnvironmentType.MONITORING,
            EnvironmentType.TRAINING,
        }


def classify_environment(
    *,
    requested: EnvironmentType = EnvironmentType.UNKNOWN,
    inventory_environment: str | None = None,
    hostname: str | None = None,
    objective: str = "",
) -> EnvironmentClassification:
    if requested != EnvironmentType.UNKNOWN:
        return EnvironmentClassification(requested, "operator", 100, "ambiente informado explicitamente pelo operador")

    if inventory_environment:
        try:
            stored = EnvironmentType(inventory_environment)
        except ValueError:
            stored = EnvironmentType.UNKNOWN
        if stored != EnvironmentType.UNKNOWN:
            return EnvironmentClassification(stored, "inventory", 100, "ambiente confirmado no inventário persistente")

    text = f"{hostname or ''} {objective}".casefold()
    rules: tuple[tuple[EnvironmentType, int, tuple[str, ...], str], ...] = (
        (EnvironmentType.TRAINING, 75, ("training", "treinamento", "laboratorio", "lab-", "homolog"), "marcadores de treinamento/laboratório"),
        (EnvironmentType.STANDBY, 75, ("standby", "stand-by", "secundario", "secondary", "-std", "_std"), "marcadores de standby"),
        (EnvironmentType.PRODUCTION, 75, ("production", "producao", "prod", "primary", "primario"), "marcadores de produção"),
        (EnvironmentType.MONITORING, 70, ("monitor", "checkmk", "check-mk", "omd", "zabbix", "prometheus"), "marcadores de monitoramento"),
    )
    for environment, confidence, markers, reason in rules:
        if any(re.search(rf"(^|[^a-z0-9]){re.escape(marker)}([^a-z0-9]|$)", text) for marker in markers):
            return EnvironmentClassification(environment, "heuristic", confidence, reason)

    return EnvironmentClassification(
        EnvironmentType.UNKNOWN,
        "unclassified",
        0,
        "nenhuma evidência confiável de ambiente foi encontrada",
    )
