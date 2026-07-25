from __future__ import annotations

from enum import StrEnum


class OperationMode(StrEnum):
    INVESTIGATE = "investigate"
    PROPOSE = "propose"
    CORRECT = "correct"

    @property
    def label(self) -> str:
        return {
            self.INVESTIGATE: "investigar",
            self.PROPOSE: "propor",
            self.CORRECT: "corrigir",
        }[self]

    @classmethod
    def from_cli(cls, value: str) -> "OperationMode":
        normalized = (value or "").strip().casefold()
        aliases = {
            "investigar": cls.INVESTIGATE,
            "investigate": cls.INVESTIGATE,
            "validar": cls.INVESTIGATE,
            "propor": cls.PROPOSE,
            "propose": cls.PROPOSE,
            "corrigir": cls.CORRECT,
            "correct": cls.CORRECT,
        }
        if normalized not in aliases:
            raise ValueError("modo deve ser investigar, propor ou corrigir")
        return aliases[normalized]
