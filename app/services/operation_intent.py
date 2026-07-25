from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class OperationIntent:
    mode: str
    approve: bool
    read_only: bool
    reason: str


READ_ONLY_PATTERNS = (
    r"\bvalid(?:a|ar|e|em|acao|ando|ado|ada)?\b",
    r"\bverific(?:a|ar|e|em|acao|ando|ado|ada)?\b",
    r"\banalis(?:a|ar|e|em|ando|ado|ada)?\b",
    r"\binvestig(?:a|ar|ue|uem|acao|ando|ado|ada)?\b",
    r"\bdiagnostic(?:a|ar|e|o|ando|ado|ada)?\b",
    r"\bauditor(?:ia|ar|e|ando|ado|ada)?\b",
    r"\bconsult(?:a|ar|e|ando|ado|ada)?\b",
    r"\bchequ(?:e|ear|ando|ado|ada)?\b",
    r"\bsomente\s+(?:validar|verificar|analisar|investigar|diagnosticar|consultar)\b",
    r"\bapenas\s+(?:validar|verificar|analisar|investigar|diagnosticar|consultar)\b",
)

CORRECTION_PATTERNS = (
    r"\bcorrij(?:a|am|ir)\b",
    r"\bresolv(?:a|am|er)\b",
    r"\barrum(?:e|em|ar)\b",
    r"\brecuper(?:e|em|ar)\b",
    r"\bnormaliz(?:e|em|ar)\b",
)


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def infer_operation_intent(text: str) -> OperationIntent:
    """Interpreta o texto sem transformar ambiguidade em autorização.

    O modo padrão é ``propose``: o agente investiga e prepara uma correção, mas
    não a executa. Somente ``--modo corrigir`` pode autorizar a etapa corretiva.
    """
    normalized = _normalize(text or "")
    for pattern in READ_ONLY_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            return OperationIntent(
                mode="investigate",
                approve=False,
                read_only=True,
                reason="pedido contém verbo explícito de validação; operação somente leitura",
            )
    for pattern in CORRECTION_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            return OperationIntent(
                mode="propose",
                approve=False,
                read_only=False,
                reason="pedido solicita correção, mas execução exige --modo corrigir e ambiente autorizado",
            )
    return OperationIntent(
        mode="propose",
        approve=False,
        read_only=False,
        reason="pedido operacional ambíguo; investigar e propor é o comportamento seguro padrão",
    )
