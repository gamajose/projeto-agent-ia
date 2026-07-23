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
    r"\bvalid(?:a|ar|e|em|acao|ação|ando|ado|ada)?\b",
    r"\bverific(?:a|ar|e|em|acao|ação|ando|ado|ada)?\b",
    r"\banalis(?:a|ar|e|em|ando|ado|ada|e)?\b",
    r"\binvestig(?:a|ar|e|em|acao|ação|ando|ado|ada)?\b",
    r"\bdiagnostic(?:a|ar|e|o|ar|ando|ado|ada)?\b",
    r"\bauditor(?:ia|ar|e|ando|ado|ada)?\b",
    r"\bconsult(?:a|ar|e|ando|ado|ada)?\b",
    r"\bchequ(?:e|ear|ando|ado|ada)?\b",
    r"\bsomente\s+(?:validar|verificar|analisar|investigar|diagnosticar|consultar)\b",
    r"\bapenas\s+(?:validar|verificar|analisar|investigar|diagnosticar|consultar)\b",
)


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def infer_operation_intent(text: str) -> OperationIntent:
    """Define o comportamento padrão do agente.

    Quando o pedido contém verbo explícito de observação em português, o agente
    apenas investiga e valida. Sem esses verbos, o objetivo é tratado como pedido
    de resolução completa, com correções seguras executadas automaticamente.
    """
    normalized = _normalize(text or "")
    for pattern in READ_ONLY_PATTERNS:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            return OperationIntent(
                mode="investigate",
                approve=False,
                read_only=True,
                reason="pedido contém verbo explícito de validação em português",
            )
    return OperationIntent(
        mode="correct",
        approve=True,
        read_only=False,
        reason="pedido operacional sem restrição explícita; executar correções seguras",
    )
