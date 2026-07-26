# Preflight dos provedores de IA

## Objetivo

O Agent valida a IA selecionada antes de resolver o alvo ou abrir SSH. Uma
falha de modelo, token, rota ou conectividade encerra a operação com uma
mensagem em português e orienta o uso de:

```bash
agent doctor ai
```

Não existe fallback silencioso para outro provedor ou modelo.

## Estados

| Estado | Significado |
|---|---|
| `available` | endpoint, credencial, modelo/rota e JSON foram validados |
| `unavailable` | endpoint não respondeu, recusou conexão ou excedeu timeout |
| `misconfigured` | token, modelo ou rota foram recusados ou não existem |
| `degraded` | serviço respondeu, mas parte da resposta ou das rotas é inválida |
| `not_configured` | a credencial obrigatória não está configurada |

## Ollama

O preflight:

1. consulta `GET /api/tags`;
2. exige correspondência exata com `OLLAMA_MODEL`;
3. executa uma geração JSON mínima;
4. valida que a resposta confirma o teste.

Um modelo semelhante, mas com tag diferente, não é aceito automaticamente.

## OmniRoute

Existem duas camadas de credenciais:

1. credenciais dos provedores conectados, armazenadas no OmniRoute;
2. `OMNIROUTE_API_KEY`, token local do endpoint usado pelo Agent.

O Agent consulta `GET /v1/models` e só permite rotas publicadas por esse
endpoint. Configure ao menos uma rota:

```env
OMNIROUTE_DEFAULT_ROUTE=auto/coding
OMNIROUTE_ROUTES=Código=auto/coding,Rápido=auto/fast
```

## Provedores diretos

Gemini, Groq e OpenRouter exigem a API key correspondente. Quando configurados,
o preflight realiza uma geração JSON mínima usando exatamente o modelo
declarado.

## Timeout e segurança

```env
AI_PREFLIGHT_TIMEOUT_SECONDS=8
```

O diagnóstico nunca inclui credenciais, headers, prompts operacionais ou
payloads completos de erro. Os testes usam mocks e não dependem de serviços
reais.
