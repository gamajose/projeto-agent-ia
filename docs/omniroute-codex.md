# OmniRoute e Codex CLI no Agent IA

## Papel de cada componente

O **OmniRoute não é uma IA ou um modelo**. Ele roda como um serviço separado na mesma VM ou em outro host confiável, expõe uma API compatível com OpenAI e encaminha as chamadas para provedores, modelos, rotas ou combos configurados no painel.

O **Codex CLI** é uma ferramenta interativa local. No Agent IA ele aparece no `agent --menu` e é iniciado diretamente no diretório configurado, sem exigir `cd` prévio.

Os dois recursos têm funções diferentes:

- OmniRoute: gateway centralizado para acessar outras IAs usando um único token no Agent;
- Codex CLI: agente de terminal aberto como processo interativo independente.

## Arquitetura recomendada

```text
Agent IA
   ↓ token do endpoint
OmniRoute
   ├── Gemini
   ├── Groq / Llama
   ├── OpenAI / GPT
   ├── Anthropic / Claude
   ├── OpenRouter
   └── rotas e combos definidos no painel
```

As chaves reais dos provedores ficam armazenadas no OmniRoute. O `.env` do Agent IA recebe somente o token do endpoint e a URL do gateway.

## Instalar e iniciar o OmniRoute

Instalação adotada pelo projeto:

```bash
npm install -g omniroute
omniroute setup
omniroute --no-open
```

Por padrão:

```text
Painel: http://127.0.0.1:20128
API:    http://127.0.0.1:20128/v1
```

No painel:

1. conecte somente provedores autorizados pela empresa;
2. crie um endpoint e copie a chave gerada;
3. configure modelos, rotas ou combos apropriados;
4. anote os identificadores das rotas que serão enviados no campo `model`;
5. teste o endpoint antes de habilitá-lo no Agent IA.

Para abrir o painel localmente por uma VM remota, use um túnel SSH autorizado:

```bash
ssh -L 20128:127.0.0.1:20128 jose@IP_DA_VM
```

Depois abra `http://127.0.0.1:20128` no navegador local.

## Configuração mínima no Agent IA

```env
OMNIROUTE_API_KEY=CHAVE_DO_ENDPOINT
OMNIROUTE_BASE_URL=http://127.0.0.1:20128/v1
OMNIROUTE_DEFAULT_ROUTE=auto/coding
```

O token local não substitui a credencial do provedor conectado ao OmniRoute.
Para o gateway ficar selecionável, ele precisa possuir ao menos um
provedor/modelo conectado e a rota configurada precisa aparecer em
`GET /v1/models`.

## Rotas exibidas no menu

Para cadastrar atalhos amigáveis:

```env
OMNIROUTE_ROUTES=Código=auto/coding,Rápido=auto/fast,Econômico=auto/cheap,Inteligente=auto/smart
```

Formato de cada item:

```text
Nome amigável=identificador enviado ao OmniRoute
```

O identificador precisa corresponder a uma rota, modelo ou combo existente no gateway.

Também é possível selecionar **Informar outra rota manualmente** no menu. Esse valor vale apenas para a operação atual e não altera o `.env`.

## Rota padrão para uso fora do menu

Quando `AI_PROVIDER=omniroute` for usado pela API, worker, webhook ou CLI direta, configure uma rota padrão:

```env
AI_PROVIDER=omniroute
OMNIROUTE_DEFAULT_ROUTE=auto/coding
```

`OMNIROUTE_MODEL` continua aceito como compatibilidade com versões anteriores, mas o nome recomendado agora é `OMNIROUTE_DEFAULT_ROUTE`.

## Provedores diretos continuam opcionais

O menu separa três origens:

```text
1. OmniRoute — gateway centralizado
2. Provedores diretos
3. Ollama local
```

Ao usar OmniRoute, o Agent não precisa das chaves individuais:

```env
GEMINI_API_KEY=
GROQ_API_KEY=
OPENROUTER_API_KEY=
```

Essas variáveis só são necessárias quando o operador escolhe **Provedores diretos**. A segunda IA revisora também precisa de uma origem válida; ela pode continuar direta ou usar o OmniRoute com uma rota padrão.

## Configurar o Codex CLI

O caminho pode apontar para o executável ou para a pasta de instalação:

```env
CODEX_CLI_PATH=/home/jose/.local/bin/codex
CODEX_WORKDIR=/home/jose/projeto-agent-ia
CODEX_HOME=/home/jose/.codex
```

Quando `CODEX_CLI_PATH` aponta para uma pasta, o Agent procura automaticamente:

```text
codex
bin/codex
node_modules/.bin/codex
target/release/codex
codex-rs/target/release/codex
```

Também existe fallback para um `codex` disponível no `PATH`.

Valide diretamente na VM:

```bash
command -v codex || true
find /home/jose/ia/codex -maxdepth 4 -type f -name codex -perm -u+x 2>/dev/null
```

Depois execute:

```bash
agent doctor ai
agent --menu
```

O diagnóstico consulta `/v1/models` e impede a seleção de token ausente,
gateway indisponível ou rota inexistente. Nenhum valor de token é mostrado.

Escolha **OpenAI Codex CLI** para abrir a ferramenta no `CODEX_WORKDIR` configurado. O Codex não recebe automaticamente credenciais nem uma sessão SSH do Agent IA.

## Segurança operacional

- nenhuma senha, token ou chave deve ser adicionada ao Git;
- o OmniRoute pode encaminhar dados para terceiros, portanto use somente provedores aprovados;
- a escolha de rota não altera as políticas operacionais do Agent;
- selecionar Codex não inicia SSH pelo Agent IA;
- reboot de servidores continua bloqueado;
- acesso a bancos de dados de clientes continua bloqueado;
- ações remotas permanecem sob políticas, revisão e lista positiva de ferramentas.
