# Agent IA Infra — Plataforma AIOps segura

O Agent IA investiga problemas de infraestrutura, seleciona playbooks, coleta evidências via SSH, consulta casos semelhantes, propõe correções controladas, exige revisão de uma segunda IA e valida funcionalmente cada ação permitida.

A versão atual mantém as regras fundamentais:

- nunca acessar bancos de dados de clientes;
- nunca reiniciar, desligar ou parar o host;
- nunca controlar o ciclo de vida de containers;
- produção e standby recebem somente investigação e proposta;
- ambiente desconhecido nunca recebe alteração;
- correções automáticas ficam limitadas a monitoramento e treinamento;
- toda correção exige ferramenta autorizada, aprovação, segunda IA e pós-validação;
- segredos são removidos de evidências, histórico e integrações.

## Instalação

```bash
git clone https://github.com/gamajose/projeto-agent-ia.git /opt/agent-ia
cd /opt/agent-ia
sudo chown -R "$USER":"$USER" /opt/agent-ia
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
cp .env.example .env
python -m app.db.init_db
pytest -q
```

O `pip install -e .` registra o comando `agent` no ambiente virtual.

## Modos operacionais

O modo padrão é **propor**. Uma frase ambígua nunca vira autorização automática.

```bash
agent ALVO "problema informado" --modo investigar
agent ALVO "problema informado" --modo propor
agent ALVO "problema informado" --modo corrigir
```

- `investigar`: somente leitura;
- `propor`: investiga, seleciona playbook, prepara ação e solicita aprovação;
- `corrigir`: tenta executar somente quando ambiente, política, evidência e segunda IA autorizam.

Compatibilidade:

```bash
agent ALVO "problema" --somente-validar
```

Sem `--modo`, palavras como “validar”, “analisar” e “investigar” selecionam somente leitura. Todos os demais pedidos ficam em proposta.

## Classificação de ambiente

Ambientes disponíveis:

```text
production
standby
monitoring
training
unknown
```

A saída informa ambiente, origem e confiança. Somente `monitoring` ou `training`, confirmados explicitamente ou pelo inventário com confiança alta, podem receber correções.

```bash
agent 172.27.232.203 "Systemd Socket Summary CRITICAL" \
  --ambiente monitoring --modo propor
```

Produção e standby nunca executam correções automáticas. Reboot permanece bloqueado em todos os ambientes; em treinamento ele pode ser discutido externamente, mas nunca executado pelo Agent IA.

## Ferramentas estruturadas

A IA escolhe ferramentas nomeadas, não strings shell livres. Exemplos:

```text
systemd.inspect_unit
systemd.recover_unit
journal.read_unit
checkmk.discover
checkmk.find_omd_service
checkmk.recover_omd_service
checkmk.inspect_agent_socket
docker.inspect_health
filesystem.usage
memory.swap
network.test_port
vpn.inspect
```

O código valida argumentos, gera o comando, registra pré-condições, executa e realiza pós-validação funcional. Comandos legados continuam disponíveis somente para leitura durante a transição e podem ser desativados com:

```env
AGENT_ALLOW_LEGACY_READ_COMMANDS=false
```

## Playbooks incluídos

Os playbooks ficam em `config/playbooks/`:

- Checkmk Systemd Socket Summary;
- agente Checkmk/porta 6556;
- automation-helper parado;
- rrdcached parado;
- container unhealthy;
- SNMP timeout;
- serviço vanished;
- filesystem ou inodes altos;
- swap alta;
- SSH reset by peer;
- túnel VPN indisponível.

A IA pode complementar o playbook com novas ferramentas de leitura, mas somente as correções permitidas pelo playbook podem avançar para aprovação.

Um playbook pode declarar a porta de conexão do alvo:

```yaml
id: servidor-noc-custom
title: Servidor NOC com SSH alternativo
ssh_port: 2222
profiles: [any]
```

Também são reconhecidos `target.ssh_port`, `target.default_port` e
`target.port_env`. A porta efetiva segue a precedência: valor informado pelo
operador, playbook selecionado, inventário salvo e `SSH_DEFAULT_PORT` (22 por
padrão).

## Segunda IA revisora

Antes de uma correção, uma IA independente verifica:

- se a causa provável é sustentada pelas evidências;
- se a ação pertence ao playbook;
- se o impacto é baixo;
- se a pós-validação é suficiente;
- se existem lacunas críticas.

Configuração:

```env
AI_PROVIDER=gemini
AI_REVIEWER_PROVIDER=groq
AI_REVIEWER_REQUIRED_FOR_CORRECTIONS=true
AI_REVIEWER_MIN_CONFIDENCE=80
```

Sem segunda IA configurada, a investigação funciona, mas a correção permanece bloqueada.

## Aprovação humana assinada

No modo `propor`, quando a segunda IA aprova e o ambiente permite alteração, o Agent gera um token temporário vinculado ao UUID da investigação e ao conteúdo exato das ações.

```env
APPROVAL_SECRET=VALOR_LONGO_E_ALEATORIO
APPROVAL_TTL_MINUTES=30
```

Execução pelo terminal:

```bash
agent approve UUID_DA_INVESTIGACAO 'TOKEN_ASSINADO' --por jose
```

Qualquer alteração nas ações, assinatura inválida ou expiração bloqueia a execução.

## Memória e replay

O PostgreSQL mantém planos, evidências, avaliações, causa provável, modelo, confiança e duração. O agente procura casos semelhantes por objetivo, perfil, alvo e causa anterior.

Uma investigação pode ser reanalisada por outro modelo sem abrir SSH:

```bash
agent replay UUID_DA_INVESTIGACAO --provedor gemini
agent replay UUID_DA_INVESTIGACAO --provedor groq
agent replay UUID_DA_INVESTIGACAO --provedor ollama
```

Isso permite comparar modelos usando exatamente as mesmas evidências.

## Webhook do Checkmk

Execute a API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Configure:

```env
CHECKMK_WEBHOOK_TOKEN=TOKEN_EXCLUSIVO_DO_CHECKMK
CHECKMK_WEBHOOK_AUTO_CORRECT=false
AGENT_API_TOKEN=TOKEN_DA_API_ADMINISTRATIVA
```

Exemplo:

```bash
curl -X POST http://127.0.0.1:8080/webhooks/checkmk \
  -H 'Content-Type: application/json' \
  -H 'X-Agent-Token: TOKEN_EXCLUSIVO_DO_CHECKMK' \
  -d '{
    "host":"checkmk-cliente",
    "service":"Systemd Socket Summary",
    "state":"CRITICAL",
    "output":"1 failed socket",
    "site":"cliente",
    "environment":"monitoring",
    "auto_correct":false
  }'
```

O webhook usa proposta por padrão. `auto_correct=true` só tem efeito quando `CHECKMK_WEBHOOK_AUTO_CORRECT=true` e todas as demais políticas aprovam.

## API administrativa

Com `X-Agent-Token: AGENT_API_TOKEN`:

```text
GET  /api/investigations/{id}
POST /api/investigations/{id}/replay
POST /api/investigations/{id}/approve
GET  /api/metrics
GET  /metrics
```

`/metrics` fornece métricas em formato Prometheus: total, duração média, status, modos e execuções aprovadas.

## Helpdesk

Uma integração genérica pode publicar apenas o resumo redigido, sem credenciais ou evidência bruta:

```env
HELPDESK_WEBHOOK_URL=
HELPDESK_WEBHOOK_TOKEN=
HELPDESK_PUBLISH_AUTOMATICALLY=false
```

O adapter pode ser conectado depois ao Movidesk, ServiceNow, Jira Service Management, GLPI ou outro sistema por meio de webhook/n8n.

## Segurança SSH e bastion

O padrão agora usa verificação estrita de chave de host:

```env
SSH_STRICT_HOST_KEY_CHECKING=true
SSH_KNOWN_HOSTS_PATH=/home/jose/.ssh/known_hosts
```

Cadastre a chave antes do primeiro acesso:

```bash
ssh-keyscan -H IP_DO_SERVIDOR >> ~/.ssh/known_hosts
```

Para acessar clientes por um bastion/VPN sem `ProxyCommand` shell:

```env
SSH_BASTION_HOST=10.17.181.1
SSH_BASTION_PORT=22
SSH_BASTION_USER=
SSH_BASTION_PASSWORD=
SSH_BASTION_PRIVATE_KEY_PATH=
SSH_BASTION_PRIVATE_KEY_PASSPHRASE=
```

O Paramiko abre um canal `direct-tcpip` pelo bastion. Nenhuma senha ou chave é armazenada no GitHub.

## Origens dos modelos e Codex CLI

O `agent --menu` separa claramente a origem do modelo:

```text
1. OmniRoute — gateway centralizado
2. Provedores diretos
3. Ollama local
```

O **OmniRoute não é uma IA**. Ele usa um único token no Agent IA e encaminha a solicitação para uma rota, modelo ou combo configurado no gateway. As credenciais reais de Gemini, Groq, OpenAI, Anthropic e outros provedores permanecem no OmniRoute.

Configuração mínima:

```env
OMNIROUTE_API_KEY=TOKEN_DO_ENDPOINT
OMNIROUTE_BASE_URL=http://127.0.0.1:20128/v1
```

Rotas opcionais para o menu:

```env
OMNIROUTE_DEFAULT_ROUTE=auto/coding
OMNIROUTE_ROUTES=Código=auto/coding,Rápido=auto/fast,Econômico=auto/cheap,Inteligente=auto/smart
```

Os **provedores diretos** continuam disponíveis quando suas API keys individuais estiverem configuradas. O **Ollama** permanece como modelo local.

Antes de abrir SSH, o Agent valida o provedor selecionado. O Ollama precisa
responder, possuir exatamente o modelo configurado e produzir JSON válido. O
OmniRoute precisa ter token local, rota configurada, endpoint acessível e a rota
precisa aparecer em `/v1/models`.

```bash
agent doctor ai
```

O diagnóstico mostra estado, modelo/rota, latência e motivo sem exibir
credenciais. O tempo limite pode ser ajustado com:

```env
AI_PREFLIGHT_TIMEOUT_SECONDS=8
```

O Codex CLI é uma ferramenta local interativa e não recebe automaticamente credenciais SSH do Agent IA.

```env
CODEX_CLI_PATH=/home/jose/.local/bin/codex
CODEX_WORKDIR=/home/jose/projeto-agent-ia
CODEX_HOME=/home/jose/.codex
```

Veja [`docs/omniroute-codex.md`](docs/omniroute-codex.md).

## Laboratório reproduzível

O laboratório usa um servidor SSH simulado com cenários controlados:

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

Consulte [`labs/README.md`](labs/README.md). Use sempre `--ambiente training`. O laboratório nunca deve apontar para produção ou standby.

## Desenvolvimento e versionamento

```bash
python -m compileall -q app tests labs
pytest -q
```

O GitHub Actions valida dependências, sintaxe, testes, SemVer e tag inédita. O merge ocorre somente depois do CI aprovado.
