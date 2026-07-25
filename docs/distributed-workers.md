# Workers distribuídos

## Quando usar

Use `AGENT_EXECUTION_MODE=queue` quando a API central não possui rota para todos os clientes ou quando cada conjunto de ambientes deve possuir identidade SSH e segredos separados.

## Topologia recomendada

```text
Checkmk / Helpdesk
        |
        v
 API central do Agent
        |
        v
 Redis com TLS e autenticação
        |
        +--> worker-vpn-principal --> clientes da VPN principal
        +--> worker-globopack     --> rede GLOBOPACK
        +--> worker-laboratorio   --> apenas treinamento
```

O job contém apenas:

- alvo ou alias;
- objetivo;
- ambiente declarado;
- modo de proposta;
- porta SSH opcional;
- metadados redigidos do alerta.

Senhas, chaves privadas, tokens de IA e segredos de aprovação não entram na fila.

## API central

```env
AGENT_EXECUTION_MODE=queue
REDIS_URL=rediss://usuario:senha@redis.exemplo:6379/1
AGENT_QUEUE_NAME=agent-ia:jobs
AGENT_RESULT_PREFIX=agent-ia:result:
```

O webhook retorna um `job_id`. Consulte:

```bash
curl -H 'X-Agent-Token: TOKEN' \
  http://127.0.0.1:8080/api/jobs/JOB_ID
```

## Worker

Cada worker usa seu próprio `.env` ou caminho Vault:

```env
AGENT_WORKER_NAME=vpn-principal
SECRET_BACKEND=vault
VAULT_SECRET_PATH=agent-ia/workers/vpn-principal
SSH_STRICT_HOST_KEY_CHECKING=true
SSH_KNOWN_HOSTS_PATH=/var/lib/agent-ia/known_hosts
```

Inicie:

```bash
agent-worker run
```

Para processar apenas um job durante teste:

```bash
agent-worker run --once --bloqueio 0
```

Consultar localmente:

```bash
agent-worker job JOB_ID
```

## Segurança da fila

- use Redis com TLS;
- restrinja ACL do worker à fila e ao prefixo de resultado;
- não exponha Redis à internet;
- configure retenção curta com `AGENT_JOB_TTL_SECONDS`;
- separe filas quando zonas não puderem compartilhar destinos;
- monitore jobs parados em `running` e workers ausentes;
- jobs distribuídos nunca executam correção diretamente: solicitações `correct` são convertidas em `propose`.

## Seleção de worker

A primeira implementação utiliza uma fila por implantação. Para separar zonas, configure nomes distintos:

```env
# API e worker da zona A
AGENT_QUEUE_NAME=agent-ia:jobs:vpn-a

# API e worker da zona B
AGENT_QUEUE_NAME=agent-ia:jobs:vpn-b
```

O roteamento pode ser feito por n8n, API gateway ou regras do Checkmk, escolhendo a instância/endpoint correspondente à zona do cliente.

## Disponibilidade

Execute pelo menos dois workers somente quando ambos possuem a mesma conectividade e o mesmo escopo de credenciais. Em zonas diferentes, use filas distintas para evitar que um job seja consumido pelo worker errado.
