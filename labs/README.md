# Laboratório de incidentes

O laboratório simula hosts SSH e respostas operacionais sem acessar servidores de clientes.
Ele existe para comparar provedores, validar playbooks, reproduzir falhas e testar políticas.

## Subir o cenário padrão

```bash
docker compose -f docker-compose.lab.yml up -d --build
```

O alvo fica disponível em `127.0.0.1:2222` com usuário e senha `lab`.
Essas credenciais existem somente no laboratório.

Use uma configuração `.env` separada:

```env
SSH_DEFAULT_USER=lab
SSH_DEFAULT_PASSWORD=lab
SSH_DEFAULT_PORT=2222
SSH_STRICT_HOST_KEY_CHECKING=false
POSTGRES_DSN=postgresql+psycopg://agent_ia:agent_ia@127.0.0.1:5432/agent_ia
REDIS_URL=redis://127.0.0.1:6379/1
```

Execute sempre como treinamento:

```bash
agent 127.0.0.1 --porta 2222 --ambiente training \
  "falha no sensor Systemd Socket Summary" --modo propor
```

## Trocar o cenário

```bash
LAB_SCENARIO=/labs/scenarios/linux-filesystem-high.yml \
  docker compose -f docker-compose.lab.yml up -d --build --force-recreate
```

Cenários disponíveis:

- `checkmk-systemd-socket.yml`
- `checkmk-container-unhealthy.yml`
- `linux-filesystem-high.yml`
- `linux-swap-high.yml`
- `network-ssh-reset-peer.yml`
- `network-vpn-down.yml`

## Comparar modelos sem abrir SSH

Depois de uma investigação, use o replay:

```bash
agent replay UUID_DA_INVESTIGACAO --provedor gemini
agent replay UUID_DA_INVESTIGACAO --provedor groq
agent replay UUID_DA_INVESTIGACAO --provedor ollama
```

Todos os provedores recebem as mesmas evidências persistidas. Nenhuma conexão remota é criada durante o replay.

## Limites

O servidor SSH é simulado. Ele reproduz saída de comandos e códigos de retorno, mas não substitui homologação final em uma VM de treinamento com systemd, Checkmk e rede reais. Produção e standby nunca devem ser usados como laboratório.
