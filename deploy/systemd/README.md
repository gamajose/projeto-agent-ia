# Implantação com systemd

Os arquivos são exemplos para uma instalação em `/opt/agent-ia`, executada pelo usuário `jose`.
Revise usuário, grupo, caminhos e permissões antes de instalar.

## API

```bash
sudo cp deploy/systemd/agent-ia-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent-ia-api.service
systemctl status agent-ia-api.service --no-pager -l
```

A API escuta somente em `127.0.0.1:8080`. Exponha-a por Nginx, túnel privado ou balanceador com TLS e autenticação de rede.

## Worker

```bash
sudo cp deploy/systemd/agent-ia-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent-ia-worker.service
systemctl status agent-ia-worker.service --no-pager -l
```

O worker consome a fila definida por `AGENT_QUEUE_NAME`.

## Atualização

Antes de atualizar:

```bash
cd /opt/agent-ia
git status --short
```

Somente com árvore limpa:

```bash
git fetch origin --tags --prune
git switch main
git pull --ff-only origin main
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
pytest -q
```

Reinicie apenas os serviços da aplicação após os testes:

```bash
sudo systemctl restart agent-ia-api.service
sudo systemctl restart agent-ia-worker.service
```

Isso não reinicia a VM nem qualquer servidor de cliente.

## Permissões

- `.env`: modo `0600`;
- diretório `/opt/agent-ia`: gravável apenas pelo usuário da aplicação;
- `known_hosts`: gravável somente durante cadastro controlado de fingerprints;
- token Vault: preferencialmente entregue por autenticação de máquina, arquivo protegido ou agent, não em linha de comando;
- logs: não devem imprimir payloads completos de job nem valores de segredo.
