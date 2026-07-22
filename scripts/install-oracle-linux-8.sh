#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/gamajose/projeto-agent-ia.git"
INSTALL_DIR="/opt/agent-ia"
SERVICE_NAME="agent-ia"
RUN_USER="${SUDO_USER:-${USER}}"

log() { printf '\n\033[1;34m[Agent IA]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[AVISO]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[ERRO]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Execute como root: sudo bash scripts/install-oracle-linux-8.sh"
[[ -f /etc/oracle-release ]] || die "Este instalador foi preparado para Oracle Linux 8."
grep -qE 'release 8([. ]|$)' /etc/oracle-release || die "Versão não suportada: $(cat /etc/oracle-release)"
id "$RUN_USER" >/dev/null 2>&1 || die "Usuário de execução inválido: $RUN_USER"

log "Sistema identificado: $(cat /etc/oracle-release)"
log "Usuário do serviço: $RUN_USER"

log "Instalando dependências básicas"
dnf install -y dnf-plugins-core git curl ca-certificates openssl gcc libffi-devel openssl-devel

if rpm -q podman-docker >/dev/null 2>&1; then
  log "Removendo podman-docker para evitar conflito com o Docker Engine"
  dnf remove -y podman-docker
fi

if ! command -v docker >/dev/null 2>&1; then
  log "Instalando Docker Engine"
  dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
  dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

systemctl enable --now docker
usermod -aG docker "$RUN_USER"

docker version >/dev/null
docker compose version >/dev/null

log "Instalando Python 3.11"
if ! command -v python3.11 >/dev/null 2>&1; then
  dnf install -y python3.11 python3.11-pip python3.11-devel || die "Não foi possível instalar Python 3.11 pelos repositórios configurados."
fi

PYTHON_BIN="$(command -v python3.11)"

if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Atualizando repositório existente"
  git -C "$INSTALL_DIR" pull --ff-only origin main
else
  if [[ -e "$INSTALL_DIR" ]]; then
    BACKUP="${INSTALL_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    warn "$INSTALL_DIR já existe e será movido para $BACKUP"
    mv "$INSTALL_DIR" "$BACKUP"
  fi
  log "Clonando o projeto"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

log "Criando ambiente virtual Python"
rm -rf .venv
sudo -u "$RUN_USER" "$PYTHON_BIN" -m venv .venv
sudo -u "$RUN_USER" .venv/bin/python -m pip install --upgrade pip setuptools wheel
sudo -u "$RUN_USER" .venv/bin/pip install -r requirements.txt

if [[ ! -f .env ]]; then
  log "Criando credenciais locais"
  POSTGRES_PASSWORD="$(openssl rand -hex 24)"
  REDIS_PASSWORD="$(openssl rand -hex 24)"

  cat > .env <<EOF
APP_ENV=production
LOG_LEVEL=INFO

SSH_DEFAULT_USER=2com
SSH_DEFAULT_PASSWORD=
SSH_DEFAULT_PORT=22
SSH_CONNECT_TIMEOUT=15
SSH_COMMAND_TIMEOUT=60

POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
POSTGRES_DSN=postgresql+psycopg://agent_ia:${POSTGRES_PASSWORD}@127.0.0.1:5432/agent_ia
REDIS_URL=redis://:${REDIS_PASSWORD}@127.0.0.1:6379/1

CHECKMK_API_USER=
CHECKMK_API_SECRET=
GEMINI_API_KEY=

RECURRENCE_WARNING_COUNT=2
RECURRENCE_WARNING_DAYS=7
RECURRENCE_CRITICAL_COUNT=4
RECURRENCE_CRITICAL_DAYS=30
EOF
  chmod 600 .env
  chown "$RUN_USER:$RUN_USER" .env
else
  log "Arquivo .env existente preservado"
fi

log "Subindo PostgreSQL e Redis"
docker compose up -d

log "Aguardando PostgreSQL ficar saudável"
for _ in {1..60}; do
  if docker inspect -f '{{.State.Health.Status}}' agent-ia-postgres 2>/dev/null | grep -q healthy; then
    break
  fi
  sleep 2
done

docker inspect -f '{{.State.Health.Status}}' agent-ia-postgres 2>/dev/null | grep -q healthy \
  || die "PostgreSQL não ficou saudável. Verifique: docker logs agent-ia-postgres"

log "Inicializando banco da aplicação"
sudo -u "$RUN_USER" .venv/bin/python -m app.db.init_db

log "Executando testes"
sudo -u "$RUN_USER" .venv/bin/python -m pytest -q

mkdir -p "$INSTALL_DIR/logs"
chown -R "$RUN_USER:$RUN_USER" "$INSTALL_DIR/logs"

log "Criando serviço systemd"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Agent IA AIOps
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

sleep 3
systemctl is-active --quiet "$SERVICE_NAME" || {
  systemctl status "$SERVICE_NAME" --no-pager -l || true
  journalctl -u "$SERVICE_NAME" -n 100 --no-pager || true
  die "O serviço Agent IA não iniciou corretamente."
}

log "Validando API local"
curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null \
  || warn "O serviço iniciou, mas /health não respondeu. Verifique a rota implementada na aplicação."

cat <<EOF

============================================================
Instalação concluída.

Projeto:       ${INSTALL_DIR}
Serviço:       ${SERVICE_NAME}
PostgreSQL:    agent-ia-postgres (127.0.0.1:5432)
Redis:         agent-ia-redis (127.0.0.1:6379)
API:           http://127.0.0.1:8080

Próximos comandos:
  sudo systemctl status ${SERVICE_NAME} --no-pager -l
  docker compose -f ${INSTALL_DIR}/docker-compose.yml ps
  sudo -u ${RUN_USER} ${INSTALL_DIR}/.venv/bin/python -m app.cli.main run

Edite as credenciais e integrações em:
  ${INSTALL_DIR}/.env

Por segurança, o instalador não abre portas no firewall.
Faça logout e login novamente para o usuário ${RUN_USER} usar Docker sem sudo.
============================================================
EOF
