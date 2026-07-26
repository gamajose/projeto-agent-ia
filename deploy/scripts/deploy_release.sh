#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
MODE=""
STAGE_DIR=""
SMOKE_PID=""

log() {
  printf '[deploy] %s\n' "$*"
}

fail() {
  printf '[deploy] ERRO: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Uso:
  deploy_release.sh --prepare
  deploy_release.sh --activate

Modos:
  --prepare   Monta e valida a release sem trocar a versão ativa.
  --activate  Monta, valida, ativa e reinicia os serviços com rollback.

Variáveis:
  AGENT_SOURCE_DIR             Checkout a empacotar (padrão: GITHUB_WORKSPACE ou pwd).
  AGENT_DEPLOY_ROOT            Raiz das releases (padrão: ~/agent-ia-production).
  AGENT_ENV_FILE               Arquivo de ambiente externo ao Git.
  AGENT_RELEASE_SHA            SHA hexadecimal da release.
  AGENT_DEPLOY_APPROVED_SHA    Deve ser igual ao SHA para permitir --activate.
  AGENT_HEALTH_URL             Health da API ativa (padrão: http://127.0.0.1:8080/health).
  AGENT_SMOKE_PORT             Porta temporária de validação (padrão: 18080).
EOF
}

cleanup() {
  if [[ -n "$SMOKE_PID" ]] && kill -0 "$SMOKE_PID" 2>/dev/null; then
    kill "$SMOKE_PID" 2>/dev/null || true
    wait "$SMOKE_PID" 2>/dev/null || true
  fi
  if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
    rm -rf -- "$STAGE_DIR"
  fi
}
trap cleanup EXIT

case "${1:-}" in
  --prepare)
    MODE="prepare"
    ;;
  --activate)
    MODE="activate"
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

SOURCE_DIR="${AGENT_SOURCE_DIR:-${GITHUB_WORKSPACE:-$(pwd)}}"
DEPLOY_ROOT="${AGENT_DEPLOY_ROOT:-$HOME/agent-ia-production}"
ENV_FILE="${AGENT_ENV_FILE:-$HOME/.config/agent-ia/production.env}"
RELEASE_SHA="${AGENT_RELEASE_SHA:-}"
HEALTH_URL="${AGENT_HEALTH_URL:-http://127.0.0.1:8080/health}"
SMOKE_PORT="${AGENT_SMOKE_PORT:-18080}"
SYSTEMD_USER_DIR="${AGENT_SYSTEMD_USER_DIR:-$HOME/.config/systemd/user}"
UNIT_SOURCE_DIR="$SOURCE_DIR/deploy/systemd/release"
RELEASES_DIR="$DEPLOY_ROOT/releases"
STATE_DIR="$DEPLOY_ROOT/state"
CURRENT_LINK="$DEPLOY_ROOT/current"

readonly API_UNIT="agent-ia-api.service"
readonly WORKER_TEMPLATE="agent-ia-worker@.service"
readonly -a ACTIVE_SERVICES=(
  "agent-ia-api.service"
  "agent-ia-worker@1.service"
  "agent-ia-worker@2.service"
  "agent-ia-worker@3.service"
)

git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
  fail "AGENT_SOURCE_DIR não é um checkout Git: $SOURCE_DIR"
[[ -f "$SOURCE_DIR/requirements.txt" ]] || fail "requirements.txt ausente em $SOURCE_DIR"
[[ -f "$SOURCE_DIR/pyproject.toml" ]] || fail "pyproject.toml ausente em $SOURCE_DIR"
[[ -f "$UNIT_SOURCE_DIR/$API_UNIT" ]] || fail "unidade da API ausente"
[[ -f "$UNIT_SOURCE_DIR/$WORKER_TEMPLATE" ]] || fail "unidade dos workers ausente"
[[ -f "$ENV_FILE" ]] || fail "arquivo de ambiente ausente: $ENV_FILE"

if [[ -z "$RELEASE_SHA" ]]; then
  RELEASE_SHA="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
fi
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "AGENT_RELEASE_SHA deve ser um SHA Git completo"

SOURCE_SHA="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
[[ "$SOURCE_SHA" == "$RELEASE_SHA" ]] || fail "checkout $SOURCE_SHA difere da release aprovada $RELEASE_SHA"

ENV_MODE="$(stat -c '%a' "$ENV_FILE")"
ENV_OWNER="$(stat -c '%U' "$ENV_FILE")"
[[ "$ENV_OWNER" == "$(id -un)" ]] || fail "$ENV_FILE deve pertencer ao usuário $(id -un)"
[[ "$ENV_MODE" == "600" || "$ENV_MODE" == "400" ]] || fail "$ENV_FILE deve usar permissão 600 ou 400, atual: $ENV_MODE"

if [[ "$MODE" == "activate" ]]; then
  [[ "${AGENT_DEPLOY_APPROVED_SHA:-}" == "$RELEASE_SHA" ]] ||
    fail "ativação exige AGENT_DEPLOY_APPROVED_SHA idêntico à release"
  if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
    [[ "${GITHUB_EVENT_NAME:-}" == "push" || "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]] ||
      fail "Actions só pode ativar em evento push ou workflow_dispatch"
    [[ "${GITHUB_REF:-}" == "refs/heads/main" ]] || fail "Actions só pode ativar a main"
    [[ "${GITHUB_SHA:-}" == "$RELEASE_SHA" ]] || fail "GITHUB_SHA difere da release"
  fi
fi

mkdir -p "$RELEASES_DIR" "$STATE_DIR"
chmod 700 "$DEPLOY_ROOT" "$RELEASES_DIR" "$STATE_DIR"

RELEASE_DIR="$RELEASES_DIR/$RELEASE_SHA"

project_version() {
  "$1" - "$2" <<'PY'
import sys
import tomllib
from pathlib import Path

with (Path(sys.argv[1]) / "pyproject.toml").open("rb") as stream:
    print(tomllib.load(stream)["project"]["version"])
PY
}

wait_for_health() {
  local url="$1"
  local expected_version="$2"
  local output_file="$3"
  local attempt

  for attempt in $(seq 1 40); do
    if curl --fail --silent --show-error --max-time 2 "$url" >"$output_file" 2>/dev/null; then
      if python3 - "$output_file" "$expected_version" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit(1)
if payload.get("version") != sys.argv[2]:
    raise SystemExit(1)
PY
      then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

smoke_release() {
  local release_dir="$1"
  local expected_version="$2"
  local smoke_log="$STATE_DIR/smoke-$RELEASE_SHA.log"
  local smoke_output="$STATE_DIR/smoke-$RELEASE_SHA.json"

  if ss -ltn | awk '{print $4}' | grep -Eq "[:.]${SMOKE_PORT}$"; then
    fail "porta temporária $SMOKE_PORT já está em uso"
  fi

  log "iniciando smoke test na porta $SMOKE_PORT"
  (
    cd "$release_dir"
    exec "$release_dir/.venv/bin/uvicorn" app.main:app \
      --host 127.0.0.1 \
      --port "$SMOKE_PORT"
  ) >"$smoke_log" 2>&1 &
  SMOKE_PID="$!"

  if ! wait_for_health "http://127.0.0.1:$SMOKE_PORT/health" "$expected_version" "$smoke_output"; then
    tail -n 80 "$smoke_log" >&2 || true
    fail "smoke test da release falhou"
  fi

  kill "$SMOKE_PID" 2>/dev/null || true
  wait "$SMOKE_PID" 2>/dev/null || true
  SMOKE_PID=""
  log "smoke test aprovado para a versão $expected_version"
}

prepare_release() {
  if [[ -f "$RELEASE_DIR/.ready" ]]; then
    log "release já preparada: $RELEASE_SHA"
    [[ "$(<"$RELEASE_DIR/.release-sha")" == "$RELEASE_SHA" ]] ||
      fail "metadado da release existente não corresponde ao SHA"
    RELEASE_VERSION="$(<"$RELEASE_DIR/.release-version")"
    smoke_release "$RELEASE_DIR" "$RELEASE_VERSION"
    return
  fi
  [[ ! -e "$RELEASE_DIR" ]] || fail "release incompleta já existe: $RELEASE_DIR"

  STAGE_DIR="$RELEASE_DIR"
  mkdir "$STAGE_DIR"
  chmod 700 "$STAGE_DIR"
  log "copiando checkout para a release final"
  tar \
    --exclude='.git' \
    --exclude='.env' \
    --exclude='.venv' \
    --exclude='.pytest_cache' \
    --exclude='__pycache__' \
    -C "$SOURCE_DIR" -cf - . |
    tar -C "$STAGE_DIR" -xf -

  ln -s "$ENV_FILE" "$STAGE_DIR/.env"

  log "criando ambiente Python isolado"
  python3 -m venv "$STAGE_DIR/.venv"
  "$STAGE_DIR/.venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
  "$STAGE_DIR/.venv/bin/python" -m pip install --disable-pip-version-check -r "$STAGE_DIR/requirements.txt"
  "$STAGE_DIR/.venv/bin/python" -m pip install --disable-pip-version-check --no-deps -e "$STAGE_DIR"
  "$STAGE_DIR/.venv/bin/python" -m compileall -q "$STAGE_DIR/app" "$STAGE_DIR/tests" "$STAGE_DIR/labs"
  "$STAGE_DIR/.venv/bin/agent" --help >/dev/null

  RELEASE_VERSION="$(project_version "$STAGE_DIR/.venv/bin/python" "$STAGE_DIR")"
  smoke_release "$STAGE_DIR" "$RELEASE_VERSION"

  printf '%s\n' "$RELEASE_SHA" >"$STAGE_DIR/.release-sha"
  printf '%s\n' "$RELEASE_VERSION" >"$STAGE_DIR/.release-version"
  touch "$STAGE_DIR/.ready"
  STAGE_DIR=""
  log "release preparada em $RELEASE_DIR"
}

configure_user_bus() {
  export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"
  [[ -S "$XDG_RUNTIME_DIR/bus" ]] || fail "barramento systemd do usuário não está disponível"
}

switch_current() {
  local target="$1"
  local temporary_link="$DEPLOY_ROOT/.current.$$.tmp"
  ln -s "$target" "$temporary_link"
  mv -Tf "$temporary_link" "$CURRENT_LINK"
}

backup_units() {
  local backup_dir="$1"
  local unit

  mkdir -p "$backup_dir"
  chmod 700 "$backup_dir"
  for unit in "$API_UNIT" "$WORKER_TEMPLATE"; do
    if [[ -f "$SYSTEMD_USER_DIR/$unit" ]]; then
      cp -a "$SYSTEMD_USER_DIR/$unit" "$backup_dir/$unit"
    else
      touch "$backup_dir/$unit.missing"
    fi
  done
}

install_release_units() {
  mkdir -p "$SYSTEMD_USER_DIR"
  install -m 600 "$UNIT_SOURCE_DIR/$API_UNIT" "$SYSTEMD_USER_DIR/$API_UNIT"
  install -m 600 "$UNIT_SOURCE_DIR/$WORKER_TEMPLATE" "$SYSTEMD_USER_DIR/$WORKER_TEMPLATE"
}

restore_units() {
  local backup_dir="$1"
  local unit

  for unit in "$API_UNIT" "$WORKER_TEMPLATE"; do
    if [[ -f "$backup_dir/$unit" ]]; then
      install -m 600 "$backup_dir/$unit" "$SYSTEMD_USER_DIR/$unit"
    elif [[ -f "$backup_dir/$unit.missing" ]]; then
      rm -f -- "$SYSTEMD_USER_DIR/$unit"
    fi
  done
}

restart_services() {
  systemctl --user daemon-reload || return 1
  systemctl --user enable "$API_UNIT" \
    "agent-ia-worker@1.service" \
    "agent-ia-worker@2.service" \
    "agent-ia-worker@3.service" >/dev/null || return 1
  systemctl --user restart "${ACTIVE_SERVICES[@]}" || return 1
}

rollback() {
  local previous_release="$1"
  local unit_backup="$2"

  log "iniciando rollback"
  if [[ -n "$previous_release" && -d "$previous_release" ]]; then
    switch_current "$previous_release"
  else
    if [[ -L "$CURRENT_LINK" ]]; then
      rm -f -- "$CURRENT_LINK"
    fi
    restore_units "$unit_backup"
  fi
  restart_services
  log "rollback concluído"
}

activate_release() {
  local previous_release=""
  local run_key="${GITHUB_RUN_ID:-manual}-$(date -u +%Y%m%dT%H%M%SZ)"
  local unit_backup="$STATE_DIR/systemd-$run_key"
  local expected_version
  local health_output="$STATE_DIR/health-$RELEASE_SHA.json"

  if [[ -L "$CURRENT_LINK" ]]; then
    previous_release="$(readlink -f "$CURRENT_LINK")"
  elif [[ -e "$CURRENT_LINK" ]]; then
    fail "$CURRENT_LINK existe e não é um symlink"
  fi

  expected_version="$(<"$RELEASE_DIR/.release-version")"
  configure_user_bus
  backup_units "$unit_backup"
  if ! install_release_units || ! systemctl --user daemon-reload; then
    restore_units "$unit_backup"
    systemctl --user daemon-reload || true
    fail "não foi possível instalar as unidades; configuração anterior restaurada"
  fi
  if ! switch_current "$RELEASE_DIR"; then
    restore_units "$unit_backup"
    systemctl --user daemon-reload || true
    fail "não foi possível trocar a release; configuração anterior restaurada"
  fi

  if ! restart_services; then
    rollback "$previous_release" "$unit_backup"
    fail "restart da release falhou; rollback aplicado"
  fi

  if ! wait_for_health "$HEALTH_URL" "$expected_version" "$health_output"; then
    rollback "$previous_release" "$unit_backup"
    fail "health check da release falhou; rollback aplicado"
  fi

  for service in "${ACTIVE_SERVICES[@]}"; do
    if ! systemctl --user is-active --quiet "$service"; then
      rollback "$previous_release" "$unit_backup"
      fail "$service não permaneceu ativo; rollback aplicado"
    fi
  done

  printf '%s\n' "$RELEASE_SHA" >"$STATE_DIR/last-successful-sha"
  log "release $RELEASE_SHA ativada com saúde confirmada"
}

log "script: $SCRIPT_NAME"
log "modo: $MODE"
log "release: $RELEASE_SHA"
prepare_release

if [[ "$MODE" == "prepare" ]]; then
  log "preparação concluída; versão ativa não foi alterada"
  exit 0
fi

activate_release
