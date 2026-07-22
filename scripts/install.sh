#!/usr/bin/env bash
set -euo pipefail

cd /opt/agent-ia
sudo chown -R "$USER":"$USER" /opt/agent-ia
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp -n .env.example .env || true
printf '\nInstalação concluída. Edite /opt/agent-ia/.env antes de executar.\n'
