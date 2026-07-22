# Agent IA — MVP seguro

Primeira base aplicando os pontos alinhados:

- fluxo Linux/pfSense;
- host afetado e servidor de monitoramento separados;
- somente opções sim/não para monitoramento no mesmo host;
- persistência relacional em PostgreSQL;
- Redis previsto para cache e sessões;
- histórico de incidentes e recorrência;
- reboot bloqueado em produção, standby e ambiente desconhecido;
- reboot em treinamento somente com aprovação explícita;
- acesso a banco de cliente bloqueado por política e por executor;
- restart de serviço, OMD ou container exige aprovação explícita.

## Instalação

```bash
git clone https://github.com/gamajose/projeto-agent-ia.git /opt/agent-ia
cd /opt/agent-ia
sudo chown -R "$USER":"$USER" /opt/agent-ia
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Edite `.env` e inicialize o banco:

```bash
python -m app.db.init_db
```

Teste as políticas:

```bash
pytest -q
```

Execute o menu:

```bash
python -m app.cli.main run
```

Execute a API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```
