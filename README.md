# Agent IA — MVP seguro

Primeira base aplicando os pontos alinhados:

- fluxo Linux/pfSense;
- host afetado e servidor de monitoramento separados;
- persistência relacional em PostgreSQL;
- Redis previsto para cache e sessões;
- histórico de incidentes e recorrência;
- reboot bloqueado em todos os ambientes;
- acesso a banco de cliente bloqueado por política e por executor;
- ciclo de vida de containers Docker bloqueado;
- ajustes seguros em serviços Linux e serviços internos do OMD com validação obrigatória.

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
```

O comando `pip install -e .` registra o executável `agent` no ambiente virtual.

Edite `.env` e inicialize o banco:

```bash
python -m app.db.init_db
```

Teste as políticas:

```bash
pytest -q
```

## Comando único

```bash
agent ALVO [CONTEXTO LIVRE]
```

Exemplos:

```bash
agent 172.27.225.31
agent bsi
agent checkmk-bsi-25
agent bsi srv está lento
agent bsi docker
agent 172.27.225.31 interface de gerenciamento não comunica
```

O alvo pode ser um IP VPN, hostname, site OMD, container ou alias já salvo. Quando o alvo é um IP novo, o Agent usa a porta SSH padrão, executa a descoberta e persiste os dados encontrados para as próximas execuções.

Opções disponíveis:

```bash
agent 172.27.225.31 --port 2222
agent bsi --environment monitoring
agent bsi --read-only
agent --help
```

O fluxo antigo continua disponível para compatibilidade:

```bash
python -m app.cli.main run
```

Execute a API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```
