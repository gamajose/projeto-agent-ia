# Ajuda completa do Agent IA

A partir da versão 1.1.1, os comandos abaixo exibem o mesmo guia operacional completo:

```bash
agent --help
agent -h
agent help
agent
```

A ajuda principal não abre conexão SSH, não prepara o banco e não executa validações remotas.

Ela reúne em uma única tela:

- execução direta por IP, hostname ou alias;
- modos `investigar`, `propor` e `corrigir`;
- ambientes aceitos;
- `agent --menu` e seus fluxos;
- comandos internos da sessão interativa;
- seleção automática, manual ou sem playbook;
- `agent replay`;
- `agent approve`;
- comandos do `agent-worker`;
- inicialização da API e do laboratório;
- exemplos e proteções obrigatórias.

## Ajuda específica

Os subcomandos mantêm a ajuda própria do Typer:

```bash
agent replay --help
agent approve --help
agent doctor ai
agent-worker --help
agent-worker run --help
agent-worker job --help
```

O entrypoint só intercepta a ajuda no nível principal. Assim, `agent replay --help` continua descrevendo os argumentos de replay, em vez de abrir o guia geral.

## Diagnóstico das IAs

```bash
agent doctor ai
```

O comando verifica configuração, conectividade, modelo ou rota, resposta JSON
e latência. Ollama e OmniRoute só ficam selecionáveis no menu quando passam no
preflight. Senhas, tokens e API keys nunca são exibidos.

## Versão instalada

```bash
agent --version
agent -V
agent version
```

## Comandos da sessão interativa

Dentro do fluxo **Sessão interativa com servidor**:

```text
/ajuda
/status
/evidencias
/proposta
/trocar-servidor IP
/exit
```

O menu solicita a porta SSH antes da conexão. Pressionar Enter usa, nesta
ordem, a porta do playbook, a porta salva no inventário ou
`SSH_DEFAULT_PORT=22`. Para execução direta:

```bash
agent 192.168.28.10 "validar saúde geral" --porta 2222 --modo investigar
```

Também são aceitas solicitações em linguagem natural, como:

```text
veja os logs do serviço
faça outra validação
reinicie o serviço X
arrume
conecte no servidor 10.45.0.149
sair
```

Pedidos corretivos continuam sujeitos à classificação do ambiente, ferramenta autorizada, evidência, segunda IA, token assinado e confirmação humana. Reboot do host, acesso a banco de cliente e ciclo de vida de containers permanecem bloqueados.
