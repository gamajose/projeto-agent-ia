# Menu e sessão operacional interativa

## Objetivo

A versão 1.1 adiciona uma interface interativa sem remover o CLI, a API, os workers, os playbooks, o replay ou o fluxo de aprovação existentes.

```bash
agent --menu
```

O menu principal oferece:

1. **Validação automática** — executa o mesmo motor atual, apresenta o resultado e volta ao menu.
2. **Sessão interativa com servidor** — realiza a investigação inicial e mantém um chat operacional até o operador sair ou trocar de servidor.
3. **OpenAI Codex CLI** — abre a ferramenta local de desenvolvimento, separada da execução operacional.

## Ordem do assistente

1. Selecionar o provedor de IA.
2. Escolher playbook automático, manual ou nenhum.
3. Informar IP, hostname ou alias.
4. Informar o problema.
5. Informar a porta SSH ou pressionar Enter.
6. Declarar ou deixar o ambiente como desconhecido.
7. Conferir o resumo e iniciar.

A seleção de provedor e playbook vale somente para a operação atual. O `.env` não é alterado e outras execuções concorrentes não são afetadas.

## Saída global e interrupções

Em qualquer campo do assistente ou submenu, os comandos abaixo encerram o menu de forma limpa:

```text
q
\q
quit
exit
sair
encerrar
fechar
esc
```

`Ctrl+C` e `Ctrl+D` também encerram o menu sem traceback. Entradas comuns inválidas continuam exibindo a mensagem de validação correspondente e o operador pode tentar novamente.

A palavra `esc` deve ser digitada e confirmada com Enter. A tecla física Esc isolada não é interpretada de forma portátil pelo prompt de linha atual.

O número `0` mantém o comportamento específico de cada tela: volta em submenus que oferecem essa opção e encerra quando selecionado no menu principal.

## Porta SSH

O menu solicita a porta tanto na validação automática quanto na sessão
interativa. Ao trocar de servidor dentro da sessão, a porta também é solicitada.

- digitando `2222`, a conexão usa `2222`;
- pressionando Enter, o Agent tenta a porta declarada no playbook;
- sem porta no playbook, usa a porta do alvo salvo no inventário;
- para um IP novo sem outra configuração, usa `SSH_DEFAULT_PORT`, cujo padrão é
  `22`.

A precedência completa é:

```text
porta informada > playbook > inventário > SSH_DEFAULT_PORT
```

No CLI direto, use:

```bash
agent 192.168.28.10 "validar saúde geral" --porta 2222 --modo investigar
```

Nos playbooks, a forma recomendada é:

```yaml
ssh_port: 2222
```

Playbooks de inventário existentes também podem usar `target.ssh_port`,
`target.default_port` ou `target.port_env`.

## Sem playbook

A opção `0` na tela de playbooks executa a validação inicial sem playbook. Nesse caso:

- o modo inicial é obrigatoriamente `investigate`;
- não existe allowlist corretiva fornecida por playbook;
- nenhuma alteração pode ser executada;
- o operador pode continuar pedindo validações somente leitura.

## Chat operacional

Depois da investigação inicial, a sessão mantém:

- identificador da sessão;
- provedor escolhido;
- servidor atual;
- ambiente classificado;
- playbook escolhido;
- histórico recente do diálogo;
- última investigação e suas evidências;
- última causa provável;
- última proposta revisada e seu token, quando aplicável.

Exemplos de mensagens:

```text
veja os logs do serviço
valide também o rrdcached
confira se existem outras unidades em falha
reinicie o serviço automation-helper
arrume
troque para o servidor 10.45.0.149
exit
```

Pedidos de alteração específica, como `reinicie o serviço X`, não são executados diretamente. O Agent realiza nova validação, cria uma proposta estruturada e submete a proposta à revisão da segunda IA. A execução somente fica disponível quando todas as políticas existentes permitem.

## Comandos explícitos

```text
/status
/evidencias
/proposta
/trocar-servidor IP
/ajuda
/exit
```

Também são aceitos `exit`, `sair`, `encerrar`, `finalizar` e `desconectar servidor` dentro do chat operacional.

## Aprovação

Quando o operador escreve `arrume`, `corrija` ou `execute`, o menu:

1. mostra a proposta atual;
2. solicita confirmação explícita;
3. solicita a identificação do aprovador;
4. executa somente as ações contidas no token assinado;
5. apresenta as pós-validações;
6. mantém a sessão aberta.

Sem token válido, revisão aprovada e ambiente permitido, a execução é recusada.

## Segurança preservada

Continuam bloqueados:

- reboot ou desligamento da máquina;
- acesso a banco de dados de cliente;
- ciclo de vida de containers;
- ações destrutivas;
- correções automáticas em produção, standby ou ambiente desconhecido.

A sessão é lógica. Cada nova rodada pode restabelecer a conexão SSH usando o mesmo alvo e as mesmas verificações de `known_hosts`, sem perder o histórico conversacional.

## Compatibilidade

Os comandos existentes continuam disponíveis:

```bash
agent IP "problema" --modo investigar
agent IP "problema" --modo propor
agent replay UUID
agent approve UUID TOKEN
agent-worker run
```

Somente o entrypoint instalado foi ampliado para interceptar `agent --menu`; os demais argumentos continuam sendo encaminhados ao CLI já existente.
