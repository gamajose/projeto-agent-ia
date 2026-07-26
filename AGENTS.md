# Agent IA Infra

## Objetivo

Este repositório automatiza investigação N1/N2 de infraestrutura e monitoramento.
Priorize diagnóstico baseado em evidências, baixo impacto e rastreabilidade.

## Limites operacionais obrigatórios

- Investigações e coleta somente leitura podem ser automáticas.
- Nunca execute correção, restart, reload, alteração de configuração ou rollback sem
  uma aprovação humana explícita e vinculada às ações exatas.
- Nunca acesse bancos de dados de clientes.
- Nunca reinicie ou desligue hosts.
- Nunca controle o ciclo de vida de containers.
- Produção, standby e ambientes desconhecidos recebem somente investigação e proposta.
- Não reduza as validações de `known_hosts`, a revisão por segunda IA, a lista positiva
  de ferramentas, a assinatura das aprovações ou a pós-validação.
- Não grave senhas, tokens, chaves ou evidências sensíveis no Git.

## Desenvolvimento

- Preserve a separação entre análise, proposta, aprovação e execução.
- Prefira ferramentas estruturadas a comandos shell livres.
- Toda nova ação corretiva precisa de política, precondição, aprovação, rollback seguro
  quando aplicável e validação funcional.
- Antes de concluir uma mudança, execute:

```bash
python -m compileall -q app tests labs
pytest -q
```
