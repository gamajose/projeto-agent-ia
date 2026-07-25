# Arquitetura da plataforma AIOps 1.0

## Objetivo

Transformar alertas e solicitações operacionais em investigações rastreáveis, propostas seguras e correções validadas, sem dar liberdade irrestrita de shell ao modelo de IA.

## Fluxo principal

```text
Operador / Checkmk / Helpdesk
              |
              v
        API ou CLI do Agent
              |
              +--> Classificação do ambiente
              +--> Inventário e resolução do alvo
              +--> Seleção do playbook
              +--> Busca de casos semelhantes
              |
              v
       Planejador de IA principal
              |
              v
       Ferramentas estruturadas
              |
              v
       Executor SSH com políticas
              |
              v
     Evidências + sinais determinísticos
              |
              v
         Análise e conclusão
              |
              +--> Texto para ticket
              +--> Proposta de correção
              |
              v
       Segunda IA independente
              |
              v
       Aprovação humana assinada
              |
              v
  Pré-condição -> ação -> pós-validação
```

## Componentes

### CLI

`agent` executa investigações, replay e aprovações. `agent --menu` seleciona provedores ou abre o Codex CLI.

### API

A FastAPI recebe webhooks do Checkmk, expõe investigações, replay, aprovação e métricas.

### Workers

`agent-worker run` consome jobs Redis. Cada worker possui conectividade própria, known_hosts, identidade SSH e backend de segredos. Assim, um worker pode operar na VPN principal e outro em uma rede isolada sem transferir chaves dentro do job.

### Banco PostgreSQL

Armazena inventário, mapeamentos de monitoramento, incidentes, investigações, evidências redigidas e execuções aprovadas.

### Redis

É usado como fila distribuída e armazenamento temporário do estado dos jobs. Os jobs não carregam senhas, chaves privadas ou tokens de provedores.

### Provedores de IA

O motor suporta Gemini, Groq, OpenRouter, Ollama e OmniRoute. O provedor principal planeja e analisa; um provedor diferente pode revisar correções.

### Ferramentas estruturadas

A IA escolhe nomes e argumentos. O código gera o shell correspondente, valida parâmetros e aplica a política. Isso evita que o modelo introduza pipes, redirecionamentos ou comandos compostos não aprovados.

### Playbooks

Os YAMLs definem padrões de seleção, ferramentas iniciais, correções permitidas e validações. O playbook restringe o espaço de ação, mas a IA pode complementar a investigação com ferramentas somente leitura.

## Modos

- `investigate`: somente leitura;
- `propose`: investiga, revisa e emite aprovação temporária;
- `correct`: execução direta apenas quando explicitamente solicitada e todas as políticas aprovam;
- jobs distribuídos sempre são rebaixados de `correct` para `propose`, impedindo autorização implícita pela fila.

## Ambientes

| Ambiente | Investigar | Propor | Corrigir automaticamente |
|---|---:|---:|---:|
| unknown | sim | sim | não |
| production | sim | sim | não |
| standby | sim | sim | não |
| monitoring | sim | sim | apenas com confiança, revisão e aprovação |
| training | sim | sim | apenas com confiança, revisão e aprovação |

O Agent nunca executa reboot, inclusive em treinamento.

## Rastreabilidade

Cada investigação registra:

- alvo, hostname, ambiente, perfil e duração;
- provedor e modelo;
- playbook escolhido;
- ferramentas planejadas;
- comandos gerados pelo código;
- stdout/stderr redigidos;
- pré-condições e pós-validações;
- causa provável e mapa de evidências;
- revisão da segunda IA;
- ações propostas e resultado da aprovação.

## Replay

O replay envia as evidências persistidas a outro modelo sem abrir SSH. Ele permite avaliação comparativa, regressão de prompts e auditoria de conclusões.

## Extensibilidade

Uma nova capacidade deve ser adicionada nesta ordem:

1. ferramenta estruturada;
2. validação de argumentos;
3. testes unitários;
4. playbook que a utiliza;
5. cenário de laboratório;
6. documentação;
7. CI aprovado.

Não se deve ampliar o catálogo permitindo shell genérico para acelerar uma integração.
