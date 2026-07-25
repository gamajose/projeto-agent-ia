# OmniRoute e Codex CLI no Agent IA

## Papel de cada componente

O **OmniRoute** deve rodar como um serviço separado na mesma VM ou em outro host confiável. Ele expõe uma API compatível com OpenAI e encaminha as chamadas para provedores, modelos ou combos configurados no painel.

O **Codex CLI** é uma ferramenta interativa local. No Agent IA ele aparece no `agent --menu` e é iniciado diretamente no diretório configurado, sem exigir `cd /home/jose/ia/codex` antes.

Esses dois recursos têm funções diferentes:

- OmniRoute: provedor/gateway usado pelo fluxo de investigação do Agent IA;
- Codex CLI: agente de terminal aberto como processo interativo independente.

## Instalar e iniciar o OmniRoute

Instalação recomendada pelo projeto:

```bash
npm install -g omniroute
omniroute setup
omniroute --no-open
```

Por padrão, o painel e a API ficam em:

```text
Painel:   http://127.0.0.1:20128
API:      http://127.0.0.1:20128/v1
```

No painel:

1. conecte somente provedores autorizados pela empresa;
2. crie um endpoint e copie a chave gerada;
3. escolha um modelo ou combo apropriado para análise de infraestrutura;
4. teste o endpoint antes de habilitá-lo no Agent IA.

Se o OmniRoute estiver na VM e o painel precisar ser aberto no computador local, use um túnel SSH autorizado:

```bash
ssh -L 20128:127.0.0.1:20128 jose@IP_DA_VM
```

Depois abra `http://127.0.0.1:20128` no navegador local.

## Configurar o OmniRoute no Agent IA

No `.env` do Agent IA:

```env
OMNIROUTE_API_KEY=CHAVE_DO_ENDPOINT
OMNIROUTE_MODEL=MODELO_OU_COMBO_ESCOLHIDO
OMNIROUTE_BASE_URL=http://127.0.0.1:20128/v1
```

Para usar apenas na sessão atual:

```bash
export AI_PROVIDER=omniroute
agent 172.27.232.203 falha no sensor Systemd Socket Summary
```

Para deixar permanente:

```env
AI_PROVIDER=omniroute
```

O Gemini permanece como padrão quando `AI_PROVIDER` não é alterado.

## Configurar o Codex CLI

O caminho pode apontar para o executável ou para a pasta de instalação. Para o ambiente informado:

```env
CODEX_CLI_PATH=/home/jose/ia/codex
CODEX_WORKDIR=/home/jose/ia/codex
CODEX_HOME=
```

Quando `CODEX_CLI_PATH` aponta para uma pasta, o Agent procura automaticamente:

```text
codex
bin/codex
node_modules/.bin/codex
target/release/codex
codex-rs/target/release/codex
```

Também existe fallback para um `codex` disponível no `PATH`.

Valide diretamente na VM:

```bash
command -v codex || true
find /home/jose/ia/codex -maxdepth 4 -type f -name codex -perm -u+x 2>/dev/null
```

Depois execute:

```bash
agent --menu
```

Escolha **OpenAI Codex CLI**. O Agent mostrará a versão detectada e abrirá o Codex no `CODEX_WORKDIR` configurado.

## Segurança operacional

- nenhuma senha, token ou chave deve ser adicionada ao Git;
- o OmniRoute pode encaminhar dados para terceiros, portanto não envie informações de clientes para provedores não aprovados;
- o Codex é iniciado com as permissões do usuário local e continua sujeito ao próprio fluxo de aprovações;
- selecionar Codex não inicia SSH pelo Agent IA;
- reboot de servidores continua bloqueado;
- acesso a bancos de dados de clientes continua bloqueado;
- ações remotas permanecem sob as políticas e a lista positiva do executor do Agent IA.
