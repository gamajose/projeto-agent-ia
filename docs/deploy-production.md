# Deploy automático na VM

O deploy de produção usa o runner self-hosted com o label estável
`agent-ia-prod`. O job só executa depois que a validação e a criação da tag
terminam com sucesso em um `push` na `main`.

Pull requests nunca executam código no runner de produção.

## Layout

```text
~/.config/agent-ia/production.env     # segredos, modo 600, fora do Git
~/agent-ia-production/
├── current -> releases/SHA
├── releases/
│   └── SHA/
└── state/
```

Cada release possui código e `.venv` próprios. O script inicia a API numa porta
temporária, valida `/health` e só então troca `current` de forma atômica.

## Proteções

- checkout fixado no SHA validado pela CI;
- ativação aceita somente o SHA explicitamente aprovado pelo workflow;
- execução automática restrita a `push` na `main`;
- `.env` externo ao checkout e com permissão `600` ou `400`;
- apenas um deploy de produção por vez;
- workflows de pull request continuam em runners hospedados pelo GitHub;
- backup das unidades systemd antes de cada ativação;
- rollback para a release ou unidades anteriores se restart, health ou workers
  falharem.

## Primeiro bootstrap

O runner deve estar online com os labels:

```text
self-hosted
Linux
X64
agent-ia-prod
```

Prepare o arquivo de ambiente uma única vez:

```bash
install -d -m 700 ~/.config/agent-ia
install -m 600 ~/projeto-agent-ia/.env ~/.config/agent-ia/production.env
```

Não remova o checkout legado até que o primeiro deploy tenha sido validado. Se
a primeira ativação falhar, o script restaura as unidades que apontavam para
esse checkout.

## Preparação sem ativação

O comando abaixo instala e testa uma release, mas não troca o symlink nem
reinicia serviços:

```bash
AGENT_RELEASE_SHA="$(git rev-parse HEAD)" \
  bash deploy/scripts/deploy_release.sh --prepare
```

## Ativação manual de emergência

A ativação manual exige repetir o SHA exato para evitar troca acidental:

```bash
sha="$(git rev-parse HEAD)"
AGENT_RELEASE_SHA="$sha" \
AGENT_DEPLOY_APPROVED_SHA="$sha" \
  bash deploy/scripts/deploy_release.sh --activate
```

O caminho normal continua sendo CI, tag e deploy pelo GitHub Actions.
