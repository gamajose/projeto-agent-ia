# Fluxo de branches, validação e versões

## Branches

A branch `main` representa a versão estável que pode ser atualizada nos servidores.
Toda alteração deve ser feita em uma branch separada:

- `feature/<descricao>` para funcionalidades;
- `fix/<descricao>` para correções;
- `chore/<descricao>` para manutenção, documentação e pipeline.

Não faça commits de desenvolvimento diretamente na `main`.

## Pull request e validação

Abra um pull request da branch de trabalho para a `main`.
O workflow `CI e versionamento` executa automaticamente:

1. instalação das dependências;
2. compilação dos módulos Python;
3. execução dos testes com `pytest`;
4. validação da versão no formato `MAJOR.MINOR.PATCH`;
5. verificação de que a tag da versão ainda não existe.

O pull request deve ser integrado somente depois que o job `Validar código` estiver concluído com sucesso.

## Versionamento

A versão oficial está no arquivo `pyproject.toml`:

```toml
[project]
version = "0.2.0"
```

Use versionamento semântico:

- `PATCH`, por exemplo `0.2.0` para `0.2.1`: correção compatível;
- `MINOR`, por exemplo `0.2.0` para `0.3.0`: nova funcionalidade compatível;
- `MAJOR`, por exemplo `0.2.0` para `1.0.0`: mudança incompatível ou versão estável principal.

Cada pull request que será integrado precisa declarar uma versão ainda não publicada.

## Tags automáticas

Depois do merge, o push na `main` executa novamente todos os testes. Se a validação passar, o workflow cria e publica automaticamente uma tag anotada no formato:

```text
vMAJOR.MINOR.PATCH
```

Exemplo:

```text
v0.2.0
```

Se a tag já existir, o pipeline falha para impedir que duas versões diferentes usem o mesmo número.

## Atualização dos servidores

Para acompanhar sempre a versão estável da `main`:

```bash
cd /opt/agent-ia
git switch main
git pull --ff-only origin main
```

Para instalar uma versão específica:

```bash
cd /opt/agent-ia
git fetch --tags
git switch --detach v0.2.0
```

Antes de atualizar um servidor operacional, confira o resultado do GitHub Actions e a tag publicada.
