# Plan: verificação de nova versão no início do programa

## Design

Novo pacote `internal/selfupdate/` (sem dependência de main; logging fica no
chamador — o pacote retorna erros e o main loga via logx):

- `LatestRelease(ctx, insecure bool) (*Release, error)` — `net/http` puro
  (client com `InsecureSkipVerify` quando `--insecure-skip-tls`), timeout de
  10s para o GET; parseia `tag_name` e `assets[]` (name +
  `browser_download_url`) do JSON da API.
- seleção do asset dentro de `parseRelease(data, goos, goarch)` — escolhe o
  asset `artifactor_<goos>_<goarch>.tar.gz` (naming gerado pelo goreleaser,
  ver abaixo); sem asset compatível → erro tratado como aviso.
- `IsNewer(current, latest string) (bool, error)` — comparação semver com
  `github.com/Masterminds/semver/v3` (já em go.sum como indireta; vira
  dependência direta). Prefixo `v` do tag é removido. Versões não-semver
  retornam erro (main ignora — build "dev").
- `(*Release).Apply(ctx, target string, insecure bool) error`:
  1. baixa o asset para temp em `os.TempDir()` (sem timeout fixo, obedece ao
     ctx);
  2. abre o `.tar.gz` (stdlib `compress/gzip` + `archive/tar`) e extrai
     **apenas** a entrada `artifactor` (regular file), com proteção contra
     path traversal (entrada deve ser um único componente `artifactor`);
  3. destino = `filepath.EvalSymlinks(target)` (path do binário em execução);
     se o diretório de destino for gravável (`unix.Access(W_OK)`):
     extrai para `<destino>.new` no mesmo diretório, `chmod 0755` e
     `os.Rename` (atômico, funciona com o binário em execução no Linux/macOS);
  4. se não for gravável: extrai em `os.TempDir()` e executa
     `sudo install -m 0755 <temp> <destino>` com stdin/stdout/stderr ligados
     ao terminal (o sudo pede a senha). `sudo` ausente → erro claro.

## Integração no main

- Flag `--no-check-update-version` (env `NO_CHECK_UPDATE_VERSION`) no
  FlagSet do `scan`.
- `checkForUpdate()` chamada no início de `runScanCmd` (depois do parse das
  flags e do setup do log), **antes** do branch in-cluster/export/servidor:
  - skip quando: flag/env ligados; `KUBERNETES_SERVICE_HOST` setado (dentro
    de pod — mesmo sinal do `rest.InClusterConfig`); `--hold` (flag interna do
    pod in-cluster); `version == "dev"` ou não-semver;
  - consulta o release e compara; sem release novo → nada (debug log);
  - release novo + stdin é TTY (`os.Stdin.Stat()` `ModeCharDevice`) →
    pergunta com `askYN` (já existe em in_cluster.go); "não" → segue;
  - release novo + sem TTY → só `logx.Warnf` avisando;
  - "sim" → `Apply` com `os.Executable()`; sucesso → `logx.Infof` avisando
    que a nova versão vale após reiniciar; falha → `logx.Warnf` e segue.
- `install`/`uninstall`/`cat`/`--version` não verificam.

## Releases do GitHub

- `.goreleaser.yaml`: adicionar seção `archives` (formats `tar.gz`,
  `name_template: "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}"`), para os
  releases publicarem `artifactor_linux_amd64.tar.gz` e
  `artifactor_linux_arm64.tar.gz` contendo apenas o binário. Sem isso o
  release não tem asset para baixar. O workflow `release.yaml` já usa
  `goreleaser release --clean`, que faz o upload automático dos archives.

## Riscos

- API do GitHub sem token tem rate limit (60/h por IP); falha vira aviso e
  não bloqueia.
- Binário grande (~100MB+ pelas libs syft/grype): download pode demorar; sem
  progress bar (só log), aceitável para v1.
- Trocar o binário em execução: rename atômico no mesmo diretório funciona no
  Linux/macOS; o processo antigo continua rodando até o usuário reiniciar.
- Testes não podem depender de rede: parse/compare/extração/instalação
  testados com dados locais.
