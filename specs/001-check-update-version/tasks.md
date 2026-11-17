# Tasks: verificação de nova versão no início do programa

- [x] Adicionar seção `archives` ao `.goreleaser.yaml` (tar.gz por
      linux/amd64 e linux/arm64 com o binário `artifactor`)
- [x] Criar `internal/selfupdate/selfupdate.go`: `LatestRelease` (+ seleção
      do asset em `parseRelease`), `IsNewer` (Masterminds/semver v3 como dep
      direta) e `Apply` (download + extração do binário + instalação atômica
      com fallback `sudo install`)
- [x] Criar `internal/selfupdate/selfupdate_test.go`: semver, seleção de
      asset, extração de tar.gz (incl. path traversal) e instalação em
      diretório gravável
- [x] Integrar em `main.go`: flag `--no-check-update-version` (env
      `NO_CHECK_UPDATE_VERSION`), `checkForUpdate()` no início de
      `runScanCmd` com os skips (flag, pod via `KUBERNETES_SERVICE_HOST` /
      `--hold`, versão "dev"), prompt via `askYN` só com TTY e aplicação via
      `Apply(os.Executable())`
- [x] Atualizar AGENTS.md (mapa do repo, CLI e ideias concluídas)
- [x] `make build`, `go vet ./...` e `make test`
