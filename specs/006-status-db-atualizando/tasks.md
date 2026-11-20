# Tasks: status line "Updating vulnerability DB" no SPA

- [x] `internal/scanner/grypedb.go`: campo `Updating` no `DBStatus`
      (json `updating,omitempty`)
- [x] `main.go`: `dbStatus` inicial com `Updating: true`; tick do refresh
      marca `Updating=true` antes do `RefreshDB` e limpa após (sucesso via
      atribuição do status; falha zera só o campo)
- [x] `internal/api/server_test.go`: assertion do campo `updating` no
      payload de `/api/status`
- [x] `web/index.html`: CSS/HTML da `.statusline` fixa na base + toggle em
      `refreshStatus` (`!SNAPSHOT && db.updating`), texto
      "Updating vulnerability DB…" com dot pulsante
- [x] AGENTS.md (ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test`
