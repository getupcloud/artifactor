# Tasks: TTL de 2h no update automático do DB + botão de atualização manual

- [x] `internal/scanner`: `DBOptions.Force`, `newCurator(..., force)`,
      TTL no `directUpdate` (gate antes da rede, gravação do
      `last_update_check` nos checks bem-sucedidos) +
      `grypedbdirect_test.go`
- [x] `internal/api`: rota `POST /api/db/update` (202/409/503) com
      `Options.RefreshDB` + testes em `server_test.go`
- [x] `main.go`: `doDBRefresh(force)`, `refreshNow` para a API, tick com
      guard de `Updating`
- [x] `web/index.html`: botão 🗘 no db-chip (escondido em snapshot,
      disabled durante update, POST + banner)
- [x] AGENTS.md (endpoints/concluídos), READMEs (tabela da API) e spec 016
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test` + smoke
