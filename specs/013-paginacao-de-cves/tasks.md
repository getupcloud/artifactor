# Tasks: paginação da lista de CVEs (SPA live e snapshot exportado)

- [x] `internal/api`: endpoint `GET /api/cves-page` (filtros de
      `/api/cves` + `page`/`pageSize`; ordem determinística já vem do
      `cveRows`; clamp; 400/truncamento) + testes em `server_test.go`
- [x] SPA live: `cvePage`/`cvePageSize`/`cveTotal` no state, `loadCVEs`
      paginado (reset para página 1 em mudança de filtro, sincronização
      do clamp no poll), barra de paginação (Prev/Next/Page X of Y/
      page size/total)
- [x] Snapshot: case `/api/cves-page` no `snapshotAPI` (mesmo shape,
      clamp client-side) + `downloadCSVClient` usando todas as linhas
      filtradas (não só a página)
- [x] Docs: AGENTS.md (endpoints) + READMEs (tabela da API)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test` + smoke live e snapshot (paginar offline, CSV completo)
