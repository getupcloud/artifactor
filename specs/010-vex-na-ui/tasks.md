# Tasks: gestão de VEX no SPA (upload, reprocessamento e diálogo)

- [x] `internal/scanner`: `VexDoc`, `Options.VexDocs`, matches/
      `pkgContext` crus no `Result`, `applyVex` por doc, `SetVexDocs`,
      `ReprocessVex`, `Store.ReplaceCVEs` + testes
- [x] `internal/vex`: `Manager` (Add/Remove/List/Content/Docs, temp
      files, resumo OpenVEX/CSAF) + testes
- [x] `internal/api`: endpoints `/api/vex` (GET/POST/DELETE/download) +
      `applyVexDocs` (SetVexDocs + ReprocessVex) + testes
- [x] `main.go`: docs do startup (basename), `VexDocs` no scanner/api e
      `Vex: vex.New()` no servidor
- [x] `web/index.html`: seção VEX na cluster bar (add + diálogo com
      lista selecionável, Download/Copy/Remove, Ctrl+C), upload
      sequencial e refresh
- [x] AGENTS.md (mapa, CLI/endpoints, ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test` + smoke
