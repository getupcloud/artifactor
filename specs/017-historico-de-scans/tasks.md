# Tasks: histórico de scans no pod + gráfico de evolução de CVEs

- [ ] `internal/scanner`: `Store.scanStartedAt` em `TryStartScan` +
      getter `ScanStartedAt()` + teste em `store_test.go`
- [ ] `internal/api/history.go`: `HistoryEntry` (+`cluster`/`context` do
      registro de clusters), `SaveHistory`
      (summary.json + scan.json em `<dia>/<hora>`), endpoints
      `GET /api/history` e `GET /api/history/{name...}` (path confinado),
      `Options.HistoryDir`, hook no `handleScan` +
      `history_test.go`
- [ ] `main.go`: flag `--history-dir` (env `HISTORY_DIR`), repasse ao
      `api.Options`, `server.SaveHistory()` no `runScan` bem-sucedido
- [ ] `deploy/deployment.yaml`: env `HISTORY_DIR=/data/history`
- [ ] `web/index.html`: `snapshotAPI`/`snapshotFilterCVEs` com `data`,
      `historyData` + `loadHistoryScan`/`exitHistory`, seção History na
      cluster bar (contador de scans + cluster/contexto/data do scan
      carregado no `#hist-stats`), modal com gráfico SVG (Line/Bar, séries
      por severidade + total) e lista de scans (com cluster · contexto),
      view "Back to live" com guards
- [ ] AGENTS.md (CLI/endpoints/concluídos), READMEs (flags + tabela da
      API) e spec 017
- [ ] JS check, `make build`, `go vet ./...`,
      `go vet -tags integration ./...`, `make test` + smoke
