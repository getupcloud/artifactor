# Tasks: access log dos servidores HTTP (métricas, SPA e API)

- [x] `internal/api`: `statusRecorder`, middleware `AccessLog` exportado
      (pula `/healthz`, loga `http: <método> <path> <status> <duração>
      <bytes>B <remote>` via logx) e `Options.AccessLog` ligando o wrap em
      `Handler()`
- [x] `internal/api/server_test.go`: testes do middleware (200/404/bytes,
      skip do `/healthz`, resposta intacta)
- [x] `main.go`: `AccessLog: true` no servidor do SPA e
      `api.AccessLog(metrics.New(store))` no servidor de métricas
- [x] AGENTS.md (formato de log, ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test` + smoke dos três endpoints
