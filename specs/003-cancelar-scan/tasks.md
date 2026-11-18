# Tasks: cancelar o scan em andamento pela UI

- [x] `internal/scanner`: `Store.TryStartScan(cancel)`, `CancelScan()`
      (cancela + re-marca `scanning`→`queued`), `FinishScan` limpa o cancel;
      producers com `break` rotulado no `ctx.Done()` e workers que pulam/
      descartam resultados após o cancelamento (`RunOnce` e `runFromSBOM`)
- [x] `internal/scanner/store_test.go`: registro do cancel, rejeição de
      segundo start, `CancelScan` (com/sem scan), re-marcação de status
- [x] `internal/api`: rota `POST /api/scan/cancel`, `handleScan` com
      `context.WithCancel` registrado no store
- [x] `internal/api/server_test.go`: cancel com scan → 200; sem scan → 409
- [x] `main.go`: rescan por intervalo com cancel registrado no store
- [x] `web/index.html`: botão "Scan now" ↔ "Cancel scan" (classe danger),
      clique de cancelar chama `/api/scan/cancel` e atualiza a view
- [x] Spec 003 (spec/plan/tasks) e AGENTS.md
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test`
