# Plan: cancelar o scan em andamento pela UI

## Design

### `internal/scanner` (Store)

- `Store` ganha `scanCancel context.CancelFunc`.
- `TryStartScan(cancel context.CancelFunc) bool` — registra o cancel
  atomicamente ao iniciar (sem janela entre "scanning=true" e o registro).
- `CancelScan() bool` — sob o lock: chama o cancel, devolve imagens
  `scanning` → `queued` (limpa `StartedAt`) e retorna false quando não há
  scan. Workers que terminarem depois do cancel descartam resultados parciais
  (não sobrescrevem o "queued").
- `FinishScan()` limpa o `scanCancel`.

### `internal/scanner` (RunOnce / runFromSBOM)

- Producer: `break` rotulado no `select` do `ctx.Done()` (o `break` atual
  sai só do select e continuava enfileirando).
- Workers: pulam as imagens restantes quando `ctx.Err() != nil` e, após
  `scanImage`/`scanSBOMFile`, descartam o resultado se o contexto foi
  cancelado (o Store já devolveu a imagem para "queued").
- `return ctx.Err()` já garante que o cancelamento não vira erro de DB nos
  chamadores (`err != context.Canceled`).

### `internal/api`

- `POST /api/scan/cancel` → `Store.CancelScan()`; 200 `{"status":"canceled"}`
  ou 409 `{"error":"no scan is running"}`.
- `handleScan` cria `scanCtx, cancel := context.WithCancel(context.Background())`
  e passa `cancel` para `TryStartScan`.

### `main.go`

- O rescan por intervalo também deriva `scanCtx` do ctx principal com cancel
  registrado no `TryStartScan` (o cancelamento pela UI funciona para scans
  iniciados por intervalo também).

### SPA (`web/index.html`)

- `refreshStatus`: `scan-btn` habilitado durante o scan (disabled só por
  `!loaded`), texto "Cancel scan" + classe `danger` quando `scanning`.
- `scan-btn.onclick`: se `scanning` → `POST /api/scan/cancel`, banner de
  info "Scan canceled" e refresh imediato de status/imagens; senão o fluxo
  atual de iniciar scan.

## Riscos

- Race cancel × worker finalizando: resolvido descartando resultados de
  `scanImage` quando o ctx já foi cancelado (a re-marcação para "queued" do
  `CancelScan` não é sobrescrita).
- Scan por `--scan-interval` em andamento também é cancelável (mesmo
  mecanismo); o próximo tick dispara um novo scan normalmente.

## Testes

- `internal/scanner/store_test.go`: `TryStartScan` registra o cancel e
  rejeita um segundo start; `CancelScan` chama o cancel e devolve
  `scanning`→`queued`; `CancelScan` sem scan → false; `FinishScan` limpa o
  cancel.
- `internal/api/server_test.go`: `POST /api/scan/cancel` → 409 sem scan;
  200 com scan iniciado (via `TryStartScan`).
