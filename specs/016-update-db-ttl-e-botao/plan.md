# Plan: TTL de 2h no update automático do DB + botão de atualização manual

## Design

### `internal/scanner/grypedb.go`

- `DBOptions.Force bool` — atualização manual (botão): ignora o TTL.
- `newCurator(dbRoot, appVersion, caCert string, force bool)`:
  `cfg.UpdateCheckMaxFrequency = 0` quando `force` (o curator passa a
  permitir o check sempre; `0` = sem frequência máxima, já suportado pela
  lib). Chamadas de `NewProvider` usam `Force: opts.Force` (false no
  startup) e de `RefreshDB` idem.

### `internal/scanner/grypedbdirect.go`

- Constantes `dbLastUpdateCheckFileName = "last_update_check"` e
  `dbUpdateCheckMaxFrequency = 2 * time.Hour` (espelham o curator v6).
- `directUpdate` reordenado: ler o description instalado **antes** do fetch
  do listing; então
  `if !opts.Force && current != nil && !directUpdateCheckAllowed(opts.Root)`
  → `return false, nil` com debug log (nenhuma rede).
- `directUpdateCheckAllowed(dbRoot string) bool` — lê
  `<dbRoot>/<model>/last_update_check`: ausente/ilegível → true; RFC3339 →
  `time.Since(lastCheck) > dbUpdateCheckMaxFrequency` (mesma comparação
  `>` do curator).
- `setDirectUpdateCheck(dbRoot string)` — grava `time.Now().UTC().Format
  (time.RFC3339)` no mesmo arquivo; chamado no branch "já atualizado" e
  após `directActivate` bem-sucedido (falhas não gravam — igual ao
  curator).
- `grypedbdirect_test.go` (novo): helpers com dir temporário (arquivo
  recente → false; antigo → true; ausente → true; conteúdo inválido →
  true; escrita do arquivo).

### `internal/api/server.go`

- `Options.RefreshDB func() error` — callback do main que dispara o refresh
  forçado em background; nil → endpoint indisponível.
- Rota `POST /api/db/update` → `handleDBUpdate`: callback nil → 503;
  erro do callback (update já em andamento) → 409 `{"error":…}`; ok →
  `202 {"status":"started"}`.

### `main.go`

- Extrai o corpo do tick em `doDBRefresh(force bool)`: marca
  `dbStatus.Updating=true` sob `dbMu` (antes, na verdade — ver abaixo),
  chama `scanner.RefreshDB(DBOptions{..., Force: force})`, atualiza
  `dbStatus`/provider e loga — mesmo comportamento atual.
- `refreshNow := func() error` para a API: sob `dbMu`, se
  `dbStatus.Updating` → erro "update in progress"; senão marca
  `Updating=true` e `go doDBRefresh(true)`; retorna nil. Passado como
  `api.Options.RefreshDB`.
- O tick de `--db-refresh-interval` passa a checar `Updating` antes de
  disparar (não sobrescreve um update manual em andamento) e usa
  `doDBRefresh(false)`.
- Inicialização (`NewProvider`) continua `Force: false` (gated pelo TTL).

### SPA (`web/index.html`)

- Chip vira `<span class="chip" id="db-chip"><span id="db-chip-text">…
  </span><button class="chip-btn" id="db-update-btn" title="Update the
  vulnerability database now">🗘</button></span>`.
- `refreshStatus`: escreve em `db-chip-text`; esconde o botão em snapshot;
  `disabled = !!db.updating`.
- `onclick`: `POST /api/db/update` (padrão do cancel do scan): sucesso →
  banner info "Vulnerability DB update started." + `refreshStatus()`; 409
  → banner com o erro do JSON.
- CSS `.chip-btn`: transparente, muted → hover accent, `disabled`
  esmaecido, padding pequeno.

## Riscos

- O gate direto usa a MESMA janela/semântica do curator (`>` 2h), então
  alternar entre os modos de download compartilha o estado corretamente.
- Update manual durante scan: troca de provider idêntica à do tick —
  scans em voo usam o provider capturado.
- O primeiro run (sem DB) sempre baixa, independente do TTL (sem DB para
  usar).

## Testes

- `grypedbdirect_test.go`: `directUpdateCheckAllowed`/`setDirectUpdateCheck`
  (sem rede).
- `server_test.go`: `POST /api/db/update` → 202 com callback ok, 409 com
  callback que erra, 503 sem callback.
- SPA: sem testes automatizados — smoke manual (botão, 409, snapshot) +
  node check + build/vet/test.
