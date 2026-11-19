# Plan: status line "Atualizando DB de vulnerabilidades" no SPA

## Design

### Backend

- `internal/scanner/grypedb.go`: `DBStatus` ganha
  `Updating bool \`json:"updating,omitempty"\``. `NewProvider`/`RefreshDB`
  não mexem no campo (retornam false) — quem controla o ciclo é o `main`,
  que sabe quando a operação começa e termina.
- `main.go`:
  - `dbStatus` inicial vira `scanner.DBStatus{Dir: *dbDir, Updating: true}`
    (a goroutine de init começa logo em seguida; o SPA já sobe mostrando o
    estado);
  - a goroutine de init já faz `dbStatus = status` ao concluir — o
    `status` retornado tem `Updating=false`, então a linha "apaga" sozinha
    (sucesso ou `--ignore-grype-db-unavailable`);
  - o tick do `--db-refresh-interval` marca `dbStatus.Updating = true`
    antes de `RefreshDB` e limpa depois: em sucesso via `dbStatus = status`;
    em falha mantém os campos anteriores e apenas zera `Updating`.
- `/api/status` já serializa `db` inteiro — o campo flui sem mudanças no
  `internal/api` (só um assertion novo no teste do status endpoint).

### SPA (`web/index.html`)

- CSS: `.statusline` — barra em fluxo normal (sem `position` nem
  `z-index`, mesmo plano z do resto da página), mesma paleta do banner
  info, `display: none` / `.show`; reusa a classe `.dot.scanning` (pulse)
  como indicador.
- HTML: `<div class="statusline" id="status-line"></div>` como primeiro
  elemento do `<body>` (antes do header), empurrando o conteúdo em vez de
  sobrepô-lo.
- JS: em `refreshStatus` (que já lê `state.status.db`), se
  `!SNAPSHOT && db.updating` → preenche a linha (texto fixo + dot) e
  adiciona `.show`; senão remove `.show`. O poll de 8 s remove a linha
  quando o update termina.

## Riscos

- A linha usa texto fixo (sem dados do usuário) — sem risco de XSS.
- Em snapshots o campo `updating` pode existir no JSON congelado; o guard
  `!SNAPSHOT` impede a linha de aparecer no relatório exportado.
- Aparecer/sumir da linha desloca o conteúdo (layout shift) por um
  instante; aceitável — acontece só no início/fim da atualização do DB.

## Testes

- `internal/api/server_test.go`: o campo `updating` do `DBStatus` chega ao
  payload de `/api/status`.
- SPA: validação visual por smoke (o SPA não tem testes automatizados).
