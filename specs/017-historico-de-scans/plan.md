# Plan: histórico de scans no pod + gráfico de evolução de CVEs

## Design

### `internal/scanner` (Store)

- `Store.scanStartedAt *time.Time` (UTC) gravado em `TryStartScan` (o
  início oficial do run) + getter `ScanStartedAt()`. Não é limpo no
  `FinishScan` (o save roda após o run).

### `internal/api/history.go` (novo)

- `Options.HistoryDir string` ("" = desligado).
- `HistoryEntry` (summary): `{name, startedAt, durationSec, images, total,
  critical, high, medium, low, negligible, unknown, cluster, context}` —
  `cluster`/`context` vêm do registro de clusters (nome selecionado +
  `CurrentContext`) no `SaveHistory`; omitidos quando não há registro.
- `SaveHistory()`: no-op quando `HistoryDir == ""` ou sem `ScanStartedAt`;
  monta `exportSnapshot` via `buildSnapshot()`, conta CVEs por severidade
  (lowercase), nome do dir `startedAt.Format("2006-01-02/15-04-05")` com
  sufixo `-2`… em colisão; `os.MkdirAll` e grava `summary.json` +
  `scan.json` (indentado); log `scan history saved to <dir> (N images, M
  CVE(s))`; qualquer erro vira `logx.Warnf` (nunca falha o scan).
- `handleHistoryList` (`GET /api/history`): desligado → `{"entries":[]}`;
  senão varre `HistoryDir` em dois níveis (dia/hora) lendo os
  `summary.json` (dirs sem o arquivo são ignorados), ordena desc por
  `startedAt`.
- `handleHistoryGet` (`GET /api/history/{name...}`): `r.PathValue("name")`
  limpo com `filepath.Clean` e confinado a `HistoryDir` (prefixo +
  separador; `..`/absolutos → 404); lê `scan.json` e responde como JSON.
- Rotas no `Handler()`: `GET /api/history` e `GET /api/history/{name...}`.
- `statusPayload()`: `"history": HistoryDir != ""` (o SPA usa para
  mostrar/esconder a seção).
- `handleScan`: no goroutine pós-`RunOnce`, `err == nil` → `s.SaveHistory()`.

### `main.go`

- Flag `--history-dir` (env `HISTORY_DIR`, default "") no FlagSet do
  `scan`; repassado em `api.Options.HistoryDir`.
- No loop de rescan (`runScan`), após `RunOnce` com `err == nil` →
  `server.SaveHistory()` (o closure `runScan` já é definido após o
  `server`).

### `deploy/deployment.yaml`

- Env `HISTORY_DIR=/data/history` ao lado de `DB_DIR=/data/db` (o
  emptyDir `/data` já existe).

### SPA (`web/index.html`)

- `snapshotAPI(path, data)` e `snapshotFilterCVEs(params, data)`
  parametrizados (antes liam `SNAPSHOT` direto); `SNAPSHOT` continua
  `const` (só o export real).
- `let historyData = null` + `state.historyName`:
  - `api(path)`: `SNAPSHOT` → snapshot com `SNAPSHOT`; senão, se
    `historyData` e o path for um dos endpoints de dados (status, images,
    cves, cves-page, namespaces, named-vulns, artifacts) → snapshot com
    `historyData`; demais paths vão para o servidor live;
  - `loadHistoryScan(name)`: `fetch("/api/history/"+name)` direto (nunca
    via `api()`), `historyData = data`, reset de seleção/expansões,
    `poll()`; `exitHistory()`: `historyData = null`, `poll()`.
- Seção "History" na cluster bar (após a VEX, separador vertical
  `.vex-sep`; `.hist-sec` reusa o CSS de `.vex-sec`): `#hist-stats`
  (`.hist-count`) entre o título e o botão mostra a quantidade de scans
  salvos — `renderHistoryStats()` — e, com `state.historyScan` (summary do
  scan carregado, setado em `loadHistoryScan`/limpo em `exitHistory`),
  também "· cluster · contexto · data" do scan exibido; o contador é
  atualizado a cada `poll()` (via `loadHistoryCount()`) quando
  `status.history === true` e ao abrir o modal; botão abre o modal;
  `refreshStatus` mostra a seção (e o separador `#hist-sep`) apenas quando
  `status.history === true` (ou com `historyData` carregado).
- Modal `#history-modal`: toolbar (botões Line/Bar), área do gráfico
  (`#hist-chart`), lista (`#hist-list`) e ações.
- Gráfico em SVG puro (sem lib; funciona offline):
  - `renderHistoryChart(entries, mode)`: séries = total + `SEVS`, cores
    via `getComputedStyle` (`--accent`, `--critical`, …); eixo y com
    gridlines rotuladas; eixo x = data de cada scan (`MM-DD HH:MM`, rótulos
    espaçados quando muitos pontos); modo line = `<polyline>` por série;
    modo bar = barras agrupadas por scan (uma barra por série); hover no
    SVG mostra tooltip (`#hist-tip`) com os valores de todas as séries do
    scan mais próximo do ponteiro + linha-guia tracejada (`hist-cursor`);
  - legenda com quadrado de cor + nome por série.
- `renderHistoryList(entries)`: linhas clicáveis (data completa
  `YYYY/MM/DD HH:MM:SS` via `fmtHistFullDate`, "cluster · contexto"
  quando presentes, total, badges por severidade); a entrada em exibição
  fica destacada; clique → `loadHistoryScan` + fecha o modal + banner
  info "Showing historical scan from <data>".
- Modo histórico (view): `refreshStatus` põe o botão principal em
  "Back to live" (`scan-btn.onclick` vira `exitHistory()`); status line
  mostra "Viewing history: <name>"; cluster/context/add/remove e botões
  VEX desabilitados; CSV/export usam `historyData || SNAPSHOT`.

## Riscos

- O histórico mora no emptyDir: morre com o pod (escopo pedido; PVC fica
  para depois).
- Snapshot completo por scan pode ocupar espaço com o tempo (dezenas de
  MB por scan em clusters grandes) — aceitável no escopo; listagem só lê
  os summaries.
- Dois scans no mesmo segundo: sufixo `-2` garante unicidade.
- `historyData` não persiste entre page loads (estado de view, como o
  resto da SPA).

## Testes

- `store_test.go`: `TryStartScan` grava `ScanStartedAt`; getter.
- `internal/api/history_test.go` (novo): `SaveHistory` cria
  `<dia>/<hora>` com `summary.json`+`scan.json` (conteúdo do summary
  confere com o store fixture); lista ordena desc e ignora dirs sem
  summary; get devolve o scan.json; 404 para nome desconhecido e para
  path traversal (`../`); `HistoryDir` vazio → lista vazia e SaveHistory
  no-op.
- SPA: sem testes automatizados — smoke manual (gráfico line/bar, load,
  back to live) + node check + build/vet/test.
