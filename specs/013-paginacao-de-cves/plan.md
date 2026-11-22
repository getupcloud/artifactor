# Plan: paginação da lista de CVEs (SPA live e snapshot exportado)

## Design

### `internal/api` — endpoint paginado (sem quebrar o existente)

- **Novo** `GET /api/cves-page`: `mux.HandleFunc("GET /api/cves-page", …)`.
  - Reusa `filteredCVEs(r.URL.Query())` (mesmos filtros de `/api/cves`) e
    aplica `page`/`pageSize`:
    - parse de `page` (default 1) e `pageSize` (default 100): não numérico
      ou < 1 → `400 {"error": …}`; `pageSize` truncado em 500.
    - a ordem **já é determinística**: `cveRows()` ordena por severidade →
      pacote → CVE id (mesmo comparador do snapshot) — o endpoint apenas
      fatia, sem novo sort.
    - clamp de `page` ao último índice (`page = min(page, ceil(total/pageSize))`,
      mínimo 1) e slice `[(page-1)*pageSize : page*pageSize]` (clamp do fim).
    - resposta: `{"rows": [...], "total": N, "page": P, "pageSize": S}`.
  - `/api/cves` (array) e `/api/cves.csv` ficam **intocados** (CSV continua
    completo; testes existentes não quebram).
- Docstring do novo handler documentando params/erros; linha na tabela da
  API nos READMEs.

### SPA live (`web/index.html`)

- `state` ganha `cvePage` (1-based), `cvePageSize` (100) e `cveTotal`.
- `loadCVEs()` chama `api("/api/cves-page?" + buildCVEsParams() + "&page=&pageSize=")`;
  `state.lastCVERows = data.rows`; atualiza `cveTotal`.
  - A lógica de `lastQuery` (mudou filtro → esquece expansões) também zera
    `cvePage` para 1.
  - Poll com o mesmo query re-busca a página atual; se `cvePage` passou do
    fim (total encolheu), o servidor já faz clamp e a UI sincroniza
    `cvePage = data.page`.
- **Barra de paginação** (nova, entre a tabela e o rodapé do main):
  `<div id="pager">` com `< Prev`, "Page X of Y", `Next >`, total
  ("N CVE(s)") e `<select>` de page size (50/100/250/500). `Prev`/`Next`
  disparam `loadCVEs()`; o select zera `cvePage` para 1. Oculta quando
  `total <= pageSize` (ou sempre visível com controles desabilitados —
  decisão de implementação: mostrar só quando `total > pageSize`).
- CSV live continua `window.location.href = "/api/cves.csv?..."`
  (server-side completo — não usa `lastCVERows`).

### Snapshot/export (HTML único)

- `snapshotAPI` ganha o case `"/api/cves-page"`: reusa `snapshotFilterCVEs`
  (filtra + ordena tudo) e fatia client-side retornando o **mesmo shape**
  `{rows, total, page, pageSize}` com clamp idêntico ao servidor.
- O comparador já existe no snapshot (`snapshotFilterCVEs`); documentar que
  server e client **precisam** manter a mesma ordem (mesma regra).
- **Correção obrigatória**: `downloadCSVClient()` hoje usa
  `state.lastCVERows` (que passaria a ser só a página atual). Passar a
  construir o CSV de `snapshotFilterCVEs(buildCVEsParams())` (todas as
  linhas) — mantém o CSV offline completo.

## Riscos

- **Ordem instável**: `cveRows()` itera maps — sem o sort explícito, as
  páginas "pulam" entre polls. Mitigado pelo sort determinístico no
  endpoint e no snapshot.
- **CSV truncado**: o maior risco de regressão é o CSV offline usar
  `lastCVERows` (agora paginado) — tratado explicitamente acima.
- **Poll vs página**: novo scan pode encolher o total; o clamp no server +
  sincronização de `cvePage` na resposta evitam página vazia.
- **Custo server**: o slice filtrado completo continua sendo construído por
  request (mesmo custo de hoje); só o payload muda. Indexação/paginação
  incremental fica fora do escopo.

## Testes

- `internal/api/server_test.go`: `/api/cves-page` — página 1 default,
  pageSize default 100, filtros + paginação combinados, clamp de `page`
  alta, `page=0`/`abc` → 400, `pageSize` truncado em 500, `total` correto
  com/sem filtros, ordem estável entre duas chamadas.
- SPA: sem testes automatizados — smoke manual live + snapshot (abrir o
  `scan.html` exportado e paginar offline, CSV offline completo).

## Tarefas (resumo)

1. `internal/api`: handler `/api/cves-page` + `sortCVEs` + testes.
2. SPA live: estado de paginação, `loadCVEs` paginado, barra de paginação,
   reset de página em mudança de filtro.
3. Snapshot: case `/api/cves-page` no `snapshotAPI` + CSV offline completo.
4. Docs: AGENTS.md (endpoints) + READMEs (tabela da API).
5. `make build`, `go vet ./...`, `go vet -tags integration ./...`,
   `make test` + smokes.
