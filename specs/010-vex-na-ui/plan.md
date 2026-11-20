# Plan: gestão de VEX no SPA (upload, reprocessamento e diálogo)

## Design

### `internal/scanner` — matches crus + reprocessamento

- `VexDoc{Path, Name}` (exportado): um documento VEX — o path que o
  processador do grype lê e o nome exibido/atribuído.
- `Options.VexFiles` vira `Options.VexDocs []VexDoc` (o main resolve os
  paths e usa `filepath.Base` como nome); `Scanner` guarda
  `vexDocs []VexDoc` (mu) com `SetVexDocs(docs)` para o conjunto corrente.
- `Result` ganha campos não exportados `matches *match.Matches` e
  `pkgContext pkg.Context` (sempre preenchidos no scan — o reprocessamento
  pode ser pedido a qualquer momento; cópias no `Snapshot` são rasas, os
  matches são só de leitura após o `Put`).
- `matchCVEs` passa a devolver também os matches: a cadeia VEX vira
  `applyVex(matches, pkgContext, docs) ([]CVE, error)` — constrói um
  processador por doc a cada chamada (a lib relê os arquivos de qualquer
  forma) e atribui `VexFile = doc.Name`.
- `ReprocessVex() error`: itera `Store.Snapshot("")`, re-aplica
  `applyVex` com os docs correntes em quem tem matches e grava com o novo
  `Store.ReplaceCVEs(img, cves)` (recalcula `Cves` e `Severities`;
  `summary()` já deriva `CVECount` de `len(Cves)`).

### Novo pacote `internal/vex` — arquivos enviados em memória

- `Manager`: nome → conteúdo, ordem de inserção, temp dir próprio
  (`os.MkdirTemp` no primeiro Add) para o processador ler; `Add` valida o
  formato via `grype/vex.NewProcessor` sobre o temp file (mesma checagem
  do `ResolveVexFiles`), gera o resumo e guarda; `Remove`, `List`,
  `Content(name)` e `Docs() []scanner.VexDoc` (Path = temp file, Name =
  nome do upload).
- Resumo por formato (parse genérico do JSON, sem dependências novas):
  OpenVEX → `N statements (x not_affected, y fixed, …) · M CVE(s)`;
  CSAF → `"<título>" · N vuln(s) · M CVE(s)`.
- Erros: `ErrDuplicate`, `ErrNotFound`, formato inválido.

### `internal/api`

- `Options.VexDocs []scanner.VexDoc` (docs do startup) e `Vex *vex.Manager`
  (nil nos testes/exports).
- Endpoints: `GET /api/vex` (`{files:[Info...]}`),
  `POST /api/vex` (`{name, content}`, MaxBytesReader 1 MiB; 201 ou 400/409),
  `DELETE /api/vex/{name}`, `GET /api/vex/{name}` (download raw).
- `handleVexChange()`: combina `Options.VexDocs` + `manager.Docs()` e chama
  `Scanner.SetVexDocs` + `Scanner.ReprocessVex()` (erro → 500 com a
  mensagem; o manager já registrou o arquivo). 503 quando `Scanner` é nil.

### `main.go`

- Depois do `ResolveVexFiles`: `docs := makeVexDocs(vexFiles)` (basename);
  `scanner.Options.VexDocs = docs`, `api.Options.VexDocs = docs`,
  `api.Options.Vex = vex.New()` no caminho do servidor (não nos exports).

### SPA

- Na cluster bar, logo após o select de cluster:
  `<button id="add-vex-btn">+ Add VEX</button>` +
  `<button id="vex-files-btn">VEX files</button>` + `<input type="file"
  multiple hidden accept=".json,application/json">`.
- Upload: FileReader por arquivo → `POST /api/vex` sequencial → `poll()`;
  erro no banner (`showBannerError`).
- Diálogo `#vex-modal` (estilo do modal de clusters): lista de arquivos
  (nome + badge do formato + resumo), clique seleciona (`.active`);
  botões Download (blob + `<a download>`), Copy (`copyText` com o conteúdo
  buscado) e Remove (DELETE + `poll()`); Ctrl+C dentro do diálogo copia o
  selecionado.
- Barra oculta em snapshot/`--from-sbom` → seção não aparece (o `--vex` do
  startup continua valendo).

## Riscos

- Memória: guardar os matches crus por imagem aumenta o footprint
  (dezenas de MB em clusters grandes) — aceitável (limite 4Gi no deployment).
- Reprocessar durante um scan: workers finalizando gravam o resultado com
  os docs que leram; o `ReprocessVex` roda depois e sobrescreve com o
  conjunto novo — janela pequena, consistência eventual (o poll corrige).
- Temp files dos uploads: criados em `os.MkdirTemp`, removidos no
  `Remove`; o processo os limpa no encerramento do SO.

## Testes

- `internal/scanner`: `ReprocessVex`/`ReplaceCVEs` (com e sem docs; CVE
  marcada volta ao normal ao remover o doc).
- `internal/vex`: Add (openvex/csaf/inválido/duplicado), resumo, Remove,
  Docs, Content.
- `internal/api`: endpoints (lista vazia, add→reprocessa store, 400/409,
  download, delete→reprocessa).
- SPA: smoke manual.
