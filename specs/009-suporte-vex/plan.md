# Plan: suporte a VEX (flag --vex, indicador e filtro no SPA)

## Design

### `internal/scanner` — carregamento e aplicação

- `vex.go` (novo): `ResolveVexFiles(paths []string) ([]string, error)` —
  expande cada caminho: arquivo → ele mesmo; diretório → arquivos regulares
  diretos (não recursivo, ordenados); valida existência e formato
  (tenta `vex.NewProcessor` por arquivo — detecta OpenVEX/CSAF) e devolve a
  lista final de arquivos.
- `scanner.Options.VexFiles []string` (arquivos já resolvidos);
  `Scanner.New` constrói um `*vex.Processor` **por arquivo** (erro guardado
  em `s.vexErr` — impossível se `ResolveVexFiles` validou, mas defensivo).
- `CVE` ganha `VexStatus string` (`json:"vexStatus,omitempty"`) e
  `VexFile string` (`json:"vexFile,omitempty"`).
- `matchCVEs`: refatora o match→CVE num helper `cveFromMatch`; chama
  `FindMatchesContext` **sem** `VexProcessor` e aplica os processadores em
  cadeia com `ApplyVEX(&pkgContext, remaining, nil)` por arquivo — as
  ignoradas (`not_affected`/`fixed`) viram CVEs com `VexStatus` (do
  `AppliedIgnoreRules[0].VexStatus`) e `VexFile` do arquivo corrente. A
  ordem (normalize → VEX) é a mesma do CLI do grype (o VEX roda após o
  normalize dentro do `FindMatchesContext`).

### `internal/api`

- `filteredCVEs`: parâmetro novo `exclude-vex=1` — pula linhas com
  `VexStatus != ""`. Documentar na docstring de `/api/cves`.
- Nenhuma outra mudança: `cveOut` embute `CVE`, então os campos novos
  fluem para a API, o snapshot e o CSV automaticamente.

### `main.go` / exports / in-cluster

- Flag `--vex` (`pflag.StringArray`, repetível) + env `VEX` (vírgula →
  entradas extras, como os outros flags com env); `ResolveVexFiles` no
  startup com `fatalf("--vex: %v", err)`.
- `runExport` ganha o parâmetro `vexFiles []string` (resolvido antes da
  chamada) e repassa ao `scanner.Options`.
- `in_cluster.go`: `--in-cluster` rejeita `--vex` (arquivos locais), mesmo
  padrão do `--from-sbom`.

### SPA (`web/index.html`)

- Linha da CVE: quando `c.vexStatus` existe, badge `VEX` (estilo próprio,
  muted) + `c.vexFile` (basename visível; caminho completo + status no
  `title`), no cell do ID.
- Checkbox novo `vex-filter` ("Hide VEX excluded") **à esquerda** do
  `fixed-filter`; `buildCVEsParams` manda `exclude-vex=1`; `clear-btn`
  limpa; `snapshotFilterCVEs` espelha o filtro (`!excludeVex ||
  !c.vexStatus`).

## Riscos

- A lib relê os documentos a cada `ApplyVEX` (um processador por arquivo,
  por imagem): arquivos VEX são pequenos; aceitável (o grype CLI faz o
  mesmo).
- Um match pode ser "afetado" num VEX e "não afetado" em outro: a cadeia
  decide pela ordem dos arquivos (o augment só adiciona; o filter remove
  do `remaining`).
- Cardinalidade/UI: CVEs VEX-ignoradas continuam contando nos chips de
  severidade (comportamento pedido; o checkbox é o filtro).

## Testes

- `internal/scanner/vex_test.go`: `ResolveVexFiles` (arquivo, diretório
  ordenado, vazio, inexistente, formato inválido).
- `internal/api/server_test.go`: `exclude-vex=1` filtra linhas com
  `VexStatus` (store com CVEs marcadas e não marcadas) e CSV idem.
- Smoke manual com um OpenVEX real + `--from-sbom`.
