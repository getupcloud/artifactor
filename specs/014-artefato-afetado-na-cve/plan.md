# Plan: PURL e localização do artefato afetado na CVE

## Design

### `internal/scanner` — dados do artefato na CVE

- `CVE` ganha:
  - `PURL string \`json:"purl,omitempty"\``
  - `Locations []string \`json:"locations,omitempty"\`` (paths legíveis, em
    ordem estável, sem duplicatas)
- `cveFromMatch` preenche os dois campos a partir do match do grype:
  - `PURL = m.Package.PURL` (campo `PURL string` do `grype/pkg.Package`);
  - `Locations`: itera `m.Package.Locations.ToSlice()` (o set
    `file.LocationSet` da syft; `ToSlice()` sem sorters já garante ordem
    estável) e usa `loc.Path()` — AccessPath quando presente, senão RealPath
    (o `String()` do `file.Location` é representação de debug
    `Location<RealPath="…">` e não serve para exibição); paths vazios são
    pulados e duplicatas removidas preservando a ordem.
- `applyVex` reusa `cveFromMatch` — as CVEs ignoradas por VEX ganham os
  campos automaticamente.

### `internal/api` — CSV server-side

- `csvColumns`: adicionar `"PURL"` e `"Location"` após `"Type"`.
- `writeCVEsCSV`: gravar `row.PURL` e `strings.Join(row.Locations, "; ")`.
- Nada mais muda: o `cveOut` embute `scanner.CVE`, então `purl`/`locations`
  fluem para `/api/cves`, `/api/cves-page` e o snapshot sem alterações.

### `internal/api/export_files.go` — grype JSON por imagem

- `buildGrypeReport`: preencher `grypeArtifact.PURL` com `c.PURL` e
  `grypeArtifact.Locations` com `c.Locations` (campos já existiam no struct,
  sempre vazios).

### SPA (`web/index.html`)

- `toggleExpansion`: entre o bloco de imagens e a descrição, novo bloco
  `exp-artifact` (oculto quando a CVE não tem PURL nem localizações):
  - label "Artifact:" (`exp-label`), PURL em mono e a lista de localizações
    (uma por linha, mono, `word-break: break-all` para paths longos);
  - tudo escapado com `esc()`.
- CSS: `.exp-artifact` (margem como `.exp-urls`) + `.exp-purl`/`.exp-locs`
  mono, tamanho 12px.
- `downloadCSVClient` (CSV offline do snapshot): mesmas colunas do servidor —
  header ganha `"PURL", "Location"` após `"Type"` e as linhas ganham
  `c.purl || ""` e `(c.locations || []).join("; ")`.

## Riscos

- `m.Package.Locations` pode ser vazio (depende do matcher/catalogador):
  células vazias e bloco omitido — comportamento coberto pelos testes.
- Paths com `; ` no nome quebrariam a coluna CSV — aceitável (mesma
  convenção já usada em `Fixed In`).
- A linha principal da tabela não muda (já tem 7 colunas); os dados novos
  ficam na expansão, que já abriga descrição/URLs.

## Testes

- `internal/scanner/cve_test.go` (novo): `cveFromMatch` com
  `match.Match{Package: pkg.Package{PURL, Locations}}` — PURL copiado,
  locations ordenadas/sem duplicatas/path vazio pulado; package sem
  locations → campo vazio (construção via `file.NewLocationSet`).
- `internal/api/server_test.go`: fixture da CVE-2024-0001 ganha PURL + 2
  localizações; `TestCVEsCSV` passa a conferir o header (`PURL`/`Location`)
  e a linha (`purl`, `libssl.so.3`); `/api/cves-page` e snapshot seguem
  cobertos pelos testes existentes.
- SPA: smoke manual live + snapshot (expansão da linha e CSV offline).
