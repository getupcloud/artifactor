# Tasks: PURL e localização do artefato afetado na CVE

- [x] `internal/scanner`: campos `PURL`/`Locations` no `CVE` +
      `cveFromMatch` preenchendo de `m.Package` (ordem estável, dedupe,
      paths vazios pulados) + `internal/scanner/cve_test.go`
- [x] `internal/api`: colunas `PURL`/`Location` no `csvColumns` e no
      `writeCVEsCSV` + fixture/assertions em `server_test.go`
- [x] `internal/api/export_files.go`: `buildGrypeReport` preenchendo
      `artifact.purl`/`artifact.locations`
- [x] `web/index.html`: bloco `exp-artifact` (PURL + localizações) na
      expansão da linha + CSS + colunas no `downloadCSVClient`
- [x] AGENTS.md (ideias concluídas) e spec 014
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test` + smoke live e snapshot
- [x] `internal/scanner`: `Locations` vira `[]CVEArtifactLocation{Path,
      Kind}` com `locationKind` por tipo de pacote (package/filename/
      metadata/config) + testes
- [x] `internal/api`: CSV/grype export usam só os paths das localizações
      + fixture com kinds em `server_test.go`
- [x] `web/index.html`: labels `purl:`/`package:`/`filename:`/
      `metadata:`/`path:` no bloco do artefato, título "DESCRIPTION"
      acima da descrição, CSV offline com paths
- [x] revalidar: JS check, `make build`, `go vet` (comum e integration),
      `make test`
