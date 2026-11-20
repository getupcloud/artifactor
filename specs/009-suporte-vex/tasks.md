# Tasks: suporte a VEX (flag --vex, indicador e filtro no SPA)

- [x] `internal/scanner/vex.go`: `ResolveVexFiles` (arquivo/diretório
      não recursivo, validação de existência e formato OpenVEX/CSAF) +
      `vex_test.go`
- [x] `scanner`: `Options.VexFiles`, processador por arquivo em `New`,
      `CVE.VexStatus`/`CVE.VexFile`, `cveFromMatch` e `matchCVEs`
      encadeando `ApplyVEX` por arquivo
- [x] `internal/api`: filtro `exclude-vex=1` em `filteredCVEs` +
      testes
- [x] `main.go`: flag `--vex` repetível (env `VEX`), `ResolveVexFiles`
      com fatalf, repasse ao scanner e ao `runExport`
- [x] `in_cluster.go`: rejeitar `--vex` com `--in-cluster`
- [x] `web/index.html`: badge VEX + arquivo na linha da CVE, checkbox
      "Hide VEX excluded" à esquerda do "Only CVEs with fix",
      `exclude-vex=1` nos params e no filtro de snapshot, clear
- [x] AGENTS.md (mapa, CLI, ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test` + smoke com OpenVEX real
