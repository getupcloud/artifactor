# Tasks: suporte a GKE Workload Identity (registries Google)

- [x] `internal/gcp/gcp.go`: `IsGoogleRegistry` (gcr.io/\*.gcr.io/\*.pkg.dev)
      + `Provider` (token do metadata server, cache por `expires_in`) +
      `gcp_test.go`
- [x] `scanner`: `Options.GCP`, fallback em `scanImage` (só sem pull secret
      casado; warning em falha)
- [x] `main.go`: flag `--gcp-auth` (env `GCP_AUTH`, default true), provider
      nos caminhos do scan e do `runExport`
- [x] AGENTS.md (mapa, CLI, ideias concluídas) + READMEs (flags e seção)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test`
