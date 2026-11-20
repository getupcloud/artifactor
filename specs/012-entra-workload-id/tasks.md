# Tasks: suporte a Microsoft Entra Workload ID (ACR)

- [x] `internal/azure/azure.go`: `IsACRRegistry` (*.azurecr.io|us|cn|de) +
      `Provider` (client assertion flow via envs do AKS, cache por
      `expires_in`) + `azure_test.go`
- [x] `scanner`: `Options.Azure`, fallback em `scanImage` (só sem pull
      secret casado; warning em falha)
- [x] `main.go`: flag `--azure-auth` (env `AZURE_AUTH`, default true),
      provider nos caminhos do scan e do `runExport`
- [x] AGENTS.md (mapa, CLI, ideias concluídas) + READMEs (flags e seção)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...`,
      `make test`
