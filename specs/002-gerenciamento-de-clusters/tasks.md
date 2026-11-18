# Tasks: gerenciamento de clusters no SPA

- [x] `internal/k8s`: `DefaultKubeconfigPath`, `KubeconfigContexts` e
      `NewFromKubeconfig` (refatorar `New()` para reusar o path default)
- [x] `internal/k8s/kubeconfig_test.go`: contexts (ordem + fallback primeiro),
      client válido, YAML inválido, context inexistente
- [x] Novo pacote `internal/clusters`: `Manager` (AddStartup/Add/Remove/
      Select/SetContext/Client/SelectedClient/List)
- [x] `internal/clusters/clusters_test.go`: fluxo add/list/select/remove,
      último cluster recusado, context switch, startup com erro
- [x] `internal/scanner`: `RunOnce(ctx, client *k8s.Client)`, remover
      `Options.Client`, guard "no cluster selected"
- [x] `internal/api`: endpoints `/api/clusters` (GET/POST/DELETE/select/
      context), `handleScan` com `SelectedClient`, `statusPayload` com
      `selectedCluster`/`clusterError`/mode do selecionado
- [x] `internal/api/server_test.go`: testes dos endpoints de clusters e do
      status
- [x] `main.go`: construir o manager (entrada startup com nome/kubeconfig/
      erro), passar para o `api.Options`, rescan com `SelectedClient`,
      `runExport` com o client próprio
- [x] `web/index.html`: barra de clusters (selects + Add/Remove), modal de
      adição (nome + kubeconfig + erro), troca de cluster/context limpando a
      view, barra oculta em snapshot e desabilitada durante scan, erro de
      cluster no banner
- [x] Atualizar AGENTS.md (mapa do repo, SPA, ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test`
