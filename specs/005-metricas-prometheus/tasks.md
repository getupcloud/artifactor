# Tasks: métricas Prometheus do scan (--metrics-listen, default 0.0.0.0:9090)

- [x] `internal/metrics/metrics.go`: `ParseListen` (IP/porta opcionais,
      defaults `0.0.0.0`/`9090`, validação da porta), `splitImageRef`
      (digest + tag), `Handler` com `artifactor_image_status` e
      `artifactor_image_cve` a partir do `Store` (escaping de labels, saída
      ordenada, `Content-Type` text exposition)
- [x] `internal/metrics/metrics_test.go`: `ParseListen`, `splitImageRef`,
      render (status/CVEs/`last_scan`), escaping e ordem
- [x] labels `namespace`/`kind`/`object` por instância de workload nas duas
      métricas (`splitController` + série única com labels vazios para
      imagens sem workload) e teste golden atualizado
- [x] `main.go`: flag `--metrics-listen` (env `METRICS_LISTEN`), parse fatal
      em valor inválido, segundo `http.Server` com `/metrics` no caminho do
      servidor local, shutdown no `ctx.Done`, bind failure = warning
- [x] `deploy/deployment.yaml` + `deploy/service.yaml`: porta `metrics` 9090
- [x] `deploy/servicemonitor.yaml.tmpl` + flag `install --service-monitor`
      (template condicional, `matchNames` com placeholder de namespace) e
      testes em `install_test.go`
- [x] AGENTS.md (mapa do repo, referência de CLI, ideias concluídas)
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test`
