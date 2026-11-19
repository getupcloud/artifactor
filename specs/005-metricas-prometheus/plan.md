# Plan: métricas Prometheus do scan (--metrics-listen, default 0.0.0.0:9090)

## Design

### Novo pacote `internal/metrics` — exposição texto sem dependências novas

- `ParseListen(s string) (string, error)` — normaliza o valor de
  `--metrics-listen` para um endereço `net.Listen` (`[ip]:porta`):
  - vazio → `0.0.0.0:9090` (defaults);
  - `ip:porta` / `:porta` → `net.SplitHostPort`; host vazio vira `0.0.0.0`,
    porta vazia vira `9090`;
  - `[::1]:9091` → SplitHostPort; `[::1]` (sem porta) → host `::1` + porta
    default; IPv6 nu (`::1`) → host inteiro + porta default;
  - sem `:` e só dígitos → porta sozinha (host `0.0.0.0`); sem `:` e com
    outros caracteres → IP/hostname sozinho (porta default);
  - porta deve ser numérica e 0–65535 (erro claro caso contrário).
- `New(store *scanner.Store) *Handler` + `Handler.ServeHTTP` — renderiza em
  cada scrape a partir de `Store.Snapshot("")` (o scrape sempre vê o estado
  atual, sem cache), com `Content-Type: text/plain; version=0.0.4;
  charset=utf-8`:
  - `artifactor_image_status{image,tag,status,last_scan} 1` — uma série por
    imagem do store (queued/scanning/scanned/error);
  - `artifactor_image_cve{image,tag,cve,severity,last_scan} 1` — uma série
    por CVE de imagem `scanned`;
  - `last_scan` = `Result.ScannedAt` em RFC3339 UTC (vazio quando nil — a
    imagem nunca foi escaneada com sucesso);
  - labels escapados (`\`, `"`, newline) e séries ordenadas (saída
    determinística, fácil de testar).
- `splitImageRef(ref) (name, tag)` — remove o digest (`@sha256:...`) e separa
  a tag pelo último `:` **depois do último `/`** (o `:` de
  `registry:5000/...` não é tag): `registry:5000/app:v1` →
  `name=registry:5000/app, tag=v1`; sem tag → `tag=""`.

Sem `prometheus/client_golang`: a exposição é um gauge estático e o formato
texto é estável — net/http puro, na linha do ADR-0002 (download direto do DB
sem a lib). Escapamento e formatação cobertos por testes golden.

### `main.go` — segundo `http.Server` ao lado do SPA

- Flag `--metrics-listen` (string, env `METRICS_LISTEN`, default `""` →
  `0.0.0.0:9090` via `ParseListen`) no FlagSet do `scan`; valor inválido →
  `fatalf("--metrics-listen: %v", err)` no parse (mesmo padrão do
  `--image-pull-policy`).
- No caminho do servidor local (após o `httpServer` do SPA): `metrics.New(store)`
  + `http.Server{Addr: addr, Handler: ..., ReadHeaderTimeout: 10s}` em
  goroutine; log `metrics listening on http://<addr>/metrics`. Falha de bind
  (`ListenAndServe` ≠ `ErrServerClosed`) vira `logx.Warnf` — o SPA continua
  (métricas são auxiliares; o conflito de porta não pode derrubar o scan).
- No `ctx.Done()` do loop principal, `metricsServer.Shutdown` junto com o
  `httpServer`.
- Caminhos que não servem HTTP (`--in-cluster`, exports one-shot) não são
  tocados — o servidor de métricas simplesmente não existe lá.

### Manifests (`deploy/`)

- `deployment.yaml`: `containerPort` `metrics` 9090 ao lado do `http` 8080.
- `service.yaml`: porta `metrics` 9090 → `targetPort: metrics`, para o
  Prometheus do cluster descobrir o endpoint.
- `servicemonitor.yaml.tmpl` (novo): ServiceMonitor do Prometheus Operator
  selecionando o Service pela porta `metrics` com `path: /metrics` e
  `interval: 60s`; template condicional (padrão do `--openshift`) incluído
  só com a flag `install --service-monitor`, porque o CRD
  `monitoring.coreos.com` pode não existir no cluster (aplicar sem o
  operator quebraria o `install`). O placeholder `__NAMESPACE__` do
  `matchNames` segue o `--namespace`.

## Riscos

- Porta 9090 ocupada (outro artifactor ou outro app): bind falha → warning e
  segue sem métricas (comportamento escolhido de propósito).
- `last_scan` como label (string RFC3339) em vez de timestamp: é o que foi
  pedido; consultas por tempo podem usar a label diretamente.
- Cardinalidade: uma série por CVE por imagem — aceitável para o escopo
  (centenas de imagens); o scrape não aloca estado no processo (renders a
  cada request).

## Testes

- `internal/metrics/metrics_test.go`: `ParseListen` (defaults, ip só, porta
  só, `[::1]`, IPv6 nu, porta inválida), `splitImageRef` (com/sem tag, com
  porta no registry, digest), render com store populado (status + cves +
  `last_scan`), escaping de labels e ordem determinística.
