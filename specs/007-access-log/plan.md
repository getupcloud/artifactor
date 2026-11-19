# Plan: access log dos servidores HTTP (métricas, SPA e API)

## Design

### `internal/api`

- `statusRecorder` — `http.ResponseWriter` wrapper que captura o status
  efetivo (primeiro `WriteHeader`, default 200 no `Write`) e os bytes
  escritos, repassando tudo ao writer real.
- `AccessLog(next http.Handler) http.Handler` (exportado) — middleware que
  mede a duração, registra a linha
  `http: <método> <path> <status> <duração> <bytes>B <remote>` via
  `logx.Infof` após a resposta e **pula `GET /healthz`**. Duração em ms
  (`Round(time.Millisecond)`), µs quando < 1 ms.
- `Options.AccessLog bool` — `Handler()` envolve o mux com o middleware só
  quando true (os testes do pacote continuam silenciosos); o main liga no
  servidor real.
- O path logado é `r.URL.Path` (sem query); o remote é `r.RemoteAddr`.

### `main.go`

- `api.Options{AccessLog: true}` no caminho do servidor local (SPA+API).
- O servidor de métricas usa o mesmo middleware:
  `metricsServer.Handler = api.AccessLog(metrics.New(store))` — os scrapes
  do Prometheus passam a aparecer no log. O handler de métricas não tem
  `/healthz`, então o skip não afeta nada lá.
- Exports one-shot e `--in-cluster` não servem HTTP: nada muda.

## Riscos

- Volume: scrape do Prometheus a cada 60 s adiciona uma linha por scrape;
  é o comportamento pedido (e o `/healthz`, mais frequente, fica de fora).
- Writer wrapper: nenhum handler usa `http.Flusher`/`Hijacker` — sem risco
  de quebra de interface; se aparecer, usar `http.ResponseController`.

## Testes

- `internal/api/server_test.go`: middleware registra método/path/status
  (200 e 404) e bytes; `GET /healthz` não é logado (logx com writer
  capturado, como os testes existentes do pacote); resposta chega intacta
  ao cliente.
