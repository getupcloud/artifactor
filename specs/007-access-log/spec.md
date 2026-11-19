# Spec: access log dos servidores HTTP (métricas, SPA e API)

## O quê

Os servidores HTTP do artifactor passam a registrar uma linha de log por
request, após a resposta: método, path, status, duração, bytes enviados e
endereço remoto. Vale para o servidor principal (SPA + `/api/*`) **e** para
o servidor de métricas (`--metrics-listen`, porta 9090 — os scrapes do
Prometheus aparecem no log). O endpoint `/healthz` (probes do K8s) é
excluído para não poluir o log.

## Por quê

Depurar o uso da UI, da API e do scraping de métricas (quem chamou o quê,
o que falhou, quanto demorou) hoje exige instrumentação externa; com o log
de acesso cada interação vira uma linha no formato padrão do artifactor
(`[customer/cluster] ... arquivo:linha: http: ...`), visível em execuções
locais e no log do pod.

## Requisitos

1. Uma linha por request nos dois servidores, no formato
   `http: <método> <path> <status> <duração> <bytes>B <remote>` via logx
   (mesmo formato das demais linhas, com `arquivo:linha` do middleware).
2. O path registrado é o caminho sem query string (queries da SPA podem ser
   longas); o status é o efetivamente enviado; a duração é ms (µs quando
   < 1 ms).
3. `GET /healthz` não é logado (readiness/liveness do K8s).
4. Nenhuma mudança nos handlers; o log não altera a resposta (writer de
   contagem de status/bytes transparente).

## Critérios de aceite

- Acessar `http://127.0.0.1:<port>/` e `/api/status` produz duas linhas de
  access log com status 200, path e duração.
- `curl http://127.0.0.1:9090/metrics` produz uma linha de access log no
  servidor de métricas.
- Um request a `/api/nao-existe` loga status 404.
- `GET /healthz` não aparece no log.
- `go test ./...` permanece sem ruído de access log (habilitado apenas nos
  servidores reais).
