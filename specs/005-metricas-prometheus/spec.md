# Spec: métricas Prometheus do scan (porta 9090)

## O quê

Enquanto o servidor do `scan` roda (o mesmo caminho que serve o SPA — local
ou o deployment instalado no cluster), expor um endpoint Prometheus
`GET /metrics` numa porta HTTP dedicada (**9090** por padrão) com o estado
atual do scan:

- **status de cada imagem** (queued / scanning / scanned / error);
- **cada CVE encontrada**, com a criticidade, por imagem.

Toda série carrega como labels: o **nome da imagem** (referência sem tag nem
digest), a **tag da imagem**, a **CVE** (só na métrica de CVEs), a
**criticidade da CVE** (só na métrica de CVEs) e a **data do último scan** da
imagem (RFC3339 UTC, vazia quando a imagem nunca foi escaneada com sucesso).

## Por quê

O artifactor já serve os resultados na SPA e em relatórios exportados, mas
quem opera clusters com Prometheus (padrão da Getup) precisa das CVEs e do
status do scan como séries temporais para dashboards e alertas (ex. "imagem
X tem CVE crítica há N dias"), sem parsear a API JSON ou os relatórios.

## Requisitos

1. Endpoint `GET /metrics` num listen separado da SPA: flag
   `--metrics-listen <[ip][:porta]>` (env `METRICS_LISTEN`), com **IP e porta
   opcionais** — IP default `0.0.0.0` e porta default `9090`. Formatos
   aceitos: `0.0.0.0:9090`, `127.0.0.1`, `:9091`, `[::1]:9091`, `::1`,
   `9091` (porta sozinha). Porta inválida (não numérica ou fora de
   0–65535) é erro fatal de flag no startup. O formato da exposição é o
   text exposition do Prometheus (`text/plain; version=0.0.4`).
2. Métrica `artifactor_image_status` (gauge, valor 1) — uma série por
   imagem conhecida do store **por instância de workload**, com labels
   `image` (referência sem tag/digest), `tag`, `status`
   (queued/scanning/scanned/error), `namespace`, `kind` (tipo do objeto:
   deployment/statefulset/daemonset/pod/...), `object` (nome do objeto) e
   `last_scan` (último scan com sucesso da imagem).
3. Métrica `artifactor_image_cve` (gauge, valor 1) — uma série por CVE de
   imagem escaneada **por instância de workload**, com labels `image`,
   `tag`, `cve`, `severity` (critical/high/medium/low/negligible/unknown),
   `namespace`, `kind`, `object` e `last_scan`.
4. O servidor de métricas sobe junto com o servidor local do `scan` (inclusive
   `--from-sbom` e o deployment instalado no cluster, que roda o mesmo
   caminho); **não** sobe nos exports one-shot nem no CLI `--in-cluster`
   (que não servem HTTP).
5. Falha de bind na porta de métricas vira aviso no log e o scan continua
   (o SPA não pode morrer por causa das métricas).
6. Valores de labels são escapados conforme o formato Prometheus
   (`\`, `"`, newline); as séries são emitidas em ordem determinística.
7. Nenhuma credencial ou conteúdo de kubeconfig aparece nas métricas.

## Critérios de aceite

- Com o servidor rodando, `curl http://127.0.0.1:9090/metrics` retorna
  `text/plain; version=0.0.4` com `# HELP`/`# TYPE` e uma série
  `artifactor_image_status` por imagem (status e `last_scan` corretos) e uma
  série `artifactor_image_cve` por CVE (com `severity`).
- `artifactor scan --metrics-listen 127.0.0.1:9091` escuta só nesse
  IP/porta; `--metrics-listen 127.0.0.1` usa a porta default 9090;
  `--metrics-listen :9092` usa o IP default 0.0.0.0.
- `--metrics-listen 0.0.0.0:abc` falha no startup com erro claro.
- Imagem referenciada como `registry.exemplo.com:5000/app/api:v1.2.3` vira
  `image="registry.exemplo.com:5000/app/api"`, `tag="v1.2.3"`; referência
  por digest (`img@sha256:...`) fica com `tag=""`.
- Imagem rodando num Deployment `api` no namespace `prod` e num StatefulSet
  `api` no `staging` gera duas séries por CVE:
  `{namespace="prod",kind="deployment",object="api",...}` e
  `{namespace="staging",kind="statefulset",object="api",...}`; imagem sem
  workload (`--from-sbom`) gera série com os três labels vazios.
- Exportações (`--export*`) e `--in-cluster` continuam sem abrir a porta.
- O deployment manifest expõe a porta 9090 (containerPort + Service) para o
  Prometheus scrape do cluster.
