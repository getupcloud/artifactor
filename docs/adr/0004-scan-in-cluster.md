# ADR-0004: scan --in-cluster (pod one-shot + download via exec)

- Data: 2026-10-31
- Status: Aceito

## Contexto

Quando a máquina local não alcança os registries (ou o banco grype), o scan
precisa rodar DENTRO do cluster, com os mesmos parâmetros, e trazer o
relatório de volta — usando a client lib do Kubernetes (não kubectl).

## Decisão

`scan --in-cluster` cria um pod one-shot `artifactor-scan` no ns `artifactor`
(+ namespace/SA/RBAC quando faltam) com as mesmas flags:

- `--export`→`/data/report` e `--db-dir`→`/data/db` reescritos (o root fs do
  container não é gravável para uid 65532; só o emptyDir `/data` com fsGroup
  65532);
- `--db-ca-cert` copiado via ConfigMap `artifactor-db-ca` (montado em
  `/etc/artifactor/ca`);
- o pod empacota o relatório em `.tar.gz` **atômico** (`.part` + rename, flag
  oculta `--export-tar`) e mantém o container vivo (flag oculta `--hold`,
  sai com SIGTERM) — `kubectl exec` só funciona em containers running;
- o CLI baixa o `.tar.gz` por exec do subcomando oculto `artifactor cat`
  (remotecommand), em polling de 2s, e extrai no `--export` local
  (`<dir>.tar.gz` mantido); `--open` funciona no relatório baixado;
- logs do pod exibidos localmente por **polling** (`PodLogs` GET com
  `SinceTime`), pois streams follow de longa duração não funcionam de forma
  confiável no ambiente;
- recursos existentes são sobrescritos/removidos só após perguntar;
  `--in-cluster-force` pula os prompts; `--openshift` aplica o SCC + RBAC
  (SCC via dynamic client, não está no scheme do client-go);
  `--image-pull-policy` define a política do pod; `--in-cluster-image`
  sobrescreve a imagem (precisa conter `--hold`/`--export-tar`/`cat`).

## Consequências

- Requer `--export <dir>`; `--from-sbom` e os demais `--export*` são
  rejeitados (destinos locais).
- A imagem publicada precisa ser mantida atualizada para o fluxo funcionar
  (flags/subcomandos ocultos).
- Acoplamento do download ao ciclo de vida do pod (`--hold` até o download).
