# AGENTS.md — artifactor

> Contexto e convenções do projeto para agentes de IA (DeepSeek Coder,
> Claude Code, Cursor, Codex...). Carregue este arquivo no início de toda
> sessão de desenvolvimento. Responda ao usuário em **português**.
> Decisões de arquitetura detalhadas: `docs/adr/`. Specs de features:
> `specs/###-titulo/{spec,plan,tasks}.md` (Spec Kit).

## 1. Visão geral

- **artifactor** — app web (Pod + Service no Kubernetes) que escaneia **todas
  as imagens de contêiner rodando no cluster** em busca de CVEs, usando
  **syft** e **grype como bibliotecas Go embutidas** (nenhum binário externo)
  e o **client-go** oficial (in-cluster via `kubernetes.default.svc`, fallback
  kubeconfig para dev local).
- Módulo `github.com/getupcloud/artifactor`; o diretório local do repo é
  `/workspace` (nome diferente do módulo).
- Remote: `git@github.com:getupcloud/artifactor.git`.
- Resultados exibidos numa SPA filtrável (severidade, artefato/pacote, CVE id)
  e exportados como relatórios auto-contidos (HTML/CSV/SBOM/grype).

## 2. Mapa do repositório

- `main.go` — CLI: `scan` (padrão), `install`, `uninstall` e o subcomando
  oculto `cat`; flags; orquestração dos exports.
- `install.go` — renderização dos manifests (embed de `deploy/*.yaml` e
  templates `.tmpl`), apply/delete via kubectl.
- `in_cluster.go` — feature `scan --in-cluster` (criação do pod, polling de
  logs, download do relatório, prompts).
- `internal/scanner/` — pipeline: discovery → syft/grype → store;
  `grypedb.go` (curator/provider do DB), `grypedbdirect.go` (download
  direto), `scanstats.go` (stats incl. taxas de erro por registry),
  `grypelog.go` (roteia logs do grype pelo logx).
- `internal/k8s/` — wrapper do client (discovery, pull secrets, cadeia de
  owners), `podops.go` (apply/delete de objetos, helpers de pod, exec).
- `internal/api/` — servidor HTTP, endpoints JSON, exports HTML/CSV/SBOM.
- `internal/registryauth/` — parsing de docker config, extração de authority.
- `internal/ecr/` — cadeia de credenciais AWS (IRSA) para ECR.
- `internal/logx/` — logger nivelado; toda linha carrega `arquivo:linha` do
  chamador (path relativo ao repo).
- `web/index.html` — SPA (go:embed); `web/names.json` — lista de
  vulnerabilidades nomeadas (fallback embutido, refresh do GitHub).
- `deploy/` — namespace/SA/RBAC/deployment/service + templates
  (`dbca.yaml.tmpl`, `openshift.yaml.tmpl`, `imagepullsecret.yaml.tmpl`).
- `.goreleaser.yaml`, `Makefile`, `Dockerfile` (imagem de produção),
  `Dockerfile.session` (container de sessão: `make build-session`),
  `SESSION.md` (bootstrap de sessão — aponta para este arquivo),
  `.github/workflows/` (docker-build + release).

## 3. Decisões de arquitetura (resumo)

- syft + grype como bibliotecas embutidas; versões pinadas: grype v0.121.0
  (syft v1.55.0, stereoscope v0.3.4, clio v0.1.1), client-go v0.37.1;
  Go ≥ 1.26.8 (usa `os.OpenRoot`). → `docs/adr/0001`
- Banco grype v6 via curator + flag `--grype-db-direct-download`. → `docs/adr/0002`
- Fail-fast quando o banco está indisponível e o download falha. → `docs/adr/0003`
- `scan --in-cluster` (pod one-shot, `--hold`, download via exec, polling de
  logs). → `docs/adr/0004`
- Formato de log com `arquivo:linha` relativo ao repo e `[customer/cluster]`.
  → `docs/adr/0005`
- Pipeline: discovery k8s (pods incl. init/ephemeral; imagePullSecrets de
  pod.spec + ServiceAccount) → credenciais `registryauth` → `pkg.Provide()`
  (SBOM syft + pacotes grype) → matchers grype (stock CPEs, dpkg epoch zero,
  rpm epoch auto) → Store em memória → SPA/API.
- Resultados **apenas em memória** (sem persistência).
- Ao fim de cada scan, taxas de erro de acesso por registry
  (`ScanStats.Registries`: erro de acesso = falha na fase syft/pull, erro com
  prefixo `"syft: "`) são logadas (WARNING quando há erros) e exibidas na SPA
  e nos HTML exportados.

## 4. Build, teste e execução

- `make build` = `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"` (VERSION no Makefile — hoje 0.4.1).
- `make test` = `go test ./... -count=1` (sempre `-count=1`: o cache do Go
  pode repetir falhas velhas).
- `make vet` — rodar também `go vet -tags integration ./...`.
- `make docker-build` = `goreleaser release --clean --snapshot` (o Makefile
  exporta `IS_LATEST ?= false`; os templates do goreleaser FALHAM se a env
  `IS_LATEST` não existir).
- Testes de integração: `go test -tags integration -run TestScanAlpine
  ./internal/scanner` com `CIS_TEST_DB_DIR` apontando para um dir com o banco
  grype. TestScanAlpine (alpine:3.20 real) espera 14 artifacts e 6 CVEs,
  incl. CVE-2025-60876.
- Quirks do sandbox de dev: sem make/docker/sudo/python3/kubectl/kind; usar
  `export PATH=/home/deepseek/.local/bin:/home/deepseek/.local/go/bin:$PATH`;
  o sandbox reseta e apaga `/workspace` e `/home/deepseek/.local` (reinstalar
  o Go; cache de módulos baixa de novo no primeiro build); após reset o
  `/workspace` pode ficar do uid 1000 — o usuário roda `! chmod 777 /workspace`.
  Banco grype cacheado em `/tmp/artifactor-direct-test` (v6.1.10, ~3,2GB,
  morre no reset).
- Sessões: `make build-session` (container dev, usuário do host — com Go,
  make/gcc, git, curl, jq, kubectl v1.37, grype CLI v0.121.0 e o CLI
  DeepSeek Code `@qingj/deepseekcode` instalado dentro da imagem, exposto
  como `deepseek`) e `make start-session` (sessão DeepSeek Coder com
  `SESSION.md` como contexto inicial; repo montado em /workspace; sem
  dependências do host; `DEEPSEEK ?= deepseek`).

## 5. Referência de CLI (scan é o subcomando padrão)

- Exports (one-shot, sai ao final): `--export-html`, `--export-sbom`,
  `--export-grype`, `--export <dir>` (scan.html + sbom/ + grype/ + CSV),
  `--export-csv`; `--open <cmd>` abre o scan.html depois (`${FILE}`
  substituído; default `xdg-open`).
- `--from-sbom <file|dir>` — scan só-grype de SBOMs locais (sem cluster).
- Discovery/scan: `--namespace a,b`, `--scan-interval`, `--concurrency`,
  `--scan-timeout`, `--platform`, `--keep-sbom`, `--ecr-auth`,
  `--insecure-skip-tls` (registries, refresh do names.json e downloads
  diretos do DB).
- Banco: `--db-dir`, `--db-auto-update`, `--db-refresh-interval`,
  `--db-ca-cert <pem>`, `--grype-db-direct-download`,
  `--ignore-grype-db-unavailable`.
- `--customer-name`/`--cluster-name` — exibidos como `[customer/cluster]` em
  todas as linhas de log.
- In-cluster: `--in-cluster`, `--in-cluster-force`, `--in-cluster-image`,
  `--openshift`, `--image-pull-policy` (política do pod; no `install`
  sobrescreve o deployment). Flags ocultas: `--export-tar` (.tar.gz no pod),
  `--hold` (mantém o container vivo); subcomando oculto `cat` (streams um
  arquivo do pod para stdout).
- `install`: `--dump`, `--dry-run`, `--image`, `--image-pull-policy`,
  `--namespace`, `--customer-name`/`--cluster-name` (env do deployment),
  `--openshift` (SCC+RBAC), `--db-ca-cert` (ConfigMap + mount),
  `--image-token-env[=VAR]` (imagePullSecret do ghcr.io a partir de GH_TOKEN
  ou GITHUB_TOKEN).
- `--help`/`-h`/`help` na raiz lista os subcomandos.

## 6. Banco de vulnerabilidades do grype — conhecimento crítico

- A distribuição da anchore agora serve um único arquivo `.tar.zst`
  multi-plataforma (`latest.json` com schemaVersion/path/checksum) que o
  downloader da lib grype v0.121.0 (só xz) **NÃO suporta** — downloads novos
  devem usar `--grype-db-direct-download` (net/http puro; honra
  `--insecure-skip-tls` e `--db-ca-cert`; verifica sha256; extrai zstd+tar;
  hidrata; grava `import.json`; rename atômico para `<db-dir>/6`).
- O primeiro download é grande (~3GB hidratado); o init roda em goroutine de
  fundo para o HTTP subir logo.

## 7. Scan in-cluster (`scan --in-cluster`)

- Cria um pod one-shot `artifactor-scan` no ns `artifactor` (+ namespace/SA/
  ClusterRole/ClusterRoleBinding quando faltam) com as mesmas flags:
  `--export`→`/data/report`, `--db-dir`→`/data/db` reescritos (o root fs do
  container NÃO é gravável para uid 65532 — só o emptyDir `/data` com fsGroup
  65532).
- `--db-ca-cert` é copiado para o pod via ConfigMap `artifactor-db-ca`
  (montado em `/etc/artifactor/ca`).
- O pod empacota o diretório do relatório em `.tar.gz` (atômico: `.part` +
  rename, via `--export-tar` oculto) e mantém o container vivo (`--hold`
  oculto, sai com SIGTERM) até o CLI baixar via exec do `artifactor cat`
  oculto (remotecommand).
- Logs do pod (stdout+stderr fundidos pelo runtime) são exibidos localmente
  por POLLING a cada 2s (`PodLogs` GET com `SinceTime = última linha + 1s`) —
  o ambiente NÃO entrega streams follow de longa duração; exec funciona.
- Pod/ConfigMap existentes são sobrescritos e removidos só após perguntar;
  `--in-cluster-force` pula os prompts; `--openshift` aplica o SCC +
  ClusterRole/ClusterRoleBinding `artifactor-scc` (o SCC não está no scheme
  do client-go — tratado como unstructured via dynamic client).
- Requer `--export <dir>`; `--from-sbom` e os demais `--export*` são
  rejeitados; `--open` funciona no relatório baixado; o `.tar.gz` fica em
  `<dir>.tar.gz` e é extraído no diretório do export.
- A imagem do pod precisa ser ATUAL (com `--hold`/`--export-tar`/`cat`) —
  passe `--in-cluster-image` ou atualize `deploy/deployment.yaml`.

## 8. Convenções

- **Formato de log** (logx): toda linha é
  `artifactor: [customer/cluster] AAAA/MM/DD HH:MM:SS arquivo:linha: mensagem`
  — `arquivo:linha` é o path do chamador relativo ao repo (arquivos fora do
  repo, ex. lib grype, mostram os dois últimos componentes do path).
  Mensagens fatais do pacote main passam por `fatalf()` (mesmo formato).
- Mensagens de commit: resumo curto imperativo em inglês + corpo;
  trailer `Co-Authored-By` no final (veja o git log).
- NÃO sobrescrever a identidade git repo-local (Mateus Caruccio
  <mateus.caruccio@getupcloud.com>) nem o remote origin.
- Não commitar artefatos locais não rastreados (`banco-senff-hml/`,
  `db-ca.crt`, `bin/`, `dist/`, `export/`).

## 9. Imagens Docker (conhecimento)

- Produção (`./Dockerfile`): alpine:3.24 + ca-certificates + tzdata; uid
  fixo 65532 (exigido pelo deployment K8s e pelo SCC do OpenShift);
  `WORKDIR /data`; `DB_DIR=/data/db`, `PORT=8080`;
  `ENTRYPOINT ["/usr/local/bin/artifactor", "scan"]`. Binário estagiado pelo
  GoReleaser (`$TARGETPLATFORM/artifactor`), multi-arch linux/amd64+arm64,
  publicado em ghcr.io/getupcloud/artifactor.
- Padrão "usuário do host" (imagens locais cujos mounts devem manter a
  ownership do host): `ARG UID=1000/GID=1000` → `adduser -u ${UID}` +
  `chown ${UID}:${GID} <workdir>` + `USER ${UID}:${GID}`, com
  `--build-arg UID=$(id -u) --build-arg GID=$(id -g)`. O container de sessão
  (`Dockerfile.session`) usa exatamente esse padrão.
- CI: workflow docker-build a cada push no main (tags :main, :<sha>, :latest
  — IS_LATEST="true"); workflow release manual (lê VERSION, falha se a tag
  existir, publica :latest só para a versão mais nova); auth no ghcr.io
  prefere o secret GHCR_PAT, fallback GITHUB_TOKEN.

## 10. Restrições e pegadinhas

- `kubectl exec` só funciona em containers RUNNING — por isso o `--hold` no
  pod in-cluster.
- Streams follow de logs podem não funcionar em alguns ambientes — usar
  polling (já implementado).
- Fontes de imagem apenas-registry: imagens inalcançáveis ficam com status
  error (sem fallback kubelet/node-runtime ainda).
- Relatórios são em memória; reiniciar o servidor perde resultados.
- Sandbox: `go test` com `-count=1`; tag integration não coberta pelo
  `go vet` comum; a ferramenta grep pode quebrar após resets (usar grep do
  bash).

## 11. Ideias futuras / trabalho pendente

- Fallback kubelet/node-runtime para imagens inalcançáveis via registry.
- Watch por informers (rescan automático em mudanças) em vez de só intervalo.
- UI de override de credenciais por imagem.
- Persistência de resultados (disco/DB) em vez de só memória.
- (Concluído recentemente: --in-cluster, taxas de erro por registry, prefixo
  [customer/cluster], --openshift, --image-pull-policy, download direto do
  DB, política fail-fast do DB, formato de log com arquivo:linha.)
