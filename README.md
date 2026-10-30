# Artifactor

Web app (Pod + Service no Kubernetes) que escaneia **todas as imagens de contêiner rodando no cluster** em busca de CVEs, usando **syft** e **grype como bibliotecas Go embutidas** (nenhum binário externo é instalado) e o **client-go oficial** para falar com a API do cluster via `kubernetes.default.svc`.

O resultado é apresentado em uma **SPA** que permite filtrar os CVEs pelos **nomes dos artefatos (pacotes) encontrados pelo syft**, por severidade e por ID de CVE.

> [!IMPORTANT]
> O comando deve ser executado a partir de um local que tenha acesso tanto a API do cluster através do `kubeconfig`, quanto dos `registros de imagens` de containers que executam no cluster.
> As credenciais de cada registro são coletadas durante a execução, baseado no campo `imagePullSecrets` de cada Pod, ou através de `IRSA` para clusters EKS.

## TL;DR;

Baixe o ultimo binário em [release](https://github.com/getupcloud/artifactor/releases) e execute o scan:

```
$ tar xzvf artifactor_0.0.1_linux_arm64.tar.gz artifactor
$ ./artifactor --export my-cluster
$ xdg-open my-cluster/scan.html
```

> [!TIP]
> Se o chrome estiver quebrando, use o firefox. Relatórios grandes (>=1GB total) podem não ser carregados devidamente no chrome.
> Outra opção é fazer o scan limitado a um ou mais namespaces usando a flag `--namespace ns1,ns2,...`.

O diretorio `my-cluster` é criado contendo o relatorio estatico e auto-contido do scan completo. Basta enviar ao cliente ou usar para analisar as imagens;
Abaixo está a arvore de arquivos criadas com o scan apenas dos namespaces `flux-system` e `metallb-system`:

```
$ ./artifactor --namespace flux-system,metallb-system --export my-cluster
$ tree my-cluster/
my-cluster/
├── grype
│   ├── ghcr.io_fluxcd_helm-controller_v1.1.0.grype.json
│   ├── ghcr.io_fluxcd_image-automation-controller_v0.39.0.grype.json
│   ├── ghcr.io_fluxcd_image-reflector-controller_v0.33.0.grype.json
│   ├── ghcr.io_fluxcd_kustomize-controller_v1.4.0.grype.json
│   ├── ghcr.io_fluxcd_notification-controller_v1.4.0.grype.json
│   ├── ghcr.io_fluxcd_source-controller_v1.4.1.grype.json
│   ├── quay.io_frrouting_frr_10.4.3.grype.json
│   ├── quay.io_metallb_controller_v0.16.1.grype.json
│   ├── quay.io_metallb_frr-k8s_v0.0.25.grype.json
│   └── quay.io_metallb_speaker_v0.16.1.grype.json
├── sbom
│   ├── ghcr.io_fluxcd_helm-controller_v1.1.0.sbom.json
│   ├── ghcr.io_fluxcd_image-automation-controller_v0.39.0.sbom.json
│   ├── ghcr.io_fluxcd_image-reflector-controller_v0.33.0.sbom.json
│   ├── ghcr.io_fluxcd_kustomize-controller_v1.4.0.sbom.json
│   ├── ghcr.io_fluxcd_notification-controller_v1.4.0.sbom.json
│   ├── ghcr.io_fluxcd_source-controller_v1.4.1.sbom.json
│   ├── quay.io_frrouting_frr_10.4.3.sbom.json
│   ├── quay.io_metallb_controller_v0.16.1.sbom.json
│   ├── quay.io_metallb_frr-k8s_v0.0.25.sbom.json
│   └── quay.io_metallb_speaker_v0.16.1.sbom.json
└── scan.html

3 directories, 21 files
```

## Como funciona

1. **Descoberta (client-go)**: lista os Pods de todos os namespaces e coleta as imagens de `containers`, `initContainers` e `ephemeralContainers`, registrando também o **namespace e o controller** (Deployment/StatefulSet/DaemonSet/Job…) dono de cada Pod (via ownerReferences + ReplicaSets).
2. **imagePullSecrets**: para cada Pod, resolve `spec.imagePullSecrets` **e** os `imagePullSecrets` do ServiceAccount do Pod. Os payloads `.dockerconfigjson`/`.dockercfg` são decodificados e as credenciais são mapeadas para o registry de cada imagem (ex.: `index.docker.io`, `ghcr.io`). As credenciais são injetadas no pull feito pelo syft via `image.RegistryOptions`.
3. **SBOM (syft)**: `pkg.Provide(...)` gera o SBOM da imagem — o syft baixa a imagem diretamente do registry usando as credenciais do passo 2.
4. **CVEs (grype)**: o banco de vulnerabilidades do grype (v6) é baixado/atualizado na inicialização e os pacotes do SBOM são casados contra ele com `VulnerabilityMatcher.FindMatchesContext`.
5. **API + SPA**: resultados ficam em memória e são servidos via API JSON + `index.html` (embutido no binário).

> **Atenção**: o scan puxa as imagens **do registry** (não do runtime do nó). O Pod precisa de acesso de rede aos registries — imagens em registries inacessíveis aparecem com status `error` na UI.

## Estrutura

```
main.go                     wiring: flags, k8s client, DB, servidor HTTP, loop de scan
internal/k8s/               descoberta de imagens + resolução de imagePullSecrets
internal/registryauth/      parse do docker config JSON -> credenciais por registry
internal/scanner/           syft (SBOM) + grype (CVE) como bibliotecas; store em memória
internal/api/               API JSON + serve o SPA
web/index.html              SPA (vanilla JS, sem build)
deploy/                     namespace, SA, ClusterRole(Binding), Deployment, Service
Dockerfile / Makefile       build da imagem e automação
```

## API

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/status` | modo do client k8s, estado do banco grype, se um scan está rodando |
| GET | `/api/images` | resumo por imagem: status, contagem de CVEs por severidade |
| GET | `/api/cves?image=&artifact=&severity=&exclude=&id=&fixed=&namespace=` | CVEs filtrados (artifact = substring do nome do pacote syft) |
| GET | `/api/namespaces` | namespaces distintos dos workloads das imagens escaneadas |
| GET | `/api/artifacts?image=&q=` | nomes distintos de artefatos (pacotes) encontrados pelo syft |
| POST | `/api/scan` | dispara um rescan de todas as imagens |
| GET | `/api/export` | baixa o relatório como um **único HTML auto-contido** (dados embutidos; funciona offline) |
| GET | `/healthz` | liveness/readiness |

## Variáveis / flags

| Flag | Env | Default | Descrição |
|---|---|---|---|
| `--port` | `PORT` | `8080` | porta HTTP |
| `--namespace` | `NAMESPACE` | (todos) | restringe o scan a uma **lista de namespaces separados por vírgula** (`--namespace a,b`); vazio = todos |
| `--scan-interval` | `SCAN_INTERVAL` | `6h` | intervalo de rescan automático (`0` desliga) |
| `--concurrency` | `CONCURRENCY` | `3` | scans paralelos |
| `--db-dir` | `DB_DIR` | cache do usuário | diretório do banco de vulnerabilidades do grype |
| `--db-auto-update` | `DB_AUTO_UPDATE` | `true` | baixa/atualiza o banco grype na inicialização |
| `--grype-db-direct-download` | `GRYPE_DB_DIRECT_DOWNLOAD` | `false` | baixa o banco grype e seus metadados (`latest.json` + arquivo) diretamente via HTTP(S), sem a biblioteca de download do grype; respeita `--insecure-skip-tls` e `--db-ca-cert` |
| `--ignore-grype-db-unavailable` | `IGNORE_GRYPE_DB_UNAVAILABLE` | `false` | continua servindo quando o banco grype não está disponível e não pôde ser baixado (os scans falham até ele ficar disponível); sem a flag, o artifactor encerra |
| `--platform` | `PLATFORM` | `linux/<GOARCH>` | plataforma da imagem a escanear |
| `--scan-timeout` | `SCAN_TIMEOUT` | `15m` | timeout por imagem |
| `--export-html <arquivo>` | `EXPORT_HTML` | — | escaneia uma vez, exporta o relatório em um único HTML auto-contido e sai |
| `--export-sbom <dir>` | `EXPORT_SBOM` | — | escaneia uma vez, exporta um SBOM syft (syft-json) por imagem no diretório e sai |
| `--export-grype <dir>` | `EXPORT_GRYPE` | — | escaneia uma vez, exporta um relatório grype (JSON) por imagem no diretório e sai |
| `--export <dir>` | `EXPORT` | — | escaneia uma vez, exporta o relatório completo (`scan.html` + `sbom/` + `grype/`) no diretório e sai |

## Construir e rodar

```bash
make build          # binário local
make run            # dev local (usa ~/.kube/config ou KUBECONFIG)
make docker-build   # imagens multi-arch (linux/amd64 + arm64) via GoReleaser, sem push (snapshot)
make deploy         # aplica os manifests (ns artifactor + RBAC + Deployment + Service)
make port-forward   # kubectl port-forward svc/artifactor 8080:8080
make logs           # logs do Pod
```

Depois do port-forward, abra **http://localhost:8080**.

### Exportar o relatório

- **Pela UI**: o botão **Export** no cabeçalho baixa o relatório como um único HTML auto-contido (snapshot dos dados embutido — os filtros funcionam offline, sem o servidor).
- **Pela CLI** (escaneia uma vez e sai):
  - `artifactor --export-html report.html` — só o HTML auto-contido
  - `artifactor --export-sbom sboms/` — um SBOM syft (`syft-json`) por imagem
  - `artifactor --export-grype grype/` — um relatório grype (JSON) por imagem
  - `artifactor --export export/` — os três: `scan.html` + `sbom/` + `grype/`
  - ou `make export` (equivale ao `--export export/`)

A imagem é construída e publicada pelo **GoReleaser** (`.goreleaser.yaml`): binário estático linux/amd64 + arm64 e manifest multi-arch no ghcr.io (o workflow do GitHub Actions roda a cada push no `main` e em tags `v*`). Localmente: `make docker-build` (snapshot, sem push) ou, para publicar, crie uma tag e rode `make docker-push` com login no registry.

Para usar sua própria imagem, ajuste `deploy/deployment.yaml` ou:
```bash
kubectl -n artifactor set image deployment/artifactor scanner=ghcr.io/getupcloud/artifactor:0.0.1
```

## Publicação no ghcr.io (tokens)

Os workflows autenticam no ghcr.io preferindo o secret **`GHCR_PAT`** (PAT com scope `write:packages`) e usando `GITHUB_TOKEN` como fallback. Se o push falhar com `denied: permission_denied: read_package` usando o `GITHUB_TOKEN`, uma destas opções resolve:

1. **Adicionar o secret `GHCR_PAT`** no repositório (recomendado — mesmo PAT do imagePullSecret `docker-ghcr`, desde que tenha `write:packages`).
2. **Vincular o pacote ao repositório**: GitHub → conta/org `getupcloud` → *Packages* → `artifactor` → *Package settings* → *Manage Actions access* → adicionar o repo com papel *Write*.
3. **Recriar o pacote com Actions**: se o pacote foi criado por push local com outro token, apague-o no UI do ghcr.io e deixe o workflow recriá-lo.
4. Habilitar, na org, *Packages* → permissões de criação/accesso para GitHub Actions.

## Release

O workflow `release` (disparado manualmente na aba **Actions**) lê a variável `VERSION` do Makefile, **falha se a tag `v<VERSION>` já existir** (local ou remoto), cria e publica a tag e roda o GoReleaser: imagens multi-arch no ghcr.io (`:<VERSION>` e `:<sha>` sempre; **`:latest` apenas quando a versão é a mais nova** entre as tags `v*`) + GitHub Release com os binários. Para lançar uma nova versão, edite `VERSION` no Makefile e dispare o workflow.

## RBAC

O scanner usa uma ServiceAccount dedicada com permissões mínimas (ClusterRole):
`pods` (list/get/watch), `replicasets` (list/get — para resolver a cadeia de owners Pod → ReplicaSet → Deployment e exibir o controller de cada imagem), `serviceaccounts` (get) e `secrets` (get) — estes dois últimos apenas para resolver os `imagePullSecrets` referenciados pelos Pods/SAs.

## Limitações conhecidas

- Imagens hospedadas em registries sem rota de rede a partir do Pod do scanner ficam com status `error`.
- O primeiro download do banco de vulnerabilidades do grype exige acesso à internet (ou forneça um banco já existente via `--db-dir` + `--db-auto-update=false`). Se não houver banco utilizável e o download falhar, o processo encerra (use `--ignore-grype-db-unavailable` para continuar servindo mesmo assim).
- Credenciais de `credHelpers`/`credStore` (clientes docker externos) não se aplicam; apenas o conteúdo dos secrets é usado.
