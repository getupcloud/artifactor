# Artifactor

Web app (Pod + Service no Kubernetes) que escaneia **todas as imagens de contêiner rodando no cluster** em busca de CVEs, usando **syft** e **grype como bibliotecas Go embutidas** (nenhum binário externo é instalado) e o **client-go oficial** para falar com a API do cluster via `kubernetes.default.svc`.

O resultado é apresentado em uma **SPA** que permite filtrar os CVEs pelos **nomes dos artefatos (pacotes) encontrados pelo syft**, por severidade e por ID de CVE.

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
| GET | `/api/cves?image=&artifact=&severity=&id=` | CVEs filtrados (artifact = substring do nome do pacote syft) |
| GET | `/api/artifacts?image=&q=` | nomes distintos de artefatos (pacotes) encontrados pelo syft |
| POST | `/api/scan` | dispara um rescan de todas as imagens |
| GET | `/api/export` | baixa o relatório como um **único HTML auto-contido** (dados embutidos; funciona offline) |
| GET | `/healthz` | liveness/readiness |

## Variáveis / flags

| Flag | Env | Default | Descrição |
|---|---|---|---|
| `--port` | `PORT` | `8080` | porta HTTP |
| `--namespace` | `NAMESPACE` | (todos) | restringe o scan a namespaces; **repetível** (`--namespace a --namespace b`) ou separado por vírgulas (`--namespace a,b`); vazio = todos |
| `--scan-interval` | `SCAN_INTERVAL` | `6h` | intervalo de rescan automático (`0` desliga) |
| `--concurrency` | `CONCURRENCY` | `3` | scans paralelos |
| `--db-dir` | `DB_DIR` | cache do usuário | diretório do banco de vulnerabilidades do grype |
| `--db-auto-update` | `DB_AUTO_UPDATE` | `true` | baixa/atualiza o banco grype na inicialização |
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
make docker-build   # imagem do container (syft+grype já embutidos no binário)
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

Para usar sua própria imagem, ajuste `deploy/deployment.yaml` ou:
```bash
make docker-build docker-push REGISTRY=registry.exemplo.com IMAGE=artifactor:v1
kubectl -n artifactor set image deployment/artifactor scanner=registry.exemplo.com/artifactor:v1
```

## RBAC

O scanner usa uma ServiceAccount dedicada com permissões mínimas (ClusterRole):
`pods` (list/get/watch), `replicasets` (list/get — para resolver a cadeia de owners Pod → ReplicaSet → Deployment e exibir o controller de cada imagem), `serviceaccounts` (get) e `secrets` (get) — estes dois últimos apenas para resolver os `imagePullSecrets` referenciados pelos Pods/SAs.

## Limitações conhecidas

- Imagens hospedadas em registries sem rota de rede a partir do Pod do scanner ficam com status `error`.
- O primeiro download do banco de vulnerabilidades do grype exige acesso à internet (ou forneça um banco já existente via `--db-dir` + `--db-auto-update=false`).
- Credenciais de `credHelpers`/`credStore` (clientes docker externos) não se aplicam; apenas o conteúdo dos secrets é usado.
