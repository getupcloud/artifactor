# Artifactor

Web app (Pod + Service on Kubernetes) that scans **all container images running in the cluster** for CVEs, using **syft** and **grype as embedded Go libraries** (no external binary is installed) and the **official client-go** to talk to the cluster API through `kubernetes.default.svc`.

Results are presented in a **SPA** (Single-Page Application) that lets you filter CVEs by the **artifact (package) names found by syft**, by severity and by CVE ID.

> [!IMPORTANT]
> The command must run from a machine that can reach both the cluster API (through the `kubeconfig`) and the **container image registries** of the images running in the cluster.
> Credentials for each registry are collected at runtime from the `imagePullSecrets` field of each Pod, or through the cloud workload identities: `IRSA` on EKS, **GKE Workload Identity** and **Microsoft Entra Workload ID** (AKS).

## TL;DR;

Download the latest binary from the [release](https://github.com/getupcloud/artifactor/releases) page and run the scan:

```
$ wget https://github.com/getupcloud/artifactor/releases/download/v0.4.5/artifactor_0.4.5_linux_amd64.tar.gz
$ tar xzvf artifactor_0.4.5_linux_amd64.tar.gz artifactor

## To run locally (your host must reach the image registries)
$ ./artifactor scan --export my-cluster

## To run in a Pod inside the cluster - the report is transferred to your local host
$ ./artifactor scan --export my-cluster --in-cluster

## Open the local report
$ xdg-open my-cluster/scan.html
```

> [!TIP]
> If Chrome is misbehaving, use Firefox. Large reports (>=1GB total) may not load properly in Chrome.
> Another option is to limit the scan to one or more namespaces with the `--namespace ns1,ns2,...` flag.

The `my-cluster` directory is created with the static, self-contained report of the full scan. Just open the generated `scan.html` file.
The files used in the analysis are also available in the `sbom/` and `grype/` directories.

> [!TIP]
> SBOM files can later be used for scanning directly with grype: `grype path/to/file.sbom`.

Below is the file tree created by scanning only the `flux-system` and `metallb-system` namespaces:

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

## How it works

1. **Discovery (client-go)**: lists the Pods of every namespace and collects the images from `containers`, `initContainers` and `ephemeralContainers`, also recording the **namespace and the controller** (Deployment/StatefulSet/DaemonSet/Job…) that owns each Pod (via ownerReferences + ReplicaSets).
2. **imagePullSecrets**: for each Pod, resolves `spec.imagePullSecrets` **and** the `imagePullSecrets` of the Pod's ServiceAccount. The `.dockerconfigjson`/`.dockercfg` payloads are decoded and the credentials are mapped to the registry of each image (e.g. `index.docker.io`, `ghcr.io`). The credentials are injected into the pull made by syft via `image.RegistryOptions`.
3. **SBOM (syft)**: `pkg.Provide(...)` generates the SBOM of the image — syft downloads the image directly from the registry using the credentials from step 2.
4. **CVEs (grype)**: the grype vulnerability database (v6) is downloaded/updated at startup and the SBOM packages are matched against it with `VulnerabilityMatcher.FindMatchesContext`.
5. **API + SPA**: results are kept in memory and served through a JSON API + `index.html` (embedded in the binary).

> **Note**: the scan pulls the images **from the registry** (not from the node runtime). The Pod needs network access to the registries — images in unreachable registries show up with status `error` in the UI.

## Structure

```
main.go                     wiring: flags, k8s client, DB, HTTP server, scan loop
internal/k8s/               image discovery + imagePullSecrets resolution
internal/registryauth/      docker config JSON parsing -> credentials per registry
internal/scanner/           syft (SBOM) + grype (CVE) as libraries; in-memory store
internal/api/               JSON API + serves the SPA
web/index.html              SPA (vanilla JS, no build)
deploy/                     namespace, SA, ClusterRole(Binding), Deployment, Service
Dockerfile / Makefile       image build and automation
```

## API

| Method | Route | Description |
|---|---|---|
| GET | `/api/status` | k8s client mode, grype DB state, whether a scan is running |
| GET | `/api/images` | per-image summary: status, CVE count by severity |
| GET | `/api/cves?image=&artifact=&severity=&exclude=&id=&fixed=&namespace=` | filtered CVEs (artifact = substring of the syft package name) |
| GET | `/api/namespaces` | distinct namespaces of the workloads running scanned images |
| GET | `/api/artifacts?image=&q=` | distinct artifact (package) names found by syft |
| POST | `/api/scan` | triggers a rescan of all images |
| GET | `/api/export` | downloads the report as a **single self-contained HTML** (embedded data; works offline) |
| GET | `/healthz` | liveness/readiness |

## Monitoring

While the scan server runs (locally or as the deployment installed in the cluster), a Prometheus `GET /metrics` endpoint is served on a separate listen address — `--metrics-listen <[ip][:port]>` (env `METRICS_LISTEN`), with both IP and port optional (defaults `0.0.0.0:9090`). The deployment exposes port 9090 as `metrics` on the Service.

Metrics (text exposition format, no external dependencies):

| Metric | Description |
|---|---|
| `artifactor_image_status{image,tag,status,namespace,kind,object,last_scan}` | one series per image **per workload instance**: `queued`/`scanning`/`scanned`/`error` status, the image without tag/digest, the workload (namespace, object kind and name) and the last successful scan (RFC3339 UTC) |
| `artifactor_image_cve{image,tag,cve,severity,namespace,kind,object,last_scan}` | one series per CVE **per workload instance**: CVE + severity (`critical`/`high`/`medium`/`low`/`negligible`/`unknown`) |

To integrate with the Prometheus Operator, `artifactor install --service-monitor` applies, besides the ServiceMonitor (scraping the `metrics` port every 60s), a PrometheusRule with CVE alerts:

- **ArtifactorImageCriticalCVEs** and **ArtifactorImageHighCVEs**: fire when an image has `critical` or `high` CVEs (5m duration), routed with a `severity` label and annotated with the workload, namespace, CVE count and last scan time.

## VEX (Vulnerability Exploitability eXchange)

Artifactor accepts **VEX documents** (**OpenVEX** or **CSAF**) that mark CVEs as `not_affected` or `fixed`, reducing alert/triage noise for CVEs that don't apply to an image (component not used, version not exploitable, etc.).

- **CLI**: `--vex <file|dir>` (repeatable; env `VEX`, comma-separated) loads documents at startup — a directory contributes all its direct files (non-recursive); a missing path or unsupported format fails at startup. Rejected together with `--in-cluster` (the files are local). Ignored CVEs are still listed in the SPA, marked with a **VEX badge** and the name of the file that ignored them; the "**Hide VEX excluded**" checkbox hides them (also applies to the CSV and the exported snapshot).
- **UI**: the **+ Add VEX** and **VEX files** buttons (cluster bar) upload OpenVEX/CSAF documents (≤ 1 MiB) **without restarting**: on add/remove, the already-computed CVE matches are reprocessed in place — no rescan, no SBOM rebuild, no image pull. The "VEX files" dialog lists the documents with a summary and lets you select, copy (Ctrl+C), download and remove each one — startup `--vex` documents appear in the dialog too (copy/download), but cannot be removed from the UI. Uploaded files are kept **in memory only** (plus a temp file for the grype processor) — the API never returns their content except on an explicit download.

## Variables / flags

| Flag | Env | Default | Description |
|---|---|---|---|
| `--port` | `PORT` | `8080` | HTTP port |
| `--metrics-listen <[ip][:port]>` | `METRICS_LISTEN` | `0.0.0.0:9090` | listen address (IP and/or port, both optional) of the Prometheus `GET /metrics` endpoint |
| `--access-log` | `ACCESS_LOG` | `false` | logs one line per HTTP request on the SPA/API and metrics servers (`GET /healthz` is skipped); the installed deployment runs with `ACCESS_LOG=true` |
| `--namespace` | `NAMESPACE` | (all) | restricts the scan to a **comma-separated namespace list** (`--namespace a,b`); empty = all |
| `--label-selector <sel>` | `LABEL_SELECTOR` | (all) | restricts the discovery to the pods matching this **Kubernetes label selector** (e.g. `app=web,tier in (frontend,api)`); empty = all pods |
| `--scan-interval` | `SCAN_INTERVAL` | `6h` | automatic rescan interval (`0` disables) |
| `--concurrency` | `CONCURRENCY` | `3` | parallel scans |
| `--db-dir` | `DB_DIR` | user cache | grype vulnerability database directory |
| `--db-auto-update` | `DB_AUTO_UPDATE` | `true` | downloads/updates the grype DB at startup |
| `--grype-db-direct-download` | `GRYPE_DB_DIRECT_DOWNLOAD` | `false` | downloads the grype DB and its metadata (`latest.json` + file) directly over HTTP(S), without grype's download library; honors `--insecure-skip-tls` and `--db-ca-cert` |
| `--ignore-grype-db-unavailable` | `IGNORE_GRYPE_DB_UNAVAILABLE` | `false` | keeps serving when the grype DB is unavailable and could not be downloaded (scans fail until it becomes available); without the flag, artifactor exits |
| `--in-cluster` | `IN_CLUSTER` | `false` | runs the scan **inside the cluster** in a temporary pod with the same parameters (requires `--export <dir>`); the report is packed as a `.tar.gz` in the pod, downloaded via the Kubernetes API and extracted locally |
| `--in-cluster-force` | `IN_CLUSTER_FORCE` | `false` | with `--in-cluster`: overwrites existing resources and removes everything at the end **without asking** |
| `--in-cluster-keep` | `IN_CLUSTER_KEEP` | `false` | with `--in-cluster`: **keeps** the created resources (pod and CA ConfigMap) when exiting and prints the `kubectl` command to remove them manually |
| `--in-cluster-image` | `IN_CLUSTER_IMAGE` | deployment image | scan pod image (the image must contain an `artifactor` supporting `--export-tar` and the internal `cat` subcommand) |
| `--image-pull-policy` | `IMAGE_PULL_POLICY` | `IfNotPresent` | `imagePullPolicy` of the `--in-cluster` pod (`Always`, `IfNotPresent` or `Never`) |
| `--in-cluster-resources` | `IN_CLUSTER_RESOURCES` | `requests.cpu=100m,requests.memory=256Mi,limits.cpu=2,limits.memory=4Gi` | resources (CPU/memory requests/limits) of the `--in-cluster` pod container, as comma-separated `(requests\|limits).(memory\|cpu)=<quantity>` entries (the entries override the defaults) |
| `--openshift` | `OPENSHIFT` | `false` | with `--in-cluster`: applies the OpenShift/OKD manifests (`SecurityContextConstraints` + RBAC) that allow the scan pod to run (requires cluster-admin) |
| `--platform` | `PLATFORM` | `linux/<GOARCH>` | image platform to scan |
| `--scan-timeout` | `SCAN_TIMEOUT` | `15m` | per-image timeout |
| `--gcp-auth` | `GCP_AUTH` | `true` | authenticates to Google registries (`gcr.io`/Artifact Registry `*.pkg.dev`) via **GKE Workload Identity** (metadata server access token) when no pull secret matches |
| `--azure-auth` | `AZURE_AUTH` | `true` | authenticates to Azure Container Registry (`*.azurecr.io`) via **Microsoft Entra Workload ID** (AKS federated credential exchange, `AZURE_*` envs) when no pull secret matches |
| `--vex <file\|dir>` | `VEX` | — | loads OpenVEX/CSAF documents that mark CVEs as `not_affected`/`fixed` (repeatable; a directory contributes its direct files); rejected with `--in-cluster` |
| `--export-html <file>` | `EXPORT_HTML` | — | scans once, exports the report as a single self-contained HTML and exits |
| `--export-sbom <dir>` | `EXPORT_SBOM` | — | scans once, exports one syft SBOM (syft-json) per image into the directory and exits |
| `--export-grype <dir>` | `EXPORT_GRYPE` | — | scans once, exports one grype report (JSON) per image into the directory and exits |
| `--export <dir>` | `EXPORT` | — | scans once, exports the full report (`scan.html` + `sbom/` + `grype/`) into the directory and exits |

## Build and run

```bash
make build          # local binary
make run            # local dev (uses ~/.kube/config or KUBECONFIG)
make docker-build   # multi-arch images (linux/amd64 + arm64) via GoReleaser, no push (snapshot)
make deploy         # applies the manifests (artifactor ns + RBAC + Deployment + Service)
make port-forward   # kubectl port-forward svc/artifactor 8080:8080
make logs           # Pod logs
```

After the port-forward, open **http://localhost:8080**.

### Exporting the report

- **From the UI**: the **Export** button in the header downloads the report as a single self-contained HTML (snapshot with embedded data — the filters work offline, without the server).
- **From the CLI** (scans once and exits):
  - `artifactor --export-html report.html` — only the self-contained HTML
  - `artifactor --export-sbom sboms/` — one syft SBOM (`syft-json`) per image
  - `artifactor --export-grype grype/` — one grype report (JSON) per image
  - `artifactor --export export/` — all three: `scan.html` + `sbom/` + `grype/`
  - or `make export` (equivalent to `--export export/`)

### In-cluster scan (`--in-cluster`)

When the local machine cannot reach the registries (or the grype DB), the scan can run **inside the cluster** with the same parameters:

```bash
artifactor scan --in-cluster --export report/ --customer-name acme --grype-db-direct-download
```

Flow:
1. Artifactor creates an **`artifactor-scan` pod** in the `artifactor` namespace (along with the namespace/SA/RBAC when they don't exist yet) running the scan with the same parameters — except `--export` and `--db-dir`, rewritten to paths inside the pod. With `--db-ca-cert`, the certificate is copied to the pod via **ConfigMap** (Kubernetes API). On **OpenShift/OKD** clusters, also pass `--openshift` to apply the `SecurityContextConstraints` + RBAC that allow the pod to run.
2. The pod runs the scan and packs the entire `--export` directory into a **`.tar.gz`** (internal `--export-tar` flag).
3. The pod logs (**stdout + stderr**, merged by the runtime) are shown on the local terminal as they are produced (2s polling via the Kubernetes API; each poll re-reads the log from the beginning and skips the lines already shown by the number of the last recorded line, so a dropped connection resumes from the last line without repeating the log); the process **downloads the `.tar.gz` via the Kubernetes API** (exec `artifactor cat`) and extracts it into the local `--export` directory (the `.tar.gz` is kept at `<dir>.tar.gz`). With `--open`, the downloaded `scan.html` is opened locally.
4. At the end, the pod and the CA ConfigMap are removed — **after asking** (use `--in-cluster-force` to overwrite existing resources and remove them without asking, or `--in-cluster-keep` to **keep** the resources in the cluster and print the `kubectl` command to remove them manually).

The image is built and published by **GoReleaser** (`.goreleaser.yaml`): static linux/amd64 + arm64 binary and a multi-arch manifest on ghcr.io (the GitHub Actions workflow runs on every push to `main` and on `v*` tags). Locally: `make docker-build` (snapshot, no push) or, to publish, create a tag and run `make docker-push` logged into the registry.

To use your own image, adjust `deploy/deployment.yaml` or:
```bash
kubectl -n artifactor set image deployment/artifactor scanner=ghcr.io/getupcloud/artifactor:0.0.1
```

## Developing

For development, there is a **containerized development session**
(`make build-session` / `make start-session`): a complete environment that runs
**as the local user** (same uid/gid — files written to the mounted repo keep
the correct owner) and **with no host toolchain dependencies**.

```bash
make build-session   # builds the artifactor-session image from Dockerfile.session
make start-session   # starts a DeepSeek Coder session with SESSION.md as the initial context
```

The image (`Dockerfile.session`) already ships everything development needs:

- Go, make + gcc, git, bash, curl, jq;
- `kubectl` (version aligned with the repo's client-go) and the `grype` CLI (same version as the library embedded in `go.mod`);
- python3 + pip and the `security-guidance` plugin (loaded by the session via `--plugin-dir`);
- the DeepSeek Code CLI (installed in the image, exposed as `deepseek`).

`make start-session` mounts the current directory at `/workspace`, injects the
`DEEPSEEK_API_KEY` (read from 1Password via `op`) and starts `deepseek` using
`SESSION.md` as the bootstrap — which points to `AGENTS.md`, `docs/adr/` and
`specs/` as the project context. The container is disposable (`--rm`): the
state lives in the mounted repo, not in the image.

Variables: `SESSION_IMAGE` (image name), `DEEPSEEK` (CLI command) and
`BUILD_SESSION_EXTRA_PARAMS` (extra parameters for `docker build`).

## Publishing to ghcr.io (tokens)

The workflows authenticate to ghcr.io preferring the **`GHCR_PAT`** secret (a PAT with the `write:packages` scope) and falling back to `GITHUB_TOKEN`. If the push fails with `denied: permission_denied: read_package` using the `GITHUB_TOKEN`, one of these options resolves it:

1. **Add the `GHCR_PAT` secret** to the repository (recommended — the same PAT as the `docker-ghcr` imagePullSecret, as long as it has `write:packages`).
2. **Link the package to the repository**: GitHub → `getupcloud` account/org → *Packages* → `artifactor` → *Package settings* → *Manage Actions access* → add the repo with the *Write* role.
3. **Recreate the package with Actions**: if the package was created by a local push with another token, delete it in the ghcr.io UI and let the workflow recreate it.
4. Enable, in the org, *Packages* → creation/access permissions for GitHub Actions.

## Release

The `release` workflow (triggered manually from the **Actions** tab) reads the `VERSION` variable from the Makefile, **fails if the `v<VERSION>` tag already exists** (local or remote), creates and publishes the tag and runs GoReleaser: multi-arch images on ghcr.io (`:<VERSION>` and `:<sha>` always; **`:latest` only when the version is the newest** among the `v*` tags) + a GitHub Release with the binaries. To ship a new version, edit `VERSION` in the Makefile and trigger the workflow.

## RBAC

The scanner uses a dedicated ServiceAccount with minimal permissions (ClusterRole):
`pods` (list/get/watch), `replicasets` (list/get — to resolve the Pod → ReplicaSet → Deployment owner chain and show the controller of each image), `serviceaccounts` (get) and `secrets` (get) — the last two only to resolve the `imagePullSecrets` referenced by Pods/SAs.

## Known limitations

- Images hosted in registries without a network route from the scanner Pod get status `error`.
- The first grype vulnerability database download requires internet access (or provide an existing database via `--db-dir` + `--db-auto-update=false`). If there is no usable database and the download fails, the process exits (use `--ignore-grype-db-unavailable` to keep serving anyway).
- `credHelpers`/`credStore` credentials (external docker clients) do not apply; only the content of the secrets is used.
