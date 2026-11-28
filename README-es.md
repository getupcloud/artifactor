# Artifactor

Aplicación web (Pod + Service en Kubernetes) que escanea **todas las imágenes de contenedor que se ejecutan en el clúster** en busca de CVEs, usando **syft** y **grype como librerías Go embebidas** (no se instala ningún binario externo) y el **client-go oficial** para comunicarse con la API del clúster a través de `kubernetes.default.svc`.

Los resultados se presentan en una **SPA** (Single-Page Application) que permite filtrar los CVEs por los **nombres de los artefactos (paquetes) encontrados por syft**, por severidad y por ID de CVE.

> [!IMPORTANT]
> El comando debe ejecutarse desde una máquina con acceso tanto a la API del clúster (mediante el `kubeconfig`) como a los **registros de imágenes** de contenedores que se ejecutan en el clúster.
> Las credenciales de cada registro se recogen durante la ejecución a partir del campo `imagePullSecrets` de cada Pod, o mediante las identidades de workload de la nube: `IRSA` en EKS, **GKE Workload Identity** y **Microsoft Entra Workload ID** (AKS).

## TL;DR;

Descarga el último binario desde la página de [releases](https://github.com/getupcloud/artifactor/releases) y ejecuta el escaneo:

```
$ wget https://github.com/getupcloud/artifactor/releases/download/v0.4.5/artifactor_0.4.5_linux_amd64.tar.gz
$ tar xzvf artifactor_0.4.5_linux_amd64.tar.gz artifactor

## Para ejecutarlo localmente (tu equipo debe alcanzar los registros de imágenes)
$ ./artifactor scan --export my-cluster

## Para ejecutarlo en un Pod dentro del clúster - el informe se transfiere a tu equipo local
$ ./artifactor scan --export my-cluster --in-cluster

## Abre el informe local
$ xdg-open my-cluster/scan.html
```

> [!TIP]
> Si Chrome falla, usa Firefox. Los informes grandes (>=1GB en total) pueden no cargar correctamente en Chrome.
> Otra opción es limitar el escaneo a uno o varios namespaces con la flag `--namespace ns1,ns2,...`.

El directorio `my-cluster` se crea con el informe estático y autocontenido del escaneo completo. Basta con abrir el fichero `scan.html` generado.
Los ficheros usados en el análisis también están disponibles en los directorios `sbom/` y `grype/`.

> [!TIP]
> Los ficheros SBOM pueden usarse posteriormente para escanear directamente con grype: `grype path/to/file.sbom`.

A continuación, el árbol de ficheros creado al escanear solo los namespaces `flux-system` y `metallb-system`:

```
$ ./artifactor --namespace flux-system,metallb-system --export my-cluster
$ tree my-cluster/
my-cluster/
├── grype
│   ├── ghcr.io_fluxcd_helm-controller_v1.1.0.grype.json
│   ├── ghcr.io_fluxcd_image-automation-controller_v0.39.0.grype.json
│   ├── ghcr.io_fluxcd_image-reflector-controller_v0.33.0.grype.json
│   ├── ghcr.io_fluxcd_kustomize-controller_v1.4.0.grype.json
│   ├── ghcr.io_fluxcd_notification-controller_v1.4.0.grype.json
│   ├── ghcr.io_fluxcd_source-controller_v1.4.1.grype.json
│   ├── quay.io_frrouting_frr_10.4.3.grype.json
│   ├── quay.io_metallb_controller_v0.16.1.grype.json
│   ├── quay.io_metallb_frr-k8s_v0.0.25.grype.json
│   └── quay.io_metallb_speaker_v0.16.1.grype.json
├── sbom
│   ├── ghcr.io_fluxcd_helm-controller_v1.1.0.sbom.json
│   ├── ghcr.io_fluxcd_image-automation-controller_v0.39.0.sbom.json
│   ├── ghcr.io_fluxcd_image-reflector-controller_v0.33.0.sbom.json
│   ├── ghcr.io_fluxcd_kustomize-controller_v1.4.0.sbom.json
│   ├── ghcr.io_fluxcd_notification-controller_v1.4.0.sbom.json
│   ├── ghcr.io_fluxcd_source-controller_v1.4.1.sbom.json
│   ├── quay.io_frrouting_frr_10.4.3.sbom.json
│   ├── quay.io_metallb_controller_v0.16.1.sbom.json
│   ├── quay.io_metallb_frr-k8s_v0.0.25.sbom.json
│   └── quay.io_metallb_speaker_v0.16.1.sbom.json
└── scan.html

3 directories, 21 files
```

## Cómo funciona

1. **Descubrimiento (client-go)**: lista los Pods de todos los namespaces y recoge las imágenes de `containers`, `initContainers` y `ephemeralContainers`, registrando también el **namespace y el controller** (Deployment/StatefulSet/DaemonSet/Job…) propietario de cada Pod (mediante ownerReferences + ReplicaSets).
2. **imagePullSecrets**: para cada Pod, resuelve `spec.imagePullSecrets` **y** los `imagePullSecrets` del ServiceAccount del Pod. Los payloads `.dockerconfigjson`/`.dockercfg` se decodifican y las credenciales se mapean al registro de cada imagen (p. ej. `index.docker.io`, `ghcr.io`). Las credenciales se inyectan en la descarga que hace syft mediante `image.RegistryOptions`.
3. **SBOM (syft)**: `pkg.Provide(...)` genera el SBOM de la imagen — syft descarga la imagen directamente del registro usando las credenciales del paso 2.
4. **CVEs (grype)**: la base de datos de vulnerabilidades de grype (v6) se descarga/actualiza en el arranque y los paquetes del SBOM se comparan con ella mediante `VulnerabilityMatcher.FindMatchesContext`.
5. **API + SPA**: los resultados se mantienen en memoria y se sirven a través de una API JSON + `index.html` (embebido en el binario).

> **Nota**: el escaneo descarga las imágenes **del registro** (no del runtime del nodo). El Pod necesita acceso de red a los registros — las imágenes en registros inaccesibles aparecen con estado `error` en la UI.

## Estructura

```
main.go                     cableado: flags, cliente k8s, DB, servidor HTTP, bucle de escaneo
internal/k8s/               descubrimiento de imágenes + resolución de imagePullSecrets
internal/registryauth/      parseo del docker config JSON -> credenciales por registro
internal/scanner/           syft (SBOM) + grype (CVE) como librerías; store en memoria
internal/api/               API JSON + sirve la SPA
web/index.html              SPA (vanilla JS, sin build)
deploy/                     namespace, SA, ClusterRole(Binding), Deployment, Service
chart/artifactor/           Helm chart (los mismos recursos que `artifactor install`)
Dockerfile / Makefile       build de la imagen y automatización
```

## Helm chart

Un Helm chart que instala los mismos recursos que `artifactor install` vive en
[`chart/artifactor/`](chart/artifactor/README.md): ServiceAccount,
ClusterRole/ClusterRoleBinding, Deployment y Service, además de ServiceMonitor,
PrometheusRule, SCC/RBAC de OpenShift, ConfigMap del CA del banco y
imagePullSecret opcionales.

```
$ helm install artifactor ./chart/artifactor -n artifactor --create-namespace
```

Cada opción del deployment es un valor del chart (`image.tag`, `customerName`,
`clusterName`, `scanInterval`, `concurrency`, `resources`, `dbCaCert`,
`imagePullSecret`, `serviceMonitor.enabled`, `prometheusRule.enabled`,
`openshift.enabled`, …) — consulta el README del chart para la lista completa.

## API

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/status` | modo del cliente k8s, estado de la DB de grype, si hay un escaneo en curso |
| GET | `/api/images` | resumen por imagen: estado, recuento de CVEs por severidad |
| GET | `/api/cves?image=&artifact=&severity=&exclude=&id=&fixed=&namespace=` | CVEs filtrados (artifact = subcadena del nombre del paquete syft) |
| GET | `/api/cves-page?…&page=1&pageSize=100&sort=&dir=` | CVEs paginados (mismos filtros que `/api/cves`): `{rows, total, page, pageSize}`; `sort` es uno de `cve`, `severity`, `package`, `version`, `image` o `matcher` y `dir` es `asc`/`desc` (vacío = orden por defecto severity/package/id); `page` se ajusta a la última página y `pageSize` se limita a 500 |
| GET | `/api/namespaces` | namespaces distintos de los workloads de las imágenes escaneadas |
| GET | `/api/artifacts?image=&q=` | nombres distintos de artefactos (paquetes) encontrados por syft |
| POST | `/api/scan` | lanza un reescaneo de todas las imágenes |
| POST | `/api/db/update` | fuerza una actualización de la DB de grype en segundo plano (ignora la ventana de 2h; 409 si ya hay una en curso) |
| GET | `/api/history` | escaneos guardados (más recientes primero) con cluster/contexto y conteos de CVEs por severidad y total; vacío cuando el historial está desactivado |
| GET | `/api/history/{name}` | snapshot completo (scan.json) de un escaneo guardado |
| GET | `/api/export` | descarga el informe como un **único HTML autocontenido** (datos embebidos; funciona sin conexión) |
| GET | `/healthz` | liveness/readiness |

## Monitorización

Mientras el servidor de escaneo está en ejecución (localmente o como deployment instalado en el clúster), un endpoint Prometheus `GET /metrics` se sirve en una dirección de escucha separada — flag `--metrics-listen <[ip][:puerto]>` (env `METRICS_LISTEN`), con IP y puerto opcionales (por defecto `0.0.0.0:9090`). El deployment expone el puerto 9090 como `metrics` en el Service.

Métricas (formato text exposition, sin dependencias externas):

| Métrica | Descripción |
|---|---|
| `artifactor_image_status{image,tag,status,namespace,kind,object,last_scan}` | una serie por imagen **por instancia de workload**: estado `queued`/`scanning`/`scanned`/`error`, la imagen sin tag/digest, el workload (namespace, tipo y nombre del objeto) y el último escaneo con éxito (RFC3339 UTC) |
| `artifactor_image_cve{image,tag,cve,severity,namespace,kind,object,last_scan}` | una serie por CVE **por instancia de workload** (deduplicada cuando la misma CVE afecta a varios paquetes de la imagen; prevalece la mayor severidad): CVE + severidad (`critical`/`high`/`medium`/`low`/`negligible`/`unknown`) |

Para integrarse con el Prometheus Operator, `artifactor install --service-monitor` aplica, además del ServiceMonitor (scrape del puerto `metrics` cada 60s), una PrometheusRule con alertas de CVE:

- **ArtifactorImageCriticalCVEs** y **ArtifactorImageHighCVEs**: se disparan cuando una imagen tiene CVEs `critical` o `high` (persistencia de 5m), enrutadas con la etiqueta `severity` y anotadas con el workload, el namespace, el recuento de CVEs y el último escaneo.

## VEX (Vulnerability Exploitability eXchange)

Artifactor acepta **documentos VEX** (**OpenVEX** o **CSAF**) que marcan CVEs como `not_affected` o `fixed`, reduciendo el ruido de alertas/triaje para CVEs que no aplican a una imagen (componente no usado, versión no explotable, etc.).

- **CLI**: `--vex <fichero|dir>` (repetible; env `VEX`, separada por comas) carga documentos en el arranque — un directorio aporta todos sus ficheros directos (no recursivo); una ruta inexistente o un formato no soportado falla en el arranque. Se rechaza junto con `--in-cluster` (los ficheros son locales). Los CVEs ignorados siguen apareciendo en la SPA, marcados con un **badge VEX** y el nombre del fichero que los ignoró; el checkbox "**Hide VEX excluded**" los oculta (también aplica al CSV y al snapshot exportado).
- **UI**: los botones **+ Add VEX** y **VEX files** (cluster bar) suben documentos OpenVEX/CSAF (≤ 1 MiB) **sin reiniciar**: al añadir/eliminar, los matches de CVE ya calculados se reprocesan al momento — sin reescaneo, sin reconstruir el SBOM, sin pull de imagen. El diálogo "VEX files" lista los documentos con resumen y permite seleccionar, copiar (Ctrl+C), descargar y eliminar cada uno — los documentos `--vex` del arranque también aparecen en el diálogo (copiar/descargar), pero no pueden eliminarse desde la UI. Los ficheros subidos permanecen **solo en memoria** (+ un fichero temporal para el procesador de grype) — la API nunca devuelve su contenido, salvo en la descarga explícita.

## Variables / flags

| Flag | Env | Default | Descripción |
|---|---|---|---|
| `--port` | `PORT` | `8080` | puerto HTTP |
| `--metrics-listen <[ip][:puerto]>` | `METRICS_LISTEN` | `0.0.0.0:9090` | dirección de escucha (IP y/o puerto, ambos opcionales) del endpoint Prometheus `GET /metrics` |
| `--access-log` | `ACCESS_LOG` | `false` | registra una línea por petición HTTP en los servidores SPA/API y de métricas (`GET /healthz` se omite); el deployment instalado se ejecuta con `ACCESS_LOG=true` |
| `--namespace` | `NAMESPACE` | (todos) | restringe el escaneo a una **lista de namespaces separados por comas** (`--namespace a,b`); vacío = todos |
| `--label-selector <sel>` | `LABEL_SELECTOR` | (todos) | restringe el descubrimiento a los pods que coinciden con este **label selector de Kubernetes** (p. ej. `app=web,tier in (frontend,api)`); vacío = todos los pods |
| `--scan-interval` | `SCAN_INTERVAL` | `6h` | intervalo de reescaneo automático (`0` lo desactiva) |
| `--concurrency` | `CONCURRENCY` | `3` | escaneos en paralelo |
| `--db-dir` | `DB_DIR` | caché del usuario | directorio de la base de datos de vulnerabilidades de grype |
| `--db-auto-update` | `DB_AUTO_UPDATE` | `true` | descarga/actualiza la DB de grype en el arranque |
| `--grype-db-direct-download` | `GRYPE_DB_DIRECT_DOWNLOAD` | `false` | descarga la DB de grype y sus metadatos (`latest.json` + fichero) directamente por HTTP(S), sin la librería de descarga de grype; respeta `--insecure-skip-tls` y `--db-ca-cert` |
| `--ignore-grype-db-unavailable` | `IGNORE_GRYPE_DB_UNAVAILABLE` | `false` | sigue sirviendo cuando la DB de grype no está disponible y no pudo descargarse (los escaneos fallan hasta que esté disponible); sin la flag, artifactor termina |
| `--in-cluster` | `IN_CLUSTER` | `false` | ejecuta el escaneo **dentro del clúster** en un pod temporal con los mismos parámetros (requiere `--export <dir>`); el informe se empaqueta como `.tar.gz` en el pod, se descarga mediante la API de Kubernetes y se extrae localmente |
| `--in-cluster-force` | `IN_CLUSTER_FORCE` | `false` | con `--in-cluster`: sobrescribe los recursos existentes y lo elimina todo al final **sin preguntar** |
| `--in-cluster-keep` | `IN_CLUSTER_KEEP` | `false` | con `--in-cluster`: **conserva** los recursos creados (pod y ConfigMap de la CA) al salir e imprime el comando `kubectl` para eliminarlos manualmente |
| `--in-cluster-image` | `IN_CLUSTER_IMAGE` | imagen del deployment | imagen del pod de escaneo (la imagen debe contener un `artifactor` compatible con `--export-tar` y el subcomando interno `cat`) |
| `--image-pull-policy` | `IMAGE_PULL_POLICY` | `IfNotPresent` | `imagePullPolicy` del pod de `--in-cluster` (`Always`, `IfNotPresent` o `Never`) |
| `--in-cluster-resources` | `IN_CLUSTER_RESOURCES` | `requests.cpu=100m,requests.memory=256Mi,limits.cpu=2,limits.memory=4Gi` | recursos (requests/limits de CPU/memoria) del contenedor del pod de `--in-cluster`, como entradas `(requests\|limits).(memory\|cpu)=<cantidad>` separadas por comas (las entradas sobrescriben los valores por defecto) |
| `--openshift` | `OPENSHIFT` | `false` | con `--in-cluster`: aplica los manifests de OpenShift/OKD (`SecurityContextConstraints` + RBAC) que permiten ejecutar el pod de escaneo (requiere cluster-admin) |
| `--platform` | `PLATFORM` | `linux/<GOARCH>` | plataforma de la imagen a escanear |
| `--scan-timeout` | `SCAN_TIMEOUT` | `15m` | timeout por imagen |
| `--gcp-auth` | `GCP_AUTH` | `true` | autentica en registros de Google (`gcr.io`/Artifact Registry `*.pkg.dev`) mediante **GKE Workload Identity** (access token del metadata server) cuando ningún pull secret coincide |
| `--azure-auth` | `AZURE_AUTH` | `true` | autentica en Azure Container Registry (`*.azurecr.io`) mediante **Microsoft Entra Workload ID** (intercambio federado de AKS, envs `AZURE_*`) cuando ningún pull secret coincide |
| `--vex <fichero\|dir>` | `VEX` | — | carga documentos OpenVEX/CSAF que marcan CVEs como `not_affected`/`fixed` (repetible; un directorio aporta sus ficheros directos); rechazado con `--in-cluster` |
| `--export-html <fichero>` | `EXPORT_HTML` | — | escanea una vez, exporta el informe como un único HTML autocontenido y termina |
| `--export-sbom <dir>` | `EXPORT_SBOM` | — | escanea una vez, exporta un SBOM syft (syft-json) por imagen en el directorio y termina |
| `--export-grype <dir>` | `EXPORT_GRYPE` | — | escanea una vez, exporta un informe grype (JSON) por imagen en el directorio y termina |
| `--export <dir>` | `EXPORT` | — | escanea una vez, exporta el informe completo (`scan.html` + `sbom/` + `grype/`) en el directorio y termina |

## Compilar y ejecutar

```bash
make build          # binario local
make run            # desarrollo local (usa ~/.kube/config o KUBECONFIG)
make docker-build   # imágenes multi-arch (linux/amd64 + arm64) mediante GoReleaser, sin push (snapshot)
make deploy         # aplica los manifests (ns artifactor + RBAC + Deployment + Service)
make port-forward   # kubectl port-forward svc/artifactor 8080:8080
make logs           # logs del Pod
```

Tras el port-forward, abre **http://localhost:8080**.

### Exportar el informe

- **Desde la UI**: el botón **Export** de la cabecera descarga el informe como un único HTML autocontenido (snapshot con los datos embebidos — los filtros funcionan sin conexión, sin el servidor).
- **Desde la CLI** (escanea una vez y termina):
  - `artifactor --export-html report.html` — solo el HTML autocontenido
  - `artifactor --export-sbom sboms/` — un SBOM syft (`syft-json`) por imagen
  - `artifactor --export-grype grype/` — un informe grype (JSON) por imagen
  - `artifactor --export export/` — los tres: `scan.html` + `sbom/` + `grype/`
  - o `make export` (equivalente a `--export export/`)

### Escaneo dentro del clúster (`--in-cluster`)

Cuando la máquina local no puede alcanzar los registros (o la DB de grype), el escaneo puede ejecutarse **dentro del clúster** con los mismos parámetros:

```bash
artifactor scan --in-cluster --export report/ --customer-name acme --grype-db-direct-download
```

Flujo:
1. Artifactor crea un **pod `artifactor-scan`** en el namespace `artifactor` (junto con el namespace/SA/RBAC cuando aún no existen) que ejecuta el escaneo con los mismos parámetros — salvo `--export` y `--db-dir`, reescritos a rutas dentro del pod. Con `--db-ca-cert`, el certificado se copia al pod mediante **ConfigMap** (API de Kubernetes). En clústeres **OpenShift/OKD**, pasa también `--openshift` para aplicar el `SecurityContextConstraints` + RBAC que permiten ejecutar el pod.
2. El pod ejecuta el escaneo y empaqueta todo el directorio de `--export` en un **`.tar.gz`** (flag interna `--export-tar`).
3. Los logs del pod (**stdout + stderr**, fusionados por el runtime) se muestran en el terminal local a medida que se producen (polling de 2s mediante la API de Kubernetes; cada poll relee el log desde el principio y salta las líneas ya mostradas por el número de la última línea registrada, de modo que una conexión caída se reanuda desde la última línea sin repetir el log); el proceso **descarga el `.tar.gz` mediante la API de Kubernetes** (exec `artifactor cat`) y lo extrae en el directorio local de `--export` (el `.tar.gz` se conserva como `<dir>.tar.gz`). Con `--open`, el `scan.html` descargado se abre localmente.
4. Al final, el pod y el ConfigMap de la CA se eliminan — **preguntando antes** (usa `--in-cluster-force` para sobrescribir los recursos existentes y eliminar sin preguntar, o `--in-cluster-keep` para **conservar** los recursos en el clúster e imprimir el comando `kubectl` para eliminarlos manualmente).

La imagen se compila y publica con **GoReleaser** (`.goreleaser.yaml`): binario estático linux/amd64 + arm64 y manifest multi-arch en ghcr.io (el workflow de GitHub Actions se ejecuta en cada push a `main` y en las tags `v*`). Localmente: `make docker-build` (snapshot, sin push) o, para publicar, crea una tag y ejecuta `make docker-push` con sesión iniciada en el registro.

Para usar tu propia imagen, ajusta `deploy/deployment.yaml` o:
```bash
kubectl -n artifactor set image deployment/artifactor scanner=ghcr.io/getupcloud/artifactor:0.0.1
```

## Desarrollo

Para el desarrollo existe una **sesión de desarrollo en contenedor**
(`make build-session` / `make start-session`): un entorno completo que se ejecuta
**como el usuario local** (mismo uid/gid — los ficheros escritos en el repo montado
conservan el propietario correcto) y **sin dependencias del toolchain del host**.

```bash
make build-session   # compila la imagen artifactor-session a partir del Dockerfile.session
make start-session   # inicia una sesión DeepSeek Coder con SESSION.md como contexto inicial
```

La imagen (`Dockerfile.session`) ya incluye todo lo que necesita el desarrollo:

- Go, make + gcc, git, bash, curl, jq;
- `kubectl` (versión alineada con el client-go del repo) y el CLI `grype` (misma versión que la librería embebida en `go.mod`);
- python3 + pip y el plugin `security-guidance` (cargado por la sesión mediante `--plugin-dir`);
- el CLI DeepSeek Code (instalado en la imagen, expuesto como `deepseek`).

`make start-session` monta el directorio actual en `/workspace`, inyecta la
`DEEPSEEK_API_KEY` (leída de 1Password mediante `op`) e inicia `deepseek` usando
`SESSION.md` como bootstrap — que apunta a `AGENTS.md`, `docs/adr/` y
`specs/` como contexto del proyecto. El contenedor es desechable (`--rm`): el
estado vive en el repo montado, no en la imagen.

Variables: `SESSION_IMAGE` (nombre de la imagen), `DEEPSEEK` (comando del CLI) y
`BUILD_SESSION_EXTRA_PARAMS` (parámetros extra para `docker build`).

## Publicación en ghcr.io (tokens)

Los workflows se autentican en ghcr.io dando prioridad al secret **`GHCR_PAT`** (un PAT con el scope `write:packages`) y usando `GITHUB_TOKEN` como fallback. Si el push falla con `denied: permission_denied: read_package` usando el `GITHUB_TOKEN`, una de estas opciones lo resuelve:

1. **Añadir el secret `GHCR_PAT`** al repositorio (recomendado — el mismo PAT que el imagePullSecret `docker-ghcr`, siempre que tenga `write:packages`).
2. **Vincular el paquete al repositorio**: GitHub → cuenta/org `getupcloud` → *Packages* → `artifactor` → *Package settings* → *Manage Actions access* → añadir el repo con el rol *Write*.
3. **Recrear el paquete con Actions**: si el paquete se creó con un push local con otro token, elimínalo en la UI de ghcr.io y deja que el workflow lo recree.
4. Habilitar, en la org, *Packages* → permisos de creación/acceso para GitHub Actions.

## Release

El workflow `release` (lanzado manualmente desde la pestaña **Actions**) lee la variable `VERSION` del Makefile, **falla si la tag `v<VERSION>` ya existe** (local o remota), crea y publica la tag y ejecuta GoReleaser: imágenes multi-arch en ghcr.io (`:<VERSION>` y `:<sha>` siempre; **`:latest` solo cuando la versión es la más reciente** entre las tags `v*`) + una GitHub Release con los binarios. Para publicar una nueva versión, edita `VERSION` en el Makefile y lanza el workflow.

## RBAC

El escáner usa una ServiceAccount dedicada con permisos mínimos (ClusterRole):
`pods` (list/get/watch), `replicasets` (list/get — para resolver la cadena de propietarios Pod → ReplicaSet → Deployment y mostrar el controller de cada imagen), `serviceaccounts` (get) y `secrets` (get) — estos dos últimos solo para resolver los `imagePullSecrets` referenciados por los Pods/SAs.

## Limitaciones conocidas

- Las imágenes alojadas en registros sin ruta de red desde el Pod del escáner obtienen el estado `error`.
- La primera descarga de la base de datos de vulnerabilidades de grype requiere acceso a internet (o proporciona una base de datos existente mediante `--db-dir` + `--db-auto-update=false`). Si no hay una base de datos utilizable y la descarga falla, el proceso termina (usa `--ignore-grype-db-unavailable` para seguir sirviendo de todos modos).
- Las credenciales de `credHelpers`/`credStore` (clientes docker externos) no se aplican; solo se usa el contenido de los secrets.
