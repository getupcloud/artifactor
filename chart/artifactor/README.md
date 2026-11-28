# artifactor Helm chart

Helm chart for [artifactor](https://github.com/getupcloud/artifactor): scans
**every container image running in the cluster** for CVEs (syft + grype as
embedded Go libraries) and serves a filterable web UI with Prometheus
metrics.

It installs the same resources as `artifactor install` (namespace-scoped
ServiceAccount/Deployment/Service + cluster-scoped ClusterRole/
ClusterRoleBinding), plus optional ServiceMonitor, PrometheusRule,
OpenShift SCC/RBAC, DB CA ConfigMap and imagePullSecret.

## Install

```sh
helm install artifactor ./chart/artifactor -n artifactor --create-namespace
```

Open the UI:

```sh
kubectl port-forward -n artifactor svc/artifactor 8080:8080
# browse http://127.0.0.1:8080/
```

## Configuration

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` / `image.tag` | `ghcr.io/getupcloud/artifactor` / chart `appVersion` | scanner container image |
| `image.pullPolicy` | `IfNotPresent` | image pull policy |
| `customerName` / `clusterName` | `""` | shown as `[customer/cluster]` in logs and report title |
| `scanOnStart` | `true` | runs one scan as soon as the grype DB is ready at startup (the `scanInterval` ticker still applies) |
| `scanInterval` | `0` | seconds between automatic rescans (`0` = no periodic rescans) |
| `concurrency` | `3` | images scanned in parallel |
| `dbDir` / `historyDir` | `/data/db` / `/data/history` | paths inside the pod (emptyDir `/data`) |
| `resources` | requests `100m`/`256Mi`, limits `2`/`4Gi` | container resources |
| `dbCaCert` | `""` | PEM CA of the grype DB server: creates the ConfigMap, mount and `DB_CA_CERT` |
| `imagePullSecret.create` / `.dockerconfigjson` | `false` / `""` | dockerconfigjson Secret (plain JSON; base64-encoded by the chart) |
| `openshift.enabled` | `false` | OpenShift SCC + RBAC (requires cluster-admin) |
| `serviceMonitor.enabled` / `.interval` | `false` / `60s` | Prometheus Operator ServiceMonitor |
| `prometheusRule.enabled` | `false` | PrometheusRule with high/critical CVE alerts |
| `nameOverride` / `fullnameOverride` | `""` | override generated resource names |

Examples:

```sh
# customer/cluster names + service monitor and alerts
helm install artifactor ./chart/artifactor -n artifactor --create-namespace \
  --set customerName=acme --set clusterName=prod \
  --set serviceMonitor.enabled=true --set prometheusRule.enabled=true

# CA certificate for the grype DB server
helm install artifactor ./chart/artifactor -n artifactor --create-namespace \
  --set-file dbCaCert=db-ca.crt

# private image registry
helm install artifactor ./chart/artifactor -n artifactor --create-namespace \
  --set imagePullSecret.create=true \
  --set-file imagePullSecret.dockerconfigjson=config.json
```

## Upgrading the chart

```sh
helm upgrade artifactor ./chart/artifactor -n artifactor
```

The chart `version`/`appVersion` follow the artifactor release (see
`Makefile` `VERSION`).
