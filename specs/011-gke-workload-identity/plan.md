# Plan: suporte a GKE Workload Identity (registries Google)

## Design

### `internal/gcp` (novo) — token do metadata server

- `gcp.go`: espelha o `internal/ecr`:
  - `googleRegistryPattern` — `^([a-z0-9-]+\.)*gcr\.io$` (cobre `gcr.io`,
    `us.gcr.io`, `marketplace.gcr.io`…) e `^[a-z0-9-]+\.pkg\.dev$` (cobre
    `us-docker.pkg.dev` etc.); `IsGoogleRegistry(registry string) bool`.
    `registry.k8s.io`/`k8s.gcr.io` ficam de fora (públicos, sem auth).
  - `Provider{mu, token, expires, ttl, now, fetch}`;
    `NewProvider()` e `Credentials(ctx) (username, password string, err error)`
    com `username = "oauth2accesstoken"`.
  - `fetch` (net/http puro): `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform`
    com header `Metadata-Flavor: Google`, timeout curto (5s); parse do JSON
    `{access_token, expires_in}`; cache por `expires_in - 5min` (mínimo 60s).

### `internal/scanner`

- `Options.GCP *gcp.Provider` (nil desliga).
- Em `scanImage`, logo após o bloco do ECR, um bloco idêntico: quando
  `len(credentials) == 0` e `s.opts.GCP != nil` e
  `gcp.IsGoogleRegistry(authority)` → `Credentials(ctx)` e append de
  `image.RegistryCredentials{Authority: authority, Username, Password}`;
  erro vira `logx.Warnf("gcp credentials for %s: %v", …)`.

### `main.go`

- Flag `--gcp-auth` (env `GCP_AUTH`, default `true`, como o `--ecr-auth`);
  `gcp.NewProvider()` nos dois caminhos (servidor do `scan` e `runExport`)
  e repasse em `scanner.Options.GCP` (assinatura do `runExport` ganha mais
  um parâmetro).

## Riscos

- O metadata server só resolve dentro do GKE/GCE: fora dele o fetch falha
  rápido (DNS/timeout de 5s) e vira warning — sem bloqueio do scan.
- O token vale ~1h; a identidade precisa de `roles/artifactregistry.reader`
  no projeto (configuração do usuário, fora do escopo).
- Sem TLS no metadata server (169.254.169.254/metadata.google.internal é
  HTTP local) — o `--insecure-skip-tls` não se aplica a esse fetch.

## Testes

- `internal/gcp/gcp_test.go`: `IsGoogleRegistry` (positivos/negativos);
  `Provider` com fetch fake (`httptest.Server`): primeira chamada busca,
  segunda usa cache, expiração renova, erro do fetch propagado.
- Smoke manual: scan com `--gcp-auth=false` e sem provider não consulta o
  metadata server.
