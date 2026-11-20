# Plan: suporte a Microsoft Entra Workload ID (ACR)

## Design

### `internal/azure` (novo) — client assertion flow

- `azure.go`: espelha o `internal/ecr`:
  - `acrRegistryPattern` — `^[a-zA-Z0-9][a-zA-Z0-9-]*\.azurecr\.(io|us|cn|de)$`;
    `IsACRRegistry(registry string) bool`.
  - `Provider{mu, token, expires, ttl, now, exchange}`;
    `NewProvider()` e `Credentials(ctx) (username, password string, err error)`
    com `username = "00000000-0000-0000-0000-000000000000"`.
  - `exchange` (net/http puro, timeout 10s): lê `AZURE_TENANT_ID`,
    `AZURE_CLIENT_ID` e `AZURE_FEDERATED_TOKEN_FILE` (envs padrão do AKS
    Workload Identity); relê o arquivo federado a cada renovação; `POST`
    `<AZURE_AUTHORITY_HOST|https://login.microsoftonline.com>/<tenant>/oauth2/v2.0/token`
    com form-urlencoded (`grant_type=client_credentials`,
    `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
    `client_assertion`, `client_id`, `scope=https://containerregistry.azure.net/.default`);
    parse do JSON `{access_token, expires_in}`; cache por
    `expires_in - 5min` (mínimo 60s).

### `internal/scanner`

- `Options.Azure *azure.Provider` (nil desliga).
- Em `scanImage`, bloco análogo ao do ECR/GCP: quando
  `len(credentials) == 0` e `s.opts.Azure != nil` e
  `azure.IsACRRegistry(authority)` → `Credentials(ctx)` e append de
  `image.RegistryCredentials{Authority: authority, Username, Password}`;
  erro vira `logx.Warnf("azure credentials for %s: %v", …)`.

### `main.go`

- Flag `--azure-auth` (env `AZURE_AUTH`, default `true`); `azure.NewProvider()`
  nos dois caminhos (servidor do `scan` e `runExport`) e repasse em
  `scanner.Options.Azure` (assinatura do `runExport` ganha mais um parâmetro).

## Riscos

- O token federado do arquivo é rotacionado pelo kubelet — reler o arquivo
  em cada exchange (não cachear o conteúdo).
- Sem as envs o exchange falha rápido (checagem de env antes do POST) e
  vira warning — sem bloqueio do scan.
- O token vale ~1h; a identidade precisa de `AcrPull` no ACR (configuração
  do usuário, fora do escopo).

## Testes

- `internal/azure/azure_test.go`: `IsACRRegistry` (positivos/negativos);
  `Provider` com exchange fake (`httptest.Server` + `t.Setenv`): primeira
  chamada busca, segunda usa cache, expiração renova (relê arquivo), erro
  propagado; envs ausentes → erro claro.
- Smoke manual: scan com `--azure-auth=false` não lê envs nem consulta o
  endpoint de token.
