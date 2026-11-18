# Plan: gerenciamento de clusters no SPA

## Design

### `internal/k8s` — construir clients a partir de conteúdo de kubeconfig

- `DefaultKubeconfigPath() string` — o path usado pelo `New()` (env
  `KUBECONFIG` ou `~/.kube/config`), extraído para o main poder ler o arquivo
  e expor os contexts do cluster de startup.
- `KubeconfigContexts(data []byte) (contexts []string, current string, err error)`
  — `clientcmd.Load` + nomes de contexts ordenados; `current` é o
  `current-context` do arquivo ou o primeiro context quando vazio.
- `NewFromKubeconfig(data []byte, contextName string) (*Client, error)` —
  `clientcmd.Load` + `NewDefaultClientConfig` com
  `ConfigOverrides{CurrentContext: contextName}`; erros claros para YAML
  inválido e context inexistente (a validação do clientcmd já cobre context
  órfão de cluster/user).

### Novo pacote `internal/clusters` — registro de clusters em memória

```go
type Info struct {           // projeção para a API (sem o kubeconfig!)
    Name           string   `json:"name"`
    Mode           string   `json:"mode"`
    Contexts       []string `json:"contexts,omitempty"`
    CurrentContext string   `json:"currentContext,omitempty"`
    Error          string   `json:"error,omitempty"`
}

type Manager struct { ... } // mu + map[name]*Entry + ordem de inserção + selected
```

- `AddStartup(name, mode string, client *k8s.Client, kubeconfig []byte, err error)`
  — entrada inicial (in-cluster ou kubeconfig local); contexts derivados do
  arquivo quando `mode == "kubeconfig"`; `err` (falha do `k8s.New()`) vira
  `Info.Error` com client nil (o botão de scan fica indisponível).
- `Add(name, kubeconfig string) error` — nome obrigatório e único; parseia
  contexts, constrói o client via `NewFromKubeconfig` com o context efetivo;
  primeira entrada adicionada vira a selecionada.
- `Remove(name string) error` — recusa remover o último cluster; ao remover o
  selecionado, seleciona o primeiro restante.
- `Select(name string) error` / `SelectedName() string` / `Selected() *Info`.
- `SetContext(name, context string) error` — reconstrói o client com o
  context novo (falha mantém o client anterior e retorna erro).
- `Client(name)` / `SelectedClient() (*k8s.Client, error)` — erro quando a
  entrada não existe ou não tem client (erro de build).

### `internal/scanner` — client por execução

- `RunOnce(ctx, client *k8s.Client)` — o client deixa de vir de
  `Options.Client` (removido); `RunOnce` usa o client recebido (nil em modo
  `--from-sbom`, que não o usa) e retorna erro "no cluster selected" quando
  nil sem `--from-sbom`. `main.go` (loop de rescan e `runExport`) e
  `handleScan` passam o client.

### `internal/api` — endpoints

- `Options.Clusters *clusters.Manager`.
- `GET /api/clusters` → `{"clusters": [Info...], "selected": name}`.
- `POST /api/clusters` corpo `{"name", "kubeconfig"}` (MaxBytesReader 1 MiB)
  → 201 com o Info; 400 inválido; 409 nome duplicado.
- `DELETE /api/clusters/{name}` → 404 desconhecido; 409 se for o último;
  200 ok (limpa o store se o removido era o selecionado).
- `POST /api/clusters/select` corpo `{"name"}` → seleciona e limpa o store
  (`SetImages(nil)`: os resultados pertencem ao cluster anterior).
- `POST /api/clusters/{name}/context` corpo `{"context"}` → troca o context
  e limpa o store.
- `handleScan`: usa `Clusters.SelectedClient()` (503 com o erro quando não há
  client; modo `from-sbom` segue sem cluster) e chama
  `Scanner.RunOnce(ctx, client)`.
- `statusPayload`: adiciona `selectedCluster` (nome) e `clusterError` (erro da
  entrada selecionada); `mode` passa a refletir o mode do cluster selecionado
  quando o manager está presente.

### `main.go`

- Constrói o `clusters.Manager` depois do `k8s.New()`: entrada startup com o
  nome (`--cluster-name` ou `default`/`in-cluster`), o client, o conteúdo do
  kubeconfig (quando kubeconfig) e o erro; pula em `--from-sbom`.
- Passa `Clusters` para o `api.Options`; o loop de rescan usa
  `mgr.SelectedClient()` a cada disparo; `runExport` continua passando o seu
  client único.

### SPA (`web/index.html`)

- Barra `#cluster-bar` entre o header e o banner (oculta por padrão; aparece
  quando `/api/clusters` responde com clusters — nunca em snapshot/`file:`).
- Selects de cluster/context + botões Add/Remove; modal overlay com nome +
  textarea de kubeconfig + mensagem de erro.
- Trocar cluster/context: POST no endpoint, refresh de status/imagens/CVEs
  (o store foi limpo no servidor). Adicionar: POST + select do novo cluster.
  Remover: `confirm()` + DELETE.
- Selects e botões da barra ficam desabilitados durante scan (o scan em
  andamento usa o client já capturado).
- `refreshStatus` mostra `status.clusterError` no banner e desabilita/habilita
  a barra conforme `scanning`; erro do `POST /api/scan` também vai para o
  banner.

## Riscos

- Kubeconfigs colados contêm credenciais: ficam só em memória, nunca saem do
  processo (GET devolve apenas metadados) — documentar na UI ("o kubeconfig
  fica em memória até o processo terminar").
- Trocar cluster durante um scan: o scan em andamento continua no client
  antigo e escreve no store depois da limpeza (resultados do alvo antigo
  voltam a aparecer); mitigado desabilitando a barra durante o scan.
- O banco grype é global (independe do cluster) e continua compartilhado.

## Testes

- `internal/k8s/kubeconfig_test.go`: parse de contexts (ordenação e fallback
  do primeiro), `NewFromKubeconfig` (válido, YAML inválido, context
  inexistente).
- `internal/clusters/clusters_test.go`: add/list/select/remove (incl. último
  cluster recusado e reseleção), context switch (válido/inválido), startup
  com erro.
- `internal/api/server_test.go`: fluxo completo dos endpoints (add inválido/
  duplicado, select limpa o store, remove do selecionado limpa o store, 409
  no último) e `statusPayload` com `selectedCluster`/`clusterError`.
