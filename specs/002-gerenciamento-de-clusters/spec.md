# Spec: gerenciamento de clusters no SPA

## O quê

Adicionar no topo do SPA uma área para gerenciar clusters:

- **adicionar** um cluster informando um nome e colando o conteúdo de um
  kubeconfig;
- **selecionar** o cluster ativo (o alvo do scan);
- **selecionar o context** do kubeconfig usado para aquele cluster;
- **remover** clusters adicionados.

O botão "Scan now" escaneia o cluster selecionado (com o context selecionado).

## Por quê

Hoje o artifactor escaneia um único cluster, fixado no startup (in-cluster ou
o kubeconfig local). Quem opera vários clusters precisa reiniciar o processo
para trocar de alvo. Uma gestão de clusters na própria UI permite alternar o
alvo sem restart.

## Requisitos

1. Barra no topo do SPA (logo abaixo do header) com: seletor de cluster,
   seletor de context, botão "Add cluster" e botão "Remove".
2. Adicionar cluster: modal com campo de nome + textarea para o kubeconfig. O
   backend valida o kubeconfig (parse) e lista os contexts dele.
3. O context ativo de cada cluster pode ser trocado (override do
   `current-context` do kubeconfig); kubeconfig sem `current-context` usa o
   primeiro context.
4. O cluster do startup aparece como entrada inicial: em modo kubeconfig com
   os contexts do arquivo local; em modo in-cluster sem contexts. Nome:
   `--cluster-name` quando informado, senão `default` (kubeconfig) ou
   `in-cluster`.
5. O scan (`/api/scan`, botão "Scan now" e `--scan-interval`) usa o cluster
   selecionado. A flag `--namespace` continua valendo para todos os clusters.
6. Trocar de cluster (ou de context) limpa os resultados atuais, que
   pertencem ao alvo anterior; o usuário dispara o novo scan explicitamente.
7. Remover cluster é permitido desde que não seja o último restante; ao
   remover o selecionado, a seleção passa para o primeiro restante e os
   resultados são limpos.
8. Clusters vivem **apenas em memória** (mesma filosofia dos resultados).
   O conteúdo dos kubeconfigs **nunca** é retornado pela API (só nome, mode,
   contexts e erro) nem logado.
9. Erros (kubeconfig inválido, nome duplicado/vazio, cluster sem acesso) são
   exibidos na UI sem derrubar o app.
10. Relatórios exportados (snapshot) e o modo `--from-sbom` não mostram a
    barra.

## Critérios de aceite

- Adicionar um cluster com um kubeconfig válido o lista na barra com seus
  contexts; selecioná-lo e apertar "Scan now" descobre as imagens desse
  cluster.
- Trocar o context de um cluster refaz o client com o context escolhido.
- Trocar cluster/context limpa os resultados exibidos.
- Kubeconfig inválido exibe erro no modal e nada é adicionado.
- Remover o último cluster restante é recusado.
- O HTML exportado não mostra a barra de clusters.
- O fluxo atual (cluster único do startup, in-cluster e `--from-sbom`)
  continua funcionando sem regressão.
