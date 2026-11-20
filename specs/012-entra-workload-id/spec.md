# Spec: suporte a Microsoft Entra Workload ID (ACR)

## O quê

Imagens hospedadas no **Azure Container Registry** (**\*.azurecr.io**, e os
clouds soberanos `.azurecr.us`/`.azurecr.cn`/`.azurecr.de`) passam a ser
autenticadas via **Microsoft Entra Workload ID** do AKS: o artifactor troca
o token federado do pod por um access token do Entra ID e usa esse token
como senha do registry, quando nenhum imagePullSecret casou com a imagem.
Flag **`--azure-auth`** (env `AZURE_AUTH`, default `true`).

## Por quê

Em clusters AKS com Workload Identity o kubelet puxa do ACR usando a
identidade do workload (sem docker config secret no Pod). Hoje o artifactor
só autentica via imagePullSecrets ou via o chain AWS (ECR/IRSA); imagens de
ACRs privados ficam com status `error`.

## Requisitos

1. Novo pacote `internal/azure` com `IsACRRegistry` e um `Provider` que
   executa o **client assertion flow** do Entra ID com as envs injetadas
   pelo AKS (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
   `AZURE_FEDERATED_TOKEN_FILE`; `AZURE_AUTHORITY_HOST` opcional):
   `POST <authority>/<tenant>/oauth2/v2.0/token` com
   `grant_type=client_credentials`,
   `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
   `client_assertion=<token do arquivo federado>` e
   `scope=https://containerregistry.azure.net/.default`; username
   `00000000-0000-0000-0000-000000000000` e password = access token.
2. O token é cacheado pelo `expires_in` (com margem) e renovado ao expirar
   (o arquivo federado é relido a cada renovação); falha do fetch vira
   warning e o scan segue sem credencial (mesmo comportamento do ECR).
3. O fallback acontece **apenas** quando nenhum pull secret casou com a
   imagem, e **apenas** para registries ACR.
4. Flag `--azure-auth` (env `AZURE_AUTH`, default `true`) vale para o scan
   e para os exports one-shot; desligada, nenhum provider é criado.
5. Sem regressão: registries não-ACR e execuções sem as envs/configuração
   não mudam de comportamento.

## Critérios de aceite

- Com provider ativo (teste com server de token fake), uma imagem de
  `myregistry.azurecr.io/app:v1` sem pull secret recebe a credencial
  (username `0000…` + access token).
- Token expirado é renovado (novo exchange, arquivo federado relido).
- Envs ausentes ou exchange falho logam warning sem quebrar o scan.
- `--azure-auth=false` (ou env) não cria provider.
