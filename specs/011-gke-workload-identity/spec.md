# Spec: suporte a GKE Workload Identity (registries Google)

## O quê

Imagens hospedadas em registries Google (**gcr.io**, **\*.gcr.io** e
**\*.pkg.dev** — Google Artifact Registry) passam a ser autenticadas com o
token OAuth2 do **GKE Workload Identity** (metadata server), quando nenhum
imagePullSecret casou com a imagem. Flag **`--gcp-auth`** (env `GCP_AUTH`,
default `true`) liga/desliga.

## Por quê

Em clusters GKE com Workload Identity o kubelet puxa imagens do GAR/gcr.io
com a identidade do pod (não há docker config secret no Pod). Hoje o
artifactor só autentica via imagePullSecrets ou via o chain AWS (ECR/IRSA);
imagens de registries Google protegidos ficam com status `error`.

## Requisitos

1. Novo pacote `internal/gcp` com `IsGoogleRegistry` e um `Provider` que
   busca o access token no metadata server do GKE
   (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`,
   header `Metadata-Flavor: Google`, scope `cloud-platform`), usando
   `oauth2accesstoken` como username e o token como password.
2. O token é cacheado pelo `expires_in` retornado (com margem de segurança)
   e renovado ao expirar; falha do fetch vira warning no log e o scan segue
   sem credencial (mesmo comportamento do ECR).
3. O fallback acontece **apenas** quando nenhum pull secret casou com a
   imagem, e **apenas** para registries Google (mesma semântica do
   `--ecr-auth`).
4. Flag `--gcp-auth` (env `GCP_AUTH`, default `true`) vale para o scan e
   para os exports one-shot; desligada, nenhum provider é criado.
5. Sem regressão: registries não-Google e execuções sem provider configurado
   não mudam de comportamento.

## Critérios de aceite

- Com provider ativo (teste com fetch fake), uma imagem de
  `us-docker.pkg.dev/proj/repo/app:v1` sem pull secret recebe a credencial
  `oauth2accesstoken`/token.
- `gcr.io` e `*.gcr.io` idem; `docker.io`/quay.io **não** consultam o
  metadata server.
- Token expirado é renovado (novo fetch); falha do fetch loga warning e o
  scan da imagem segue sem a credencial.
- `--gcp-auth=false` (ou env) não cria provider.
