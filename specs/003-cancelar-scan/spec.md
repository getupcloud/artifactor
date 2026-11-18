# Spec: cancelar o scan em andamento pela UI

## O quê

Enquanto um scan está rodando, o botão "Scan now" do SPA muda para
"Cancel scan"; clicar cancela o scan em andamento. Ao cancelar, as imagens
que estavam sendo escaneadas voltam ao estado "Waiting" (queued) e os
resultados já concluídos são mantidos.

## Por quê

Hoje um scan iniciado pela UI só termina sozinho (ou com o processo). Scans
de clusters grandes demoram e não há como abortá-los sem reiniciar o
artifactor.

## Requisitos

1. Botão "Scan now" vira "Cancel scan" (estilo de perigo) enquanto
   `status.scanning` é true; permanece habilitado durante o scan.
2. Clicar em "Cancel scan" chama `POST /api/scan/cancel`, que cancela o
   contexto do scan em execução.
3. Ao cancelar: imagens com status "scanning" voltam para "queued"
   (resultados parciais em voo são descartados; imagens já concluídas
   permanecem com seus resultados); `scanning` volta a false.
4. O cancelamento é rápido: o pipeline para de enviar novas imagens e os
   workers pulam as restantes quando o contexto é cancelado.
5. Cancelar sem scan em andamento retorna 409 com erro claro.
6. Comportamento em snapshot/export inalterado.

## Critérios de aceite

- Durante um scan, o botão mostra "Cancel scan"; clicar interrompe o scan e
  as imagens "scanning" voltam a "Waiting".
- Sem scan ativo, `POST /api/scan/cancel` responde 409.
- Cancelar um scan por cancelamento não registra erro de DB.
- O fluxo de `--scan-interval` e o botão de novo scan continuam funcionando.
