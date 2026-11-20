# Spec: status line "Updating vulnerability DB" no SPA

## O quê

Enquanto o banco de vulnerabilidades do grype está sendo baixado/atualizado
(na inicialização ou no refresh periódico), o SPA mostra uma status line
no topo da página, no fluxo normal do documento (sem posicionamento fixo
nem z-index próprio — ela empurra o conteúdo e não sobrepõe nada), com o
texto "Updating vulnerability DB…". Quando a atualização termina,
a linha é removida.

## Por quê

O primeiro download do banco é grande (~3 GB hidratado) e roda em background;
hoje o usuário não vê nada na UI indicando que o DB ainda está sendo
preparado — o db-chip mostra apenas "n/a" até o fim, dando a impressão de
que o app está quebrado.

## Requisitos

1. O `DBStatus` (payload de `/api/status`) ganha o campo `updating`
   (bool), true enquanto o DB está sendo preparado/atualizado.
2. O servidor marca `updating=true` ao iniciar a preparação do DB e
   `false` ao concluir (sucesso ou falha); o refresh periódico
   (`--db-refresh-interval`) também marca/desmarca o campo.
3. O SPA mostra a status line no topo do `<body>` (antes do header), no
   fluxo normal — mesmo plano z do resto da página, sem `position`/
   `z-index`, sem sobrepor o conteúdo — com o texto "Updating vulnerability
   DB…" (indicador pulsante) enquanto `status.db.updating` é
   true; remove quando vira false.
4. A linha nunca aparece em snapshots exportados (dados congelados).
5. Nenhuma mudança no comportamento do banner de erros (erros do DB
   continuam no banner depois que a atualização termina).

## Critérios de aceite

- Com o DB baixando, o SPA mostra a linha no topo (empurrando o header
  para baixo, sem sobreposição); ao terminar (sucesso ou falha), a linha
  some no próximo poll (≤ 8 s).
- Com o DB já pronto (ou `--db-auto-update=false` com DB existente), a
  linha aparece só pelo instante da preparação e some.
- O HTML exportado não mostra a linha.
