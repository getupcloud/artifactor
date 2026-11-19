# Spec: erros de conexão com o backend na status line do SPA

## O quê

Quando o SPA não consegue falar com o backend (servidor fora, erro de
rede ou resposta HTTP de erro), a status line do topo da página (a mesma
área usada pelo "Atualizando DB de vulnerabilidades…") passa a mostrar um
erro em vermelho: "Erro de conexão com o backend: <motivo>". Quando o
próximo poll de status volta a funcionar, a linha é limpa (e volta ao
estado do DB, se ainda estiver atualizando).

## Por quê

Hoje a falha de conexão é silenciosa: o poll captura o erro e a página
simplesmente para de atualizar, parecendo travada. Mostrar o erro na
própria área de status deixa claro que o problema é o backend e não o
scan.

## Requisitos

1. `refreshStatus` registra a falha (mensagem do erro) em
   `state.backendError` e renderiza a status line; o sucesso limpa o campo
   e renderiza de novo.
2. Prioridade na status line: **erro de conexão > DB atualizando > nada**
   (o erro não some por causa do estado do DB).
3. Estilo de erro (vermelho, mesma paleta do banner de erro) com dot
   vermelho; a mensagem é escapada (nada de HTML do erro vira markup).
4. Snapshots exportados nunca mostram a linha (sem backend).
5. O restante do poll continua como está (as demais chamadas já engolem
   seus erros).

## Critérios de aceite

- Com o servidor derrubado, o SPA mostra "Erro de conexão com o backend:
  Failed to fetch" (ou similar) na status line em vermelho.
- Subindo o servidor de novo, a linha some no próximo poll (≤ 8 s) e, se o
  DB estiver atualizando, volta a mostrar "Atualizando DB de
  vulnerabilidades…".
- O relatório exportado (snapshot) não mostra a linha.
