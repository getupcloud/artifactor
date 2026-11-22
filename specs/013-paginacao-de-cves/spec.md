# Spec: paginação da lista de CVEs (SPA live e snapshot exportado)

## O quê

A tabela de CVEs do painel principal passa a ser **paginada**, tanto no modo
live (backend + SPA) quanto no modo export (HTML único auto-contido):

1. **Live**: a API ganha paginação server-side — o SPA busca apenas a página
   atual (`GET /api/cves-page`), em vez de baixar todas as linhas filtradas.
2. **Snapshot**: o relatório exportado continua embutindo **todos** os dados;
   a paginação é aplicada client-side sobre o resultado do filtro (mesmos
   controles da UI, funcionando offline).
3. A UI ganha uma **barra de paginação** no painel principal: página
   anterior/próxima, "Page X of Y", total de CVEs e seletor de tamanho de
   página (50/100/250/500, default 100).

## Por quê

Clusters grandes produzem milhares de CVEs; hoje o SPA baixa e renderiza
todas as linhas a cada poll (payloads de vários MB e DOM pesado). Paginar
reduz o payload por request e o custo de render, mantendo os filtros e os
exports (CSV e HTML) completos.

## Requisitos

1. `GET /api/cves-page` aceita **os mesmos filtros** de `/api/cves`
   (`image`, `artifact`, `severity`, `exclude`, `id`, `fixed`, `namespace`,
   `exclude-vex`) mais `page` (1-based, default 1) e `pageSize` (default
   100, máximo 500) e responde `{rows, total, page, pageSize}`.
2. A ordem das linhas é **determinística e idêntica** entre server e
   snapshot (severidade → pacote → CVE id), para as páginas serem estáveis
   entre polls e modos.
3. `page`/`pageSize` inválidos (não numérico, < 1) → 400; `pageSize > 500`
   → truncado para 500; `page` além do fim → última página (clamp), nunca
   erro.
4. `/api/cves` (array completo) e `/api/cves.csv` **não mudam** — o CSV
   exportado continua completo em ambos os modos (live: server-side;
   snapshot: todas as linhas filtradas client-side, não só a página atual).
5. Live SPA: filtros alterados **voltam para a página 1**; o poll de 8 s
   re-busca a página atual e faz clamp se o total encolher (novo scan).
6. Snapshot SPA: o `snapshotAPI` responde `/api/cves-page` com o mesmo
   shape, filtrando + ordenando + fatiando client-side; a barra de
   paginação funciona offline.
7. Sem regressão: expansões de linha, badges VEX, contagens e CSV
   continuam funcionando.

## Critérios de aceite

- Com > 1 página de CVEs, a UI mostra a barra de paginação; avançar/voltar
  troca as linhas sem recarregar tudo; "Page X of Y" e o total batem.
- Trocar qualquer filtro volta para a página 1.
- `page=999` retorna a última página (não vazio nem erro); `page=0` → 400;
  `pageSize=5000` → 500 por página.
- O CSV baixado (live e snapshot) contém **todas** as CVEs dos filtros, não
  só a página visível.
- O HTML exportado pagina offline com os mesmos controles.
