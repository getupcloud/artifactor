# Spec: esconder a lista de imagens para expandir a área de CVEs

## O quê

A sidebar com a lista de imagens ganha um botão para ser **escondida**,
liberando toda a largura para a tabela de CVEs; quando escondida, um botão
discreto na borda esquerda permite **mostrá-la de novo**.

## Por quê

Em clusters com muitos CVEs (ou telas menores), a sidebar fixa de 300px
consome espaço útil da tabela. O operador que está triando CVEs raramente
precisa da lista de imagens o tempo todo — poder recolhê-la expande a área
de leitura sem perder a funcionalidade (filtros por imagem continuam
valendo).

## Requisitos

1. Botão "✕" no cabeçalho da sidebar esconde a lista de imagens; a área de
   CVEs passa a ocupar toda a largura do layout.
2. Com a sidebar escondida, um botão vertical discreto ("Images ›") na borda
   esquerda do layout a mostra de novo.
3. A ação é puramente visual (CSS + JS): não limpa seleção, filtros nem
   resultados; o filtro de imagem e o estado selecionado continuam valendo
   com a sidebar oculta.
4. Funciona no modo live **e** no snapshot exportado (não depende de API).
5. Sem regressão: render da lista, busca, seleção de imagem e stats
   continuam funcionando.

## Critérios de aceite

- Clicar em "✕" esconde a sidebar e a tabela de CVEs expande para a largura
  toda; o botão "Images ›" aparece na borda esquerda.
- Clicar em "Images ›" restaura a sidebar com o estado anterior (busca e
  seleção preservadas).
- O relatório exportado (snapshot) tem o mesmo comportamento.
