# Plan: esconder a lista de imagens para expandir a área de CVEs

## Design (só SPA — `web/index.html`)

- HTML:
  - dentro de `<div class="layout">`, antes do `<aside class="sidebar">`,
    novo `<button class="sidebar-toggle" id="sidebar-toggle" title="Show the
    image list">Images ›</button>` (oculto por padrão);
  - no `.head` da sidebar, o input de busca entra numa `.head-row` com o
    novo `<button class="icon-btn" id="sidebar-hide" title="Hide the image
    list (expands the CVE area)">✕</button>`.
- CSS:
  - `body.sidebar-hidden .sidebar { display: none; }`;
  - `body.sidebar-hidden .sidebar-toggle { display: flex; }` (padrão
    `display: none`);
  - `.sidebar-toggle`: botão vertical (`writing-mode: vertical-rl;
    transform: rotate(180deg)`), mesma paleta da sidebar (panel/border/
    muted, hover accent);
  - `.sidebar .head-row { display: flex; gap: 8px; align-items: center; }`
    com o input `flex: 1; min-width: 0`;
  - `.icon-btn`: mesmo estilo dos botões `secondary` compactos (panel2,
    border, muted → hover accent).
- JS:
  - `toggleSidebar(hidden)` alterna a classe `sidebar-hidden` no `<body>`;
  - `$("sidebar-hide").onclick` esconde; `$("sidebar-toggle").onclick`
    mostra;
  - nada mais muda: `renderImageList`, busca, seleção e stats seguem
    intactos (a classe no body não é tocada pelos re-renders).

## Riscos

- Nenhum: mudança puramente visual, sem estado persistente nem API.
- A sidebar oculta não impede o filtro por imagem (o estado `selected`
  continua aplicado) — comportamento intencional (requisito 3).

## Testes

- SPA sem testes automatizados: validação por smoke manual (live e
  snapshot) + checagem de sintaxe do JS embutido + build/vet/test do Go.
