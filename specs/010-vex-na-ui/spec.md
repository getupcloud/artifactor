# Spec: gestão de VEX no SPA (upload, reprocessamento e diálogo)

## O quê

Uma seção "VEX" no SPA, à direita do select de cluster, com:

1. **Adicionar** arquivos OpenVEX ou CSAF (upload do navegador). Ao incluir,
   a lista de CVEs é **reprocessada imediatamente** com os novos documentos
   — **sem refazer o scan nem o SBOM** (sem pull de imagem, sem acesso ao
   banco grype): o VEX é re-aplicado sobre os matches já calculados.
2. **Mostrar** os arquivos OpenVEX/CSAF num diálogo, de forma resumida
   (lista com os itens importantes: formato, tamanho e resumo — nº de
   statements por status para OpenVEX; título e nº de vulnerabilidades/CVEs
   para CSAF), permitindo **selecionar** cada arquivo na lista.
3. **Copiar** (botão e Ctrl+C) e **baixar** cada arquivo individualmente.

Os arquivos enviados ficam **apenas em memória** (mesma filosofia dos
kubeconfigs): a API nunca devolve conteúdo sem pedido explícito de
download, e nada é persistido em disco além de um temp file para o
processador do grype ler. Remover um arquivo (botão no diálogo) também
reprocessa as CVEs.

## Por quê

Hoje o VEX só entra via `--vex` no startup: quem está operando a UI precisa
reiniciar o processo para ajustar os documentos. Upload + reprocessamento
em tempo real permite iterar nos documentos enquanto o scan está de pé.

## Requisitos

1. O scanner guarda os **matches crus** (pós-grype, pré-VEX) e o
   `pkg.Context` de cada imagem em memória, para reprocessar o VEX sem
   re-executar syft/grype (custo de memória aceitável; o resultado atual já
   fica todo em memória).
2. `POST /api/vex` `{name, content}` (≤ 1 MiB): valida o formato
   (OpenVEX/CSAF), registra em memória e **reprocessa** todas as imagens
   escaneadas (`Scanner.ReprocessVex`); 400 formato inválido; 409 nome
   duplicado. `DELETE /api/vex/{name}` remove e reprocessa.
3. `GET /api/vex` lista os arquivos com `name`, `size`, `format` e
   `summary`; `GET /api/vex/{name}` baixa o conteúdo (Content-Disposition
   com o nome).
4. O conjunto ativo de documentos = `--vex` do startup + uploads
   (`Scanner.SetVexDocs`); scans em andamento usam o conjunto corrente no
   momento de cada imagem (worker lê na finalização).
5. SPA: seção VEX à direita do select de cluster (na cluster bar — oculta
   em snapshot/from-sbom, onde não há barra); botão "Add VEX" (input file,
   múltiplo) e botão "VEX files" (diálogo com lista selecionável,
   resumo por arquivo, Download/Copy/Remove); Ctrl+C copia o selecionado.
6. A atribuição `vexFile` nas CVEs usa o **nome** do arquivo (upload name ou
   basename do `--vex`), não o temp path.

## Critérios de aceite

- Enviar um OpenVEX que marca `not_affected` para uma CVE conhecida
  reprocessa a lista (a CVE ganha o badge VEX com o nome do arquivo) sem
  novo scan; remover o arquivo restaura a CVE.
- O diálogo lista os arquivos com resumo, seleção por clique, download e
  cópia (Ctrl+C) do conteúdo.
- Nome duplicado → 409; conteúdo inválido → 400.
- Snapshot/`--from-sbom` sem barra não mostram a seção (o `--vex` do
  startup continua valendo).
