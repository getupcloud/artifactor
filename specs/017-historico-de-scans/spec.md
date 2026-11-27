# Spec: histórico de scans no pod + gráfico de evolução de CVEs

## O quê

1. O servidor do `scan` passa a **salvar um snapshot do resultado de cada
   scan concluído** em `<history-dir>/<dia>/<hora-min-seg>` (data/hora até
   segundos do **início** do scan). No deployment criado pelo `install`, o
   diretório é `/data/history` (dentro do emptyDir do pod — sobrevive a
   restarts do container, morre com o pod). Scans cancelados ou com falha
   não são salvos.
2. O SPA ganha a seção **"History"** na cluster bar, ao lado da seção VEX
   (separada por linha vertical), com um diálogo que:
   - mostra um **gráfico de linha ou barras** (alternável) com a evolução
     da quantidade de CVEs entre os scans — eixo x = data/hora do scan,
     eixo y = quantidade de CVEs — com uma série por criticidade
     (critical/high/medium/low/negligible/unknown) e uma série com o
     **total**;
   - lista os scans salvos e permite **carregar os dados de um scan do
     histórico**, trocando apenas os dados exibidos (sem refresh da
     página, sem rescan); um botão "Back to live" restaura os dados
     atuais.

## Por quê

Hoje os resultados só existem em memória e cada scan sobrescreve o
anterior: não dá para ver a tendência de CVEs ao longo do tempo nem
revisar o estado de um scan passado sem exportar manualmente a cada
execução. O pod do `install` já tem um volume gravável (`/data`), então o
histórico pode viver lá sem persistência externa.

## Requisitos

1. Flag `--history-dir` (env `HISTORY_DIR`, default vazio = desligado);
   o deployment instalado define `HISTORY_DIR=/data/history`.
2. Ao fim de cada scan **bem-sucedido** (RunOnce sem erro; cancelado/falho
   não salva), o backend grava em `<history-dir>/<AAAA-MM-DD>/<HH-MM-SS>/`
   (início do scan; colisão de mesmo segundo ganha sufixo `-2`, `-3`…):
   - `summary.json` — `{name, startedAt, durationSec, images, total,
     critical, high, medium, low, negligible, unknown, cluster, context}`
     (`cluster` = nome do cluster selecionado, `context` = contexto do
     kubeconfig usado no scan; ausentes quando não há registro de
     clusters, ex. `--from-sbom`);
   - `scan.json` — o snapshot completo no mesmo formato do export
     (`exportSnapshot`: status, images, cves, namespaces, namedVulns,
     artifacts, artifactsByImage).
3. Endpoints:
   - `GET /api/history` → `{entries: [summary...]}` ordenado do mais
     recente; vazio (não erro) quando o histórico está desligado;
   - `GET /api/history/{name...}` → o `scan.json` do diretório indicado
     (404 para desconhecido; path sempre confinado ao history-dir).
4. SPA: seção "History" ao lado da VEX (separador vertical) — **apenas
   quando o histórico está habilitado no backend** (`/api/status` reporta
   `history: true`; com a flag desligada a seção e o separador ficam
   ocultos); entre o título e o botão, um contador com a quantidade de
   scans salvos (e, com um scan histórico carregado, o cluster, contexto
   e data desse scan junto do contador); botão abre o diálogo com o
   gráfico (toggle Line/Bar) e a lista de scans (cada linha mostra
   cluster · contexto quando presentes); clicar num scan carrega seus
   dados na view (título "Viewing history: <data>" na status line; botão
   principal vira "Back to live").
5. Com histórico carregado, só os **dados** mudam: sem refresh de página,
   sem rescan; as ações que alteram estado (scan, clusters, VEX) ficam
   desabilitadas; CSV/export usam os dados exibidos.
6. Sem regressão: com `--history-dir` vazio nada muda; snapshots
   exportados não mostram a seção (não há cluster bar); falha de escrita
   vira warning e nunca quebra o scan.

## Critérios de aceite

- Rodando com `--history-dir`, dois scans criam `…/<dia1>/<hh-mm-ss>1/` e
  `…/<dia2>/<hh-mm-ss>2/`, cada um com `summary.json` e `scan.json`.
- `GET /api/history` lista os scans (mais recente primeiro) com contagens
  por severidade e total; `GET /api/history/<nome>` devolve o snapshot.
- A UI mostra o gráfico com séries por severidade + total (line e bar,
  alternáveis) e a lista; carregar um scan troca os dados na hora e
  "Back to live" restaura.
- Cancelar um scan não gera entrada no histórico; `--history-dir` vazio
  não cria nada.
- Com `--history-dir` vazio, a seção History não aparece no SPA.
- O deployment manifest expõe `HISTORY_DIR=/data/history`.
