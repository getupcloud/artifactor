# Spec: TTL de 2h no update automático do DB + botão de atualização manual

## O quê

1. O banco de vulnerabilidades do grype só é **atualizado automaticamente**
   (na inicialização do `scan` e no tick de `--db-refresh-interval`) quando o
   **último update check** aconteceu há **mais de 2 horas** — a data vem do
   arquivo `last_update_check` (RFC3339) em `<db-dir>/6/`, o mesmo arquivo
   que o curator do grype escreve/lê. Dentro da janela de 2h, nenhuma
   requisição de rede é feita (o DB local é usado como está).
2. O chip do DB no header do SPA ganha um botão **🗘** que **atualiza o banco
   na hora**, ignorando o TTL (update manual = sempre verifica).

## Por quê

O caminho de download direto (`--grype-db-direct-download`) consulta o
`latest.json` a cada inicialização, mesmo minutos depois de um update
recente — o curator nativo do grype já tem o TTL de 2h via
`last_update_check`, mas o download direto não o honrava. Além disso, não há
como forçar um update sem reiniciar o processo; o botão resolve isso pela
UI (o status line "Updating vulnerability DB…" já reflete o progresso).

## Requisitos

1. `directUpdate` passa a honrar o TTL de 2h (semântica do curator):
   - lê o description do DB instalado **antes** de qualquer chamada de rede;
   - com DB instalado e `last_update_check` com menos de 2h, retorna sem
     tocar na rede (debug log);
   - grava `last_update_check` (RFC3339 UTC) após um check bem-sucedido —
     tanto "já atualizado" quanto "atualizado agora"; falhas não gravam;
   - arquivo ausente/ilegível → check permitido (primeira execução).
2. `scanner.DBOptions.Force bool` — update manual (botão) ignora o TTL:
   no download direto pula o gate; no caminho do curator usa
   `UpdateCheckMaxFrequency=0` (mesma semântica).
3. `POST /api/db/update` — dispara o refresh **forçado** em background
   (mesmo fluxo do tick): `202 {"status":"started"}`; `409 {"error":…}`
   quando um update já está em andamento; `503` quando indisponível
   (exports/testes sem callback). O status line do SPA já acompanha
   `db.updating`.
4. SPA: botão 🗘 dentro do chip `db: …` (oculto em snapshot, desabilitado
   enquanto `db.updating`), com feedback no banner; o poll de 8s reflete o
   estado.
5. Sem regressão: o tick de `--db-refresh-interval` e a inicialização
   continuam gated pelo TTL; update manual não quebra scans em andamento
   (a troca de provider é a mesma do tick).

## Critérios de aceite

- Com `last_update_check` recente (< 2h), rodar `scan` local não consulta a
  rede do DB (debug log de skip) e usa o banco instalado.
- Com o arquivo ausente ou antigo (> 2h), o update acontece e o arquivo é
  regravado.
- Clicar 🗘 inicia o update mesmo dentro da janela de 2h; o botão desabilita
  e o status line mostra "Updating vulnerability DB…" até concluir; um
  segundo clique durante o update recebe 409.
- Snapshot exportado não mostra o botão.
