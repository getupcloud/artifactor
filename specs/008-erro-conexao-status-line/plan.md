# Plan: erros de conexão com o backend na status line do SPA

## Design (só SPA — `web/index.html`)

- CSS: `.statusline.error` — variante vermelha (mesma paleta do `.banner`
  de erro: rgba(229,72,77,...)).
- Estado: `state.backendError` (null = sem erro).
- Helper `renderStatusLine()` centraliza a decisão da linha:
  1. snapshot → sempre escondida;
  2. `state.backendError` → `<dot error> Erro de conexão com o backend:
     <mensagem escapada via esc()>` + classe `error`;
  3. `status.db.updating` → mensagem atual de atualização do DB (dot
     pulsante, sem `error`);
  4. senão → escondida (remove `show` e `error`).
- `refreshStatus`: no sucesso zera `state.backendError` e chama
  `renderStatusLine()`; no `catch` (que hoje é silencioso) registra a
  mensagem e renderiza. O poll de 8 s limpa a linha automaticamente quando
  o backend volta.

## Riscos

- Mensagem do erro com HTML: neutralizado com `esc()` (mesmo helper usado
  no resto da SPA).
- Falsos positivos: qualquer falha do `GET /api/status` (ex. 500) vira
  erro de conexão na linha — é o comportamento desejado (o motivo aparece
  na mensagem).

## Testes

- SPA sem testes automatizados; validação por smoke manual + build/vet/
  test do Go (o HTML é embutido, não tem lógica testável no backend).
