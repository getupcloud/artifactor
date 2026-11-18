# Plan: abrir o SPA no navegador ao rodar o scan localmente

## Design

- Flag `--no-open-browser` (env `NO_OPEN_BROWSER`) no FlagSet do `scan`
  (opt-out, mesmo estilo do `--no-check-update-version`).
- `maybeOpenBrowser(port int, disabled bool)` no `main.go`, chamada logo
  após o spawn do `http.ListenAndServe` no caminho de servidor local (o
  branch `--in-cluster` e os exports retornam antes, então não são
  afetados):
  - skip: flag/env ligados; `KUBERNETES_SERVICE_HOST` setado (pod);
    stdin sem TTY (`isTerminal`, já existente — execuções não interativas
    como systemd não disparam navegador);
  - URL: `http://127.0.0.1:<port>/`;
  - abre via `openFile(defaultBrowserCommand(), url)` (helper existente):
    `xdg-open` no Linux, `open` no macOS, `cmd /c start` no Windows;
  - falha → `logx.Warnf` com a URL para abrir manualmente.

## Riscos

- Corrida mínima entre o spawn do listener e o navegador conectar: o bind
  acontece em milissegundos e o `xdg-open` é assíncrono; aceitável.
- `xdg-open` sem display: `cmd.Start()` não bloqueia e o erro vira warning.

## Testes

- Sem testes unitários novos (lógica fina em `main.go`, não testável sem
  processo/display); validação por smoke manual e `make build`/`vet`/`test`.
