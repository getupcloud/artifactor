# Tasks: abrir o SPA no navegador ao rodar o scan localmente

- [x] `main.go`: flag `--no-open-browser` (env `NO_OPEN_BROWSER`),
      `defaultBrowserCommand()` (xdg-open/open/cmd start) e
      `maybeOpenBrowser()` chamado após o servidor subir, com os skips
      (flag, pod via `KUBERNETES_SERVICE_HOST`, sem TTY)
- [x] AGENTS.md (referência de CLI) e spec 004
- [x] `make build`, `go vet ./...`, `go vet -tags integration ./...` e
      `make test`
