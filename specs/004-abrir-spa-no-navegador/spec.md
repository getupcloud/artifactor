# Spec: abrir o SPA no navegador ao rodar o scan localmente

## O quê

Ao executar `artifactor scan` sem `--in-cluster` (ou seja, o servidor local
que sobe para servir o SPA — incluindo `--from-sbom`), o navegador padrão do
usuário abre automaticamente em `http://127.0.0.1:<port>/`.

## Por quê

Hoje o usuário precisa copiar a URL manualmente depois do log "listening
on ...". Abrir o SPA sozinho melhora o fluxo de quem roda o scan na própria
máquina.

## Requisitos

1. O navegador abre uma única vez, logo após o servidor HTTP subir, no
   caminho local (`scan` servindo o SPA — nunca em `--in-cluster`,
   `install`, `uninstall` ou nos exports one-shot).
2. Não abre quando o processo roda dentro de um pod
   (`KUBERNETES_SERVICE_HOST`).
3. Não abre em execuções não interativas (sem TTY no stdin — ex. systemd).
4. Flag `--no-open-browser` (env `NO_OPEN_BROWSER`) desliga o auto-open.
5. Falha ao abrir (sem navegador/display) vira apenas aviso; nunca bloqueia
   o scan.

## Critérios de aceite

- `artifactor scan` num terminal com display abre o SPA no navegador.
- Com `--no-open-browser` (ou env) nada é aberto.
- Dentro do pod e em execuções sem TTY nada é aberto.
- `install`, `uninstall`, `--in-cluster` e exports continuam sem abrir nada.
