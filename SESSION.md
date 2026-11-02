# SESSION.md — artifactor (DeepSeek Coder session bootstrap)

> Este arquivo apenas **inicia a sessão**. O conhecimento e as specs do
> projeto vivem em formatos padrão, versionados no repo:
>
> - **AGENTS.md** — contexto, memórias, convenções e comandos do projeto
>   (formato aberto adotado por Cursor/Codex/Copilot/etc.)
> - **CLAUDE.md** — ponteiro para AGENTS.md (compatibilidade com Claude Code
>   / DeepSeek Code)
> - **docs/adr/** — decisões de arquitetura no formato MADR
> - **specs/###-titulo/{spec,plan,tasks}.md** — specs de features (GitHub
>   Spec Kit)
> - **README.md** — documentação para humanos

## Como usar

1. `make build-session` (opcional — container dev com usuário do host) e
   `make start-session` iniciam a sessão.
2. Primeira instrução da sessão: **leia AGENTS.md, docs/adr/ e specs/ e use
   como contexto inicial do projeto**.
3. Responda ao usuário em **português**; siga as convenções do AGENTS.md
   (formato de log, commits, identidade git, artefatos que não devem ser
   commitados).
