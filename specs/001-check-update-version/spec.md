# Spec: verificação de nova versão no início do programa

## O quê

Ao iniciar o artifactor localmente (fora do cluster), verificar se existe uma
versão mais nova publicada no GitHub (último release). Se houver, perguntar ao
usuário se quer atualizar; em caso positivo, baixar o binário do release,
extraí-lo e substituir o executável local no mesmo path. Se o diretório (ou o
arquivo) não tiver permissão de escrita, usar `sudo` (o usuário digita a senha
no terminal).

## Por quê

O artifactor é distribuído como binário CLI (além da imagem); hoje não há
nenhum aviso de versão nova e o usuário só descobre atualizações olhando o
GitHub manualmente. Um check automático no início do programa reduz o uso de
versões antigas com bugs conhecidos.

## Requisitos

1. O check roda no início do `scan` (subcomando padrão), antes do trabalho
   pesado (DB, scan, HTTP).
2. É **ignorado** quando o processo roda dentro do pod (instalação via
   `artifactor install` / pod in-cluster).
3. Flag `--no-check-update-version` (env `NO_CHECK_UPDATE_VERSION`) pula o
   check.
4. A fonte é o último release do GitHub do repo
   (`github.com/getupcloud/artifactor`), via API
   `GET /repos/getupcloud/artifactor/releases/latest`.
5. Comparação semver entre a versão embutida (`main.version`) e o `tag_name`
   do release (com/sem prefixo `v`). Builds sem versão ("dev") não verificam.
6. Falha do check (sem rede, rate limit, asset ausente) nunca bloqueia o
   programa: loga aviso e segue.
7. Pergunta interativa (padrão "não") só quando há versão nova; sem TTY,
   apenas loga que há versão nova.
8. Ao confirmar: baixa o asset do release para a plataforma local
   (`artifactor_<os>_<arch>.tar.gz`), extrai apenas o binário `artifactor` e
   substitui o executável em execução (path de `os.Executable()`, resolvendo
   symlinks), de forma atômica (temp + rename no mesmo diretório).
9. Sem permissão de escrita no diretório/arquivo de destino, executa
   `sudo install` com o stdin/stdout/stderr ligados ao terminal.
10. Após substituir, informa que a atualização foi aplicada (não reinicia o
    processo).

## Critérios de aceite

- `artifactor scan` com versão antiga e release novo no GitHub pergunta e,
  ao confirmar, substitui o binário local pelo novo.
- Rodando dentro do pod (deployment instalado ou pod `--in-cluster`) o check
  não acontece.
- `artifactor scan --no-check-update-version` (ou env) não consulta o GitHub.
- Build `dev` e sem rede não quebram o fluxo normal.
- Binário substituído mantém permissão de execução e funciona após o restart.
