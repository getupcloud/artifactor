# ADR-0003: fail-fast quando o banco grype está indisponível

- Data: 2026-10-30
- Status: Aceito

## Contexto

Antes, o servidor subia mesmo sem banco de vulnerabilidades utilizável
(avisava e deixava os scans falharem), o que deixava pods servindo uma
interface quebrada silenciosamente.

## Decisão

Se não há banco utilizável **e** o download/update falhou (ou está
desabilitado), `scan` e os `--export*` **encerram com erro** (exit 1),
exibindo o erro de leitura e o erro de download. Se um banco utilizável já
existe e apenas o update falha, continua rodando (só avisa).

Flag `--ignore-grype-db-unavailable` (env `IGNORE_GRYPE_DB_UNAVAILABLE`)
restaura o comportamento leniente anterior (servir mesmo sem banco; scans
falham até ele ficar disponível).

## Consequências

- Falha visível (exit code + log) em vez de serviço degradado; no K8s o pod
  entra em crash-loop até o banco ser obtível.
- Quem roda offline com banco pré-existente usa `--db-auto-update=false` e
  não é afetado.
