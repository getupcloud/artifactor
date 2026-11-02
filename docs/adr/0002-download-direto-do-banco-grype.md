# ADR-0002: download direto do banco grype (--grype-db-direct-download)

- Data: 2026-10-30
- Status: Aceito

## Contexto

A distribuição da anchore passou a servir o banco v6 como um único arquivo
`.tar.zst` multi-plataforma (o `latest.json` traz schemaVersion/built/path/
checksum). O downloader embutido na lib grype v0.121.0 só suporta xz/tar.xz
→ downloads novos quebram com a lib.

## Decisão

Flag `--grype-db-direct-download` (env `GRYPE_DB_DIRECT_DOWNLOAD`): baixar
`latest.json` + arquivo do banco com **net/http puro**, sem a lib de download
do grype:

- honra `--insecure-skip-tls` e `--db-ca-cert` (client próprio);
- verifica sha256 do arquivo;
- extrai zstd+tar (klauspost/compress, com proteção contra path traversal);
- hidrata (índices) via `dbv6.Hydrater()`, grava `import.json` (xxh64 +
  client version) e faz rename atômico para `<db-dir>/6`;
- compara `built` do listing com o banco instalado (mesma semântica de
  `isSupersededBy` do curator): só baixa se for mais novo do mesmo schema.

Implementação: `internal/scanner/grypedbdirect.go`; `NewProvider`/`RefreshDB`
recebem `scanner.DBOptions`.

## Consequências

- Downloads novos funcionam apesar da mudança de formato da distribuição.
- O caminho da lib continua disponível (flag desligada) para distribuições
  que sirvam formatos suportados.
- Metadados (`import.json`) precisam ser gerados localmente — o arquivo da
  distribuição não os contém.
