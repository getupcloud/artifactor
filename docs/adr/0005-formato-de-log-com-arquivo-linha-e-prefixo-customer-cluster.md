# ADR-0005: formato de log com arquivo:linha (relativo ao repo) e prefixo [customer/cluster]

- Data: 2026-10-31 (arquivo:linha), 2026-11-01 (prefixo)
- Status: Aceito

## Contexto

Depurar scans remotos (inclusive logs do pod transmitidos pelo
`--in-cluster`) exige saber DE ONDE cada linha veio e para qual
cliente/cluster ela pertence, sem paths absolutos de máquina de build.

## Decisão

Toda linha de log (logx) segue:

```
artifactor: [customer/cluster] AAAA/MM/DD HH:MM:SS arquivo:linha: mensagem
```

- `arquivo` é o path do chamador **relativo à raiz do repo** (o logx deriva a
  raiz do próprio caminho do arquivo; funciona com e sem `-trimpath`);
  arquivos fora do repo (ex. lib grype) mostram os dois últimos componentes
  do path;
- `[customer/cluster]` vem de `--customer-name`/`--cluster-name` (prefixo
  `artifactor: ` simples quando nenhum dos dois é informado);
- mensagens fatais do pacote main passam por `fatalf()` (logx.Errorf +
  exit 1) para manter o mesmo formato.

## Consequências

- Logs são rastreáveis por arquivo/linha e por cliente/cluster em execuções
  locais, no pod e nos relatórios transmitidos.
- O polling de logs do `--in-cluster` não usa o timestamp para retomar: cada
  poll relê o log do início e pula as linhas já exibidas pelo número da
  última linha registrada (o resume por `SinceTime` com parse na posição fixa
  `[12:31]` quebrava com o prefixo `[customer/cluster]` e a conexão caída
  repetia o log inteiro).
