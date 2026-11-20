# Spec: suporte a VEX (flag --vex, indicador e filtro no SPA)

## O quê

O artifactor passa a aceitar documentos **VEX** (Vulnerability
Exploitability eXchange) nos formatos OpenVEX e CSAF para marcar CVEs como
ignoradas:

1. Flag **`--vex <arquivo|diretório>`** — repetível (acumula); um diretório
   contribui com todos os arquivos diretos (não recursivo). Env `VEX`
   (lista separada por vírgulas).
2. No SPA, cada CVE ignorada pelo VEX (status `not_affected` ou `fixed`)
   ganha um **indicador** mostrando o status e o **nome do arquivo VEX**
   de referência.
3. Um **checkbox** "Hide VEX excluded" à esquerda do "Only CVEs with fix"
   esconde as CVEs ignoradas pelo VEX.

## Por quê

VEX permite documentar que uma CVE conhecida **não afeta** uma imagem
(ex.: componente não usado, versão não explorável), evitando ruído de
alerta e de triagem. Hoje o artifactor ignora documentos VEX e mostra toda
CVE casada pelo grype como ativa.

## Requisitos

1. `--vex` aceita arquivo (OpenVEX ou CSAF) ou diretório (arquivos diretos,
   não recursivo, em ordem estável); pode ser repetida e todas as entradas
   são combinadas; a env `VEX` contribui com mais caminhos (vírgula).
   Caminho inexistente ou formato não suportado falha no startup.
2. O processamento usa a própria lib do grype (`grype/vex`): um processador
   **por arquivo**, aplicado em cadeia após o match — assim cada CVE
   ignorada carrega o **arquivo** que a ignorou (a lib não expõe a origem
   por documento quando processa todos juntos).
3. CVE ignorada pelo VEX continua aparecendo no SPA, marcada com status
   VEX (`not_affected`/`fixed`) + arquivo de referência; a contagem de
   CVEs inclui as ignoradas.
4. Checkbox "Hide VEX excluded" à esquerda de "Only CVEs with fix":
   `exclude-vex=1` na API `/api/cves` (server-side) e no filtro de
   snapshot; vale também para o CSV.
5. `--in-cluster` rejeita `--vex` (os arquivos são locais, como
   `--from-sbom`); exports one-shot e `--from-sbom` aceitam `--vex`.
6. Sem regressão sem `--vex` (nenhum processador criado; comportamento
   atual).

## Critérios de aceite

- Com um OpenVEX marcando `not_affected` para uma CVE de uma imagem, o SPA
  mostra a CVE com o indicador VEX e o nome do arquivo; o checkbox esconde
  a linha.
- Vários `--vex` acumulam; diretório contribui com todos os arquivos.
- Arquivo inexistente → erro no startup com mensagem clara.
- `--in-cluster --vex x.json` → erro de validação.
- Sem `--vex`, nada muda.
