# Spec: PURL e localização do artefato afetado na CVE

## O quê

Cada CVE do relatório passa a identificar o **artefato afetado** (pacote syft)
de forma completa:

1. No **relatório** (tabela de CVEs da SPA — modo live e snapshot exportado),
   a expansão da linha da CVE ganha um bloco "Artifact" com o **PURL** do
   pacote e a(s) **localização(ões)** dele no filesystem da imagem.
2. No **CSV** (live `/api/cves.csv` e `scan.csv` do export), entram duas novas
   colunas — **PURL** e **Location** (várias localizações separadas por
   `; `).
3. O export grype por imagem (`--export-grype` / `grype/`) passa a preencher
   `artifact.purl` e `artifact.locations` (os campos já existem no formato
   grype, hoje vazios).

## Por quê

Hoje a linha da CVE mostra apenas nome/versão/tipo do pacote ("Package").
O **PURL** identifica o pacote de forma inequívoca e padronizada (ex.:
`pkg:deb/debian/libssl3@3.0.11?arch=amd64`) e a **localização** mostra onde o
pacote está no filesystem da imagem (ex.: `/usr/lib/x86_64-linux-gnu/
libssl.so.3`) — informação essencial para triagem e remediação, já disponível
nos matches do grype mas descartada hoje.

## Requisitos

1. `scanner.CVE` ganha `PURL` (`json:"purl,omitempty"`) e `Locations`
   (`json:"locations,omitempty"`, objetos `{path, kind}`), preenchidos em
   `cveFromMatch` a partir de `m.Package.PURL` e `m.Package.Locations`
   (paths em ordem estável, sem duplicatas). Cada localização carrega um
   `kind` que vira o label de exibição, derivado do tipo do pacote:
   - `package` — path é um banco de pacotes do OS (deb `/var/lib/dpkg/status`,
     apk `/lib/apk/db/installed`, rpm `/var/lib/rpm/rpmdb.sqlite`, alpm,
     portage);
   - `filename` — path é o arquivo do artefato em si (binary, java-archive,
     jenkins-plugin, linux-kernel(-module), graalvm-native-image, app bundle,
     model);
   - `metadata` — arquivos de metadados do pacote (python
     `*.dist-info/METADATA`/`PKG-INFO`, conda, R);
   - `path` — demais casos (manifests como npm `package.json`/locks,
     `go.mod`, gemspec, `Cargo.lock`, composer etc. — default para os
     demais tipos).
2. CSV (server-side e export `scan.csv`): colunas `PURL` e `Location`
   adicionadas após `Type`; localizações múltiplas separadas por `; `.
3. SPA: o `toggleExpansion` da linha da CVE mostra o bloco do artefato
   (PURL em mono prefixada por `purl:` + lista de localizações, cada uma
   prefixada pelo label do `kind` — `package:`/`filename:`/`metadata:`/
   `path:`), oculto quando vazio; um título "DESCRIPTION" separa o bloco
   do artefato da descrição da CVE; a linha principal da tabela não muda
   (já é larga). Vale para live e snapshot.
4. O CSV offline do snapshot (`downloadCSVClient`) espelha as mesmas colunas
   (server e snapshot devem permanecer idênticos).
5. `buildGrypeReport` preenche `artifact.purl` e `artifact.locations`.
6. Sem regressão: CVEs sem PURL/localizações continuam com células vazias no
   CSV e sem o bloco na expansão; os campos novos fluem para `/api/cves`,
   `/api/cves-page` e o snapshot automaticamente (o `cveOut` embute `CVE`).

## Critérios de aceite

- Com um scan real (ou fixture com PURL/localizações), a expansão da linha da
  CVE mostra o PURL e as localizações do artefato.
- `/api/cves.csv` e o `scan.csv` exportado contêm as colunas `PURL` e
  `Location` preenchidas; múltiplas localizações aparecem separadas por `; `.
- O CSV offline do snapshot exportado tem as mesmas colunas.
- O grype JSON exportado tem `artifact.purl` e `artifact.locations`
  preenchidos.
- CVE sem artefato/localizações não quebra nada (células vazias, sem bloco).
