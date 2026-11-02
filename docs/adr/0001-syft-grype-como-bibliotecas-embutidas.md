# ADR-0001: syft e grype como bibliotecas Go embutidas

- Data: 2026-10-26
- Status: Aceito

## Contexto

O artifactor precisa gerar SBOMs (syft) e casar CVEs (grype) para todas as
imagens do cluster. A alternativa seria invocar os binários CLI de syft/grype
(subescrever processos) ou instalar os binários na imagem.

## Decisão

Usar **syft** e **grype como bibliotecas Go embutidas** (nenhum binário
externo instalado na imagem):

- `pkg.Provide()` do grype para SBOM + pacotes (com `RegistryOptions` para
  credenciais de pull secrets);
- `grype.VulnerabilityMatcher.FindMatchesContext` com
  `matcher.NewDefaultMatchers` (stock `UseCPEs=true`, dpkg epoch zero, rpm
  epoch auto);
- Store de resultados em memória.

Versões pinadas: grype v0.121.0 (resolve syft v1.55.0, stereoscope v0.3.4,
clio v0.1.1), client-go v0.37.1; Go ≥ 1.26.8.

## Consequências

- Imagem menor e sem fork/exec por scan; upgrade de versões = bump de
  dependência Go.
- O progresso/erros internos do grype precisam ser roteados para o log do
  app (`internal/scanner/grypelog.go`).
- O downloader do banco do grype v0.121.0 quebrou quando a distribuição
  migrou para `.tar.zst` → motivou o `--grype-db-direct-download`
  (ADR-0002).
