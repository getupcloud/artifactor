# Specs de features (GitHub Spec Kit)

Convenção para especificar uma feature **antes** de implementar. Cada feature
tem um diretório numerado com três arquivos:

```
specs/001-nome-da-feature/
  spec.md   — requisitos (o quê e por quê; casos de uso, critérios de aceite)
  plan.md   — design técnico (o como; arquitetura, mudanças, riscos)
  tasks.md  — checklist de implementação (itens pequenos, ordenados)
```

Regras:

- Numeração sequencial (`001`, `002`, ...); o título é um slug curto.
- `spec.md` responde "o que" e "por quê" — sem detalhes de implementação.
- `plan.md` cita arquivos/pacotes concretos e decisões técnicas (se a decisão
  for de arquitetura transversal, vira um ADR em `docs/adr/` em vez de viver
  só na spec).
- `tasks.md` usa `- [ ]` para cada passo; cada item deve ser pequeno o
  bastante para virar um commit.
- Quando a feature é concluída, os arquivos permanecem como registro
  histórico (não apagar).
