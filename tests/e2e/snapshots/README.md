# Organização de Screenshots E2E

Todos os screenshots capturados durante os testes E2E devem ser salvos em subpastas de `/tests/e2e/snapshots/{jornada}/[etapa].png`.

## Convenção
- `{jornada}`: nome da jornada (ex: generate_article, download, feedback)
- `[etapa]`: nome do passo ou variação (ex: inicio, pre_submit, pos_submit, falha_validacao, download)

## Exemplo
```
snapshots/
  generate_article/
    inicio.png
    pre_submit.png
    pos_submit.png
    download.png
    falha_validacao.png
  download/
    inicio.png
    sucesso.png
  feedback/
    inicio.png
    sucesso.png
    erro.png
```

## Regras
- Sempre capture screenshots em cada etapa relevante do fluxo
- Use nomes claros e padronizados para facilitar rastreabilidade
- Compare visualmente com execuções anteriores para detectar regressões 