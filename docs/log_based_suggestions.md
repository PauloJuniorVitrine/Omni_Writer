# Sugestões Baseadas em Logs — Omni Writer

## Resumo de Falhas Extraídas

- Diversas execuções do pipeline multi (`logs/pipeline_multi_diag.log`) mostram repetições de inicialização e chamadas a `generate_article`.
- Não há registros explícitos de falhas críticas, mas a ausência de logs de erro pode indicar falta de logging de exceções ou masking de falhas.

## Correlação com Funções/Arquivos

- Função: `generate_article` (app/controller.py, infraestructure/openai_gateway.py, infraestructure/deepseek_gateway.py)
- Arquivo: `logs/pipeline_multi_diag.log`

## Sugestões de Refatoração

1. **Aprimorar logging de exceções**: Garantir que falhas em `generate_article` sejam logadas explicitamente, incluindo stacktrace e contexto.
2. **Adicionar logs de sucesso/erro em workers Celery**: Facilitar rastreio de execuções anômalas.
3. **Implementar alertas automáticos para repetições excessivas**: Detectar loops ou retries não intencionais.
4. **Auditar masking de falhas**: Revisar pontos onde exceções podem estar sendo suprimidas sem log.

## Observações
- Recomenda-se expandir logs para incluir status final de cada pipeline e detalhamento de falhas.
- Falhas não rastreadas podem comprometer a robustez e a auditabilidade do sistema. 