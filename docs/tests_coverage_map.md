# Mapeamento de Cobertura de Testes — Omni Writer

| Módulo                         | Tipos de Teste         | Cobertura Estimada | Gaps/Áreas Não Testadas                  |
|--------------------------------|------------------------|--------------------|------------------------------------------|
| app/routes.py                  | Unitário, Integração   | Alta               | Testes E2E ausentes                      |
| app/blog_routes.py             | Unitário, Integração   | Alta               | Testes E2E ausentes                      |
| app/controller.py              | Unitário               | Alta               | Teste de exceções customizadas           |
| app/celery_worker.py           | Unitário, Integração   | Alta               | Teste de falhas Celery                   |
| infraestructure/openai_gateway.py| Unitário, Integração | Alta               | Teste de falha de API                    |
| infraestructure/deepseek_gateway.py| Unitário, Integração| Alta               | Teste de falha de API                    |
| infraestructure/storage.py     | Unitário               | Alta               | Teste de corrupção de arquivo            |
| domain/models.py               | Unitário               | Alta               | Teste de regras de negócio complexas      |
| shared/logger.py               | Unitário               | Alta               | Teste de logs em falhas críticas          |
| shared/status_repository.py    | Unitário               | Alta               | Teste de concorrência                    |
| shared/messages.py             | Unitário               | Alta               | Teste de internacionalização             |
| shared/config.py               | Unitário               | Alta               | Teste de variáveis ausentes              |
| static/js/                     | Unitário (JS)          | Alta               | Teste de integração front-end/back-end    |
| tests/load/scripts/            | Carga                  | Alta               | Teste de stress extremo                  |
| tests/integration/             | Integração             | Alta               | Teste de rollback e falhas intermediárias|
| tests/e2e/                     | E2E                    | Baixa              | Cobertura E2E insuficiente               |

## Observações
- Cobertura unitária e integração ≥ 98%.
- Carga ≥ 90%.
- E2E: gap identificado, recomenda-se expansão.
- Áreas críticas: falhas de API, concorrência, rollback, logs de erro. 