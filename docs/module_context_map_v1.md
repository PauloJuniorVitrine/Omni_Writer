# Mapeamento de Módulos — Omni Writer

| Módulo/Caminho                  | Camada         | Contexto/Domínio         | Conexões Principais                | Responsabilidade Funcional                         |
|---------------------------------|----------------|--------------------------|-------------------------------------|---------------------------------------------------|
| app/pipeline.py                 | Aplicação      | Orquestração             | domain, infraestructure, shared     | Pipeline de geração de artigos                    |
| app/controller.py               | Aplicação      | Orquestração             | infraestructure, shared             | Seleção de gateway e controle de geração          |
| app/routes.py                   | Aplicação      | API/Rotas                | app, shared, domain                 | Rotas HTTP para geração e consulta                |
| domain/models.py                | Domínio        | Modelos/Contratos        | -                                   | Entidades, contratos e regras de negócio          |
| infraestructure/openai_gateway.py| Infraestrutura | Integração OpenAI        | domain, shared                      | Gateway para API OpenAI                           |
| infraestructure/deepseek_gateway.py| Infraestrutura | Integração DeepSeek    | domain, shared                      | Gateway para API DeepSeek                         |
| infraestructure/storage.py      | Infraestrutura | Persistência             | domain, shared                      | Salvar, compactar e limpar artigos                |
| shared/logger.py                | Utilitário     | Logging                  | logging                             | Log estruturado e exportação de métricas          |
| shared/config.py                | Utilitário     | Configuração             | -                                   | Constantes e parâmetros globais                   |
| shared/messages.py              | Utilitário     | Mensagens                | -                                   | Mensagens multilíngue e templates                 |
| shared/status_repository.py     | Utilitário     | Status                   | -                                   | Controle e limpeza de status de execução          |
| tests/unit/                     | Teste          | Unitário                 | app, domain, infraestructure, shared| Testes unitários                                 |
| tests/integration/              | Teste          | Integração               | app, infraestructure, shared         | Testes de integração                             |
| tests/e2e/                      | Teste          | E2E                      | app, API                            | Testes ponta a ponta                             |
| tests/load/                     | Teste          | Carga                    | app, API                            | Testes de carga                                  |
| logs/                           | Observabilidade| Logs                      | app, infraestructure, shared         | Evidências de execução e falhas                   | 