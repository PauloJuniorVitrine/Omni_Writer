# Arquitetura — Omni Writer

## Padrão Adotado

- **Hexagonal (Ports & Adapters) / Clean Architecture**
- Separação explícita entre domínio, aplicação e infraestrutura
- Domínio não depende de bibliotecas externas
- Integração com APIs e persistência apenas nas bordas

## Camadas e Responsabilidades

- **domain/**: Modelos, contratos e regras de negócio
- **app/**: Orquestração de pipelines, controle de fluxo, controllers
- **infraestructure/**: Gateways para OpenAI, DeepSeek, persistência de artigos
- **shared/**: Utilitários, logger, mensagens, status
- **tests/**: Testes unitários, integração, E2E, carga

## Fluxo Principal

1. Pipeline é iniciado via `app/pipeline.py`
2. Controller seleciona gateway conforme modelo (OpenAI, DeepSeek)
3. Gateway executa requisição externa e retorna artigo
4. Artigo é salvo via storage, status atualizado
5. Logs e métricas são registrados
6. Testes e diagnósticos podem ser executados a qualquer momento

## Relações Entre Módulos

- `app/controller.py` depende de `infraestructure/openai_gateway.py` e `infraestructure/deepseek_gateway.py`
- `infraestructure/storage.py` manipula persistência e compactação
- `shared/logger.py` e `shared/status_repository.py` são usados em todas as camadas

## Observações
- O domínio nunca depende de infraestrutura
- Testes cobrem todos os fluxos críticos
- Logs e rastreabilidade são centralizados em `logs/` 