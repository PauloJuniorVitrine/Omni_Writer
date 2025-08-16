# Dependências — Omni Writer

## Bibliotecas Principais

- **Python**: 3.10+
- **requests**: Requisições HTTP para APIs externas (OpenAI, DeepSeek)
- **celery**: Orquestração de tarefas assíncronas
- **pytest**: Testes unitários e integração
- **locust**: Testes de carga
- **logging**: Log estruturado e rastreável
- **uuid, os, shutil, zipfile**: Utilidades de sistema e manipulação de arquivos

## Justificativa por Camada

- **Domínio**: Sem dependências externas (apenas tipagem e dataclasses)
- **Aplicação**: Depende de domínio, shared e infraestrutura para orquestração
- **Infraestrutura**: `requests`, integração com APIs, manipulação de arquivos
- **Shared**: `logging`, utilitários, mensagens, status
- **Testes**: `pytest`, `locust`, mocks e fixtures

## Observações
- Todas as dependências estão listadas em `requirements.txt` e `package.json` (para testes JS)
- Não há dependências hardcoded em código de produção
- Integração com APIs externas é isolada em gateways 