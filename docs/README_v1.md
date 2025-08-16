# Omni Writer — Documentação Técnica

## Visão Geral

Omni Writer é um sistema modular para geração automatizada de artigos, com arquitetura hexagonal, suporte a múltiplos modelos de IA (OpenAI, DeepSeek), rastreabilidade por logs e pipeline de execução robusto.

- **Domínio:** Definição de entidades, regras de negócio e contratos de geração.
- **Aplicação:** Orquestração de pipelines, controle de fluxo e integração de gateways.
- **Infraestrutura:** Gateways para APIs externas, persistência e utilitários compartilhados.
- **Testes:** Cobertura unitária, integração, E2E e carga, com relatórios automatizados.

## Estrutura de Diretórios

- `app/` — Lógica de aplicação e pipelines
- `domain/` — Modelos e contratos de domínio
- `infraestructure/` — Gateways e persistência
- `shared/` — Utilitários e configurações
- `tests/` — Testes unitários, integração, E2E, carga
- `logs/` — Logs de execução e rastreabilidade
- `docs/` — Documentação técnica

## Instruções de Execução

1. Instale dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure variáveis de ambiente conforme `.env.example`.
3. Execute o pipeline principal:
   ```bash
   python app/pipeline.py
   ```
4. Para rodar testes:
   ```bash
   pytest
   ```

## Observações
- O sistema suporta reexecução automática via `docs/trigger_config.json`.
- Logs detalhados são salvos em `logs/`.
- Embeddings semânticos e análise de cobertura são gerados automaticamente. 