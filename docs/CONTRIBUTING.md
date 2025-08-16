# Guia de Contribuição — Omni Writer

## Padrões de Código
- Python: PEP-8, nomes em snake_case
- JavaScript: ESLint Airbnb, nomes em camelCase
- Comentários e docstrings obrigatórios em funções públicas
- Modularidade e SRP (Single Responsibility Principle)

## Processo de Contribuição
1. Crie branch a partir de `main`.
2. Adicione testes para toda nova funcionalidade (TDD/BDD).
3. Execute lint (`flake8`, `black`, `eslint`).
4. Submeta PR com descrição técnica e referência ao artefato/documentação.
5. Aguarde revisão automatizada e humana.
6. PRs só são aprovados com cobertura mínima (unitário ≥ 98%, integração ≥ 95%, carga ≥ 90%, E2E ≥ 85%).
7. Versionamento obrigatório para qualquer arquivo alterado.

## Revisão e Aprovação
- Toda alteração passa por revisão não destrutiva.
- Logs de decisão e execução devem ser atualizados.
- Documentação e exemplos devem ser testáveis.

## Observações
- Modificações em arquivos sensíveis disparam reexecução automática do pipeline.
- Consulte `/docs/` para arquitetura, contratos e contexto. 