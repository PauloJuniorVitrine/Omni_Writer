# Guia de Contribuição — Omni Writer

## Padrões Gerais
- Siga o padrão de arquitetura hexagonal/clean
- Separe domínio, aplicação e infraestrutura
- Use snake_case para arquivos e pastas
- Documente todas as funções públicas com docstrings
- Não inclua dados sensíveis em código ou logs

## Estilo de Código
- Python: siga PEP-8
- JavaScript: siga ESLint Airbnb
- Nomes descritivos e semânticos
- Comentários explicativos para trechos não triviais

## Processo de Pull Request
1. Crie branch a partir de `main`
2. Garanta cobertura de testes ≥ 98% (unit), 95% (integração)
3. Execute todos os testes antes de submeter
4. Descreva claramente a motivação e impacto da mudança
5. Aguarde revisão automatizada e humana

## Procedimentos de Upgrade
1. **Pré-Upgrade**
   - Verifique compatibilidade de dependências em `dependencies_v1.md`
   - Execute suite completa de testes
   - Faça backup do estado atual
   - Consulte `semantic_contracts_v1.md` para impactos

2. **Durante Upgrade**
   - Siga ordem de execução definida em `architecture_v1.md`
   - Mantenha logs detalhados em `logs/`
   - Valide cada etapa antes de prosseguir
   - Atualize documentação conforme necessário

3. **Pós-Upgrade**
   - Execute testes de regressão
   - Verifique cobertura em `tests_coverage_map_v1.md`
   - Atualize versões em `CHANGELOG.md`
   - Valide logs e métricas

4. **Rollback**
   - Mantenha pontos de restauração
   - Documente procedimento de rollback
   - Teste processo de reversão
   - Mantenha logs de decisão

## Revisão e Aprovação
- Toda alteração passa por revisão não destrutiva
- Refatorações só são aceitas se não alterarem comportamento
- Logs e decisões devem ser registrados em `logs/`

## Observações
- Consulte sempre os arquivos em `docs/` antes de propor mudanças
- Dúvidas ou sugestões: abra uma issue 