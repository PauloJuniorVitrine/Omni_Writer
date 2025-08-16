# Testes de Integração — Storage e Infraestrutura

Este diretório contém testes de integração para módulos críticos do sistema, especialmente operações de storage, concorrência, performance e integração real com sistema de arquivos e múltiplos processos.

## Critérios
- Testes que envolvem múltiplos componentes, side effects reais, concorrência, stress ou grandes volumes.
- Não devem ser executados junto com os testes unitários.
- Devem ser independentes, reprodutíveis e documentados.

## Exemplos de Casos
- Concorrência: múltiplos processos acessando funções de storage simultaneamente.
- Grandes volumes: criação, leitura e limpeza de centenas/milhares de arquivos.
- Performance: tempo de execução de operações de ZIP, limpeza, etc.
- Integração real: interação com sistema de arquivos, permissões, locks.

## Execução
```sh
pytest tests/integration/
```

## Observações
- Sempre documente o objetivo e o cenário de cada teste.
- Utilize fixtures e isolamento para evitar efeitos colaterais.
- Não misture testes unitários e de integração no mesmo arquivo. 