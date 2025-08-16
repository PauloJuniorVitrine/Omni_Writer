# Não há endpoint HTTP público para limpeza/manutenção automatizada.
# Este fluxo é acionado internamente por funções agendadas ou scripts administrativos.
# Para testes de carga, recomenda-se:
# - Executar manualmente o script de limpeza (ex: scripts/cleanup.py) em paralelo aos testes de carga.
# - Monitorar logs e uso de recursos durante operações de geração/exportação.
# Caso um endpoint venha a ser exposto, este script deve ser atualizado para simular requisições reais. 