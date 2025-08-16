# Mapeamento de Cobertura de Testes — Omni Writer

## Cenários de Teste por Módulo

### Pipeline (app/pipeline.py)
| Cenário | Tipo | Cobertura | Métricas | Exemplo |
|---------|------|-----------|----------|---------|
| Geração bem-sucedida | Unit | 100% | Tempo < 5s | `test_pipeline_success` |
| Falha de API | Integration | 98% | Retry < 3 | `test_pipeline_api_failure` |
| Timeout | Integration | 95% | Timeout = 30s | `test_pipeline_timeout` |
| Rollback | Unit | 100% | Tempo < 2s | `test_pipeline_rollback` |

### Controller (app/controller.py)
| Cenário | Tipo | Cobertura | Métricas | Exemplo |
|---------|------|-----------|----------|---------|
| Seleção de modelo | Unit | 100% | - | `test_controller_model_selection` |
| Validação de entrada | Unit | 100% | - | `test_controller_input_validation` |
| Tratamento de erro | Integration | 98% | - | `test_controller_error_handling` |

### Gateways (infraestructure/*_gateway.py)
| Cenário | Tipo | Cobertura | Métricas | Exemplo |
|---------|------|-----------|----------|---------|
| Conexão API | Integration | 95% | Latência < 1s | `test_gateway_connection` |
| Rate limiting | Integration | 90% | Retry = 5 | `test_gateway_rate_limit` |
| Autenticação | Unit | 100% | - | `test_gateway_auth` |

### Storage (infraestructure/storage.py)
| Cenário | Tipo | Cobertura | Métricas | Exemplo |
|---------|------|-----------|----------|---------|
| Persistência | Unit | 100% | IO < 100ms | `test_storage_save` |
| Recuperação | Unit | 100% | IO < 50ms | `test_storage_load` |
| Backup | Integration | 95% | Size < 1GB | `test_storage_backup` |

## Métricas de Performance

### Tempos de Resposta
- Pipeline completo: < 30s
- Geração de artigo: < 15s
- Persistência: < 1s
- Backup: < 5min

### Limites de Recursos
- CPU: < 80%
- Memória: < 2GB
- Disco: < 10GB
- Rede: < 100MB/s

## Testes de Carga

### Cenários
1. **Geração Concorrente**
   - 100 requisições simultâneas
   - Taxa de sucesso > 95%
   - Latência p95 < 45s

2. **Persistência Massiva**
   - 1000 artigos/hora
   - Sem perda de dados
   - IO < 200ms

3. **Backup Contínuo**
   - Backup a cada 6h
   - Tamanho < 1GB
   - Tempo < 5min

## Testes E2E

### Fluxos Principais
1. **Geração Completa**
   - Prompt → Geração → Persistência
   - Validação de conteúdo
   - Verificação de metadados

2. **Recuperação**
   - Busca → Carregamento → Validação
   - Verificação de integridade
   - Checagem de versões

## Observações
- Cobertura unitária ≥ 98%, integração ≥ 95%, carga ≥ 90%, E2E ≥ 85%
- Todos os testes devem ser idempotentes
- Logs de teste devem ser estruturados
- Métricas devem ser exportadas para monitoramento
- Testes de carga devem ser executados em ambiente isolado
- Cenários de falha devem simular condições reais
- Performance deve ser monitorada continuamente 