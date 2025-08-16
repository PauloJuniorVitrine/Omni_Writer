# 🚀 GUIA DE INÍCIO RÁPIDO - FRAMEWORK DE DETECÇÃO DE FLUXOS

## ⚡ Execução Rápida

### 1. Demonstração Automática
```bash
# Executa demonstração completa
python scripts/demo_flow_detection.py
```

### 2. Análise Manual de Logs
```python
from scripts.flow_detection_framework import FlowDetectionFramework

# Inicializa framework
framework = FlowDetectionFramework()

# Analisa logs estruturados
result = framework.analyze_logs("logs/structured_logs.json", "application_logs")

# Gera relatório
report = framework.generate_report()
print(f"Taxa de cobertura: {report['statistics']['coverage_rate']:.1f}%")
```

### 3. Execução de Testes
```bash
# Executa testes de integração
pytest tests/integration/test_flow_detection_framework.py -v
```

---

## 📊 O que o Framework Faz

### ✅ Detecta Automaticamente
- **Novos fluxos** não testados nos logs
- **Fluxos de alto risco** que precisam de testes prioritários
- **Padrões de uso** baseados em logs reais
- **Sugestões de teste** específicas e acionáveis

### 📈 Gera Relatórios
- **Estatísticas de cobertura** de testes
- **Lista de fluxos críticos** não testados
- **Ranking de fluxos** por frequência
- **Métricas de performance** e risco

---

## 🔍 Logs Analisados

### Fontes Suportadas
- ✅ `logs/structured_logs.json` - Logs estruturados em JSON
- ✅ `logs/pipeline_multi_diag.log` - Logs de pipeline multi-instância
- ✅ `logs/decisions_2025-01-27.log` - Logs de decisões de teste
- ✅ `logs/errors.log` - Logs de erro (quando disponível)

### Formatos Reconhecidos
```json
// Logs estruturados
{
  "timestamp": "2025-07-12T16:31:18.672042Z",
  "level": "INFO",
  "message": "Coletor de métricas inicializado",
  "service": "monitoring.metrics_collector",
  "endpoint": "/api/metrics/init",
  "request_id": "req-12345"
}
```

```
// Logs de pipeline
2025-05-03 20:35:33,130 INFO [DIAG] Iniciando pipeline multi | TESTING=None
2025-05-03 20:35:33,174 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0
```

---

## 🎯 Fluxos Identificados

### Fluxos Testados (Conhecidos)
| Fluxo | Risk Score | Status |
|-------|------------|--------|
| Geração de Artigos | 150 | ✅ Testado |
| CRUD de Blogs | 120 | ✅ Testado |
| Autenticação | 100 | ✅ Testado |
| Pagamentos | 140 | ✅ Testado |

### Fluxos Não Testados (Alto Risco)
| Fluxo | Risk Score | Status |
|-------|------------|--------|
| Geração Paralela | 130 | ❌ Não Testado |
| Retry Inteligente | 110 | ❌ Não Testado |

---

## 🧪 Sugestões de Teste Geradas

### Para `/generate`
- Implementar teste de geração com diferentes prompts
- Testar variações de temperatura e max_tokens
- Validar rate limiting e quotas

### Para `openai_gateway`
- Testar falhas de API (429, 500, 503)
- Validar circuit breaker
- Testar timeout e retry

### Para `stripe_gateway`
- Testar webhooks do Stripe
- Validar processamento de pagamentos
- Testar cenários de chargeback

---

## 📈 Interpretação dos Resultados

### Estatísticas Importantes
- **Taxa de Cobertura**: % de fluxos que possuem testes
- **Fluxos de Alto Risco**: Fluxos com risk score ≥ 100
- **Novos Fluxos**: Fluxos detectados pela primeira vez
- **Sugestões Geradas**: Número de sugestões de teste criadas

### Ações Recomendadas
1. **Priorizar fluxos** com risk score > 100
2. **Implementar testes** baseados nas sugestões
3. **Monitorar cobertura** regularmente
4. **Revisar relatórios** semanalmente

---

## 🔧 Configuração

### Arquivo de Configuração
```json
{
  "flow_detection_framework": {
    "version": "1.0",
    "tracing_id": "FLOW_DETECTION_CONFIG_20250127_001"
  },
  "risk_scoring": {
    "critical_endpoints": {
      "/generate": 30,
      "/payment": 30
    },
    "critical_services": {
      "openai_gateway": 25,
      "stripe_gateway": 25
    }
  }
}
```

### Localização
- **Configuração**: `tests/integration/flow_detection_config.json`
- **Banco de dados**: `tests/integration/flow_detection.db`
- **Relatórios**: `tests/integration/reports/`

---

## 🚨 Troubleshooting

### Problema: "Logs não encontrados"
```bash
# Verifica se arquivos existem
ls -la logs/structured_logs.json
ls -la logs/pipeline_multi_diag.log
```

### Problema: "Erro de configuração"
```bash
# Verifica arquivo de configuração
cat tests/integration/flow_detection_config.json
```

### Problema: "Banco de dados não inicializado"
```python
# Reinicializa framework
framework = FlowDetectionFramework()
# O banco é criado automaticamente
```

---

## 📞 Suporte

### Documentação Completa
- **Documentação técnica**: `docs/flow_detection_framework.md`
- **Resumo da implementação**: `docs/FLOW_DETECTION_IMPLEMENTATION_SUMMARY.md`
- **Testes**: `tests/integration/test_flow_detection_framework.py`

### Logs e Debugging
```python
import logging
logging.getLogger('scripts.flow_detection_framework').setLevel(logging.DEBUG)
```

### Tracing IDs
- **Framework**: `FLOW_DETECTION_FRAMEWORK_20250127_001`
- **Testes**: `FLOW_DETECTION_TEST_20250127_001`
- **Demo**: `FLOW_DETECTION_DEMO_20250127_001`

---

## ✅ Checklist de Uso

- [ ] **Executar demonstração**: `python scripts/demo_flow_detection.py`
- [ ] **Verificar logs**: Confirmar que arquivos de log existem
- [ ] **Analisar resultados**: Revisar relatório gerado
- [ ] **Priorizar fluxos**: Identificar fluxos de alto risco
- [ ] **Implementar testes**: Baseado nas sugestões geradas
- [ ] **Monitorar cobertura**: Acompanhar taxa de cobertura
- [ ] **Revisar periodicamente**: Executar análise regularmente

---

## 🎯 Próximos Passos

1. **Executar demonstração** para ver o framework em ação
2. **Revisar relatório** gerado automaticamente
3. **Identificar fluxos críticos** não testados
4. **Implementar testes** baseados nas sugestões
5. **Integrar ao pipeline** de CI/CD existente
6. **Configurar alertas** para fluxos de alto risco

---

*Guia de início rápido - Framework de Detecção de Fluxos v1.0*  
*Tracing ID: QUICK_START_20250127_001* 