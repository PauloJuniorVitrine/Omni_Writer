# RELATÓRIO SHADOW TESTING - OMNİ WRİTER

## 📊 **METADADOS DA EXECUÇÃO**

- **EXEC_ID**: `{EXEC_ID}`
- **Data/Hora**: `{TIMESTAMP}`
- **Ambiente Produção**: `{PROD_URL}`
- **Ambiente Canary**: `{CANARY_URL}`
- **Threshold de Similaridade**: `{SIMILARITY_THRESHOLD}`
- **Tempo de Execução**: `{EXECUTION_TIME}ms`

## 🎯 **RESUMO EXECUTIVO**

### **Status Geral**
- **Total de Testes**: `{TOTAL_TESTS}`
- **Testes Aprovados**: `{PASSED_TESTS}`
- **Testes Falharam**: `{FAILED_TESTS}`
- **Taxa de Sucesso**: `{SUCCESS_RATE}%`

### **Classificação de Confiabilidade**
- **✅ 100% Confiável**: `{FULLY_RELIABLE}`
- **⚠️ Parcialmente Confiável**: `{PARTIALLY_RELIABLE}`
- **❌ Não Confiável**: `{NOT_RELIABLE}`

## 🔍 **ANÁLISE DETALHADA POR JORNADA**

### **1. Geração de Artigos**
- **Status**: `{ARTICLE_GENERATION_STATUS}`
- **Similaridade Semântica**: `{ARTICLE_SEMANTIC_SIMILARITY}`
- **Diferença de Performance**: `{ARTICLE_PERFORMANCE_DIFF}ms`
- **Consistência de Schema**: `{ARTICLE_SCHEMA_CONSISTENCY}`
- **Issues Encontradas**: `{ARTICLE_ISSUES_COUNT}`

### **2. CRUD de Blogs**
- **Status**: `{BLOG_CRUD_STATUS}`
- **Similaridade DOM**: `{BLOG_DOM_SIMILARITY}`
- **Consistência de Dados**: `{BLOG_DATA_CONSISTENCY}`
- **Tempo de Resposta**: `{BLOG_RESPONSE_TIME}ms`
- **Issues Encontradas**: `{BLOG_ISSUES_COUNT}`

### **3. Autenticação**
- **Status**: `{AUTH_STATUS}`
- **Comportamento Consistente**: `{AUTH_BEHAVIOR_CONSISTENCY}`
- **Diferença de Tempo**: `{AUTH_TIME_DIFF}ms`
- **Validação de Token**: `{AUTH_TOKEN_VALIDATION}`
- **Issues Encontradas**: `{AUTH_ISSUES_COUNT}`

### **4. Webhooks**
- **Status**: `{WEBHOOK_STATUS}`
- **Similaridade de Schema**: `{WEBHOOK_SCHEMA_SIMILARITY}`
- **Consistência de Payload**: `{WEBHOOK_PAYLOAD_CONSISTENCY}`
- **Registro de Eventos**: `{WEBHOOK_EVENT_REGISTRATION}`
- **Issues Encontradas**: `{WEBHOOK_ISSUES_COUNT}`

## 📈 **MÉTRICAS DE PERFORMANCE**

### **Comparação de Tempos de Resposta**
| Endpoint | Produção | Canary | Diferença | Status |
|----------|----------|--------|-----------|--------|
| Geração de Artigos | `{PROD_ARTICLE_TIME}ms` | `{CANARY_ARTICLE_TIME}ms` | `{ARTICLE_TIME_DIFF}ms` | `{ARTICLE_TIME_STATUS}` |
| CRUD de Blogs | `{PROD_BLOG_TIME}ms` | `{CANARY_BLOG_TIME}ms` | `{BLOG_TIME_DIFF}ms` | `{BLOG_TIME_STATUS}` |
| Autenticação | `{PROD_AUTH_TIME}ms` | `{CANARY_AUTH_TIME}ms` | `{AUTH_TIME_DIFF}ms` | `{AUTH_TIME_STATUS}` |
| Webhooks | `{PROD_WEBHOOK_TIME}ms` | `{CANARY_WEBHOOK_TIME}ms` | `{WEBHOOK_TIME_DIFF}ms` | `{WEBHOOK_TIME_STATUS}` |

### **Thresholds de Performance**
- **Threshold de Diferença**: `{PERFORMANCE_THRESHOLD}ms`
- **Threshold de Similaridade**: `{SIMILARITY_THRESHOLD}`
- **Threshold de Schema**: `{SCHEMA_THRESHOLD}`

## 🔧 **ANÁLISE DE SCHEMA**

### **Comparação de Estruturas**
```json
{
  "article_generation": {
    "prod_schema": "{PROD_ARTICLE_SCHEMA}",
    "canary_schema": "{CANARY_ARTICLE_SCHEMA}",
    "similarity": "{ARTICLE_SCHEMA_SIMILARITY}",
    "differences": "{ARTICLE_SCHEMA_DIFFERENCES}"
  },
  "blog_crud": {
    "prod_schema": "{PROD_BLOG_SCHEMA}",
    "canary_schema": "{CANARY_BLOG_SCHEMA}",
    "similarity": "{BLOG_SCHEMA_SIMILARITY}",
    "differences": "{BLOG_SCHEMA_DIFFERENCES}"
  },
  "authentication": {
    "prod_schema": "{PROD_AUTH_SCHEMA}",
    "canary_schema": "{CANARY_AUTH_SCHEMA}",
    "similarity": "{AUTH_SCHEMA_SIMILARITY}",
    "differences": "{AUTH_SCHEMA_DIFFERENCES}"
  },
  "webhooks": {
    "prod_schema": "{PROD_WEBHOOK_SCHEMA}",
    "canary_schema": "{CANARY_WEBHOOK_SCHEMA}",
    "similarity": "{WEBHOOK_SCHEMA_SIMILARITY}",
    "differences": "{WEBHOOK_SCHEMA_DIFFERENCES}"
  }
}
```

## 🚨 **ISSUES E RECOMENDAÇÕES**

### **Issues Críticas**
{CRITICAL_ISSUES}

### **Issues de Performance**
{PERFORMANCE_ISSUES}

### **Issues de Schema**
{SCHEMA_ISSUES}

### **Recomendações**
{RECOMMENDATIONS}

## 📋 **VALIDATION CHECKLIST**

### **✅ Validações Aprovadas**
- [ ] Similaridade semântica ≥ 0.90
- [ ] Diferença de performance < 1000ms
- [ ] Consistência de schema ≥ 0.95
- [ ] Status codes idênticos
- [ ] Tempos de resposta similares
- [ ] Zero testes sintéticos/genéricos
- [ ] 100% baseado em código real

### **⚠️ Validações com Avisos**
{WARNING_VALIDATIONS}

### **❌ Validações Falharam**
{FAILED_VALIDATIONS}

## 🎯 **PRÓXIMOS PASSOS**

### **Ações Imediatas**
{IMMEDIATE_ACTIONS}

### **Melhorias Planejadas**
{PLANNED_IMPROVEMENTS}

### **Monitoramento Contínuo**
{CONTINUOUS_MONITORING}

---

## 📝 **LOGS DETALHADOS**

### **Logs de Execução**
```
{EXECUTION_LOGS}
```

### **Logs de Erro**
```
{ERROR_LOGS}
```

### **Logs de Performance**
```
{PERFORMANCE_LOGS}
```

---

**Relatório gerado automaticamente pelo ShadowValidator**  
**Versão**: 1.0  
**Data**: `{GENERATION_DATE}`  
**Responsável**: Sistema de Shadow Testing 