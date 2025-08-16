# MATRIZ DE CONFIABILIDADE - OMNİ WRİTER

## 📊 **METADADOS DA CLASSIFICAÇÃO**

- **EXEC_ID**: `{EXEC_ID}`
- **Data/Hora**: `{TIMESTAMP}`
- **Total de Jornadas**: `{TOTAL_JOURNEYS}`
- **Confiança Geral**: `{OVERALL_CONFIDENCE}%`

## 🎯 **RESUMO EXECUTIVO**

### **Distribuição de Confiabilidade**
- **✅ 100% Confiável**: `{FULLY_RELIABLE}` jornadas (`{FULLY_RELIABLE_PERCENT}%`)
- **⚠️ Parcialmente Confiável**: `{PARTIALLY_RELIABLE}` jornadas (`{PARTIALLY_RELIABLE_PERCENT}%`)
- **❌ Não Confiável**: `{NOT_RELIABLE}` jornadas (`{NOT_RELIABLE_PERCENT}%`)

### **Métricas Gerais**
- **Issues Críticas**: `{CRITICAL_ISSUES}`
- **Avisos**: `{WARNINGS}`
- **Recomendações**: `{RECOMMENDATIONS}`

## 📋 **MATRIZ DETALHADA POR JORNADA**

### **1. Geração de Artigos**
| Fator | Status | Score | Issues |
|-------|--------|-------|--------|
| **UX Validation** | `{ARTICLE_UX_STATUS}` | `{ARTICLE_UX_SCORE}%` | `{ARTICLE_UX_ISSUES}` |
| **Data Validation** | `{ARTICLE_DATA_STATUS}` | `{ARTICLE_DATA_SCORE}%` | `{ARTICLE_DATA_ISSUES}` |
| **Side Effects** | `{ARTICLE_SIDE_EFFECTS_STATUS}` | `{ARTICLE_SIDE_EFFECTS_SCORE}%` | `{ARTICLE_SIDE_EFFECTS_ISSUES}` |
| **Visual Validation** | `{ARTICLE_VISUAL_STATUS}` | `{ARTICLE_VISUAL_SCORE}%` | `{ARTICLE_VISUAL_ISSUES}` |
| **🔍 Confiabilidade Geral** | `{ARTICLE_OVERALL_RELIABILITY}` | `{ARTICLE_CONFIDENCE_SCORE}%` | `{ARTICLE_TOTAL_ISSUES}` |

### **2. CRUD de Blogs**
| Fator | Status | Score | Issues |
|-------|--------|-------|--------|
| **UX Validation** | `{BLOG_UX_STATUS}` | `{BLOG_UX_SCORE}%` | `{BLOG_UX_ISSUES}` |
| **Data Validation** | `{BLOG_DATA_STATUS}` | `{BLOG_DATA_SCORE}%` | `{BLOG_DATA_ISSUES}` |
| **Side Effects** | `{BLOG_SIDE_EFFECTS_STATUS}` | `{BLOG_SIDE_EFFECTS_SCORE}%` | `{BLOG_SIDE_EFFECTS_ISSUES}` |
| **Visual Validation** | `{BLOG_VISUAL_STATUS}` | `{BLOG_VISUAL_SCORE}%` | `{BLOG_VISUAL_ISSUES}` |
| **🔍 Confiabilidade Geral** | `{BLOG_OVERALL_RELIABILITY}` | `{BLOG_CONFIDENCE_SCORE}%` | `{BLOG_TOTAL_ISSUES}` |

### **3. Autenticação**
| Fator | Status | Score | Issues |
|-------|--------|-------|--------|
| **UX Validation** | `{AUTH_UX_STATUS}` | `{AUTH_UX_SCORE}%` | `{AUTH_UX_ISSUES}` |
| **Data Validation** | `{AUTH_DATA_STATUS}` | `{AUTH_DATA_SCORE}%` | `{AUTH_DATA_ISSUES}` |
| **Side Effects** | `{AUTH_SIDE_EFFECTS_STATUS}` | `{AUTH_SIDE_EFFECTS_SCORE}%` | `{AUTH_SIDE_EFFECTS_ISSUES}` |
| **Visual Validation** | `{AUTH_VISUAL_STATUS}` | `{AUTH_VISUAL_SCORE}%` | `{AUTH_VISUAL_ISSUES}` |
| **🔍 Confiabilidade Geral** | `{AUTH_OVERALL_RELIABILITY}` | `{AUTH_CONFIDENCE_SCORE}%` | `{AUTH_TOTAL_ISSUES}` |

### **4. Webhooks**
| Fator | Status | Score | Issues |
|-------|--------|-------|--------|
| **UX Validation** | `{WEBHOOK_UX_STATUS}` | `{WEBHOOK_UX_SCORE}%` | `{WEBHOOK_UX_ISSUES}` |
| **Data Validation** | `{WEBHOOK_DATA_STATUS}` | `{WEBHOOK_DATA_SCORE}%` | `{WEBHOOK_DATA_ISSUES}` |
| **Side Effects** | `{WEBHOOK_SIDE_EFFECTS_STATUS}` | `{WEBHOOK_SIDE_EFFECTS_SCORE}%` | `{WEBHOOK_SIDE_EFFECTS_ISSUES}` |
| **Visual Validation** | `{WEBHOOK_VISUAL_STATUS}` | `{WEBHOOK_VISUAL_SCORE}%` | `{WEBHOOK_VISUAL_ISSUES}` |
| **🔍 Confiabilidade Geral** | `{WEBHOOK_OVERALL_RELIABILITY}` | `{WEBHOOK_CONFIDENCE_SCORE}%` | `{WEBHOOK_TOTAL_ISSUES}` |

## 🔍 **ANÁLISE DETALHADA POR FATOR**

### **UX Validation**
- **DOM Validation**: Validação da estrutura do DOM
- **Visual Validation**: Validação de elementos visuais
- **Accessibility Validation**: Validação de acessibilidade
- **Interaction Validation**: Validação de interações
- **Navigation Validation**: Validação de navegação

**Thresholds**:
- ✅ **100% Confiável**: Score ≥ 95%
- ⚠️ **Parcialmente Confiável**: Score 80-94%
- ❌ **Não Confiável**: Score < 80%

### **Data Validation**
- **Persistence Validation**: Validação de persistência
- **Integrity Validation**: Validação de integridade
- **Consistency Validation**: Validação de consistência
- **Transaction Validation**: Validação de transações

**Thresholds**:
- ✅ **100% Confiável**: Score ≥ 95%
- ⚠️ **Parcialmente Confiável**: Score 90-94%
- ❌ **Não Confiável**: Score < 90%

### **Side Effects Validation**
- **Logs Validation**: Validação de logs
- **Notifications Validation**: Validação de notificações
- **Webhooks Validation**: Validação de webhooks
- **Cache Validation**: Validação de cache

**Thresholds**:
- ✅ **100% Confiável**: Score ≥ 90%
- ⚠️ **Parcialmente Confiável**: Score 70-89%
- ❌ **Não Confiável**: Score < 70%

### **Visual Validation**
- **Screenshot Comparison**: Comparação de screenshots
- **Accessibility Validation**: Validação visual de acessibilidade
- **Responsive Validation**: Validação de responsividade

**Thresholds**:
- ✅ **100% Confiável**: Score ≥ 90%
- ⚠️ **Parcialmente Confiável**: Score 80-89%
- ❌ **Não Confiável**: Score < 80%

## 🚨 **ISSUES CRÍTICAS**

### **Issues de UX**
{UX_CRITICAL_ISSUES}

### **Issues de Dados**
{DATA_CRITICAL_ISSUES}

### **Issues de Efeitos Colaterais**
{SIDE_EFFECTS_CRITICAL_ISSUES}

### **Issues Visuais**
{VISUAL_CRITICAL_ISSUES}

## 📈 **TENDÊNCIAS E ANÁLISE**

### **Evolução da Confiabilidade**
```
Período: {ANALYSIS_PERIOD}
Tendência: {TREND_DIRECTION}
Mudança: {CHANGE_PERCENTAGE}%
```

### **Fatores de Melhoria**
{IMPROVEMENT_FACTORS}

### **Fatores de Degradação**
{DEGRADATION_FACTORS}

## 🎯 **RECOMENDAÇÕES PRIORITÁRIAS**

### **Ações Imediatas (P1)**
{IMMEDIATE_ACTIONS}

### **Ações de Curto Prazo (P2)**
{SHORT_TERM_ACTIONS}

### **Ações de Médio Prazo (P3)**
{MEDIUM_TERM_ACTIONS}

## 📊 **MÉTRICAS DE QUALIDADE**

### **Distribuição de Scores**
- **90-100%**: `{SCORE_90_100}` jornadas
- **80-89%**: `{SCORE_80_89}` jornadas
- **70-79%**: `{SCORE_70_79}` jornadas
- **< 70%**: `{SCORE_BELOW_70}` jornadas

### **Análise por Categoria**
| Categoria | Média | Mediana | Desvio Padrão |
|-----------|-------|---------|---------------|
| **UX** | `{UX_AVERAGE}%` | `{UX_MEDIAN}%` | `{UX_STD_DEV}%` |
| **Dados** | `{DATA_AVERAGE}%` | `{DATA_MEDIAN}%` | `{DATA_STD_DEV}%` |
| **Efeitos Colaterais** | `{SIDE_EFFECTS_AVERAGE}%` | `{SIDE_EFFECTS_MEDIAN}%` | `{SIDE_EFFECTS_STD_DEV}%` |
| **Visual** | `{VISUAL_AVERAGE}%` | `{VISUAL_MEDIAN}%` | `{VISUAL_STD_DEV}%` |

## 🔄 **PLANO DE AÇÃO**

### **Sprint Atual**
{CURRENT_SPRINT_ACTIONS}

### **Próximo Sprint**
{NEXT_SPRINT_ACTIONS}

### **Sprint +2**
{FUTURE_SPRINT_ACTIONS}

## 📋 **CHECKLIST DE VALIDAÇÃO**

### **✅ Validações Aprovadas**
- [ ] 100% das jornadas com score ≥ 80%
- [ ] Zero jornadas com score < 70%
- [ ] Issues críticas resolvidas
- [ ] Recomendações implementadas
- [ ] Tendência de melhoria mantida

### **⚠️ Validações Pendentes**
{PENDING_VALIDATIONS}

### **❌ Validações Falharam**
{FAILED_VALIDATIONS}

---

## 📝 **LOGS DE CLASSIFICAÇÃO**

### **Logs de Execução**
```
{CLASSIFICATION_LOGS}
```

### **Logs de Issues**
```
{ISSUES_LOGS}
```

### **Logs de Recomendações**
```
{RECOMMENDATIONS_LOGS}
```

---

**Matriz gerada automaticamente pelo ReliabilityClassifier**  
**Versão**: 1.0  
**Data**: `{GENERATION_DATE}`  
**Responsável**: Sistema de Classificação de Confiabilidade 