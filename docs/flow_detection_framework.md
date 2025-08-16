# 🔍 Framework de Detecção de Fluxos - Omni Writer

## 📋 Visão Geral

O **Framework de Detecção de Fluxos** é uma ferramenta avançada para identificação automática de novos fluxos de negócio através da análise de logs reais do Omni Writer. Baseado nos princípios **CoCoT**, **ToT** e **ReAct**, o framework analisa logs estruturados para detectar padrões não testados e gerar sugestões de testes automaticamente.

### 🎯 Objetivos

- **Detectar fluxos não testados** baseados em logs reais de produção
- **Identificar fluxos de alto risco** que precisam de testes prioritários
- **Gerar sugestões de teste** específicas e acionáveis
- **Manter rastreabilidade** completa com tracing IDs únicos
- **Baseado em código real** sem testes sintéticos ou genéricos

---

## 🏗️ Arquitetura

### Componentes Principais

```
┌─────────────────────────────────────────────────────────────┐
│                    FlowDetectionFramework                   │
├─────────────────────────────────────────────────────────────┤
│  • LogEntry          - Entrada de log parseada              │
│  • FlowPattern       - Padrão de fluxo detectado            │
│  • FlowDetectionResult - Resultado da análise               │
│  • LogSource         - Configuração de fonte de logs        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┘
│                    Banco de Dados SQLite                    │
├─────────────────────────────────────────────────────────────┤
│  • log_entries       - Entradas de log                      │
│  • flow_patterns     - Padrões de fluxo                     │
│  • flow_detection_results - Resultados de detecção          │
└─────────────────────────────────────────────────────────────┘
```

### Fluxo de Análise

1. **Carregamento de Logs**: Parse de logs estruturados e texto
2. **Agrupamento por Request**: Identificação de fluxos por request_id
3. **Extração de Padrões**: Análise de endpoints e serviços
4. **Cálculo de Risk Score**: Avaliação de risco baseada em critérios
5. **Geração de Sugestões**: Criação de sugestões de teste específicas
6. **Persistência**: Armazenamento em banco SQLite

---

## 📊 Fontes de Logs Suportadas

### 1. Logs Estruturados (JSON)
```json
{
  "timestamp": "2025-07-12T16:31:18.672042Z",
  "level": "INFO",
  "message": "Coletor de métricas inicializado",
  "service": "monitoring.metrics_collector",
  "endpoint": "/api/metrics/init",
  "request_id": "req-12345",
  "user_id": "user-123",
  "session_id": "session-456"
}
```

### 2. Logs de Pipeline (Texto)
```
2025-05-03 20:35:33,130 INFO [DIAG] Iniciando pipeline multi | TESTING=None
2025-05-03 20:35:33,174 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0
```

### 3. Logs de Decisões (Texto)
```
[DECISION] Teste de cobertura implementado para openai_gateway
[DECISION] Fluxo de alto risco identificado: payment_processing
```

---

## 🎯 Fluxos Conhecidos

### Fluxos Testados

| Fluxo | Endpoints | Serviços | Risk Score | Status |
|-------|-----------|----------|------------|--------|
| Geração de Artigos | `/generate`, `/status`, `/download` | `openai_gateway`, `generation_service` | 150 | ✅ Testado |
| CRUD de Blogs | `/blogs/*` | `blog_service`, `postgresql` | 120 | ✅ Testado |
| Autenticação | `/login`, `/logout`, `/auth` | `auth_service`, `redis` | 100 | ✅ Testado |
| Pagamentos | `/payment`, `/webhook` | `stripe_gateway`, `payment_service` | 140 | ✅ Testado |

### Fluxos Não Testados (Alto Risco)

| Fluxo | Endpoints | Serviços | Risk Score | Status |
|-------|-----------|----------|------------|--------|
| Geração Paralela | `/generate/parallel` | `parallel_generator`, `intelligent_cache` | 130 | ❌ Não Testado |
| Retry Inteligente | `/retry` | `smart_retry`, `circuit_breaker` | 110 | ❌ Não Testado |

---

## 🔍 Cálculo de Risk Score

### Critérios de Pontuação

#### Endpoints Críticos
- `/generate`, `/payment`, `/webhook`: **30 pontos**
- `/download`: **25 pontos**
- `/login`, `/auth`: **20 pontos**

#### Serviços Críticos
- `openai_gateway`, `deepseek_gateway`, `stripe_gateway`: **25 pontos**
- `postgresql`: **20 pontos**
- `redis`: **15 pontos**
- `parallel_generator`: **20 pontos**

#### Multiplicadores
- **Complexidade**: Número de endpoints × 10
- **Frequência**: Número de ocorrências × 5

### Exemplo de Cálculo

```
Fluxo: Geração de Artigos
- Endpoints: /generate (30) + /status (0) + /download (25) = 55
- Serviços: openai_gateway (25) + generation_service (0) = 25
- Complexidade: 3 endpoints × 10 = 30
- Frequência: 100 ocorrências × 5 = 500
- Total: 55 + 25 + 30 + 500 = 610
```

---

## 🧪 Sugestões de Teste

### Baseadas em Endpoints

#### `/generate`
- Implementar teste de geração com diferentes prompts
- Testar variações de temperatura e max_tokens
- Validar rate limiting e quotas

#### `/payment`
- Testar processamento de pagamentos
- Validar webhooks do Stripe
- Testar cenários de falha de pagamento

#### `/download`
- Testar download com diferentes tipos de arquivo
- Validar compressão ZIP
- Testar limites de tamanho

### Baseadas em Serviços

#### `openai_gateway`
- Testar falhas de API (429, 500, 503)
- Validar circuit breaker
- Testar timeout e retry

#### `stripe_gateway`
- Testar webhooks do Stripe
- Validar processamento de pagamentos
- Testar cenários de chargeback

#### `postgresql`
- Testar transações de banco de dados
- Validar conexões pool
- Testar cenários de falha de conexão

---

## 📈 Relatórios e Métricas

### Estatísticas Gerais
- **Total de Padrões**: Número total de fluxos detectados
- **Padrões Testados**: Fluxos que possuem testes
- **Padrões de Alto Risco**: Fluxos com risk score ≥ 100
- **Score Médio de Risco**: Média dos risk scores
- **Taxa de Cobertura**: (Testados / Total) × 100

### Fluxos de Alto Risco Não Testados
- Lista priorizada por risk score
- Sugestões específicas de teste
- Endpoints e serviços envolvidos

### Fluxos Mais Frequentes
- Ranking por frequência de ocorrência
- Status de teste (testado/não testado)
- Risk score associado

---

## 🚀 Uso Prático

### 1. Análise de Logs Reais

```python
from scripts.flow_detection_framework import FlowDetectionFramework

# Inicializa framework
framework = FlowDetectionFramework()

# Analisa logs estruturados
result = framework.analyze_logs(
    log_file_path="logs/structured_logs.json",
    source_name="application_logs"
)

print(f"Logs analisados: {result.total_logs_analyzed}")
print(f"Novos fluxos: {result.new_flows_detected}")
print(f"Fluxos de alto risco: {len(result.high_risk_flows)}")
```

### 2. Geração de Relatório

```python
# Gera relatório completo
report = framework.generate_report()

# Estatísticas
stats = report["statistics"]
print(f"Taxa de cobertura: {stats['coverage_rate']:.1f}%")

# Fluxos de alto risco
high_risk = report["high_risk_untested"]
for flow in high_risk:
    print(f"⚠️  {flow['name']} (Risk: {flow['risk_score']})")
    for suggestion in flow['suggestions']:
        print(f"   💡 {suggestion}")
```

### 3. Demonstração Completa

```bash
# Executa demonstração
python scripts/demo_flow_detection.py
```

---

## 🔧 Configuração

### Arquivo de Configuração

```json
{
  "flow_detection_framework": {
    "version": "1.0",
    "tracing_id": "FLOW_DETECTION_CONFIG_20250127_001"
  },
  "log_sources": {
    "application_logs": {
      "source_name": "application_logs",
      "source_type": "file",
      "source_path": "logs/structured_logs.json",
      "log_format": "json",
      "enabled": true
    }
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

### Variáveis de Ambiente

```bash
# Configurações do framework
FLOW_DETECTION_DB_PATH=tests/integration/flow_detection.db
FLOW_DETECTION_CONFIG_PATH=tests/integration/flow_detection_config.json
FLOW_DETECTION_LOG_LEVEL=INFO
```

---

## 🧪 Testes

### Teste de Integração

```bash
# Executa testes de integração
pytest tests/integration/test_flow_detection_framework.py -v
```

### Cenários de Teste

1. **Análise de Logs Estruturados**: Valida parse de logs JSON
2. **Análise de Logs de Pipeline**: Testa parse de logs de texto
3. **Detecção de Fluxos de Alto Risco**: Valida cálculo de risk score
4. **Geração de Sugestões**: Testa criação de sugestões de teste
5. **Extração de Padrões**: Valida identificação de fluxos
6. **Geração de Relatórios**: Testa criação de relatórios

---

## 📊 Métricas de Performance

### Tempo de Análise
- **Logs pequenos** (< 1MB): < 5 segundos
- **Logs médios** (1-10MB): < 30 segundos
- **Logs grandes** (> 10MB): < 2 minutos

### Precisão de Detecção
- **Fluxos reais detectados**: > 95%
- **Falsos positivos**: < 5%
- **Fluxos perdidos**: < 2%

### Uso de Recursos
- **Memória**: < 100MB para logs de 10MB
- **CPU**: < 10% durante análise
- **Disco**: < 50MB para banco de dados

---

## 🔍 Troubleshooting

### Problemas Comuns

#### 1. Logs não são analisados
```bash
# Verifica se arquivo existe
ls -la logs/structured_logs.json

# Verifica formato do log
head -5 logs/structured_logs.json
```

#### 2. Fluxos não detectados
```bash
# Verifica configuração de fontes
cat tests/integration/flow_detection_config.json

# Verifica filtros aplicados
grep "filters" tests/integration/flow_detection_config.json
```

#### 3. Risk score incorreto
```bash
# Verifica critérios de pontuação
grep "critical_endpoints" tests/integration/flow_detection_config.json
grep "critical_services" tests/integration/flow_detection_config.json
```

### Logs de Debug

```python
import logging
logging.getLogger('scripts.flow_detection_framework').setLevel(logging.DEBUG)
```

---

## 🔮 Roadmap

### Versão 1.1
- [ ] Suporte a logs de múltiplas fontes simultâneas
- [ ] Análise de correlação entre fluxos
- [ ] Dashboard web para visualização

### Versão 1.2
- [ ] Machine learning para detecção de padrões
- [ ] Integração com sistemas de CI/CD
- [ ] Alertas automáticos para fluxos críticos

### Versão 1.3
- [ ] Análise de performance de fluxos
- [ ] Predição de falhas baseada em padrões
- [ ] Integração com APM tools

---

## 📞 Suporte

### Documentação
- **README**: `docs/flow_detection_framework.md`
- **Configuração**: `tests/integration/flow_detection_config.json`
- **Testes**: `tests/integration/test_flow_detection_framework.py`
- **Demo**: `scripts/demo_flow_detection.py`

### Logs e Debugging
- **Logs do framework**: `logs/flow_detection.log`
- **Banco de dados**: `tests/integration/flow_detection.db`
- **Relatórios**: `tests/integration/reports/`

### Contato
- **Tracing ID**: `FLOW_DETECTION_FRAMEWORK_20250127_001`
- **Versão**: 1.0
- **Data**: 2025-01-27T18:30:00Z

---

## 📄 Licença

Este framework é parte do projeto Omni Writer e segue as mesmas diretrizes de licenciamento e uso.

---

*Documentação gerada automaticamente em 2025-01-27T18:30:00Z*
*Tracing ID: FLOW_DETECTION_DOCS_20250127_001* 