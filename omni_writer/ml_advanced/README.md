# 🧠 Sistema ML Avançado - Omni Writer

## 📋 Visão Geral

O **Sistema ML Avançado** é um módulo completo que resolve os 3 principais desafios da geração de conteúdo:

1. **🔒 Não repetição** - Evita conteúdo duplicado usando embeddings e análise de similaridade
2. **👤 Humanização** - Cria conteúdo que soa natural e humano
3. **🧠 Aprendizado contínuo** - Melhora com cada geração baseado em feedback

## 🏗️ Arquitetura

```
omni_writer/ml_advanced/
├── content_optimizer.py      # Otimizador de conteúdo com ML
├── intelligent_generator.py  # Gerador inteligente com aprendizado
├── ml_integration.py         # Integração com sistema existente
├── __init__.py              # Interface pública do módulo
├── config.json              # Configurações do sistema
└── README.md                # Esta documentação
```

## 🚀 Instalação

### Dependências ML

```bash
pip install sentence-transformers scikit-learn nltk numpy pandas
```

### Verificação

```bash
python scripts/test_ml_advanced.py
```

## 📖 Uso Rápido

### 1. Otimização de Conteúdo

```python
from omni_writer.ml_advanced import quick_optimize

# Otimiza conteúdo existente
content = "Artificial intelligence is a technology..."
optimized, metrics = quick_optimize(content)

print(f"Score: {metrics['overall']:.2f}")
print(f"Unicidade: {metrics['uniqueness']:.2f}")
print(f"Humanização: {metrics['humanization']:.2f}")
```

### 2. Geração Inteligente

```python
from omni_writer.ml_advanced import quick_generate

# Gera conteúdo do zero
content = quick_generate(
    topic="machine learning",
    length=500,
    style="casual"
)
```

### 3. Sistema Completo

```python
from omni_writer.ml_advanced import MLIntegration, MLArticleRequest

# Inicializa sistema completo
ml_system = MLIntegration()

# Cria requisição
request = MLArticleRequest(
    topic="artificial intelligence in healthcare",
    target_length=800,
    style="casual",
    language="en",
    enable_optimization=True,
    enable_learning=True
)

# Gera artigo otimizado
response = ml_system.generate_article_with_ml(request)

print(f"Score: {response.quality_metrics['overall_score']:.2f}")
print(f"Conteúdo: {response.content}")
```

## 🔧 Componentes Principais

### ContentOptimizer

**Responsabilidades:**
- Análise de qualidade do conteúdo
- Detecção de repetição usando embeddings
- Otimização automática
- Sugestões de melhoria

**Métricas Analisadas:**
- 🔒 **Unicidade** - Evita repetição
- 👤 **Humanização** - Tom natural
- 📖 **Legibilidade** - Fácil compreensão
- 🔗 **Coerência** - Lógica entre sentenças
- 💡 **Criatividade** - Originalidade

### IntelligentGenerator

**Responsabilidades:**
- Geração de conteúdo do zero
- Templates de estilo (formal, casual, técnico, storytelling)
- Aplicação de padrões de sucesso
- Aprendizado contínuo

**Estilos Disponíveis:**
- 🎓 **Formal** - Acadêmico e profissional
- 😊 **Casual** - Conversacional e amigável
- ⚙️ **Técnico** - Preciso e detalhado
- 📖 **Storytelling** - Narrativo e envolvente

### MLIntegration

**Responsabilidades:**
- Integração com sistema existente
- Orquestração de componentes
- Fallback inteligente
- Histórico e estatísticas

## 📊 Métricas de Qualidade

### Score Geral
```
Score = (Unicidade × 0.25) + (Humanização × 0.25) + 
        (Legibilidade × 0.20) + (Coerência × 0.15) + 
        (Criatividade × 0.15)
```

### Unicidade
- **Alto (>0.8)**: Conteúdo único
- **Médio (0.6-0.8)**: Alguma similaridade
- **Baixo (<0.6)**: Muito similar ao existente

### Humanização
- **Alto (>0.8)**: Soa natural e humano
- **Médio (0.6-0.8)**: Moderadamente humano
- **Baixo (<0.6)**: Robótico ou formal demais

## 🧠 Aprendizado Contínuo

### Como Funciona

1. **Geração** → Conteúdo é criado
2. **Análise** → Métricas são calculadas
3. **Feedback** → Padrões são identificados
4. **Aprendizado** → Sistema melhora
5. **Aplicação** → Próximas gerações são melhores

### Padrões Aprendidos

- **Bem-sucedidos**: Pronomes pessoais, frases conversacionais, perguntas
- **Que falharam**: Conteúdo muito curto, vocabulário repetitivo, tom excessivamente formal

## ⚙️ Configuração

### Arquivo config.json

```json
{
  "ml_system": {
    "enabled": true,
    "model_name": "all-MiniLM-L6-v2"
  },
  "optimization": {
    "min_quality_score": 0.8,
    "similarity_threshold": 0.85
  },
  "generation": {
    "learning_enabled": true,
    "max_iterations": 5
  }
}
```

### Configurações Importantes

- **min_quality_score**: Score mínimo para aceitar conteúdo
- **similarity_threshold**: Limite para detectar repetição
- **max_iterations**: Máximo de tentativas de otimização
- **learning_enabled**: Habilita aprendizado contínuo

## 📈 Monitoramento

### Estatísticas Disponíveis

```python
# Estatísticas de integração
stats = ml_system.get_integration_stats(days=30)

print(f"Artigos gerados: {stats['total_articles']}")
print(f"Score médio: {stats['avg_quality_score']:.2f}")
print(f"Taxa de otimização: {stats['optimization_rate']:.2f}")
print(f"Taxa de aprendizado: {stats['learning_rate']:.2f}")
```

### Relatórios

```python
# Relatório do otimizador
optimizer = ContentOptimizer()
report = optimizer.generate_report(days=30)
print(report)
```

## 🔍 Debugging

### Logs Detalhados

```python
import logging
logging.getLogger('content_optimizer').setLevel(logging.DEBUG)
logging.getLogger('intelligent_generator').setLevel(logging.DEBUG)
logging.getLogger('ml_integration').setLevel(logging.DEBUG)
```

### Análise Manual

```python
# Analisa conteúdo sem otimizar
optimizer = ContentOptimizer()
analysis = optimizer.analyze_content(content)

print(f"Unicidade: {analysis.metrics.uniqueness_score}")
print(f"Humanização: {analysis.metrics.humanization_score}")
print(f"Keywords: {analysis.keywords}")
print(f"Tópicos: {analysis.topics}")
```

## 🚨 Troubleshooting

### Problemas Comuns

1. **ML libraries não disponíveis**
   ```bash
   pip install sentence-transformers scikit-learn nltk
   ```

2. **Modelo não carrega**
   - Verifique conexão com internet
   - Primeira execução baixa o modelo

3. **Performance lenta**
   - Reduza max_iterations
   - Use cache_enabled: true

4. **Qualidade baixa**
   - Ajuste min_quality_score
   - Verifique similarity_threshold

### Verificação de Saúde

```python
from omni_writer.ml_advanced import MLIntegration

ml_system = MLIntegration()
stats = ml_system.get_integration_stats()

if stats.get('avg_quality_score', 0) < 0.7:
    print("⚠️ Qualidade média baixa - verifique configurações")
```

## 🔮 Roadmap

### Próximas Funcionalidades

- [ ] **Fine-tuning** de modelos específicos
- [ ] **Análise de sentimento** avançada
- [ ] **Geração multimodal** (texto + imagens)
- [ ] **API REST** para integração externa
- [ ] **Dashboard** de métricas em tempo real
- [ ] **Aprendizado federado** para privacidade

### Melhorias Planejadas

- [ ] **Modelos multilíngues** nativos
- [ ] **Otimização de prompts** automática
- [ ] **Detecção de bias** e correção
- [ ] **Geração condicional** baseada em contexto
- [ ] **Integração com LLMs** externos

## 📞 Suporte

### Logs de Erro

```bash
tail -f logs/ml_advanced.log
```

### Testes Automatizados

```bash
python scripts/test_ml_advanced.py
```

### Métricas de Performance

```python
# Testa performance
from scripts.test_ml_advanced import test_performance
test_performance()
```

---

## 🎯 Resumo

O **Sistema ML Avançado** transforma o Omni Writer em uma plataforma de geração de conteúdo inteligente que:

✅ **Não repete** conteúdo existente  
✅ **Humaniza** automaticamente o tom  
✅ **Aprende** e melhora continuamente  
✅ **Integra** perfeitamente com o sistema existente  
✅ **Monitora** qualidade e performance  

**Resultado**: Conteúdo único, natural e cada vez melhor! 🚀 