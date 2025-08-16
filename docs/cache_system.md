# Sistema de Cache Inteligente - Omni Writer

## Visão Geral

O sistema de cache inteligente do Omni Writer é uma solução enterprise+ que combina múltiplas estratégias de cache, compressão, criptografia e métricas avançadas para otimizar o desempenho da aplicação.

## Arquitetura

### Componentes Principais

1. **CacheManager** - Gerenciador central que coordena todos os componentes
2. **IntelligentCache** - Cache Redis com fallback local
3. **Cache Strategies** - Estratégias específicas (LRU, LFU, FIFO, TTL)
4. **Cache Configuration** - Configurações centralizadas
5. **Compression & Encryption** - Processamento de dados

### Estrutura de Arquivos

```
shared/
├── cache_manager.py          # Gerenciador principal
├── cache_config.py           # Configurações
├── cache_strategies.py       # Estratégias de cache
└── intelligent_cache.py      # Cache Redis + local

tests/unit/shared/
├── test_cache_manager.py     # Testes do gerenciador
├── test_cache_strategies.py  # Testes das estratégias
└── test_intelligent_cache.py # Testes do cache inteligente
```

## Tipos de Cache

### CacheType Enum

```python
class CacheType(Enum):
    GENERATION_STATUS = "generation_status"  # Status de geração de artigos
    EXPORT_CACHE = "export_cache"           # Cache de exportações
    USER_PREFERENCES = "user_preferences"   # Preferências do usuário
    API_RESPONSES = "api_responses"         # Respostas de API
    METRICS = "metrics"                     # Métricas do sistema
    ARTICLE_CONTENT = "article_content"     # Conteúdo de artigos
    PROMPT_CACHE = "prompt_cache"           # Cache de prompts
```

### Configurações por Tipo

| Tipo | TTL | Estratégia | Tamanho | Compressão | Criptografia |
|------|-----|------------|---------|------------|--------------|
| GENERATION_STATUS | 1h | TTL | 100MB | ✅ | ❌ |
| EXPORT_CACHE | 2h | LRU | 500MB | ✅ | ❌ |
| USER_PREFERENCES | 24h | LRU | 50MB | ❌ | ✅ |
| API_RESPONSES | 30m | TTL | 200MB | ✅ | ❌ |
| METRICS | 5m | FIFO | 50MB | ❌ | ❌ |
| ARTICLE_CONTENT | 4h | LRU | 1GB | ✅ | ❌ |
| PROMPT_CACHE | 1h | LFU | 200MB | ❌ | ❌ |

## Estratégias de Cache

### LRU (Least Recently Used)
- Remove o item menos recentemente usado
- Ideal para dados com padrões de acesso variáveis
- Usado em: EXPORT_CACHE, USER_PREFERENCES, ARTICLE_CONTENT

### LFU (Least Frequently Used)
- Remove o item menos frequentemente usado
- Ideal para dados com padrões de acesso consistentes
- Usado em: PROMPT_CACHE

### FIFO (First In, First Out)
- Remove o primeiro item inserido
- Ideal para dados temporários
- Usado em: METRICS

### TTL (Time To Live)
- Remove itens baseado em tempo de expiração
- Ideal para dados com validade temporal
- Usado em: GENERATION_STATUS, API_RESPONSES

## Uso Básico

### Inicialização

```python
from shared.cache_manager import get_cache_manager, CacheType

# Obtém instância global
cache_manager = get_cache_manager()

# Ou cria nova instância
from shared.cache_manager import CacheManager
cache_manager = CacheManager(enable_metrics=True, enable_compression=True)
```

### Operações Básicas

```python
# Armazenar dados
success = cache_manager.set(
    CacheType.GENERATION_STATUS, 
    'trace-123', 
    {'status': 'processing', 'progress': 50}
)

# Obter dados
status = cache_manager.get(CacheType.GENERATION_STATUS, 'trace-123')
# Retorna: {'status': 'processing', 'progress': 50}

# Remover dados
success = cache_manager.delete(CacheType.GENERATION_STATUS, 'trace-123')

# Limpar todo o cache de um tipo
removed_count = cache_manager.clear(CacheType.GENERATION_STATUS)
```

### Funções Helper

```python
from shared.cache_manager import cache_get, cache_set, cache_delete

# Uso simplificado
cache_set(CacheType.EXPORT_CACHE, 'exp-123', {'file_path': '/path/to/file.zip'})
data = cache_get(CacheType.EXPORT_CACHE, 'exp-123')
cache_delete(CacheType.EXPORT_CACHE, 'exp-123')
```

## Uso Avançado

### Cache Warming

```python
# Aquecimento com dados frequentes
warm_data = {
    'user-123': {'theme': 'dark', 'language': 'pt-BR'},
    'user-456': {'theme': 'light', 'language': 'en-US'}
}

cache_manager.warm_cache(CacheType.USER_PREFERENCES, warm_data)
```

### Transações

```python
# Operações transacionais
with cache_manager.transaction(CacheType.GENERATION_STATUS) as cache:
    cache.set('trace-123', {'status': 'processing'})
    cache.set('trace-456', {'status': 'completed'})
    # Se houver erro, todas as operações são revertidas
```

### Métricas

```python
# Obter métricas detalhadas
metrics = cache_manager.get_metrics()

print(f"Hit Rate: {metrics['intelligent_cache']['hit_ratio']}%")
print(f"Total Operations: {metrics['operations']['total_operations']}")
print(f"Success Rate: {metrics['operations']['success_rate']}%")
```

## Configuração

### Variáveis de Ambiente

```bash
# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=10
REDIS_SOCKET_TIMEOUT=5
REDIS_RETRY_ON_TIMEOUT=true

# Cache por tipo
CACHE_GENERATION_STATUS_TTL=3600
CACHE_EXPORT_CACHE_STRATEGY=lru
CACHE_USER_PREFERENCES_MAX_SIZE=50

# Métricas
CACHE_ENABLE_METRICS=true
CACHE_HIT_RATE_THRESHOLD=0.8
CACHE_ALERT_ON_LOW_HIT_RATE=true
```

### Configuração Programática

```python
from shared.cache_config import CacheConfig, CacheStrategy

# Atualizar configuração
config = CacheConfig(
    ttl=7200,  # 2 horas
    strategy=CacheStrategy.LRU,
    max_size=200,  # 200MB
    compression=True,
    encryption=False,
    distributed=True
)

cache_config.update_config(CacheType.EXPORT_CACHE, config)
```

## Decorator de Cache

### Uso Básico

```python
from shared.intelligent_cache import cached

@cached('api_responses')
def fetch_user_data(user_id: str):
    # Função cara que busca dados do usuário
    return {'user_id': user_id, 'name': 'John Doe'}

# Primeira chamada executa a função
result1 = fetch_user_data('123')

# Segunda chamada usa cache
result2 = fetch_user_data('123')  # Não executa a função
```

### Uso Avançado

```python
def custom_key_func(user_id: str, include_private: bool = False):
    return f"user_{user_id}_{include_private}"

@cached('api_responses', key_func=custom_key_func, ttl=1800)
def fetch_user_data(user_id: str, include_private: bool = False):
    return {'user_id': user_id, 'private': include_private}

# Chaves diferentes para parâmetros diferentes
result1 = fetch_user_data('123', False)  # Cache key: user_123_False
result2 = fetch_user_data('123', True)   # Cache key: user_123_True
```

## Monitoramento e Métricas

### Métricas Disponíveis

```python
metrics = cache_manager.get_metrics()

# Cache Inteligente
intelligent_metrics = metrics['intelligent_cache']
print(f"Hits: {intelligent_metrics['hits']}")
print(f"Misses: {intelligent_metrics['misses']}")
print(f"Hit Ratio: {intelligent_metrics['hit_ratio']}%")

# Estratégias
strategy_metrics = metrics['strategies']
for cache_type, stats in strategy_metrics.items():
    print(f"{cache_type}: {stats['total_entries']} entries, "
          f"{stats['utilization_percent']:.1f}% utilization")

# Operações
operation_metrics = metrics['operations']
print(f"Total Operations: {operation_metrics['total_operations']}")
print(f"Success Rate: {operation_metrics['success_rate']}%")
print(f"Average Duration: {operation_metrics['avg_duration_ms']:.2f}ms")
```

### Alertas

O sistema pode configurar alertas para:
- Hit rate baixo (< 80%)
- Erros frequentes
- Cache cheio (> 90% de utilização)
- Latência alta (> 100ms)

## Performance e Otimização

### Compressão

- Automática para dados > 1KB
- Reduz uso de memória em até 70%
- Transparente para o usuário

### Criptografia

- Aplicada apenas em dados sensíveis
- Usuário preferências são criptografadas
- Chave configurável via ambiente

### Fallback

- Redis como cache principal
- Memória local como fallback
- Transparente para aplicação

## Troubleshooting

### Problemas Comuns

1. **Cache Miss Alto**
   ```python
   # Verificar configuração de TTL
   config = cache_config.get_config(CacheType.API_RESPONSES)
   print(f"TTL atual: {config.ttl} segundos")
   ```

2. **Memória Alta**
   ```python
   # Verificar utilização
   metrics = cache_manager.get_metrics()
   for cache_type, stats in metrics['strategies'].items():
       if stats['utilization_percent'] > 80:
           print(f"Cache {cache_type} com alta utilização")
   ```

3. **Latência Alta**
   ```python
   # Verificar métricas de operação
   operation_metrics = cache_manager.get_metrics()['operations']
   if operation_metrics['avg_duration_ms'] > 100:
       print("Latência de cache alta detectada")
   ```

### Logs

```python
import logging

# Configurar logging detalhado
logging.getLogger('shared.cache_manager').setLevel(logging.DEBUG)
logging.getLogger('shared.intelligent_cache').setLevel(logging.DEBUG)
```

## Testes

### Executar Testes

```bash
# Testes unitários
pytest tests/unit/shared/test_cache_manager.py -v
pytest tests/unit/shared/test_cache_strategies.py -v
pytest tests/unit/shared/test_intelligent_cache.py -v

# Testes com cobertura
pytest tests/unit/shared/ --cov=shared --cov-report=html
```

### Testes de Performance

```python
import time
from shared.cache_manager import get_cache_manager

cache_manager = get_cache_manager()

# Teste de throughput
start_time = time.time()
for i in range(1000):
    cache_manager.set(CacheType.API_RESPONSES, f'key_{i}', {'data': f'value_{i}'})

duration = time.time() - start_time
print(f"Throughput: {1000/duration:.0f} ops/sec")
```

## Roadmap

### Próximas Funcionalidades

1. **Cache Distribuído**
   - Suporte a múltiplos nós Redis
   - Sharding automático
   - Failover automático

2. **Cache Inteligente Avançado**
   - Análise semântica de prompts
   - TTL adaptativo
   - Prefetching inteligente

3. **Integração com Observabilidade**
   - Prometheus metrics
   - Grafana dashboards
   - Alertas automáticos

4. **Cache Persistente**
   - Backup automático
   - Restore em caso de falha
   - Migração de dados

## Contribuição

### Padrões de Código

- Seguir PEP 8
- Documentar todas as funções
- Incluir testes unitários
- Usar type hints

### Processo de Desenvolvimento

1. Criar branch para feature
2. Implementar funcionalidade
3. Adicionar testes
4. Atualizar documentação
5. Criar pull request

### Testes Obrigatórios

- Testes unitários para todas as funções
- Testes de integração para workflows
- Testes de performance para otimizações
- Cobertura mínima de 85% 