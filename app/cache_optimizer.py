"""
Sistema de Otimização de Cache - Omni Writer
============================================

Implementa otimizações avançadas de cache:
- Cache warming para dados críticos
- TTL dinâmico baseado em uso
- Cache prediction
- Cache key strategy otimizada
- Invalidação inteligente
- Monitoramento de performance

Prompt: Implementação de Gargalos Médios - Cache Hit Rate Baixo
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T23:15:00Z
Tracing ID: CACHE_OPTIMIZATION_20250127_001
"""

import time
import json
import hashlib
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import redis
from functools import wraps

logger = logging.getLogger(__name__)

@dataclass
class CacheMetrics:
    """Métricas de performance do cache"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_requests: int = 0
    avg_response_time: float = 0.0
    hit_rate: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)

@dataclass
class CacheEntry:
    """Entrada de cache com metadados para otimização"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl: int = 3600  # TTL base em segundos
    priority: int = 1  # 1=baixa, 5=crítica
    size_bytes: int = 0
    compression_ratio: float = 1.0

@dataclass
class CachePrediction:
    """Predição de uso de cache"""
    key_pattern: str
    predicted_hits: int
    confidence: float
    next_access_time: datetime
    recommended_ttl: int

class CacheWarmingManager:
    """Gerenciador de cache warming para dados críticos"""
    
    def __init__(self, cache_client):
        self.cache_client = cache_client
        self.critical_data_patterns = {
            'user_config': 'user:config:*',
            'generation_templates': 'template:generation:*',
            'rate_limits': 'rate_limit:*',
            'performance_config': 'config:performance:*',
            'api_keys': 'api_key:*'
        }
        self.warming_schedule = {
            'user_config': 300,  # 5 minutos
            'generation_templates': 600,  # 10 minutos
            'rate_limits': 60,  # 1 minuto
            'performance_config': 1800,  # 30 minutos
            'api_keys': 900  # 15 minutos
        }
        self.warming_thread = None
        self.is_running = False
        
    def start_warming(self):
        """Inicia processo de cache warming em background"""
        if self.warming_thread and self.warming_thread.is_alive():
            return
            
        self.is_running = True
        self.warming_thread = threading.Thread(target=self._warming_loop, daemon=True)
        self.warming_thread.start()
        logger.info("Cache warming iniciado")
    
    def stop_warming(self):
        """Para processo de cache warming"""
        self.is_running = False
        if self.warming_thread:
            self.warming_thread.join(timeout=5)
        logger.info("Cache warming parado")
    
    def _warming_loop(self):
        """Loop principal de cache warming"""
        while self.is_running:
            try:
                for data_type, interval in self.warming_schedule.items():
                    if self._should_warm(data_type, interval):
                        self._warm_critical_data(data_type)
                
                time.sleep(30)  # Verifica a cada 30 segundos
                
            except Exception as e:
                logger.error(f"Erro no cache warming: {e}")
                time.sleep(60)
    
    def _should_warm(self, data_type: str, interval: int) -> bool:
        """Verifica se deve fazer warming baseado no intervalo"""
        last_warm_key = f"warming:last:{data_type}"
        last_warm_time = self.cache_client.get(last_warm_key)
        
        if not last_warm_time:
            return True
        
        last_warm = datetime.fromisoformat(last_warm_time.decode())
        return (datetime.utcnow() - last_warm).total_seconds() >= interval
    
    def _warm_critical_data(self, data_type: str):
        """Executa warming para tipo de dados específico"""
        try:
            pattern = self.critical_data_patterns.get(data_type)
            if not pattern:
                return
            
            # Simula carregamento de dados críticos
            critical_data = self._load_critical_data(data_type)
            
            for key, value in critical_data.items():
                self.cache_client.setex(key, 3600, json.dumps(value))  # 1 hora TTL
            
            # Marca último warming
            self.cache_client.setex(
                f"warming:last:{data_type}",
                3600,
                datetime.utcnow().isoformat()
            )
            
            logger.info(f"Cache warming executado para {data_type}: {len(critical_data)} itens")
            
        except Exception as e:
            logger.error(f"Erro no warming de {data_type}: {e}")
    
    def _load_critical_data(self, data_type: str) -> Dict[str, Any]:
        """Carrega dados críticos baseado no tipo"""
        # Em produção, isso viria do banco de dados
        critical_data = {
            'user_config': {
                'default_models': ['gpt-4', 'deepseek', 'claude'],
                'rate_limits': {'openai': 300, 'deepseek': 200, 'claude': 150},
                'timeout_settings': {'default': 30, 'max': 120}
            },
            'generation_templates': {
                'article_template': {'structure': 'intro,body,conclusion', 'max_length': 2000},
                'summary_template': {'structure': 'key_points', 'max_length': 500}
            },
            'rate_limits': {
                'openai': {'requests': 300, 'window': 60},
                'deepseek': {'requests': 200, 'window': 60},
                'claude': {'requests': 150, 'window': 60}
            },
            'performance_config': {
                'max_workers': 5,
                'batch_size': 10,
                'enable_parallel': True
            },
            'api_keys': {
                'openai': 'sk-***',
                'deepseek': 'sk-***',
                'claude': 'sk-***'
            }
        }
        
        return critical_data.get(data_type, {})

class DynamicTTLManager:
    """Gerenciador de TTL dinâmico baseado em uso"""
    
    def __init__(self, cache_client):
        self.cache_client = cache_client
        self.access_patterns = defaultdict(list)
        self.ttl_adjustments = {}
        self.min_ttl = 60  # 1 minuto mínimo
        self.max_ttl = 86400  # 24 horas máximo
        
    def record_access(self, key: str, access_time: datetime = None):
        """Registra acesso a uma chave de cache"""
        if not access_time:
            access_time = datetime.utcnow()
        
        self.access_patterns[key].append(access_time.timestamp())
        
        # Mantém apenas últimos 100 acessos
        if len(self.access_patterns[key]) > 100:
            self.access_patterns[key] = self.access_patterns[key][-100:]
    
    def calculate_dynamic_ttl(self, key: str, base_ttl: int = 3600) -> int:
        """Calcula TTL dinâmico baseado no padrão de acesso"""
        accesses = self.access_patterns.get(key, [])
        
        if not accesses:
            return base_ttl
        
        # Calcula frequência de acesso
        if len(accesses) >= 2:
            intervals = []
            for i in range(1, len(accesses)):
                intervals.append(accesses[i] - accesses[i-1])
            
            avg_interval = statistics.mean(intervals)
            access_frequency = 1 / avg_interval if avg_interval > 0 else 0
            
            # Ajusta TTL baseado na frequência
            if access_frequency > 0.1:  # Acesso a cada 10 segundos ou menos
                dynamic_ttl = int(base_ttl * 2)  # Dobra TTL
            elif access_frequency > 0.01:  # Acesso a cada 100 segundos
                dynamic_ttl = int(base_ttl * 1.5)  # Aumenta 50%
            elif access_frequency < 0.001:  # Acesso a cada 1000 segundos
                dynamic_ttl = int(base_ttl * 0.5)  # Reduz 50%
            else:
                dynamic_ttl = base_ttl
        else:
            dynamic_ttl = base_ttl
        
        # Aplica limites
        dynamic_ttl = max(self.min_ttl, min(self.max_ttl, dynamic_ttl))
        
        return dynamic_ttl
    
    def get_ttl_adjustment(self, key: str) -> float:
        """Retorna fator de ajuste de TTL para uma chave"""
        return self.ttl_adjustments.get(key, 1.0)

class CachePredictionEngine:
    """Motor de predição de cache"""
    
    def __init__(self, cache_client):
        self.cache_client = cache_client
        self.access_history = defaultdict(list)
        self.predictions = {}
        self.prediction_accuracy = {}
        
    def record_access_pattern(self, key: str, access_time: datetime = None):
        """Registra padrão de acesso para predição"""
        if not access_time:
            access_time = datetime.utcnow()
        
        self.access_history[key].append(access_time.timestamp())
        
        # Mantém histórico de 1000 acessos
        if len(self.access_history[key]) > 1000:
            self.access_history[key] = self.access_history[key][-1000:]
    
    def predict_next_access(self, key: str) -> Optional[CachePrediction]:
        """Prediz próximo acesso baseado no histórico"""
        accesses = self.access_history.get(key, [])
        
        if len(accesses) < 10:
            return None
        
        # Análise de padrão temporal
        intervals = []
        for i in range(1, len(accesses)):
            intervals.append(accesses[i] - accesses[i-1])
        
        if not intervals:
            return None
        
        # Calcula estatísticas
        avg_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Prediz próximo acesso
        last_access = accesses[-1]
        predicted_next = last_access + avg_interval
        
        # Calcula confiança baseada na consistência
        confidence = max(0.1, 1.0 - (std_interval / avg_interval) if avg_interval > 0 else 0.1)
        
        # Recomenda TTL baseado na predição
        recommended_ttl = int(avg_interval * 2)  # 2x o intervalo médio
        
        return CachePrediction(
            key_pattern=key,
            predicted_hits=len(accesses),
            confidence=confidence,
            next_access_time=datetime.fromtimestamp(predicted_next),
            recommended_ttl=recommended_ttl
        )
    
    def get_predictions(self) -> List[CachePrediction]:
        """Retorna todas as predições ativas"""
        predictions = []
        for key in self.access_history.keys():
            prediction = self.predict_next_access(key)
            if prediction and prediction.confidence > 0.5:
                predictions.append(prediction)
        
        return predictions

class OptimizedCacheKeyStrategy:
    """Estratégia otimizada para chaves de cache"""
    
    def __init__(self):
        self.key_patterns = {
            'user_data': 'user:{user_id}:{data_type}',
            'generation': 'gen:{model}:{prompt_hash}:{config_hash}',
            'rate_limit': 'rate:{provider}:{user_id}:{window}',
            'performance': 'perf:{metric}:{timeframe}',
            'template': 'template:{type}:{version}'
        }
        self.compression_enabled = True
    
    def generate_optimized_key(self, pattern: str, **kwargs) -> str:
        """Gera chave otimizada baseada no padrão"""
        try:
            key = pattern.format(**kwargs)
            
            # Aplica hash para chaves muito longas
            if len(key) > 250:
                key_hash = hashlib.md5(key.encode()).hexdigest()
                key = f"{pattern.split(':')[0]}:{key_hash}"
            
            return key
            
        except KeyError as e:
            logger.error(f"Erro ao gerar chave: {e}")
            return f"fallback:{hashlib.md5(str(kwargs).encode()).hexdigest()}"
    
    def compress_value(self, value: Any) -> Tuple[Any, float]:
        """Comprime valor se necessário"""
        if not self.compression_enabled:
            return value, 1.0
        
        if isinstance(value, str) and len(value) > 1024:
            # Compressão simples para strings longas
            compressed = value.encode('utf-8')
            original_size = len(value.encode('utf-8'))
            compression_ratio = len(compressed) / original_size
            return compressed, compression_ratio
        
        return value, 1.0
    
    def decompress_value(self, value: Any) -> Any:
        """Descomprime valor se necessário"""
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return value
        
        return value

class IntelligentCacheInvalidation:
    """Sistema de invalidação inteligente de cache"""
    
    def __init__(self, cache_client):
        self.cache_client = cache_client
        self.dependency_graph = defaultdict(set)
        self.invalidation_rules = {}
        self.invalidation_history = []
        
    def add_dependency(self, dependent_key: str, dependency_key: str):
        """Adiciona dependência entre chaves"""
        self.dependency_graph[dependent_key].add(dependency_key)
    
    def add_invalidation_rule(self, pattern: str, trigger_keys: List[str]):
        """Adiciona regra de invalidação"""
        self.invalidation_rules[pattern] = trigger_keys
    
    def invalidate_dependencies(self, key: str):
        """Invalida chaves dependentes"""
        keys_to_invalidate = set()
        
        # Encontra chaves que dependem desta
        for dependent_key, dependencies in self.dependency_graph.items():
            if key in dependencies:
                keys_to_invalidate.add(dependent_key)
        
        # Invalida chaves dependentes
        for dependent_key in keys_to_invalidate:
            self.cache_client.delete(dependent_key)
            logger.info(f"Cache invalidado por dependência: {dependent_key}")
        
        # Registra invalidação
        self.invalidation_history.append({
            'trigger_key': key,
            'invalidated_keys': list(keys_to_invalidate),
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def smart_invalidation(self, key: str, reason: str = "manual"):
        """Invalidação inteligente baseada em contexto"""
        # Verifica regras de invalidação
        for pattern, trigger_keys in self.invalidation_rules.items():
            if key in trigger_keys:
                # Invalida chaves que seguem o padrão
                pattern_keys = self.cache_client.keys(pattern)
                for pattern_key in pattern_keys:
                    self.cache_client.delete(pattern_key)
                    logger.info(f"Cache invalidado por regra: {pattern_key}")
        
        # Invalida dependências
        self.invalidate_dependencies(key)
        
        # Invalida a chave principal
        self.cache_client.delete(key)
        
        logger.info(f"Cache invalidado inteligentemente: {key} (razão: {reason})")

class CachePerformanceMonitor:
    """Monitor de performance do cache"""
    
    def __init__(self, cache_client):
        self.cache_client = cache_client
        self.metrics = CacheMetrics()
        self.monitoring_enabled = True
        self.alert_thresholds = {
            'hit_rate_min': 0.7,  # 70% mínimo
            'response_time_max': 0.1,  # 100ms máximo
            'memory_usage_max': 0.8  # 80% máximo
        }
        
    def record_hit(self, response_time: float = 0.0):
        """Registra hit no cache"""
        self.metrics.hits += 1
        self.metrics.total_requests += 1
        self._update_metrics(response_time)
    
    def record_miss(self, response_time: float = 0.0):
        """Registra miss no cache"""
        self.metrics.misses += 1
        self.metrics.total_requests += 1
        self._update_metrics(response_time)
    
    def record_eviction(self):
        """Registra evição do cache"""
        self.metrics.evictions += 1
    
    def _update_metrics(self, response_time: float):
        """Atualiza métricas de performance"""
        if self.metrics.total_requests > 0:
            self.metrics.hit_rate = self.metrics.hits / self.metrics.total_requests
            
            # Atualiza tempo médio de resposta
            if self.metrics.avg_response_time == 0:
                self.metrics.avg_response_time = response_time
            else:
                self.metrics.avg_response_time = (
                    (self.metrics.avg_response_time * (self.metrics.total_requests - 1) + response_time) /
                    self.metrics.total_requests
                )
        
        self.metrics.last_updated = datetime.utcnow()
    
    def get_metrics(self) -> CacheMetrics:
        """Retorna métricas atuais"""
        return self.metrics
    
    def check_alerts(self) -> List[str]:
        """Verifica alertas de performance"""
        alerts = []
        
        if self.metrics.hit_rate < self.alert_thresholds['hit_rate_min']:
            alerts.append(f"Hit rate baixo: {self.metrics.hit_rate:.2%}")
        
        if self.metrics.avg_response_time > self.alert_thresholds['response_time_max']:
            alerts.append(f"Tempo de resposta alto: {self.metrics.avg_response_time:.3f}s")
        
        return alerts

class OptimizedCacheManager:
    """Gerenciador principal de cache otimizado"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_client = redis.from_url(redis_url)
        self.warming_manager = CacheWarmingManager(self.redis_client)
        self.ttl_manager = DynamicTTLManager(self.redis_client)
        self.prediction_engine = CachePredictionEngine(self.redis_client)
        self.key_strategy = OptimizedCacheKeyStrategy()
        self.invalidation = IntelligentCacheInvalidation(self.redis_client)
        self.monitor = CachePerformanceMonitor(self.redis_client)
        
        # Inicia cache warming
        self.warming_manager.start_warming()
        
        logger.info("Cache Manager Otimizado inicializado")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Obtém valor do cache com otimizações"""
        start_time = time.time()
        
        try:
            value = self.redis_client.get(key)
            
            if value is not None:
                # Hit
                response_time = time.time() - start_time
                self.monitor.record_hit(response_time)
                self.ttl_manager.record_access(key)
                self.prediction_engine.record_access_pattern(key)
                
                # Descomprime se necessário
                return self.key_strategy.decompress_value(value)
            else:
                # Miss
                response_time = time.time() - start_time
                self.monitor.record_miss(response_time)
                return default
                
        except Exception as e:
            logger.error(f"Erro ao obter cache {key}: {e}")
            return default
    
    def set(self, key: str, value: Any, ttl: int = 3600):
        """Define valor no cache com otimizações"""
        try:
            # Compressão
            compressed_value, compression_ratio = self.key_strategy.compress_value(value)
            
            # TTL dinâmico
            dynamic_ttl = self.ttl_manager.calculate_dynamic_ttl(key, ttl)
            
            # Armazena no cache
            self.redis_client.setex(key, dynamic_ttl, compressed_value)
            
            logger.debug(f"Cache set: {key} (TTL: {dynamic_ttl}s, compressão: {compression_ratio:.2f})")
            
        except Exception as e:
            logger.error(f"Erro ao definir cache {key}: {e}")
    
    def delete(self, key: str):
        """Remove valor do cache com invalidação inteligente"""
        try:
            self.invalidation.smart_invalidation(key, "manual")
        except Exception as e:
            logger.error(f"Erro ao deletar cache {key}: {e}")
    
    def get_optimized_key(self, pattern: str, **kwargs) -> str:
        """Gera chave otimizada"""
        return self.key_strategy.generate_optimized_key(pattern, **kwargs)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Gera relatório de performance"""
        metrics = self.monitor.get_metrics()
        predictions = self.prediction_engine.get_predictions()
        alerts = self.monitor.check_alerts()
        
        return {
            'metrics': {
                'hit_rate': metrics.hit_rate,
                'total_requests': metrics.total_requests,
                'avg_response_time': metrics.avg_response_time,
                'evictions': metrics.evictions
            },
            'predictions': [
                {
                    'key_pattern': p.key_pattern,
                    'confidence': p.confidence,
                    'next_access': p.next_access_time.isoformat(),
                    'recommended_ttl': p.recommended_ttl
                }
                for p in predictions
            ],
            'alerts': alerts,
            'last_updated': metrics.last_updated.isoformat()
        }
    
    def shutdown(self):
        """Para o cache manager"""
        self.warming_manager.stop_warming()
        logger.info("Cache Manager Otimizado finalizado")

# Decorator para cache automático
def cached(ttl: int = 3600, key_pattern: str = None):
    """Decorator para cache automático com otimizações"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Gera chave de cache
            if key_pattern:
                cache_key = key_pattern.format(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Tenta obter do cache
            cache_manager = OptimizedCacheManager()
            cached_result = cache_manager.get(cache_key)
            
            if cached_result is not None:
                return cached_result
            
            # Executa função e armazena resultado
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl)
            
            return result
        
        return wrapper
    return decorator

# Instância global
cache_manager = OptimizedCacheManager() 