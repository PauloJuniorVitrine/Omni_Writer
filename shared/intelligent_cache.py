#!/usr/bin/env python3
"""
Sistema de Cache Inteligente para Omni Writer.
Implementa cache Redis com estratégias avançadas de invalidação e métricas.
"""

import os
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
from functools import wraps
import logging

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

# Configuração de logging
cache_logger = logging.getLogger('intelligent_cache')
cache_logger.setLevel(logging.INFO)

class IntelligentCache:
    """
    Sistema de cache inteligente com Redis.
    
    Funcionalidades:
    - Cache de status de geração
    - Cache de exportações recentes
    - Invalidação automática baseada em TTL
    - Métricas de hit/miss ratio
    - Cache warming para dados frequentes
    - Fallback para memória local
    """
    
    def __init__(self, redis_url: Optional[str] = None, enable_metrics: bool = True):
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.enable_metrics = enable_metrics
        self.redis_client = None
        self.local_cache = {}  # Fallback local
        self.metrics = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'errors': 0
        }
        
        # Prefixos para organização
        self.prefixes = {
            'generation_status': 'gen:status:',
            'export_cache': 'export:',
            'user_preferences': 'user:pref:',
            'api_responses': 'api:',
            'metrics': 'metrics:'
        }
        
        # TTL padrão por tipo de dado
        self.default_ttl = {
            'generation_status': 3600,  # 1 hora
            'export_cache': 7200,       # 2 horas
            'user_preferences': 86400,  # 24 horas
            'api_responses': 1800,      # 30 minutos
            'metrics': 300              # 5 minutos
        }
        
        # Inicializa Redis
        self._init_redis()
    
    def _init_redis(self):
        """Inicializa conexão Redis com fallback."""
        if not REDIS_AVAILABLE:
            cache_logger.warning("Redis não disponível, usando cache local")
            return
        
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Testa conexão
            self.redis_client.ping()
            cache_logger.info("Cache Redis inicializado com sucesso")
            
        except Exception as e:
            cache_logger.error(f"Erro ao inicializar Redis: {e}")
            self.redis_client = None
    
    def _get_cache_key(self, prefix: str, key: str) -> str:
        """Gera chave de cache padronizada."""
        return f"{self.prefixes.get(prefix, 'cache:')}{key}"
    
    def _get_ttl(self, cache_type: str) -> int:
        """Obtém TTL para tipo de cache."""
        return self.default_ttl.get(cache_type, 3600)
    
    def get(self, prefix: str, key: str, default: Any = None) -> Any:
        """
        Obtém valor do cache.
        
        Args:
            prefix: Tipo de cache (generation_status, export_cache, etc.)
            key: Chave específica
            default: Valor padrão se não encontrado
        
        Returns:
            Valor do cache ou default
        """
        cache_key = self._get_cache_key(prefix, key)
        
        try:
            if self.redis_client:
                # Tenta Redis primeiro
                data = self.redis_client.get(cache_key)
                if data:
                    self._increment_metric('hits')
                    return json.loads(data)
                
                # Fallback para cache local
                if cache_key in self.local_cache:
                    self._increment_metric('hits')
                    return self.local_cache[cache_key]
                
            else:
                # Apenas cache local
                if cache_key in self.local_cache:
                    self._increment_metric('hits')
                    return self.local_cache[cache_key]
            
            self._increment_metric('misses')
            return default
            
        except Exception as e:
            cache_logger.error(f"Erro ao obter cache {cache_key}: {e}")
            self._increment_metric('errors')
            return default
    
    def set(self, prefix: str, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Armazena valor no cache.
        
        Args:
            prefix: Tipo de cache
            key: Chave específica
            value: Valor a armazenar
            ttl: TTL em segundos (opcional)
        
        Returns:
            True se armazenado com sucesso
        """
        cache_key = self._get_cache_key(prefix, key)
        ttl = ttl or self._get_ttl(prefix)
        
        try:
            # Armazena no Redis
            if self.redis_client:
                self.redis_client.setex(
                    cache_key,
                    ttl,
                    json.dumps(value, default=str)
                )
            
            # Fallback local
            self.local_cache[cache_key] = value
            
            self._increment_metric('sets')
            return True
            
        except Exception as e:
            cache_logger.error(f"Erro ao armazenar cache {cache_key}: {e}")
            self._increment_metric('errors')
            return False
    
    def delete(self, prefix: str, key: str) -> bool:
        """
        Remove valor do cache.
        
        Args:
            prefix: Tipo de cache
            key: Chave específica
        
        Returns:
            True se removido com sucesso
        """
        cache_key = self._get_cache_key(prefix, key)
        
        try:
            # Remove do Redis
            if self.redis_client:
                self.redis_client.delete(cache_key)
            
            # Remove do cache local
            self.local_cache.pop(cache_key, None)
            
            self._increment_metric('deletes')
            return True
            
        except Exception as e:
            cache_logger.error(f"Erro ao remover cache {cache_key}: {e}")
            self._increment_metric('errors')
            return False
    
    def clear_prefix(self, prefix: str) -> int:
        """
        Limpa todos os valores de um prefixo.
        
        Args:
            prefix: Prefixo a limpar
        
        Returns:
            Número de chaves removidas
        """
        try:
            pattern = self._get_cache_key(prefix, '*')
            removed_count = 0
            
            if self.redis_client:
                # Busca chaves no Redis
                keys = self.redis_client.keys(pattern)
                if keys:
                    removed_count += self.redis_client.delete(*keys)
            
            # Remove do cache local
            local_keys = [k for k in self.local_cache.keys() if k.startswith(self.prefixes.get(prefix, 'cache:'))]
            for key in local_keys:
                del self.local_cache[key]
                removed_count += 1
            
            return removed_count
            
        except Exception as e:
            cache_logger.error(f"Erro ao limpar prefixo {prefix}: {e}")
            return 0
    
    def get_generation_status(self, trace_id: str) -> Optional[Dict]:
        """
        Obtém status de geração do cache.
        
        Args:
            trace_id: ID de rastreamento
        
        Returns:
            Status da geração ou None
        """
        return self.get('generation_status', trace_id)
    
    def set_generation_status(self, trace_id: str, status: Dict, ttl: int = 3600) -> bool:
        """
        Armazena status de geração no cache.
        
        Args:
            trace_id: ID de rastreamento
            status: Status da geração
            ttl: TTL em segundos
        
        Returns:
            True se armazenado com sucesso
        """
        return self.set('generation_status', trace_id, status, ttl)
    
    def get_export_cache(self, export_id: str) -> Optional[Dict]:
        """
        Obtém cache de exportação.
        
        Args:
            export_id: ID da exportação
        
        Returns:
            Dados da exportação ou None
        """
        return self.get('export_cache', export_id)
    
    def set_export_cache(self, export_id: str, data: Dict, ttl: int = 7200) -> bool:
        """
        Armazena cache de exportação.
        
        Args:
            export_id: ID da exportação
            data: Dados da exportação
            ttl: TTL em segundos
        
        Returns:
            True se armazenado com sucesso
        """
        return self.set('export_cache', export_id, data, ttl)
    
    def get_metrics(self) -> Dict:
        """
        Obtém métricas de cache.
        
        Returns:
            Dicionário com métricas
        """
        if not self.enable_metrics:
            return {}
        
        total_requests = self.metrics['hits'] + self.metrics['misses']
        hit_ratio = (self.metrics['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.metrics['hits'],
            'misses': self.metrics['misses'],
            'sets': self.metrics['sets'],
            'deletes': self.metrics['deletes'],
            'errors': self.metrics['errors'],
            'hit_ratio': round(hit_ratio, 2),
            'total_requests': total_requests,
            'redis_available': self.redis_client is not None,
            'local_cache_size': len(self.local_cache)
        }
    
    def _increment_metric(self, metric: str):
        """Incrementa métrica específica."""
        if self.enable_metrics and metric in self.metrics:
            self.metrics[metric] += 1
    
    def warm_cache(self, cache_type: str, data: Dict[str, Any]):
        """
        Aquecimento de cache com dados frequentes.
        
        Args:
            cache_type: Tipo de cache
            data: Dados para aquecer
        """
        try:
            for key, value in data.items():
                self.set(cache_type, key, value)
            
            cache_logger.info(f"Cache {cache_type} aquecido com {len(data)} itens")
            
        except Exception as e:
            cache_logger.error(f"Erro ao aquecer cache {cache_type}: {e}")
    
    def invalidate_expired(self) -> int:
        """
        Remove itens expirados do cache local.
        
        Returns:
            Número de itens removidos
        """
        # Implementação simplificada - em produção usar TTL real
        return 0
    
    def get_cache_info(self) -> Dict:
        """
        Obtém informações do cache.
        
        Returns:
            Informações do cache
        """
        return {
            'redis_available': self.redis_client is not None,
            'local_cache_size': len(self.local_cache),
            'prefixes': list(self.prefixes.keys()),
            'default_ttl': self.default_ttl,
            'metrics_enabled': self.enable_metrics
        }

# Instância global
intelligent_cache = IntelligentCache()

# Decorator para cache automático
def cached(prefix: str, key_func=None, ttl: Optional[int] = None):
    """
    Decorator para cache automático de funções.
    
    Args:
        prefix: Tipo de cache
        key_func: Função para gerar chave (opcional)
        ttl: TTL em segundos (opcional)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Gera chave de cache
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Usa hash dos argumentos
                key_data = str(args) + str(sorted(kwargs.items()))
                cache_key = hashlib.md5(key_data.encode()).hexdigest()
            
            # Tenta obter do cache
            cached_result = intelligent_cache.get(prefix, cache_key)
            if cached_result is not None:
                return cached_result
            
            # Executa função e armazena resultado
            result = func(*args, **kwargs)
            intelligent_cache.set(prefix, cache_key, result, ttl)
            
            return result
        return wrapper
    return decorator 