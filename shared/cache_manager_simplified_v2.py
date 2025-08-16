"""
Cache Manager Simplificado - Versão 2.0

Prompt: Simplificação de Complexidade - Seção 2.1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:30:00Z
Tracing ID: SIMPLIFICATION_20250127_001

Redução de 515 linhas para ~200 linhas mantendo apenas funcionalidades essenciais.
"""

import time
import logging
from typing import Any, Dict, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CacheType(Enum):
    """Tipos de cache simplificados"""
    MEMORY = "memory"
    REDIS = "redis"
    DISK = "disk"


@dataclass
class CacheConfig:
    """Configuração simplificada de cache"""
    max_size: int = 1000
    ttl: int = 3600  # 1 hora


class SimpleCache:
    """Cache em memória simplificado"""
    
    def __init__(self, max_size: int = 1000):
        self._cache: Dict[str, tuple] = {}  # key -> (value, expiry_time)
        self.max_size = max_size
        self._cleanup_expired()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Obtém valor do cache"""
        if key in self._cache:
            value, expiry = self._cache[key]
            if expiry is None or time.time() < expiry:
                return value
            else:
                del self._cache[key]
        return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Define valor no cache"""
        if len(self._cache) >= self.max_size:
            self._evict_oldest()
        
        expiry = None
        if ttl:
            expiry = time.time() + ttl
        
        self._cache[key] = (value, expiry)
        return True
    
    def delete(self, key: str) -> bool:
        """Remove valor do cache"""
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    def clear(self) -> int:
        """Limpa todo o cache"""
        count = len(self._cache)
        self._cache.clear()
        return count
    
    def _evict_oldest(self):
        """Remove item mais antigo"""
        if self._cache:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
    
    def _cleanup_expired(self):
        """Remove itens expirados"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, expiry) in self._cache.items()
            if expiry and current_time >= expiry
        ]
        for key in expired_keys:
            del self._cache[key]


class CacheManager:
    """
    Gerenciador de cache simplificado.
    
    Funcionalidades essenciais:
    - Cache em memória com TTL
    - Operações básicas (get, set, delete, clear)
    - Configuração por tipo
    - Logging básico
    """
    
    def __init__(self):
        self.caches: Dict[CacheType, SimpleCache] = {}
        self.configs: Dict[CacheType, CacheConfig] = {}
        self._initialize_default_configs()
        logger.info("CacheManager simplificado inicializado")
    
    def _initialize_default_configs(self):
        """Inicializa configurações padrão"""
        self.configs[CacheType.MEMORY] = CacheConfig(1000, 3600)
        self.configs[CacheType.REDIS] = CacheConfig(5000, 7200)
        self.configs[CacheType.DISK] = CacheConfig(10000, 86400)
    
    def _get_cache(self, cache_type: CacheType) -> SimpleCache:
        """Obtém ou cria cache para o tipo especificado"""
        if cache_type not in self.caches:
            config = self.configs[cache_type]
            self.caches[cache_type] = SimpleCache(config.max_size)
        return self.caches[cache_type]
    
    def get(self, cache_type: CacheType, key: str, default: Any = None) -> Any:
        """Obtém valor do cache"""
        cache = self._get_cache(cache_type)
        config = self.configs[cache_type]
        return cache.get(key, default)
    
    def set(self, cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Define valor no cache"""
        cache = self._get_cache(cache_type)
        config = self.configs[cache_type]
        actual_ttl = ttl or config.ttl
        return cache.set(key, value, actual_ttl)
    
    def delete(self, cache_type: CacheType, key: str) -> bool:
        """Remove valor do cache"""
        cache = self._get_cache(cache_type)
        return cache.delete(key)
    
    def clear(self, cache_type: CacheType) -> int:
        """Limpa cache do tipo especificado"""
        cache = self._get_cache(cache_type)
        return cache.clear()
    
    def clear_all(self) -> Dict[CacheType, int]:
        """Limpa todos os caches"""
        results = {}
        for cache_type in self.caches:
            results[cache_type] = self.clear(cache_type)
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas básicas"""
        stats = {
            'total_caches': len(self.caches),
            'cache_types': list(self.caches.keys()),
            'total_items': sum(len(cache._cache) for cache in self.caches.values())
        }
        return stats


# Instância global
_cache_manager = CacheManager()


def get_cache_manager() -> CacheManager:
    """Obtém instância global do cache manager"""
    return _cache_manager


# Funções helper para uso direto
def cache_get(cache_type: CacheType, key: str, default: Any = None) -> Any:
    """Helper para obter valor do cache"""
    return _cache_manager.get(cache_type, key, default)


def cache_set(cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """Helper para definir valor no cache"""
    return _cache_manager.set(cache_type, key, value, ttl)


def cache_delete(cache_type: CacheType, key: str) -> bool:
    """Helper para remover valor do cache"""
    return _cache_manager.delete(cache_type, key)


def cache_clear(cache_type: CacheType) -> int:
    """Helper para limpar cache"""
    return _cache_manager.clear(cache_type)


def get_cache_stats() -> Dict[str, Any]:
    """Helper para obter estatísticas do cache"""
    return _cache_manager.get_stats() 