"""
Configuração do Cache Inteligente - Enterprise+ Implementation

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import os
from typing import Dict, Any
from dataclasses import dataclass
from enum import Enum


class CacheStrategy(Enum):
    """Estratégias de cache disponíveis"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL = "ttl"  # Time To Live


class CacheType(Enum):
    """Tipos de cache disponíveis"""
    GENERATION_STATUS = "generation_status"
    EXPORT_CACHE = "export_cache"
    USER_PREFERENCES = "user_preferences"
    API_RESPONSES = "api_responses"
    METRICS = "metrics"
    ARTICLE_CONTENT = "article_content"
    PROMPT_CACHE = "prompt_cache"


@dataclass
class CacheConfig:
    """Configuração de cache para um tipo específico"""
    ttl: int  # Time to live em segundos
    strategy: CacheStrategy
    max_size: int  # Tamanho máximo em MB
    compression: bool = False
    encryption: bool = False
    distributed: bool = True


class CacheConfiguration:
    """
    Gerenciador de configurações de cache.
    Centraliza todas as configurações de cache do sistema.
    """
    
    def __init__(self):
        self._configs: Dict[CacheType, CacheConfig] = self._load_default_configs()
        self._load_environment_configs()
    
    def _load_default_configs(self) -> Dict[CacheType, CacheConfig]:
        """Carrega configurações padrão"""
        return {
            CacheType.GENERATION_STATUS: CacheConfig(
                ttl=3600,  # 1 hora
                strategy=CacheStrategy.TTL,
                max_size=100,  # 100MB
                compression=True,
                encryption=False,
                distributed=True
            ),
            CacheType.EXPORT_CACHE: CacheConfig(
                ttl=7200,  # 2 horas
                strategy=CacheStrategy.LRU,
                max_size=500,  # 500MB
                compression=True,
                encryption=False,
                distributed=True
            ),
            CacheType.USER_PREFERENCES: CacheConfig(
                ttl=86400,  # 24 horas
                strategy=CacheStrategy.LRU,
                max_size=50,  # 50MB
                compression=False,
                encryption=True,
                distributed=True
            ),
            CacheType.API_RESPONSES: CacheConfig(
                ttl=1800,  # 30 minutos
                strategy=CacheStrategy.TTL,
                max_size=200,  # 200MB
                compression=True,
                encryption=False,
                distributed=True
            ),
            CacheType.METRICS: CacheConfig(
                ttl=300,  # 5 minutos
                strategy=CacheStrategy.FIFO,
                max_size=50,  # 50MB
                compression=False,
                encryption=False,
                distributed=True
            ),
            CacheType.ARTICLE_CONTENT: CacheConfig(
                ttl=14400,  # 4 horas
                strategy=CacheStrategy.LRU,
                max_size=1000,  # 1GB
                compression=True,
                encryption=False,
                distributed=True
            ),
            CacheType.PROMPT_CACHE: CacheConfig(
                ttl=3600,  # 1 hora
                strategy=CacheStrategy.LFU,
                max_size=200,  # 200MB
                compression=False,
                encryption=False,
                distributed=True
            )
        }
    
    def _load_environment_configs(self):
        """Carrega configurações do ambiente"""
        for cache_type in CacheType:
            env_prefix = f"CACHE_{cache_type.value.upper()}"
            
            # TTL do ambiente
            ttl_env = os.getenv(f"{env_prefix}_TTL")
            if ttl_env:
                try:
                    self._configs[cache_type].ttl = int(ttl_env)
                except ValueError:
                    pass
            
            # Estratégia do ambiente
            strategy_env = os.getenv(f"{env_prefix}_STRATEGY")
            if strategy_env:
                try:
                    self._configs[cache_type].strategy = CacheStrategy(strategy_env.lower())
                except ValueError:
                    pass
            
            # Tamanho máximo do ambiente
            max_size_env = os.getenv(f"{env_prefix}_MAX_SIZE")
            if max_size_env:
                try:
                    self._configs[cache_type].max_size = int(max_size_env)
                except ValueError:
                    pass
    
    def get_config(self, cache_type: CacheType) -> CacheConfig:
        """
        Obtém configuração para um tipo de cache.
        
        Args:
            cache_type: Tipo de cache
            
        Returns:
            CacheConfig: Configuração do cache
        """
        return self._configs.get(cache_type, self._configs[CacheType.API_RESPONSES])
    
    def update_config(self, cache_type: CacheType, config: CacheConfig):
        """
        Atualiza configuração de um tipo de cache.
        
        Args:
            cache_type: Tipo de cache
            config: Nova configuração
        """
        self._configs[cache_type] = config
    
    def get_all_configs(self) -> Dict[CacheType, CacheConfig]:
        """
        Obtém todas as configurações.
        
        Returns:
            Dict[CacheType, CacheConfig]: Todas as configurações
        """
        return self._configs.copy()
    
    def get_redis_config(self) -> Dict[str, Any]:
        """
        Obtém configuração do Redis.
        
        Returns:
            Dict[str, Any]: Configuração do Redis
        """
        return {
            'url': os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
            'max_connections': int(os.getenv('REDIS_MAX_CONNECTIONS', '10')),
            'socket_timeout': int(os.getenv('REDIS_SOCKET_TIMEOUT', '5')),
            'socket_connect_timeout': int(os.getenv('REDIS_SOCKET_CONNECT_TIMEOUT', '5')),
            'retry_on_timeout': os.getenv('REDIS_RETRY_ON_TIMEOUT', 'true').lower() == 'true',
            'health_check_interval': int(os.getenv('REDIS_HEALTH_CHECK_INTERVAL', '30')),
            'max_retries': int(os.getenv('REDIS_MAX_RETRIES', '3'))
        }
    
    def get_cache_stats_config(self) -> Dict[str, Any]:
        """
        Obtém configuração de estatísticas do cache.
        
        Returns:
            Dict[str, Any]: Configuração de estatísticas
        """
        return {
            'enable_metrics': os.getenv('CACHE_ENABLE_METRICS', 'true').lower() == 'true',
            'metrics_ttl': int(os.getenv('CACHE_METRICS_TTL', '300')),
            'hit_rate_threshold': float(os.getenv('CACHE_HIT_RATE_THRESHOLD', '0.8')),
            'alert_on_low_hit_rate': os.getenv('CACHE_ALERT_ON_LOW_HIT_RATE', 'true').lower() == 'true',
            'cleanup_interval': int(os.getenv('CACHE_CLEANUP_INTERVAL', '3600'))
        }


# Instância global da configuração
cache_config = CacheConfiguration()


def get_cache_config(cache_type: CacheType) -> CacheConfig:
    """
    Função helper para obter configuração de cache.
    
    Args:
        cache_type: Tipo de cache
        
    Returns:
        CacheConfig: Configuração do cache
    """
    return cache_config.get_config(cache_type)


def get_redis_config() -> Dict[str, Any]:
    """
    Função helper para obter configuração do Redis.
    
    Returns:
        Dict[str, Any]: Configuração do Redis
    """
    return cache_config.get_redis_config()


def get_cache_stats_config() -> Dict[str, Any]:
    """
    Função helper para obter configuração de estatísticas.
    
    Returns:
        Dict[str, Any]: Configuração de estatísticas
    """
    return cache_config.get_cache_stats_config() 