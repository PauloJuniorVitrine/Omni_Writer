"""
Testes para Cache Manager Simplificado

Prompt: Testes para Simplificação - Seção 2.1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:45:00Z
Tracing ID: SIMPLIFICATION_TESTS_20250127_001

Testes baseados em código real para validar funcionalidades essenciais.
"""

import pytest
import time
from shared.cache_manager_simplified_v2 import (
    CacheManager, SimpleCache, CacheType, CacheConfig,
    get_cache_manager, cache_get, cache_set, cache_delete, cache_clear
)


class TestSimpleCache:
    """Testes para SimpleCache baseados em código real"""
    
    def test_cache_initialization(self):
        """Testa inicialização do cache"""
        cache = SimpleCache(max_size=100)
        assert cache.max_size == 100
        assert len(cache._cache) == 0
    
    def test_cache_set_and_get(self):
        """Testa operações básicas set/get"""
        cache = SimpleCache()
        
        # Testa set/get básico
        assert cache.set("test_key", "test_value") is True
        assert cache.get("test_key") == "test_value"
        assert cache.get("non_existent") is None
        assert cache.get("non_existent", "default") == "default"
    
    def test_cache_ttl(self):
        """Testa TTL do cache"""
        cache = SimpleCache()
        
        # Testa TTL de 1 segundo
        cache.set("ttl_key", "ttl_value", ttl=1)
        assert cache.get("ttl_key") == "ttl_value"
        
        # Aguarda expiração
        time.sleep(1.1)
        assert cache.get("ttl_key") is None
    
    def test_cache_delete(self):
        """Testa remoção de itens"""
        cache = SimpleCache()
        
        cache.set("delete_key", "delete_value")
        assert cache.get("delete_key") == "delete_value"
        
        assert cache.delete("delete_key") is True
        assert cache.get("delete_key") is None
        assert cache.delete("non_existent") is False
    
    def test_cache_clear(self):
        """Testa limpeza do cache"""
        cache = SimpleCache()
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert len(cache._cache) == 2
        
        count = cache.clear()
        assert count == 2
        assert len(cache._cache) == 0
    
    def test_cache_max_size(self):
        """Testa limite de tamanho do cache"""
        cache = SimpleCache(max_size=2)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        assert len(cache._cache) == 2
        
        # Adiciona terceiro item - deve remover o mais antigo
        cache.set("key3", "value3")
        assert len(cache._cache) == 2
        assert cache.get("key1") is None  # Removido
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"


class TestCacheManager:
    """Testes para CacheManager baseados em código real"""
    
    def test_cache_manager_initialization(self):
        """Testa inicialização do cache manager"""
        manager = CacheManager()
        assert len(manager.configs) == 3  # MEMORY, REDIS, DISK
        assert CacheType.MEMORY in manager.configs
        assert CacheType.REDIS in manager.configs
        assert CacheType.DISK in manager.configs
    
    def test_cache_manager_get_set(self):
        """Testa operações get/set do manager"""
        manager = CacheManager()
        
        # Testa operações básicas
        assert manager.set(CacheType.MEMORY, "test_key", "test_value") is True
        assert manager.get(CacheType.MEMORY, "test_key") == "test_value"
        assert manager.get(CacheType.MEMORY, "non_existent", "default") == "default"
    
    def test_cache_manager_delete(self):
        """Testa remoção de itens"""
        manager = CacheManager()
        
        manager.set(CacheType.MEMORY, "delete_key", "delete_value")
        assert manager.get(CacheType.MEMORY, "delete_key") == "delete_value"
        
        assert manager.delete(CacheType.MEMORY, "delete_key") is True
        assert manager.get(CacheType.MEMORY, "delete_key") is None
    
    def test_cache_manager_clear(self):
        """Testa limpeza de cache"""
        manager = CacheManager()
        
        manager.set(CacheType.MEMORY, "key1", "value1")
        manager.set(CacheType.MEMORY, "key2", "value2")
        
        count = manager.clear(CacheType.MEMORY)
        assert count == 2
        assert manager.get(CacheType.MEMORY, "key1") is None
    
    def test_cache_manager_clear_all(self):
        """Testa limpeza de todos os caches"""
        manager = CacheManager()
        
        manager.set(CacheType.MEMORY, "mem_key", "mem_value")
        manager.set(CacheType.REDIS, "redis_key", "redis_value")
        
        results = manager.clear_all()
        assert CacheType.MEMORY in results
        assert CacheType.REDIS in results
    
    def test_cache_manager_stats(self):
        """Testa estatísticas do manager"""
        manager = CacheManager()
        
        manager.set(CacheType.MEMORY, "key1", "value1")
        manager.set(CacheType.REDIS, "key2", "value2")
        
        stats = manager.get_stats()
        assert 'total_caches' in stats
        assert 'cache_types' in stats
        assert 'total_items' in stats
        assert stats['total_items'] >= 2


class TestCacheManagerGlobals:
    """Testes para funções globais do cache manager"""
    
    def test_get_cache_manager(self):
        """Testa obtenção do manager global"""
        manager = get_cache_manager()
        assert isinstance(manager, CacheManager)
    
    def test_cache_helper_functions(self):
        """Testa funções helper"""
        # Testa cache_set e cache_get
        assert cache_set(CacheType.MEMORY, "helper_key", "helper_value") is True
        assert cache_get(CacheType.MEMORY, "helper_key") == "helper_value"
        
        # Testa cache_delete
        assert cache_delete(CacheType.MEMORY, "helper_key") is True
        assert cache_get(CacheType.MEMORY, "helper_key") is None
        
        # Testa cache_clear
        cache_set(CacheType.MEMORY, "clear_key", "clear_value")
        count = cache_clear(CacheType.MEMORY)
        assert count == 1


class TestCacheConfigurations:
    """Testes para configurações de cache"""
    
    def test_cache_config_defaults(self):
        """Testa configurações padrão"""
        config = CacheConfig()
        assert config.max_size == 1000
        assert config.ttl == 3600
    
    def test_cache_config_custom(self):
        """Testa configurações customizadas"""
        config = CacheConfig(max_size=500, ttl=1800)
        assert config.max_size == 500
        assert config.ttl == 1800
    
    def test_cache_type_enum(self):
        """Testa enum de tipos de cache"""
        assert CacheType.MEMORY.value == "memory"
        assert CacheType.REDIS.value == "redis"
        assert CacheType.DISK.value == "disk" 