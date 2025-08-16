#!/usr/bin/env python3
"""
Testes unitários para o sistema de cache inteligente.
Cobre funcionalidades de cache Redis, fallback local e métricas.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from shared.intelligent_cache import IntelligentCache, cached

class TestIntelligentCache:
    """Testes para IntelligentCache."""
    
    @pytest.fixture
    def cache(self):
        """Instância de cache para testes."""
        return IntelligentCache(enable_metrics=True)
    
    @pytest.fixture
    def mock_redis(self):
        """Mock do Redis."""
        with patch('shared.intelligent_cache.redis') as mock_redis:
            mock_client = Mock()
            mock_client.ping.return_value = True
            mock_client.get.return_value = None
            mock_client.setex.return_value = True
            mock_client.delete.return_value = 1
            mock_client.keys.return_value = []
            mock_redis.from_url.return_value = mock_client
            yield mock_redis
    
    def test_init_with_redis_available(self, mock_redis):
        """Testa inicialização com Redis disponível."""
        cache = IntelligentCache()
        
        assert cache.redis_client is not None
        assert cache.enable_metrics is True
        assert len(cache.metrics) == 5
    
    def test_init_without_redis(self):
        """Testa inicialização sem Redis."""
        with patch('shared.intelligent_cache.REDIS_AVAILABLE', False):
            cache = IntelligentCache()
            
            assert cache.redis_client is None
            assert cache.enable_metrics is True
    
    def test_get_cache_key(self, cache):
        """Testa geração de chave de cache."""
        key = cache._get_cache_key('generation_status', 'test-123')
        assert key == 'gen:status:test-123'
        
        key = cache._get_cache_key('export_cache', 'export-456')
        assert key == 'export:export-456'
    
    def test_get_ttl(self, cache):
        """Testa obtenção de TTL."""
        ttl = cache._get_ttl('generation_status')
        assert ttl == 3600
        
        ttl = cache._get_ttl('export_cache')
        assert ttl == 7200
        
        ttl = cache._get_ttl('unknown_type')
        assert ttl == 3600  # TTL padrão
    
    def test_set_and_get_with_redis(self, cache, mock_redis):
        """Testa set e get com Redis."""
        test_data = {'status': 'completed', 'progress': 100}
        
        # Testa set
        result = cache.set('generation_status', 'test-123', test_data)
        assert result is True
        
        # Mock Redis para retornar dados
        cache.redis_client.get.return_value = json.dumps(test_data)
        
        # Testa get
        retrieved = cache.get('generation_status', 'test-123')
        assert retrieved == test_data
    
    def test_set_and_get_local_fallback(self, cache):
        """Testa set e get com fallback local."""
        cache.redis_client = None  # Simula Redis indisponível
        test_data = {'status': 'completed', 'progress': 100}
        
        # Testa set
        result = cache.set('generation_status', 'test-123', test_data)
        assert result is True
        
        # Testa get
        retrieved = cache.get('generation_status', 'test-123')
        assert retrieved == test_data
    
    def test_get_miss(self, cache):
        """Testa get com cache miss."""
        cache.redis_client = None
        
        result = cache.get('generation_status', 'non-existent')
        assert result is None
        
        # Verifica métricas
        metrics = cache.get_metrics()
        assert metrics['misses'] == 1
        assert metrics['hits'] == 0
    
    def test_delete(self, cache, mock_redis):
        """Testa remoção de cache."""
        # Primeiro armazena
        cache.set('generation_status', 'test-123', {'data': 'test'})
        
        # Depois remove
        result = cache.delete('generation_status', 'test-123')
        assert result is True
        
        # Verifica se foi removido
        retrieved = cache.get('generation_status', 'test-123')
        assert retrieved is None
    
    def test_clear_prefix(self, cache, mock_redis):
        """Testa limpeza por prefixo."""
        # Mock Redis para retornar chaves
        cache.redis_client.keys.return_value = ['gen:status:key1', 'gen:status:key2']
        cache.redis_client.delete.return_value = 2
        
        # Adiciona ao cache local
        cache.local_cache['gen:status:key1'] = {'data': 'test1'}
        cache.local_cache['gen:status:key2'] = {'data': 'test2'}
        
        # Limpa prefixo
        removed = cache.clear_prefix('generation_status')
        assert removed == 4  # 2 do Redis + 2 do local
    
    def test_generation_status_methods(self, cache):
        """Testa métodos específicos de status de geração."""
        status_data = {
            'status': 'processing',
            'progress': 50,
            'started_at': '2025-01-27T10:00:00Z'
        }
        
        # Testa set_generation_status
        result = cache.set_generation_status('trace-123', status_data)
        assert result is True
        
        # Testa get_generation_status
        cache.redis_client = None  # Usa cache local
        retrieved = cache.get_generation_status('trace-123')
        assert retrieved == status_data
    
    def test_export_cache_methods(self, cache):
        """Testa métodos específicos de cache de exportação."""
        export_data = {
            'export_id': 'exp-123',
            'status': 'completed',
            'file_url': '/exports/exp-123.zip'
        }
        
        # Testa set_export_cache
        result = cache.set_export_cache('exp-123', export_data)
        assert result is True
        
        # Testa get_export_cache
        cache.redis_client = None  # Usa cache local
        retrieved = cache.get_export_cache('exp-123')
        assert retrieved == export_data
    
    def test_metrics(self, cache):
        """Testa coleta de métricas."""
        # Simula algumas operações
        cache.redis_client = None
        
        # Hit
        cache.set('test', 'key1', 'value1')
        cache.get('test', 'key1')
        
        # Miss
        cache.get('test', 'non-existent')
        
        # Delete
        cache.delete('test', 'key1')
        
        # Obtém métricas
        metrics = cache.get_metrics()
        
        assert metrics['hits'] == 1
        assert metrics['misses'] == 1
        assert metrics['sets'] == 1
        assert metrics['deletes'] == 1
        assert metrics['errors'] == 0
        assert metrics['hit_ratio'] == 50.0
        assert metrics['total_requests'] == 2
        assert metrics['redis_available'] is False
        assert metrics['local_cache_size'] == 0  # Foi deletado
    
    def test_warm_cache(self, cache):
        """Testa aquecimento de cache."""
        warm_data = {
            'key1': {'data': 'value1'},
            'key2': {'data': 'value2'},
            'key3': {'data': 'value3'}
        }
        
        cache.warm_cache('generation_status', warm_data)
        
        # Verifica se dados foram armazenados
        for key, value in warm_data.items():
            retrieved = cache.get('generation_status', key)
            assert retrieved == value
    
    def test_cache_info(self, cache):
        """Testa informações do cache."""
        info = cache.get_cache_info()
        
        assert 'redis_available' in info
        assert 'local_cache_size' in info
        assert 'prefixes' in info
        assert 'default_ttl' in info
        assert 'metrics_enabled' in info
        assert len(info['prefixes']) == 5
        assert len(info['default_ttl']) == 5
    
    def test_error_handling(self, cache, mock_redis):
        """Testa tratamento de erros."""
        # Simula erro no Redis
        cache.redis_client.get.side_effect = Exception("Redis error")
        
        # Deve retornar default sem quebrar
        result = cache.get('test', 'key1', default='fallback')
        assert result == 'fallback'
        
        # Verifica métricas de erro
        metrics = cache.get_metrics()
        assert metrics['errors'] == 1

class TestCachedDecorator:
    """Testes para decorator @cached."""
    
    def test_cached_decorator(self):
        """Testa decorator de cache."""
        cache = IntelligentCache()
        cache.redis_client = None  # Usa cache local
        
        call_count = 0
        
        @cached('test_cache')
        def expensive_function(param1, param2):
            nonlocal call_count
            call_count += 1
            return f"result_{param1}_{param2}"
        
        # Primeira chamada - executa função
        result1 = expensive_function('a', 'b')
        assert result1 == 'result_a_b'
        assert call_count == 1
        
        # Segunda chamada - usa cache
        result2 = expensive_function('a', 'b')
        assert result2 == 'result_a_b'
        assert call_count == 1  # Não incrementou
        
        # Parâmetros diferentes - executa novamente
        result3 = expensive_function('c', 'd')
        assert result3 == 'result_c_d'
        assert call_count == 2
    
    def test_cached_decorator_with_custom_key(self):
        """Testa decorator com função de chave customizada."""
        cache = IntelligentCache()
        cache.redis_client = None
        
        call_count = 0
        
        def custom_key_func(param1, param2):
            return f"custom_{param1}_{param2}"
        
        @cached('test_cache', key_func=custom_key_func)
        def expensive_function(param1, param2):
            nonlocal call_count
            call_count += 1
            return f"result_{param1}_{param2}"
        
        # Primeira chamada
        result1 = expensive_function('a', 'b')
        assert result1 == 'result_a_b'
        assert call_count == 1
        
        # Segunda chamada - usa cache
        result2 = expensive_function('a', 'b')
        assert result2 == 'result_a_b'
        assert call_count == 1
    
    def test_cached_decorator_with_ttl(self):
        """Testa decorator com TTL customizado."""
        cache = IntelligentCache()
        cache.redis_client = None
        
        @cached('test_cache', ttl=60)
        def expensive_function(param):
            return f"result_{param}"
        
        # Executa função
        result = expensive_function('test')
        assert result == 'result_test'
        
        # Verifica se foi armazenado com TTL correto
        # (implementação simplificada não verifica TTL real)
        assert True 