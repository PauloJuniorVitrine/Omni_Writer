"""
Testes unitários para IntelligentCache - Baseados em código real

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from shared.intelligent_cache import IntelligentCache


class TestIntelligentCache:
    """Testes unitários para IntelligentCache"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.cache = IntelligentCache(redis_url='redis://localhost:6379/0')
        self.sample_data = {
            'trace_id': 'test-123',
            'status': 'processing',
            'progress': 50,
            'message': 'Gerando artigos...'
        }
    
    def test_cache_initialization(self):
        """Testa inicialização do cache"""
        cache = IntelligentCache()
        assert cache is not None
        assert hasattr(cache, 'redis_client')
        assert hasattr(cache, 'local_cache')
        assert hasattr(cache, 'metrics')
    
    def test_cache_initialization_with_custom_redis_url(self):
        """Testa inicialização com URL Redis customizada"""
        custom_url = 'redis://custom-host:6379/1'
        cache = IntelligentCache(redis_url=custom_url)
        assert cache.redis_url == custom_url
    
    def test_cache_initialization_without_redis(self):
        """Testa inicialização sem Redis disponível"""
        with patch('shared.intelligent_cache.REDIS_AVAILABLE', False):
            cache = IntelligentCache()
            assert cache.redis_client is None
            assert len(cache.local_cache) == 0
    
    def test_get_cache_key_generation(self):
        """Testa geração de chaves de cache"""
        key = self.cache._get_cache_key('generation_status', 'test-123')
        assert key == 'gen:status:test-123'
        
        key = self.cache._get_cache_key('export_cache', 'export-456')
        assert key == 'export:export-456'
        
        key = self.cache._get_cache_key('unknown', 'test')
        assert key == 'cache:test'
    
    def test_get_ttl_for_cache_type(self):
        """Testa obtenção de TTL por tipo de cache"""
        ttl = self.cache._get_ttl('generation_status')
        assert ttl == 3600  # 1 hora
        
        ttl = self.cache._get_ttl('export_cache')
        assert ttl == 7200  # 2 horas
        
        ttl = self.cache._get_ttl('unknown_type')
        assert ttl == 3600  # TTL padrão
    
    @patch('shared.intelligent_cache.redis')
    def test_get_with_redis_available(self, mock_redis):
        """Testa obtenção de dados com Redis disponível"""
        # Mock do Redis
        mock_redis_client = Mock()
        mock_redis.from_url.return_value = mock_redis_client
        mock_redis_client.get.return_value = json.dumps(self.sample_data)
        
        cache = IntelligentCache()
        cache.redis_client = mock_redis_client
        
        result = cache.get('generation_status', 'test-123')
        
        assert result == self.sample_data
        assert cache.metrics['hits'] == 1
        assert cache.metrics['misses'] == 0
        mock_redis_client.get.assert_called_once_with('gen:status:test-123')
    
    def test_get_with_redis_unavailable_fallback_to_local(self):
        """Testa fallback para cache local quando Redis não disponível"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona dados ao cache local
        cache.local_cache['gen:status:test-123'] = self.sample_data
        
        result = cache.get('generation_status', 'test-123')
        
        assert result == self.sample_data
        assert cache.metrics['hits'] == 1
        assert cache.metrics['misses'] == 0
    
    def test_get_cache_miss(self):
        """Testa cache miss"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        result = cache.get('generation_status', 'non-existent')
        
        assert result is None
        assert cache.metrics['hits'] == 0
        assert cache.metrics['misses'] == 1
    
    def test_get_with_default_value(self):
        """Testa obtenção com valor padrão"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        default_value = {'status': 'not_found'}
        result = cache.get('generation_status', 'non-existent', default=default_value)
        
        assert result == default_value
        assert cache.metrics['misses'] == 1
    
    @patch('shared.intelligent_cache.redis')
    def test_set_with_redis_available(self, mock_redis):
        """Testa armazenamento com Redis disponível"""
        # Mock do Redis
        mock_redis_client = Mock()
        mock_redis.from_url.return_value = mock_redis_client
        
        cache = IntelligentCache()
        cache.redis_client = mock_redis_client
        
        success = cache.set('generation_status', 'test-123', self.sample_data)
        
        assert success is True
        assert cache.metrics['sets'] == 1
        assert cache.metrics['errors'] == 0
        mock_redis_client.setex.assert_called_once()
        
        # Verifica se também foi armazenado localmente
        assert 'gen:status:test-123' in cache.local_cache
    
    def test_set_with_redis_unavailable(self):
        """Testa armazenamento sem Redis disponível"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        success = cache.set('generation_status', 'test-123', self.sample_data)
        
        assert success is True
        assert cache.metrics['sets'] == 1
        assert 'gen:status:test-123' in cache.local_cache
    
    def test_set_with_custom_ttl(self):
        """Testa armazenamento com TTL customizado"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        custom_ttl = 1800  # 30 minutos
        success = cache.set('generation_status', 'test-123', self.sample_data, ttl=custom_ttl)
        
        assert success is True
        assert cache.metrics['sets'] == 1
    
    @patch('shared.intelligent_cache.redis')
    def test_delete_with_redis_available(self, mock_redis):
        """Testa remoção com Redis disponível"""
        # Mock do Redis
        mock_redis_client = Mock()
        mock_redis.from_url.return_value = mock_redis_client
        
        cache = IntelligentCache()
        cache.redis_client = mock_redis_client
        
        # Adiciona dados primeiro
        cache.local_cache['gen:status:test-123'] = self.sample_data
        
        success = cache.delete('generation_status', 'test-123')
        
        assert success is True
        assert cache.metrics['deletes'] == 1
        assert 'gen:status:test-123' not in cache.local_cache
        mock_redis_client.delete.assert_called_once_with('gen:status:test-123')
    
    def test_delete_with_redis_unavailable(self):
        """Testa remoção sem Redis disponível"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona dados primeiro
        cache.local_cache['gen:status:test-123'] = self.sample_data
        
        success = cache.delete('generation_status', 'test-123')
        
        assert success is True
        assert cache.metrics['deletes'] == 1
        assert 'gen:status:test-123' not in cache.local_cache
    
    def test_delete_nonexistent_key(self):
        """Testa remoção de chave inexistente"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        success = cache.delete('generation_status', 'non-existent')
        
        assert success is True
        assert cache.metrics['deletes'] == 1
    
    @patch('shared.intelligent_cache.redis')
    def test_clear_prefix_with_redis_available(self, mock_redis):
        """Testa limpeza de prefixo com Redis disponível"""
        # Mock do Redis
        mock_redis_client = Mock()
        mock_redis.from_url.return_value = mock_redis_client
        mock_redis_client.keys.return_value = ['gen:status:key1', 'gen:status:key2']
        mock_redis_client.delete.return_value = 2
        
        cache = IntelligentCache()
        cache.redis_client = mock_redis_client
        
        # Adiciona dados locais
        cache.local_cache['gen:status:key1'] = {'data': 'value1'}
        cache.local_cache['gen:status:key2'] = {'data': 'value2'}
        cache.local_cache['other:key3'] = {'data': 'value3'}
        
        removed_count = cache.clear_prefix('generation_status')
        
        assert removed_count == 4  # 2 do Redis + 2 do local
        assert 'gen:status:key1' not in cache.local_cache
        assert 'gen:status:key2' not in cache.local_cache
        assert 'other:key3' in cache.local_cache  # Não deve ser removido
        mock_redis_client.keys.assert_called_once_with('gen:status:*')
        mock_redis_client.delete.assert_called_once_with('gen:status:key1', 'gen:status:key2')
    
    def test_clear_prefix_with_redis_unavailable(self):
        """Testa limpeza de prefixo sem Redis disponível"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona dados locais
        cache.local_cache['gen:status:key1'] = {'data': 'value1'}
        cache.local_cache['gen:status:key2'] = {'data': 'value2'}
        cache.local_cache['other:key3'] = {'data': 'value3'}
        
        removed_count = cache.clear_prefix('generation_status')
        
        assert removed_count == 2
        assert 'gen:status:key1' not in cache.local_cache
        assert 'gen:status:key2' not in cache.local_cache
        assert 'other:key3' in cache.local_cache  # Não deve ser removido
    
    def test_get_generation_status(self):
        """Testa obtenção de status de geração"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona status
        cache.local_cache['gen:status:test-123'] = self.sample_data
        
        result = cache.get_generation_status('test-123')
        
        assert result == self.sample_data
    
    def test_get_generation_status_not_found(self):
        """Testa obtenção de status de geração não encontrado"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        result = cache.get_generation_status('non-existent')
        
        assert result is None
    
    def test_set_generation_status(self):
        """Testa armazenamento de status de geração"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        success = cache.set_generation_status('test-123', self.sample_data)
        
        assert success is True
        assert 'gen:status:test-123' in cache.local_cache
        assert cache.local_cache['gen:status:test-123'] == self.sample_data
    
    def test_set_generation_status_with_custom_ttl(self):
        """Testa armazenamento de status com TTL customizado"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        custom_ttl = 7200  # 2 horas
        success = cache.set_generation_status('test-123', self.sample_data, ttl=custom_ttl)
        
        assert success is True
        assert 'gen:status:test-123' in cache.local_cache
    
    def test_get_export_cache(self):
        """Testa obtenção de cache de exportação"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        export_data = {'export_id': 'exp-123', 'file_path': '/path/to/file.zip'}
        cache.local_cache['export:exp-123'] = export_data
        
        result = cache.get_export_cache('exp-123')
        
        assert result == export_data
    
    def test_set_export_cache(self):
        """Testa armazenamento de cache de exportação"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        export_data = {'export_id': 'exp-123', 'file_path': '/path/to/file.zip'}
        success = cache.set_export_cache('exp-123', export_data)
        
        assert success is True
        assert 'export:exp-123' in cache.local_cache
        assert cache.local_cache['export:exp-123'] == export_data
    
    def test_get_metrics(self):
        """Testa obtenção de métricas"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Simula algumas operações
        cache.metrics['hits'] = 10
        cache.metrics['misses'] = 5
        cache.metrics['sets'] = 8
        cache.metrics['deletes'] = 2
        cache.metrics['errors'] = 1
        
        metrics = cache.get_metrics()
        
        assert metrics['hits'] == 10
        assert metrics['misses'] == 5
        assert metrics['sets'] == 8
        assert metrics['deletes'] == 2
        assert metrics['errors'] == 1
        assert 'hit_rate' in metrics
        assert 'total_operations' in metrics
        assert metrics['total_operations'] == 26
        assert metrics['hit_rate'] == 10 / 15  # hits / (hits + misses)
    
    def test_get_metrics_with_zero_operations(self):
        """Testa métricas com zero operações"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        metrics = cache.get_metrics()
        
        assert metrics['hits'] == 0
        assert metrics['misses'] == 0
        assert metrics['hit_rate'] == 0.0
        assert metrics['total_operations'] == 0
    
    def test_increment_metric(self):
        """Testa incremento de métricas"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        cache._increment_metric('hits')
        cache._increment_metric('hits')
        cache._increment_metric('misses')
        
        assert cache.metrics['hits'] == 2
        assert cache.metrics['misses'] == 1
    
    def test_warm_cache(self):
        """Testa aquecimento do cache"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        warm_data = {
            'key1': {'status': 'ready'},
            'key2': {'status': 'processing'}
        }
        
        cache.warm_cache('generation_status', warm_data)
        
        assert 'gen:status:key1' in cache.local_cache
        assert 'gen:status:key2' in cache.local_cache
        assert cache.local_cache['gen:status:key1'] == {'status': 'ready'}
        assert cache.local_cache['gen:status:key2'] == {'status': 'processing'}
    
    def test_invalidate_expired(self):
        """Testa invalidação de entradas expiradas"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona dados que não expiram (sem TTL)
        cache.local_cache['gen:status:key1'] = {'status': 'ready'}
        cache.local_cache['gen:status:key2'] = {'status': 'processing'}
        
        removed_count = cache.invalidate_expired()
        
        # Como não há TTL implementado no cache local, nenhuma entrada deve ser removida
        assert removed_count == 0
        assert 'gen:status:key1' in cache.local_cache
        assert 'gen:status:key2' in cache.local_cache
    
    def test_get_cache_info(self):
        """Testa obtenção de informações do cache"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Adiciona alguns dados
        cache.local_cache['gen:status:key1'] = {'data': 'value1'}
        cache.local_cache['export:key2'] = {'data': 'value2'}
        
        info = cache.get_cache_info()
        
        assert 'redis_available' in info
        assert 'local_cache_size' in info
        assert 'total_keys' in info
        assert 'prefixes' in info
        assert 'default_ttl' in info
        assert info['redis_available'] is False
        assert info['total_keys'] == 2
        assert 'generation_status' in info['prefixes']
        assert 'export_cache' in info['prefixes']
    
    def test_error_handling_in_get(self):
        """Testa tratamento de erro na obtenção"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Simula erro ao acessar cache
        with patch.object(cache, '_increment_metric') as mock_increment:
            mock_increment.side_effect = Exception("Test error")
            
            result = cache.get('generation_status', 'test-123')
            
            assert result is None
            assert cache.metrics['errors'] == 1
    
    def test_error_handling_in_set(self):
        """Testa tratamento de erro no armazenamento"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Simula erro ao armazenar
        with patch.object(cache, '_increment_metric') as mock_increment:
            mock_increment.side_effect = Exception("Test error")
            
            success = cache.set('generation_status', 'test-123', self.sample_data)
            
            assert success is False
            assert cache.metrics['errors'] == 1
    
    def test_error_handling_in_delete(self):
        """Testa tratamento de erro na remoção"""
        cache = IntelligentCache()
        cache.redis_client = None
        
        # Simula erro ao remover
        with patch.object(cache, '_increment_metric') as mock_increment:
            mock_increment.side_effect = Exception("Test error")
            
            success = cache.delete('generation_status', 'test-123')
            
            assert success is False
            assert cache.metrics['errors'] == 1


class TestCacheDecorator:
    """Testes para o decorator de cache"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.cache = IntelligentCache()
        self.cache.redis_client = None
    
    def test_cached_decorator_with_simple_key(self):
        """Testa decorator de cache com chave simples"""
        from shared.intelligent_cache import cached
        
        call_count = 0
        
        @cached('api_responses')
        def test_function(param1, param2):
            nonlocal call_count
            call_count += 1
            return f"result_{param1}_{param2}"
        
        # Primeira chamada
        result1 = test_function('a', 'b')
        assert result1 == "result_a_b"
        assert call_count == 1
        
        # Segunda chamada (deve usar cache)
        result2 = test_function('a', 'b')
        assert result2 == "result_a_b"
        assert call_count == 1  # Não deve incrementar
        
        # Terceira chamada com parâmetros diferentes
        result3 = test_function('c', 'd')
        assert result3 == "result_c_d"
        assert call_count == 2  # Deve incrementar
    
    def test_cached_decorator_with_custom_key_function(self):
        """Testa decorator de cache com função de chave customizada"""
        from shared.intelligent_cache import cached
        
        call_count = 0
        
        def custom_key_func(*args, **kwargs):
            return f"custom_{args[0]}"
        
        @cached('api_responses', key_func=custom_key_func)
        def test_function(param1, param2):
            nonlocal call_count
            call_count += 1
            return f"result_{param1}_{param2}"
        
        # Primeira chamada
        result1 = test_function('a', 'b')
        assert result1 == "result_a_b"
        assert call_count == 1
        
        # Segunda chamada (deve usar cache baseado na chave customizada)
        result2 = test_function('a', 'c')  # param2 diferente
        assert result2 == "result_a_b"  # Deve retornar do cache
        assert call_count == 1  # Não deve incrementar
    
    def test_cached_decorator_with_custom_ttl(self):
        """Testa decorator de cache com TTL customizado"""
        from shared.intelligent_cache import cached
        
        call_count = 0
        
        @cached('api_responses', ttl=1800)  # 30 minutos
        def test_function(param1):
            nonlocal call_count
            call_count += 1
            return f"result_{param1}"
        
        # Primeira chamada
        result1 = test_function('test')
        assert result1 == "result_test"
        assert call_count == 1
        
        # Segunda chamada (deve usar cache)
        result2 = test_function('test')
        assert result2 == "result_test"
        assert call_count == 1 