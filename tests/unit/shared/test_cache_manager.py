"""
Testes unitários para CacheManager - Baseados em código real

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import time
import json
from unittest.mock import Mock, patch, MagicMock
from shared.cache_manager import CacheManager, CacheOperation, cache_get, cache_set, cache_delete
from shared.cache_config import CacheType, CacheStrategy


class TestCacheManager:
    """Testes unitários para CacheManager"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.manager = CacheManager(enable_metrics=True, enable_compression=True)
        self.sample_data = {
            'trace_id': 'test-123',
            'status': 'processing',
            'progress': 50,
            'message': 'Gerando artigos...'
        }
    
    def test_cache_manager_initialization(self):
        """Testa inicialização do CacheManager"""
        manager = CacheManager()
        
        assert manager is not None
        assert hasattr(manager, 'intelligent_cache')
        assert hasattr(manager, 'compressor')
        assert hasattr(manager, 'encryptor')
        assert hasattr(manager, 'strategies')
        assert hasattr(manager, 'operations')
        assert len(manager.strategies) == len(CacheType)
    
    def test_cache_manager_with_disabled_metrics(self):
        """Testa inicialização com métricas desabilitadas"""
        manager = CacheManager(enable_metrics=False)
        
        assert manager.enable_metrics is False
        assert manager.intelligent_cache.enable_metrics is False
    
    def test_cache_manager_with_disabled_compression(self):
        """Testa inicialização com compressão desabilitada"""
        manager = CacheManager(enable_compression=False)
        
        assert manager.enable_compression is False
    
    def test_initialize_strategies(self):
        """Testa inicialização das estratégias"""
        # Verifica se todas as estratégias foram criadas
        for cache_type in CacheType:
            assert cache_type in self.manager.strategies
            strategy = self.manager.strategies[cache_type]
            assert strategy is not None
    
    def test_get_with_intelligent_cache_hit(self):
        """Testa obtenção com hit no cache inteligente"""
        # Mock do cache inteligente
        with patch.object(self.manager, '_get_from_intelligent_cache') as mock_get:
            mock_get.return_value = self.sample_data
            
            result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
            
            assert result == self.sample_data
            mock_get.assert_called_once_with(CacheType.GENERATION_STATUS, 'test-123')
    
    def test_get_with_strategy_hit(self):
        """Testa obtenção com hit na estratégia específica"""
        # Mock do cache inteligente para retornar None
        with patch.object(self.manager, '_get_from_intelligent_cache') as mock_get:
            mock_get.return_value = None
            
            # Mock da estratégia
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'get_entry') as mock_strategy_get:
                mock_strategy_get.return_value = self.sample_data
                
                result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
                
                assert result == self.sample_data
                mock_strategy_get.assert_called_once_with('test-123')
    
    def test_get_cache_miss(self):
        """Testa cache miss"""
        # Mock do cache inteligente para retornar None
        with patch.object(self.manager, '_get_from_intelligent_cache') as mock_get:
            mock_get.return_value = None
            
            # Mock da estratégia para retornar None
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'get_entry') as mock_strategy_get:
                mock_strategy_get.return_value = None
                
                result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
                
                assert result is None
    
    def test_get_with_default_value(self):
        """Testa obtenção com valor padrão"""
        default_value = {'status': 'not_found'}
        
        # Mock do cache inteligente para retornar None
        with patch.object(self.manager, '_get_from_intelligent_cache') as mock_get:
            mock_get.return_value = None
            
            # Mock da estratégia para retornar None
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'get_entry') as mock_strategy_get:
                mock_strategy_get.return_value = None
                
                result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123', default=default_value)
                
                assert result == default_value
    
    def test_set_success(self):
        """Testa armazenamento bem-sucedido"""
        # Mock do processamento de valor
        with patch.object(self.manager, '_process_value_for_storage') as mock_process:
            mock_process.return_value = (self.sample_data, {'compressed': False, 'encrypted': False})
            
            # Mock do cache inteligente
            with patch.object(self.manager, '_set_in_intelligent_cache') as mock_set:
                mock_set.return_value = True
                
                # Mock da estratégia
                strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
                with patch.object(strategy, 'add_entry') as mock_add:
                    mock_add.return_value = True
                    
                    result = self.manager.set(CacheType.GENERATION_STATUS, 'test-123', self.sample_data)
                    
                    assert result is True
                    mock_process.assert_called_once()
                    mock_set.assert_called_once()
                    mock_add.assert_called_once()
    
    def test_set_with_compression(self):
        """Testa armazenamento com compressão"""
        compressed_data = b'compressed_data'
        
        # Mock do processamento de valor com compressão
        with patch.object(self.manager, '_process_value_for_storage') as mock_process:
            mock_process.return_value = (compressed_data, {'compressed': True, 'encrypted': False})
            
            # Mock do cache inteligente
            with patch.object(self.manager, '_set_in_intelligent_cache') as mock_set:
                mock_set.return_value = True
                
                # Mock da estratégia
                strategy = self.manager.strategies[CacheType.EXPORT_CACHE]
                with patch.object(strategy, 'add_entry') as mock_add:
                    mock_add.return_value = True
                    
                    result = self.manager.set(CacheType.EXPORT_CACHE, 'test-123', self.sample_data)
                    
                    assert result is True
                    mock_add.assert_called_with('test-123', compressed_data, compressed=True, encrypted=False, ttl=None)
    
    def test_set_with_encryption(self):
        """Testa armazenamento com criptografia"""
        encrypted_data = b'encrypted_data'
        
        # Mock do processamento de valor com criptografia
        with patch.object(self.manager, '_process_value_for_storage') as mock_process:
            mock_process.return_value = (encrypted_data, {'compressed': False, 'encrypted': True})
            
            # Mock do cache inteligente
            with patch.object(self.manager, '_set_in_intelligent_cache') as mock_set:
                mock_set.return_value = True
                
                # Mock da estratégia
                strategy = self.manager.strategies[CacheType.USER_PREFERENCES]
                with patch.object(strategy, 'add_entry') as mock_add:
                    mock_add.return_value = True
                    
                    result = self.manager.set(CacheType.USER_PREFERENCES, 'test-123', self.sample_data)
                    
                    assert result is True
                    mock_add.assert_called_with('test-123', encrypted_data, compressed=False, encrypted=True, ttl=None)
    
    def test_set_with_custom_ttl(self):
        """Testa armazenamento com TTL customizado"""
        custom_ttl = 1800  # 30 minutos
        
        # Mock do processamento de valor
        with patch.object(self.manager, '_process_value_for_storage') as mock_process:
            mock_process.return_value = (self.sample_data, {'compressed': False, 'encrypted': False})
            
            # Mock do cache inteligente
            with patch.object(self.manager, '_set_in_intelligent_cache') as mock_set:
                mock_set.return_value = True
                
                # Mock da estratégia
                strategy = self.manager.strategies[CacheType.API_RESPONSES]
                with patch.object(strategy, 'add_entry') as mock_add:
                    mock_add.return_value = True
                    
                    result = self.manager.set(CacheType.API_RESPONSES, 'test-123', self.sample_data, ttl=custom_ttl)
                    
                    assert result is True
                    mock_set.assert_called_with(CacheType.API_RESPONSES, 'test-123', self.sample_data, custom_ttl)
    
    def test_delete_success(self):
        """Testa remoção bem-sucedida"""
        # Mock do cache inteligente
        with patch.object(self.manager, '_delete_from_intelligent_cache') as mock_delete:
            mock_delete.return_value = True
            
            # Mock da estratégia
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'remove_entry') as mock_remove:
                mock_remove.return_value = True
                
                result = self.manager.delete(CacheType.GENERATION_STATUS, 'test-123')
                
                assert result is True
                mock_delete.assert_called_once_with(CacheType.GENERATION_STATUS, 'test-123')
                mock_remove.assert_called_once_with('test-123')
    
    def test_delete_partial_failure(self):
        """Testa remoção com falha parcial"""
        # Mock do cache inteligente
        with patch.object(self.manager, '_delete_from_intelligent_cache') as mock_delete:
            mock_delete.return_value = True
            
            # Mock da estratégia
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'remove_entry') as mock_remove:
                mock_remove.return_value = False
                
                result = self.manager.delete(CacheType.GENERATION_STATUS, 'test-123')
                
                assert result is False
    
    def test_clear_success(self):
        """Testa limpeza bem-sucedida"""
        # Mock do cache inteligente
        with patch.object(self.manager, '_clear_intelligent_cache') as mock_clear:
            mock_clear.return_value = 5
            
            # Mock da estratégia
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            strategy.entries = {'key1': 'value1', 'key2': 'value2'}
            strategy.current_size = 1024
            
            result = self.manager.clear(CacheType.GENERATION_STATUS)
            
            assert result == 7  # 5 do cache inteligente + 2 da estratégia
            assert len(strategy.entries) == 0
            assert strategy.current_size == 0
    
    def test_get_metrics(self):
        """Testa obtenção de métricas"""
        # Mock do cache inteligente
        intelligent_metrics = {
            'hits': 10,
            'misses': 5,
            'hit_ratio': 66.67
        }
        
        with patch.object(self.manager.intelligent_cache, 'get_metrics') as mock_metrics:
            mock_metrics.return_value = intelligent_metrics
            
            # Adiciona algumas operações
            self.manager.operations = [
                CacheOperation('get', CacheType.GENERATION_STATUS, 'key1', True, 10.0, time.time()),
                CacheOperation('set', CacheType.EXPORT_CACHE, 'key2', True, 15.0, time.time()),
                CacheOperation('delete', CacheType.API_RESPONSES, 'key3', False, 5.0, time.time(), 'Error')
            ]
            
            metrics = self.manager.get_metrics()
            
            assert 'intelligent_cache' in metrics
            assert 'strategies' in metrics
            assert 'operations' in metrics
            assert metrics['intelligent_cache'] == intelligent_metrics
            assert metrics['total_entries'] >= 0
            assert metrics['cache_types'] == len(CacheType)
    
    def test_warm_cache(self):
        """Testa aquecimento de cache"""
        warm_data = {
            'key1': {'status': 'ready'},
            'key2': {'status': 'processing'}
        }
        
        # Mock do cache inteligente
        with patch.object(self.manager.intelligent_cache, 'warm_cache') as mock_warm:
            # Mock da estratégia
            strategy = self.manager.strategies[CacheType.GENERATION_STATUS]
            with patch.object(strategy, 'add_entry') as mock_add:
                mock_add.return_value = True
                
                self.manager.warm_cache(CacheType.GENERATION_STATUS, warm_data)
                
                mock_warm.assert_called_once_with('generation_status', warm_data)
                assert mock_add.call_count == 2
    
    def test_cleanup_expired(self):
        """Testa limpeza de entradas expiradas"""
        # Mock das estratégias com método cleanup_expired
        strategy1 = self.manager.strategies[CacheType.METRICS]
        strategy2 = self.manager.strategies[CacheType.API_RESPONSES]
        
        with patch.object(strategy1, 'cleanup_expired') as mock_cleanup1:
            mock_cleanup1.return_value = 3
            
            with patch.object(strategy2, 'cleanup_expired') as mock_cleanup2:
                mock_cleanup2.return_value = 1
                
                result = self.manager.cleanup_expired()
                
                assert result[CacheType.METRICS] == 3
                assert result[CacheType.API_RESPONSES] == 1
                mock_cleanup1.assert_called_once()
                mock_cleanup2.assert_called_once()
    
    def test_transaction_context_manager(self):
        """Testa context manager de transação"""
        with self.manager.transaction(CacheType.GENERATION_STATUS) as cache:
            assert cache == self.manager
    
    def test_transaction_context_manager_with_error(self):
        """Testa context manager de transação com erro"""
        with pytest.raises(Exception):
            with self.manager.transaction(CacheType.GENERATION_STATUS):
                raise Exception("Test error")
    
    def test_process_value_for_storage(self):
        """Testa processamento de valor para armazenamento"""
        from shared.cache_config import CacheConfig
        
        config = CacheConfig(
            ttl=3600,
            strategy=CacheStrategy.LRU,
            max_size=100,
            compression=True,
            encryption=False,
            distributed=True
        )
        
        result, compression_info = self.manager._process_value_for_storage(self.sample_data, config)
        
        assert result is not None
        assert 'compressed' in compression_info
        assert 'encrypted' in compression_info
    
    def test_log_operation(self):
        """Testa registro de operação"""
        operation = CacheOperation(
            operation_type='get',
            cache_type=CacheType.GENERATION_STATUS,
            key='test-123',
            success=True,
            duration_ms=0,
            timestamp=time.time()
        )
        
        start_time = time.time()
        self.manager._log_operation(operation, start_time)
        
        assert len(self.manager.operations) == 1
        assert self.manager.operations[0] == operation
        assert operation.duration_ms > 0
    
    def test_calculate_operation_metrics(self):
        """Testa cálculo de métricas de operações"""
        # Adiciona operações de teste
        self.manager.operations = [
            CacheOperation('get', CacheType.GENERATION_STATUS, 'key1', True, 10.0, time.time()),
            CacheOperation('set', CacheType.EXPORT_CACHE, 'key2', True, 15.0, time.time()),
            CacheOperation('delete', CacheType.API_RESPONSES, 'key3', False, 5.0, time.time(), 'Error'),
            CacheOperation('get', CacheType.METRICS, 'key4', True, 8.0, time.time())
        ]
        
        metrics = self.manager._calculate_operation_metrics()
        
        assert metrics['total_operations'] == 4
        assert metrics['success_rate'] == 75.0  # 3 sucessos / 4 operações
        assert metrics['avg_duration_ms'] == 9.5  # (10 + 15 + 5 + 8) / 4
        assert metrics['operations_by_type']['get'] == 2
        assert metrics['operations_by_type']['set'] == 1
        assert metrics['operations_by_type']['delete'] == 1
        assert metrics['operations_by_cache_type']['generation_status'] == 1
        assert metrics['operations_by_cache_type']['export_cache'] == 1
        assert metrics['operations_by_cache_type']['api_responses'] == 1
        assert metrics['operations_by_cache_type']['metrics'] == 1
    
    def test_calculate_operation_metrics_empty(self):
        """Testa cálculo de métricas com operações vazias"""
        self.manager.operations = []
        
        metrics = self.manager._calculate_operation_metrics()
        
        assert metrics['total_operations'] == 0
        assert metrics['success_rate'] == 0.0
        assert metrics['avg_duration_ms'] == 0.0
        assert metrics['operations_by_type'] == {}
        assert metrics['operations_by_cache_type'] == {}


class TestCacheManagerHelpers:
    """Testes para funções helper do CacheManager"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.manager = CacheManager()
    
    def test_cache_get_helper(self):
        """Testa função helper cache_get"""
        with patch('shared.cache_manager.cache_manager') as mock_manager:
            mock_manager.get.return_value = {'status': 'ready'}
            
            result = cache_get(CacheType.GENERATION_STATUS, 'test-123')
            
            assert result == {'status': 'ready'}
            mock_manager.get.assert_called_once_with(CacheType.GENERATION_STATUS, 'test-123', None)
    
    def test_cache_set_helper(self):
        """Testa função helper cache_set"""
        with patch('shared.cache_manager.cache_manager') as mock_manager:
            mock_manager.set.return_value = True
            
            result = cache_set(CacheType.EXPORT_CACHE, 'test-123', {'data': 'value'})
            
            assert result is True
            mock_manager.set.assert_called_once_with(CacheType.EXPORT_CACHE, 'test-123', {'data': 'value'}, None)
    
    def test_cache_set_helper_with_ttl(self):
        """Testa função helper cache_set com TTL"""
        with patch('shared.cache_manager.cache_manager') as mock_manager:
            mock_manager.set.return_value = True
            
            result = cache_set(CacheType.API_RESPONSES, 'test-123', {'data': 'value'}, ttl=1800)
            
            assert result is True
            mock_manager.set.assert_called_once_with(CacheType.API_RESPONSES, 'test-123', {'data': 'value'}, 1800)
    
    def test_cache_delete_helper(self):
        """Testa função helper cache_delete"""
        with patch('shared.cache_manager.cache_manager') as mock_manager:
            mock_manager.delete.return_value = True
            
            result = cache_delete(CacheType.GENERATION_STATUS, 'test-123')
            
            assert result is True
            mock_manager.delete.assert_called_once_with(CacheType.GENERATION_STATUS, 'test-123')
    
    def test_get_cache_metrics_helper(self):
        """Testa função helper get_cache_metrics"""
        with patch('shared.cache_manager.cache_manager') as mock_manager:
            mock_metrics = {'hits': 10, 'misses': 5}
            mock_manager.get_metrics.return_value = mock_metrics
            
            result = get_cache_metrics()
            
            assert result == mock_metrics
            mock_manager.get_metrics.assert_called_once()


class TestCacheManagerIntegration:
    """Testes de integração do CacheManager"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.manager = CacheManager(enable_metrics=True, enable_compression=True)
    
    def test_full_cache_workflow(self):
        """Testa workflow completo do cache"""
        # 1. Armazena dados
        success = self.manager.set(CacheType.GENERATION_STATUS, 'test-123', {'status': 'processing'})
        assert success is True
        
        # 2. Obtém dados
        result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
        assert result == {'status': 'processing'}
        
        # 3. Atualiza dados
        success = self.manager.set(CacheType.GENERATION_STATUS, 'test-123', {'status': 'completed'})
        assert success is True
        
        # 4. Obtém dados atualizados
        result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
        assert result == {'status': 'completed'}
        
        # 5. Remove dados
        success = self.manager.delete(CacheType.GENERATION_STATUS, 'test-123')
        assert success is True
        
        # 6. Verifica que dados foram removidos
        result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
        assert result is None
    
    def test_multiple_cache_types(self):
        """Testa uso de múltiplos tipos de cache"""
        # Geração de status
        self.manager.set(CacheType.GENERATION_STATUS, 'gen-123', {'status': 'processing'})
        
        # Cache de exportação
        self.manager.set(CacheType.EXPORT_CACHE, 'exp-456', {'file_path': '/path/to/file.zip'})
        
        # Preferências do usuário
        self.manager.set(CacheType.USER_PREFERENCES, 'user-789', {'theme': 'dark'})
        
        # Verifica que cada tipo é independente
        gen_result = self.manager.get(CacheType.GENERATION_STATUS, 'gen-123')
        exp_result = self.manager.get(CacheType.EXPORT_CACHE, 'exp-456')
        user_result = self.manager.get(CacheType.USER_PREFERENCES, 'user-789')
        
        assert gen_result == {'status': 'processing'}
        assert exp_result == {'file_path': '/path/to/file.zip'}
        assert user_result == {'theme': 'dark'}
        
        # Verifica que não há interferência entre tipos
        assert self.manager.get(CacheType.GENERATION_STATUS, 'exp-456') is None
        assert self.manager.get(CacheType.EXPORT_CACHE, 'gen-123') is None
    
    def test_metrics_tracking(self):
        """Testa rastreamento de métricas"""
        # Executa algumas operações
        self.manager.set(CacheType.GENERATION_STATUS, 'key1', {'data': 'value1'})
        self.manager.get(CacheType.GENERATION_STATUS, 'key1')
        self.manager.get(CacheType.GENERATION_STATUS, 'key2')  # Miss
        self.manager.set(CacheType.EXPORT_CACHE, 'key3', {'data': 'value3'})
        self.manager.delete(CacheType.GENERATION_STATUS, 'key1')
        
        # Obtém métricas
        metrics = self.manager.get_metrics()
        
        # Verifica métricas de operações
        operation_metrics = metrics['operations']
        assert operation_metrics['total_operations'] == 5
        assert operation_metrics['success_rate'] == 100.0  # Todas as operações foram bem-sucedidas
        assert operation_metrics['avg_duration_ms'] > 0
        
        # Verifica tipos de operações
        assert operation_metrics['operations_by_type']['set'] == 2
        assert operation_metrics['operations_by_type']['get'] == 2
        assert operation_metrics['operations_by_type']['delete'] == 1
    
    def test_error_handling(self):
        """Testa tratamento de erros"""
        # Simula erro no cache inteligente
        with patch.object(self.manager, '_get_from_intelligent_cache') as mock_get:
            mock_get.side_effect = Exception("Test error")
            
            # Deve retornar None sem quebrar
            result = self.manager.get(CacheType.GENERATION_STATUS, 'test-123')
            assert result is None
        
        # Simula erro no armazenamento
        with patch.object(self.manager, '_set_in_intelligent_cache') as mock_set:
            mock_set.side_effect = Exception("Test error")
            
            # Deve retornar False sem quebrar
            result = self.manager.set(CacheType.GENERATION_STATUS, 'test-123', {'data': 'value'})
            assert result is False
        
        # Verifica que erros foram registrados
        metrics = self.manager.get_metrics()
        operation_metrics = metrics['operations']
        assert operation_metrics['total_operations'] >= 2 