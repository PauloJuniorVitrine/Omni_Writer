"""
Testes unitários para Cache Strategies - Baseados em código real

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import time
import json
from unittest.mock import Mock, patch
from shared.cache_strategies import (
    LRUStrategy, LFUStrategy, FIFOStrategy, TTLStrategy,
    CacheCompressor, CacheEncryptor, create_strategy
)
from shared.cache_config import CacheStrategy


class TestLRUStrategy:
    """Testes para estratégia LRU (Least Recently Used)"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.strategy = LRUStrategy(max_size=100)  # 100MB
        self.sample_data = {
            'trace_id': 'test-123',
            'status': 'processing',
            'progress': 50
        }
    
    def test_lru_strategy_initialization(self):
        """Testa inicialização da estratégia LRU"""
        strategy = LRUStrategy(max_size=50)
        assert strategy.max_size == 50 * 1024 * 1024  # Converte para bytes
        assert strategy.current_size == 0
        assert len(strategy.entries) == 0
        assert len(strategy.access_order) == 0
    
    def test_add_entry_success(self):
        """Testa adição bem-sucedida de entrada"""
        success = self.strategy.add_entry('key1', self.sample_data)
        
        assert success is True
        assert 'key1' in self.strategy.entries
        assert self.strategy.entries['key1'].value == self.sample_data
        assert 'key1' in self.strategy.access_order
    
    def test_add_entry_updates_access_order(self):
        """Testa atualização da ordem de acesso ao adicionar"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # Verifica ordem de acesso
        access_keys = list(self.strategy.access_order.keys())
        assert access_keys == ['key1', 'key2']
    
    def test_get_entry_success(self):
        """Testa obtenção bem-sucedida de entrada"""
        self.strategy.add_entry('key1', self.sample_data)
        
        result = self.strategy.get_entry('key1')
        
        assert result == self.sample_data
        assert self.strategy.entries['key1'].access_count == 1
        assert self.strategy.entries['key1'].last_accessed > time.time() - 1
    
    def test_get_entry_updates_access_order(self):
        """Testa atualização da ordem de acesso ao obter"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # Acessa key1, que deve ir para o final
        self.strategy.get_entry('key1')
        
        access_keys = list(self.strategy.access_order.keys())
        assert access_keys == ['key2', 'key1']
    
    def test_get_entry_not_found(self):
        """Testa obtenção de entrada inexistente"""
        result = self.strategy.get_entry('non-existent')
        
        assert result is None
    
    def test_remove_entry_success(self):
        """Testa remoção bem-sucedida de entrada"""
        self.strategy.add_entry('key1', self.sample_data)
        
        success = self.strategy.remove_entry('key1')
        
        assert success is True
        assert 'key1' not in self.strategy.entries
        assert 'key1' not in self.strategy.access_order
        assert self.strategy.current_size == 0
    
    def test_remove_entry_not_found(self):
        """Testa remoção de entrada inexistente"""
        success = self.strategy.remove_entry('non-existent')
        
        assert success is False
    
    def test_should_evict_oldest(self):
        """Testa identificação da entrada mais antiga para remoção"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # key1 deve ser a mais antiga
        assert self.strategy.should_evict('key1') is True
        assert self.strategy.should_evict('key2') is False
    
    def test_eviction_when_full(self):
        """Testa remoção automática quando cache está cheio"""
        # Adiciona entradas até encher o cache
        large_data = 'x' * (50 * 1024 * 1024)  # 50MB
        
        success1 = self.strategy.add_entry('key1', large_data)
        success2 = self.strategy.add_entry('key2', large_data)
        
        # A segunda entrada deve remover a primeira
        assert success1 is True
        assert success2 is True
        assert 'key1' not in self.strategy.entries
        assert 'key2' in self.strategy.entries
    
    def test_calculate_size_different_types(self):
        """Testa cálculo de tamanho para diferentes tipos de dados"""
        # String
        size = self.strategy._calculate_size("test string")
        assert size == len("test string")
        
        # Int
        size = self.strategy._calculate_size(42)
        assert size == 8
        
        # List
        size = self.strategy._calculate_size([1, 2, 3])
        assert size > 0
        
        # Dict
        size = self.strategy._calculate_size({'a': 1, 'b': 2})
        assert size > 0
    
    def test_get_stats(self):
        """Testa obtenção de estatísticas"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        stats = self.strategy.get_stats()
        
        assert stats['total_entries'] == 2
        assert stats['current_size_mb'] > 0
        assert stats['max_size_mb'] == 100
        assert stats['utilization_percent'] > 0


class TestLFUStrategy:
    """Testes para estratégia LFU (Least Frequently Used)"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.strategy = LFUStrategy(max_size=100)
        self.sample_data = {'status': 'ready'}
    
    def test_lfu_strategy_initialization(self):
        """Testa inicialização da estratégia LFU"""
        strategy = LFUStrategy(max_size=50)
        assert strategy.max_size == 50 * 1024 * 1024
        assert len(strategy.frequency_map) == 0
    
    def test_add_entry_success(self):
        """Testa adição bem-sucedida de entrada"""
        success = self.strategy.add_entry('key1', self.sample_data)
        
        assert success is True
        assert 'key1' in self.strategy.entries
        assert 'key1' not in self.strategy.frequency_map  # Só é adicionado no primeiro acesso
    
    def test_get_entry_increments_frequency(self):
        """Testa incremento de frequência ao acessar"""
        self.strategy.add_entry('key1', self.sample_data)
        
        # Primeiro acesso
        self.strategy.get_entry('key1')
        assert self.strategy.frequency_map['key1'] == 1
        
        # Segundo acesso
        self.strategy.get_entry('key1')
        assert self.strategy.frequency_map['key1'] == 2
    
    def test_should_evict_least_frequent(self):
        """Testa identificação da entrada menos frequente"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # Acessa key1 duas vezes
        self.strategy.get_entry('key1')
        self.strategy.get_entry('key1')
        
        # Acessa key2 uma vez
        self.strategy.get_entry('key2')
        
        # key2 deve ser a menos frequente
        assert self.strategy.should_evict('key2') is True
        assert self.strategy.should_evict('key1') is False
    
    def test_remove_entry_clears_frequency(self):
        """Testa limpeza do contador de frequência ao remover"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.get_entry('key1')  # Incrementa frequência
        
        self.strategy.remove_entry('key1')
        
        assert 'key1' not in self.strategy.frequency_map


class TestFIFOStrategy:
    """Testes para estratégia FIFO (First In, First Out)"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.strategy = FIFOStrategy(max_size=100)
        self.sample_data = {'status': 'ready'}
    
    def test_fifo_strategy_initialization(self):
        """Testa inicialização da estratégia FIFO"""
        strategy = FIFOStrategy(max_size=50)
        assert strategy.max_size == 50 * 1024 * 1024
        assert len(strategy.insertion_order) == 0
    
    def test_add_entry_updates_insertion_order(self):
        """Testa atualização da ordem de inserção"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        assert self.strategy.insertion_order == ['key1', 'key2']
    
    def test_should_evict_first_inserted(self):
        """Testa identificação da primeira entrada inserida"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # key1 deve ser a primeira a sair
        assert self.strategy.should_evict('key1') is True
        assert self.strategy.should_evict('key2') is False
    
    def test_access_does_not_change_order(self):
        """Testa que acesso não altera ordem FIFO"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        # Acessa key2
        self.strategy.get_entry('key2')
        
        # Ordem deve permanecer a mesma
        assert self.strategy.insertion_order == ['key1', 'key2']
    
    def test_remove_entry_updates_order(self):
        """Testa atualização da ordem ao remover entrada"""
        self.strategy.add_entry('key1', self.sample_data)
        self.strategy.add_entry('key2', {'data': 'value2'})
        
        self.strategy.remove_entry('key1')
        
        assert self.strategy.insertion_order == ['key2']


class TestTTLStrategy:
    """Testes para estratégia TTL (Time To Live)"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.strategy = TTLStrategy(max_size=100, default_ttl=1)  # 1 segundo
        self.sample_data = {'status': 'ready'}
    
    def test_ttl_strategy_initialization(self):
        """Testa inicialização da estratégia TTL"""
        strategy = TTLStrategy(max_size=50, default_ttl=3600)
        assert strategy.max_size == 50 * 1024 * 1024
        assert strategy.default_ttl == 3600
        assert len(strategy.ttl_map) == 0
    
    def test_add_entry_with_default_ttl(self):
        """Testa adição com TTL padrão"""
        success = self.strategy.add_entry('key1', self.sample_data)
        
        assert success is True
        assert 'key1' in self.strategy.ttl_map
        ttl, created_at = self.strategy.ttl_map['key1']
        assert ttl == 1  # default_ttl
        assert created_at > time.time() - 1
    
    def test_add_entry_with_custom_ttl(self):
        """Testa adição com TTL customizado"""
        success = self.strategy.add_entry('key1', self.sample_data, ttl=5)
        
        assert success is True
        ttl, created_at = self.strategy.ttl_map['key1']
        assert ttl == 5
    
    def test_should_evict_expired(self):
        """Testa identificação de entrada expirada"""
        self.strategy.add_entry('key1', self.sample_data, ttl=0.1)  # 0.1 segundos
        
        # Aguarda expiração
        time.sleep(0.2)
        
        assert self.strategy.should_evict('key1') is True
    
    def test_should_not_evict_valid(self):
        """Testa que entrada válida não é marcada para remoção"""
        self.strategy.add_entry('key1', self.sample_data, ttl=10)  # 10 segundos
        
        assert self.strategy.should_evict('key1') is False
    
    def test_cleanup_expired(self):
        """Testa limpeza de entradas expiradas"""
        self.strategy.add_entry('key1', self.sample_data, ttl=0.1)
        self.strategy.add_entry('key2', {'data': 'value2'}, ttl=10)
        
        # Aguarda expiração da key1
        time.sleep(0.2)
        
        removed_count = self.strategy.cleanup_expired()
        
        assert removed_count == 1
        assert 'key1' not in self.strategy.entries
        assert 'key2' in self.strategy.entries
    
    def test_access_does_not_extend_ttl(self):
        """Testa que acesso não estende TTL"""
        self.strategy.add_entry('key1', self.sample_data, ttl=0.1)
        created_at = self.strategy.ttl_map['key1'][1]
        
        time.sleep(0.05)  # Metade do TTL
        self.strategy.get_entry('key1')
        
        # TTL não deve ter sido estendido
        assert self.strategy.ttl_map['key1'][1] == created_at


class TestCacheCompressor:
    """Testes para compressão de cache"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.compressor = CacheCompressor()
        self.small_data = {'status': 'ready'}
        self.large_data = {'content': 'x' * 2000}  # 2KB
    
    def test_compress_small_data(self):
        """Testa que dados pequenos não são comprimidos"""
        compressed, was_compressed = self.compressor.compress(self.small_data)
        
        assert was_compressed is False
        assert len(compressed) > 0
    
    def test_compress_large_data(self):
        """Testa compressão de dados grandes"""
        compressed, was_compressed = self.compressor.compress(self.large_data)
        
        # Pode ou não ser comprimido dependendo da eficiência
        assert len(compressed) > 0
    
    def test_decompress_not_compressed(self):
        """Testa descompressão de dados não comprimidos"""
        data_bytes = json.dumps(self.small_data).encode('utf-8')
        
        result = self.compressor.decompress(data_bytes, was_compressed=False)
        
        assert result == self.small_data
    
    def test_decompress_compressed(self):
        """Testa descompressão de dados comprimidos"""
        compressed, was_compressed = self.compressor.compress(self.large_data)
        
        if was_compressed:
            result = self.compressor.decompress(compressed, was_compressed=True)
            assert result == self.large_data
    
    def test_compress_decompress_cycle(self):
        """Testa ciclo completo de compressão/descompressão"""
        compressed, was_compressed = self.compressor.compress(self.large_data)
        result = self.compressor.decompress(compressed, was_compressed)
        
        assert result == self.large_data


class TestCacheEncryptor:
    """Testes para criptografia de cache"""
    
    def setup_method(self):
        """Setup para cada teste"""
        self.encryptor = CacheEncryptor(secret_key="test-secret-key")
        self.sample_data = {'sensitive': 'data'}
    
    def test_encrypt_data(self):
        """Testa criptografia de dados"""
        encrypted, was_encrypted = self.encryptor.encrypt(self.sample_data)
        
        assert was_encrypted is True
        assert len(encrypted) > 0
        assert encrypted != json.dumps(self.sample_data).encode('utf-8')
    
    def test_decrypt_data(self):
        """Testa descriptografia de dados"""
        encrypted, was_encrypted = self.encryptor.encrypt(self.sample_data)
        decrypted = self.encryptor.decrypt(encrypted, was_encrypted)
        
        assert decrypted == self.sample_data
    
    def test_decrypt_not_encrypted(self):
        """Testa descriptografia de dados não criptografados"""
        data_bytes = json.dumps(self.sample_data).encode('utf-8')
        
        result = self.encryptor.decrypt(data_bytes, was_encrypted=False)
        
        assert result == self.sample_data
    
    def test_encrypt_with_different_keys(self):
        """Testa que chaves diferentes produzem resultados diferentes"""
        encryptor1 = CacheEncryptor(secret_key="key1")
        encryptor2 = CacheEncryptor(secret_key="key2")
        
        encrypted1, _ = encryptor1.encrypt(self.sample_data)
        encrypted2, _ = encryptor2.encrypt(self.sample_data)
        
        assert encrypted1 != encrypted2


class TestCreateStrategy:
    """Testes para factory de estratégias"""
    
    def test_create_lru_strategy(self):
        """Testa criação de estratégia LRU"""
        strategy = create_strategy(CacheStrategy.LRU, max_size=50)
        
        assert isinstance(strategy, LRUStrategy)
        assert strategy.max_size == 50 * 1024 * 1024
    
    def test_create_lfu_strategy(self):
        """Testa criação de estratégia LFU"""
        strategy = create_strategy(CacheStrategy.LFU, max_size=100)
        
        assert isinstance(strategy, LFUStrategy)
        assert strategy.max_size == 100 * 1024 * 1024
    
    def test_create_fifo_strategy(self):
        """Testa criação de estratégia FIFO"""
        strategy = create_strategy(CacheStrategy.FIFO, max_size=75)
        
        assert isinstance(strategy, FIFOStrategy)
        assert strategy.max_size == 75 * 1024 * 1024
    
    def test_create_ttl_strategy(self):
        """Testa criação de estratégia TTL"""
        strategy = create_strategy(CacheStrategy.TTL, max_size=200, default_ttl=7200)
        
        assert isinstance(strategy, TTLStrategy)
        assert strategy.max_size == 200 * 1024 * 1024
        assert strategy.default_ttl == 7200
    
    def test_create_ttl_strategy_default_ttl(self):
        """Testa criação de estratégia TTL com TTL padrão"""
        strategy = create_strategy(CacheStrategy.TTL, max_size=100)
        
        assert isinstance(strategy, TTLStrategy)
        assert strategy.default_ttl == 3600  # TTL padrão
    
    def test_create_invalid_strategy(self):
        """Testa criação de estratégia inválida"""
        with pytest.raises(ValueError, match="Estratégia não suportada"):
            create_strategy("invalid", max_size=50) 