"""
Testes para Performance Config Simplificada

Prompt: Testes para Simplificação - Seção 2.3
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:55:00Z
Tracing ID: SIMPLIFICATION_TESTS_20250127_003

Testes baseados em código real para validar funcionalidades essenciais.
"""

import pytest
import os
from unittest.mock import patch
from app.performance_config_simplified_v2 import (
    PerformanceConfig, ProviderConfig, PerformanceConfigManager,
    get_performance_config, get_provider_config, update_performance_config, get_performance_stats
)


class TestProviderConfig:
    """Testes para ProviderConfig baseados em código real"""
    
    def test_provider_config_initialization(self):
        """Testa inicialização da configuração de provedor"""
        config = ProviderConfig(
            name="test_provider",
            requests_per_minute=100,
            max_concurrent=5,
            timeout=30.0,
            priority=3
        )
        
        assert config.name == "test_provider"
        assert config.requests_per_minute == 100
        assert config.max_concurrent == 5
        assert config.timeout == 30.0
        assert config.priority == 3
    
    def test_provider_config_defaults(self):
        """Testa valores padrão da configuração de provedor"""
        config = ProviderConfig(
            name="test_provider",
            requests_per_minute=100,
            max_concurrent=5,
            timeout=30.0
        )
        
        assert config.priority == 1  # Valor padrão


class TestPerformanceConfig:
    """Testes para PerformanceConfig baseados em código real"""
    
    def test_performance_config_initialization(self):
        """Testa inicialização da configuração de performance"""
        config = PerformanceConfig()
        
        assert config.max_workers == 5
        assert config.enable_parallel is True
        assert config.enable_rate_limiting is True
        assert config.default_timeout == 30.0
        assert config.max_retries == 3
        assert config.enable_cache is True
        assert config.batch_size == 10
    
    def test_performance_config_providers(self):
        """Testa configuração de provedores"""
        config = PerformanceConfig()
        
        assert 'openai' in config.providers
        assert 'deepseek' in config.providers
        assert 'claude' in config.providers
        
        # Verifica configurações específicas
        openai_config = config.providers['openai']
        assert openai_config.name == 'openai'
        assert openai_config.requests_per_minute == 300  # Aumentado de 60
        assert openai_config.max_concurrent == 10
        assert openai_config.timeout == 30.0
        assert openai_config.priority == 5
        
        deepseek_config = config.providers['deepseek']
        assert deepseek_config.name == 'deepseek'
        assert deepseek_config.requests_per_minute == 200  # Aumentado de 60
        assert deepseek_config.max_concurrent == 8
        assert deepseek_config.timeout == 25.0
        assert deepseek_config.priority == 4
        
        claude_config = config.providers['claude']
        assert claude_config.name == 'claude'
        assert claude_config.requests_per_minute == 150  # Aumentado de 50
        assert claude_config.max_concurrent == 5
        assert claude_config.timeout == 35.0
        assert claude_config.priority == 3


class TestPerformanceConfigManager:
    """Testes para PerformanceConfigManager baseados em código real"""
    
    def test_manager_initialization(self):
        """Testa inicialização do manager"""
        manager = PerformanceConfigManager()
        assert isinstance(manager.config, PerformanceConfig)
    
    @patch.dict(os.environ, {
        'PERFORMANCE_MAX_WORKERS': '10',
        'PERFORMANCE_ENABLE_PARALLEL': 'false',
        'PERFORMANCE_ENABLE_RATE_LIMITING': 'false',
        'PERFORMANCE_DEFAULT_TIMEOUT': '60.0',
        'PERFORMANCE_MAX_RETRIES': '5',
        'PERFORMANCE_ENABLE_CACHE': 'false',
        'PERFORMANCE_BATCH_SIZE': '20'
    })
    def test_manager_load_config_from_env(self):
        """Testa carregamento de configuração de variáveis de ambiente"""
        manager = PerformanceConfigManager()
        config = manager.config
        
        assert config.max_workers == 10
        assert config.enable_parallel is False
        assert config.enable_rate_limiting is False
        assert config.default_timeout == 60.0
        assert config.max_retries == 5
        assert config.enable_cache is False
        assert config.batch_size == 20
    
    @patch.dict(os.environ, {
        'PERFORMANCE_OPENAI_RPM': '500',
        'PERFORMANCE_OPENAI_MAX_CONCURRENT': '15',
        'PERFORMANCE_OPENAI_TIMEOUT': '45.0',
        'PERFORMANCE_OPENAI_PRIORITY': '10'
    })
    def test_manager_load_provider_configs_from_env(self):
        """Testa carregamento de configurações de provedores de variáveis de ambiente"""
        manager = PerformanceConfigManager()
        openai_config = manager.config.providers['openai']
        
        assert openai_config.requests_per_minute == 500
        assert openai_config.max_concurrent == 15
        assert openai_config.timeout == 45.0
        assert openai_config.priority == 10
    
    def test_manager_get_config(self):
        """Testa obtenção da configuração"""
        manager = PerformanceConfigManager()
        config = manager.get_config()
        assert isinstance(config, PerformanceConfig)
    
    def test_manager_get_provider_config(self):
        """Testa obtenção de configuração de provedor específico"""
        manager = PerformanceConfigManager()
        
        openai_config = manager.get_provider_config('openai')
        assert openai_config.name == 'openai'
        
        # Provedor inexistente deve retornar None
        non_existent = manager.get_provider_config('non_existent')
        assert non_existent is None
    
    def test_manager_update_config(self):
        """Testa atualização de configuração"""
        manager = PerformanceConfigManager()
        
        new_config = {
            'max_workers': 15,
            'enable_parallel': False,
            'enable_rate_limiting': False,
            'default_timeout': 60.0,
            'max_retries': 5,
            'enable_cache': False,
            'batch_size': 25
        }
        
        manager.update_config(new_config)
        config = manager.config
        
        assert config.max_workers == 15
        assert config.enable_parallel is False
        assert config.enable_rate_limiting is False
        assert config.default_timeout == 60.0
        assert config.max_retries == 5
        assert config.enable_cache is False
        assert config.batch_size == 25
    
    def test_manager_get_stats(self):
        """Testa estatísticas da configuração"""
        manager = PerformanceConfigManager()
        stats = manager.get_stats()
        
        assert 'max_workers' in stats
        assert 'enable_parallel' in stats
        assert 'enable_rate_limiting' in stats
        assert 'default_timeout' in stats
        assert 'max_retries' in stats
        assert 'enable_cache' in stats
        assert 'batch_size' in stats
        assert 'providers' in stats
        assert isinstance(stats['providers'], list)


class TestPerformanceConfigGlobals:
    """Testes para funções globais da performance config"""
    
    def test_get_performance_config(self):
        """Testa obtenção da configuração global"""
        config = get_performance_config()
        assert isinstance(config, PerformanceConfig)
    
    def test_get_provider_config(self):
        """Testa obtenção de configuração de provedor global"""
        openai_config = get_provider_config('openai')
        assert openai_config.name == 'openai'
        
        # Provedor inexistente deve retornar None
        non_existent = get_provider_config('non_existent')
        assert non_existent is None
    
    def test_update_performance_config(self):
        """Testa atualização da configuração global"""
        # Obtém configuração atual
        original_config = get_performance_config()
        original_workers = original_config.max_workers
        
        # Atualiza configuração
        update_performance_config({'max_workers': 999})
        
        # Verifica se foi atualizada
        updated_config = get_performance_config()
        assert updated_config.max_workers == 999
        
        # Restaura configuração original
        update_performance_config({'max_workers': original_workers})
    
    def test_get_performance_stats(self):
        """Testa estatísticas da configuração global"""
        stats = get_performance_stats()
        
        assert 'max_workers' in stats
        assert 'enable_parallel' in stats
        assert 'enable_rate_limiting' in stats
        assert 'default_timeout' in stats
        assert 'max_retries' in stats
        assert 'enable_cache' in stats
        assert 'batch_size' in stats
        assert 'providers' in stats


class TestPerformanceConfigIntegration:
    """Testes de integração da performance config"""
    
    def test_config_consistency(self):
        """Testa consistência da configuração"""
        config = get_performance_config()
        
        # Verifica se todos os provedores têm configurações válidas
        for provider_name, provider_config in config.providers.items():
            assert provider_config.name == provider_name
            assert provider_config.requests_per_minute > 0
            assert provider_config.max_concurrent > 0
            assert provider_config.timeout > 0
            assert provider_config.priority > 0
    
    def test_config_defaults_are_reasonable(self):
        """Testa se os valores padrão são razoáveis"""
        config = get_performance_config()
        
        # Verifica valores padrão gerais
        assert 1 <= config.max_workers <= 50
        assert 1 <= config.max_retries <= 10
        assert 1.0 <= config.default_timeout <= 300.0
        assert 1 <= config.batch_size <= 100
        
        # Verifica valores padrão dos provedores
        for provider_config in config.providers.values():
            assert 50 <= provider_config.requests_per_minute <= 1000
            assert 1 <= provider_config.max_concurrent <= 50
            assert 5.0 <= provider_config.timeout <= 120.0
            assert 1 <= provider_config.priority <= 10 