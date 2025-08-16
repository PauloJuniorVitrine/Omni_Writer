"""
Testes para Adaptive Rate Limiter - Rate Limiting Inteligente

Prompt: Testes para Adaptive Rate Limiting - Seção 3.2
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T20:35:00Z
Tracing ID: TEST_ADAPTIVE_RATE_LIMITER_20250127_004

Testes baseados em código real do sistema Omni Writer.
"""

import pytest
import time
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import List, Dict, Any

from app.middleware.rate_limiter import (
    AdaptiveRateLimitConfig,
    RateLimitEntry,
    AdaptiveMetrics,
    AdaptiveRateLimitStore,
    AdaptiveRateLimiter
)


class TestAdaptiveRateLimitConfig:
    """Testes para configuração de rate limiting adaptativo"""
    
    def test_config_initialization(self):
        """Testa inicialização da configuração"""
        config = AdaptiveRateLimitConfig()
        
        # Verifica limites por IP
        assert 'general' in config.ip_limits
        assert 'generation' in config.ip_limits
        assert 'auth' in config.ip_limits
        
        # Verifica limites por usuário
        assert 'general' in config.user_limits
        assert 'generation' in config.user_limits
        assert 'auth' in config.user_limits
        
        # Verifica limites premium
        assert 'general' in config.premium_limits
        assert 'generation' in config.premium_limits
        assert 'auth' in config.premium_limits
        
        # Verifica configurações adaptativas
        assert 'monitoring_window' in config.adaptive_config
        assert 'adjustment_threshold' in config.adaptive_config
        assert 'max_adjustment_factor' in config.adaptive_config
        assert 'min_adjustment_factor' in config.adaptive_config
    
    def test_ip_limits_structure(self):
        """Testa estrutura dos limites por IP"""
        config = AdaptiveRateLimitConfig()
        
        for limit_type, limits in config.ip_limits.items():
            assert 'requests' in limits
            assert 'window' in limits
            assert isinstance(limits['requests'], int)
            assert isinstance(limits['window'], int)
            assert limits['requests'] > 0
            assert limits['window'] > 0
    
    def test_user_limits_structure(self):
        """Testa estrutura dos limites por usuário"""
        config = AdaptiveRateLimitConfig()
        
        for limit_type, limits in config.user_limits.items():
            assert 'requests' in limits
            assert 'window' in limits
            assert isinstance(limits['requests'], int)
            assert isinstance(limits['window'], int)
            assert limits['requests'] > 0
            assert limits['window'] > 0
    
    def test_premium_limits_higher_than_regular(self):
        """Testa se limites premium são maiores que regulares"""
        config = AdaptiveRateLimitConfig()
        
        for limit_type in config.user_limits:
            if limit_type in config.premium_limits:
                assert config.premium_limits[limit_type]['requests'] >= config.user_limits[limit_type]['requests']


class TestRateLimitEntry:
    """Testes para entrada de rate limiting"""
    
    def test_entry_creation(self):
        """Testa criação de entrada de rate limiting"""
        entry = RateLimitEntry(
            timestamp=time.time(),
            endpoint="/api/generate",
            method="POST",
            user_id="user123",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            response_time=1.5,
            success=True,
            error_type=None
        )
        
        assert entry.endpoint == "/api/generate"
        assert entry.method == "POST"
        assert entry.user_id == "user123"
        assert entry.ip_address == "192.168.1.1"
        assert entry.user_agent == "Mozilla/5.0"
        assert entry.response_time == 1.5
        assert entry.success is True
        assert entry.error_type is None
    
    def test_entry_defaults(self):
        """Testa valores padrão da entrada"""
        entry = RateLimitEntry(
            timestamp=time.time(),
            endpoint="/api/test",
            method="GET"
        )
        
        assert entry.user_id is None
        assert entry.ip_address == ""
        assert entry.user_agent == ""
        assert entry.response_time == 0.0
        assert entry.success is True
        assert entry.error_type is None


class TestAdaptiveMetrics:
    """Testes para métricas adaptativas"""
    
    def test_metrics_initialization(self):
        """Testa inicialização das métricas"""
        metrics = AdaptiveMetrics()
        
        assert metrics.request_count == 0
        assert metrics.success_rate == 1.0
        assert metrics.avg_response_time == 0.0
        assert metrics.error_rate == 0.0
        assert metrics.peak_usage == 0.0
        assert metrics.last_adjustment == 0.0
        assert metrics.adjustment_factor == 1.0
    
    def test_metrics_custom_values(self):
        """Testa métricas com valores customizados"""
        metrics = AdaptiveMetrics(
            request_count=100,
            success_rate=0.95,
            avg_response_time=2.5,
            error_rate=0.05,
            peak_usage=time.time(),
            last_adjustment=time.time(),
            adjustment_factor=1.2
        )
        
        assert metrics.request_count == 100
        assert metrics.success_rate == 0.95
        assert metrics.avg_response_time == 2.5
        assert metrics.error_rate == 0.05
        assert metrics.adjustment_factor == 1.2


class TestAdaptiveRateLimitStore:
    """Testes para armazenamento adaptativo"""
    
    @pytest.fixture
    def store_memory(self):
        """Fixture para store em memória"""
        return AdaptiveRateLimitStore(use_redis=False)
    
    @pytest.fixture
    def store_redis(self):
        """Fixture para store com Redis"""
        with patch('redis.Redis') as mock_redis:
            mock_redis.return_value.ping.return_value = True
            return AdaptiveRateLimitStore(use_redis=True)
    
    def test_store_initialization_memory(self, store_memory):
        """Testa inicialização do store em memória"""
        assert store_memory.use_redis is False
        assert hasattr(store_memory, 'memory_store')
        assert hasattr(store_memory, 'lock')
        assert hasattr(store_memory, 'adaptive_metrics')
    
    def test_store_initialization_redis(self, store_redis):
        """Testa inicialização do store com Redis"""
        assert store_redis.use_redis is True
        assert hasattr(store_redis, 'redis_client')
        assert hasattr(store_redis, 'adaptive_metrics')
    
    def test_add_request_memory(self, store_memory):
        """Testa adição de requisição em memória"""
        entry = RateLimitEntry(
            timestamp=time.time(),
            endpoint="/api/test",
            method="GET"
        )
        
        store_memory.add_request("test_key", entry, 60)
        
        with store_memory.lock:
            assert len(store_memory.memory_store["test_key"]) == 1
            assert store_memory.memory_store["test_key"][0] == entry
    
    def test_get_request_count_memory(self, store_memory):
        """Testa contagem de requisições em memória"""
        current_time = time.time()
        
        # Adiciona requisições em diferentes momentos
        entry1 = RateLimitEntry(timestamp=current_time - 30, endpoint="/api/test", method="GET")
        entry2 = RateLimitEntry(timestamp=current_time - 10, endpoint="/api/test", method="GET")
        entry3 = RateLimitEntry(timestamp=current_time - 70, endpoint="/api/test", method="GET")  # Expirada
        
        store_memory.add_request("test_key", entry1, 60)
        store_memory.add_request("test_key", entry2, 60)
        store_memory.add_request("test_key", entry3, 60)
        
        count = store_memory.get_request_count("test_key", 60)
        assert count == 2  # Apenas as 2 requisições dentro da janela
    
    def test_get_remaining_requests(self, store_memory):
        """Testa cálculo de requisições restantes"""
        entry = RateLimitEntry(
            timestamp=time.time(),
            endpoint="/api/test",
            method="GET"
        )
        
        store_memory.add_request("test_key", entry, 60)
        
        remaining = store_memory.get_remaining_requests("test_key", 10, 60)
        assert remaining == 9  # 10 - 1 = 9
    
    def test_get_reset_time_memory(self, store_memory):
        """Testa cálculo do tempo de reset"""
        current_time = time.time()
        entry = RateLimitEntry(
            timestamp=current_time,
            endpoint="/api/test",
            method="GET"
        )
        
        store_memory.add_request("test_key", entry, 60)
        
        reset_time = store_memory.get_reset_time("test_key", 60)
        assert reset_time == current_time + 60


class TestAdaptiveRateLimiter:
    """Testes para rate limiter adaptativo"""
    
    @pytest.fixture
    def rate_limiter(self):
        """Fixture para rate limiter"""
        with patch('threading.Thread') as mock_thread:
            return AdaptiveRateLimiter(use_redis=False)
    
    def test_rate_limiter_initialization(self, rate_limiter):
        """Testa inicialização do rate limiter"""
        assert rate_limiter.config is not None
        assert rate_limiter.store is not None
        assert len(rate_limiter.premium_users) > 0
        assert len(rate_limiter.exempt_endpoints) > 0
        assert len(rate_limiter.provider_fallback) > 0
    
    def test_get_client_ip(self, rate_limiter):
        """Testa obtenção do IP do cliente"""
        with patch('flask.request') as mock_request:
            mock_request.remote_addr = "192.168.1.100"
            mock_request.headers = {}
            
            ip = rate_limiter._get_client_ip()
            assert ip == "192.168.1.100"
    
    def test_get_client_ip_with_proxy(self, rate_limiter):
        """Testa obtenção do IP do cliente com proxy"""
        with patch('flask.request') as mock_request:
            mock_request.remote_addr = "10.0.0.1"
            mock_request.headers = {
                'X-Forwarded-For': '192.168.1.100, 10.0.0.2'
            }
            
            ip = rate_limiter._get_client_ip()
            assert ip == "192.168.1.100"
    
    def test_get_user_id_authenticated(self, rate_limiter):
        """Testa obtenção do ID do usuário autenticado"""
        with patch('flask.g') as mock_g:
            mock_g.user = Mock()
            mock_g.user.id = "user123"
            
            user_id = rate_limiter._get_user_id()
            assert user_id == "user123"
    
    def test_get_user_id_unauthenticated(self, rate_limiter):
        """Testa obtenção do ID do usuário não autenticado"""
        with patch('flask.g') as mock_g:
            mock_g.user = None
            
            user_id = rate_limiter._get_user_id()
            assert user_id is None
    
    def test_determine_rate_limit_type(self, rate_limiter):
        """Testa determinação do tipo de rate limit"""
        assert rate_limiter._determine_rate_limit_type("/api/generate") == "generation"
        assert rate_limiter._determine_rate_limit_type("/api/auth/login") == "auth"
        assert rate_limiter._determine_rate_limit_type("/api/download") == "download"
        assert rate_limiter._determine_rate_limit_type("/api/feedback") == "feedback"
        assert rate_limiter._determine_rate_limit_type("/api/test") == "general"
    
    def test_get_adaptive_limit(self, rate_limiter):
        """Testa obtenção de limite adaptativo"""
        # Testa sem ajuste
        limit = rate_limiter._get_adaptive_limit(100, "test_key")
        assert limit == 100
        
        # Testa com ajuste
        metrics = AdaptiveMetrics(adjustment_factor=1.5)
        rate_limiter.store.adaptive_metrics["test_key"] = metrics
        
        limit = rate_limiter._get_adaptive_limit(100, "test_key")
        assert limit == 150
    
    def test_apply_intelligent_backoff(self, rate_limiter):
        """Testa aplicação de backoff inteligente"""
        # Testa backoff para diferentes números de violações
        backoff1 = rate_limiter._apply_intelligent_backoff("test_key", 1)
        backoff2 = rate_limiter._apply_intelligent_backoff("test_key", 2)
        backoff3 = rate_limiter._apply_intelligent_backoff("test_key", 5)
        
        assert backoff2 > backoff1
        assert backoff3 > backoff2
        assert backoff3 <= 300  # Máximo 5 minutos
    
    def test_handle_provider_fallback(self, rate_limiter):
        """Testa fallback entre provedores"""
        # Testa fallback válido
        fallback = rate_limiter._handle_provider_fallback("openai", "rate_limit_exceeded")
        assert fallback in ["deepseek", "claude"]
        
        # Testa provedor sem fallback
        fallback = rate_limiter._handle_provider_fallback("unknown", "error")
        assert fallback is None
    
    def test_detect_anomaly(self, rate_limiter):
        """Testa detecção de comportamento anômalo"""
        # Testa IP bloqueado
        rate_limiter.anomaly_patterns['suspicious_ips'].add("192.168.1.100")
        is_anomaly = rate_limiter._detect_anomaly("192.168.1.100", "Mozilla/5.0", Mock())
        assert is_anomaly is True
        
        # Testa user agent suspeito
        is_anomaly = rate_limiter._detect_anomaly("192.168.1.101", "curl/7.68.0", Mock())
        assert is_anomaly is True
        
        # Testa comportamento normal
        is_anomaly = rate_limiter._detect_anomaly("192.168.1.102", "Mozilla/5.0", Mock())
        assert is_anomaly is False


class TestRateLimiterIntegration:
    """Testes de integração do rate limiter"""
    
    @pytest.fixture
    def rate_limiter(self):
        """Fixture para rate limiter"""
        with patch('threading.Thread') as mock_thread:
            return AdaptiveRateLimiter(use_redis=False)
    
    def test_before_request_flow(self, rate_limiter):
        """Testa fluxo completo do before_request"""
        with patch('flask.request') as mock_request:
            with patch('flask.g') as mock_g:
                # Configura mocks
                mock_request.endpoint = "/api/generate"
                mock_request.method = "POST"
                mock_request.remote_addr = "192.168.1.100"
                mock_request.headers = {"User-Agent": "Mozilla/5.0"}
                mock_g.user = None
                
                # Mock do store
                with patch.object(rate_limiter.store, 'get_request_count') as mock_count:
                    with patch.object(rate_limiter.store, 'add_request') as mock_add:
                        mock_count.return_value = 5  # 5 requisições já feitas
                        
                        # Executa before_request
                        rate_limiter.before_request()
                        
                        # Verifica se a requisição foi registrada
                        mock_add.assert_called()
    
    def test_after_request_flow(self, rate_limiter):
        """Testa fluxo completo do after_request"""
        with patch('flask.request') as mock_request:
            with patch('flask.g') as mock_g:
                # Configura mocks
                mock_request.endpoint = "/api/generate"
                mock_request.method = "POST"
                mock_request.remote_addr = "192.168.1.100"
                mock_request.headers = {"User-Agent": "Mozilla/5.0"}
                mock_g.user = None
                
                # Mock da resposta
                mock_response = Mock()
                mock_response.status_code = 200
                
                # Mock do store
                with patch.object(rate_limiter.store, 'add_request') as mock_add:
                    # Executa after_request
                    result = rate_limiter.after_request(mock_response)
                    
                    # Verifica se a requisição foi registrada com metadados
                    mock_add.assert_called()
                    assert result == mock_response


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 