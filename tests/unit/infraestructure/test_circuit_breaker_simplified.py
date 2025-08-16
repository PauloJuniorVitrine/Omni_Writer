"""
Testes para Circuit Breaker Simplificado

Prompt: Testes para Simplificação - Seção 2.2
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:50:00Z
Tracing ID: SIMPLIFICATION_TESTS_20250127_002

Testes baseados em código real para validar funcionalidades essenciais.
"""

import pytest
import time
from infraestructure.circuit_breaker_simplified_v2 import (
    CircuitBreaker, CircuitBreakerManager, CircuitBreakerConfig, CircuitState,
    CircuitBreakerOpenError, get_circuit_breaker_manager, circuit_breaker_call
)


class TestCircuitBreaker:
    """Testes para CircuitBreaker baseados em código real"""
    
    def test_circuit_breaker_initialization(self):
        """Testa inicialização do circuit breaker"""
        cb = CircuitBreaker("test_cb")
        assert cb.name == "test_cb"
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        assert cb.success_count == 0
    
    def test_circuit_breaker_config(self):
        """Testa configuração do circuit breaker"""
        config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30)
        cb = CircuitBreaker("test_cb", config)
        assert cb.config.failure_threshold == 3
        assert cb.config.recovery_timeout == 30
        assert cb.config.success_threshold == 2
    
    def test_circuit_breaker_successful_call(self):
        """Testa chamada bem-sucedida"""
        cb = CircuitBreaker("test_cb")
        
        def success_func():
            return "success"
        
        result = cb.call(success_func)
        assert result == "success"
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
    
    def test_circuit_breaker_failed_call(self):
        """Testa chamada que falha"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=2))
        
        def fail_func():
            raise ValueError("test error")
        
        # Primeira falha
        with pytest.raises(ValueError):
            cb.call(fail_func)
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 1
        
        # Segunda falha - deve abrir o circuito
        with pytest.raises(ValueError):
            cb.call(fail_func)
        assert cb.state == CircuitState.OPEN
        assert cb.failure_count == 2
    
    def test_circuit_breaker_open_state(self):
        """Testa comportamento quando circuito está aberto"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=1))
        
        def fail_func():
            raise ValueError("test error")
        
        # Falha uma vez para abrir o circuito
        with pytest.raises(ValueError):
            cb.call(fail_func)
        
        assert cb.state == CircuitState.OPEN
        
        # Tentativa de chamada quando aberto deve falhar
        def success_func():
            return "success"
        
        with pytest.raises(CircuitBreakerOpenError):
            cb.call(success_func)
    
    def test_circuit_breaker_recovery(self):
        """Testa recuperação do circuito"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=1, recovery_timeout=1))
        
        def fail_func():
            raise ValueError("test error")
        
        # Falha para abrir o circuito
        with pytest.raises(ValueError):
            cb.call(fail_func)
        
        assert cb.state == CircuitState.OPEN
        
        # Aguarda timeout de recuperação
        time.sleep(1.1)
        
        # Agora deve estar em half-open
        def success_func():
            return "success"
        
        result = cb.call(success_func)
        assert result == "success"
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.success_count == 1
    
    def test_circuit_breaker_half_open_to_closed(self):
        """Testa transição de half-open para closed"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=1, recovery_timeout=1))
        
        # Abre o circuito
        def fail_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            cb.call(fail_func)
        
        # Aguarda recuperação
        time.sleep(1.1)
        
        # Sucessos consecutivos devem fechar o circuito
        def success_func():
            return "success"
        
        cb.call(success_func)  # Primeiro sucesso
        cb.call(success_func)  # Segundo sucesso - deve fechar
        
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        assert cb.success_count == 0
    
    def test_circuit_breaker_half_open_to_open(self):
        """Testa transição de half-open para open"""
        cb = CircuitBreaker("test_cb", CircuitBreakerConfig(failure_threshold=1, recovery_timeout=1))
        
        # Abre o circuito
        def fail_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError):
            cb.call(fail_func)
        
        # Aguarda recuperação
        time.sleep(1.1)
        
        # Falha em half-open deve reabrir o circuito
        with pytest.raises(ValueError):
            cb.call(fail_func)
        
        assert cb.state == CircuitState.OPEN
    
    def test_circuit_breaker_get_state(self):
        """Testa obtenção do estado"""
        cb = CircuitBreaker("test_cb")
        assert cb.get_state() == CircuitState.CLOSED
    
    def test_circuit_breaker_get_stats(self):
        """Testa estatísticas do circuit breaker"""
        cb = CircuitBreaker("test_cb")
        
        stats = cb.get_stats()
        assert stats['name'] == "test_cb"
        assert stats['state'] == CircuitState.CLOSED.value
        assert stats['failure_count'] == 0
        assert stats['success_count'] == 0


class TestCircuitBreakerManager:
    """Testes para CircuitBreakerManager baseados em código real"""
    
    def test_manager_initialization(self):
        """Testa inicialização do manager"""
        manager = CircuitBreakerManager()
        assert len(manager.circuit_breakers) == 0
    
    def test_manager_get_circuit_breaker(self):
        """Testa obtenção de circuit breaker"""
        manager = CircuitBreakerManager()
        
        cb1 = manager.get_circuit_breaker("test_cb1")
        cb2 = manager.get_circuit_breaker("test_cb2")
        
        assert cb1.name == "test_cb1"
        assert cb2.name == "test_cb2"
        assert cb1 is not cb2
        
        # Mesmo nome deve retornar mesma instância
        cb1_again = manager.get_circuit_breaker("test_cb1")
        assert cb1 is cb1_again
    
    def test_manager_call(self):
        """Testa chamada através do manager"""
        manager = CircuitBreakerManager()
        
        def success_func():
            return "success"
        
        result = manager.call("test_cb", success_func)
        assert result == "success"
        
        # Verifica se circuit breaker foi criado
        assert "test_cb" in manager.circuit_breakers
    
    def test_manager_get_all_stats(self):
        """Testa estatísticas de todos os circuit breakers"""
        manager = CircuitBreakerManager()
        
        # Cria alguns circuit breakers
        manager.get_circuit_breaker("cb1")
        manager.get_circuit_breaker("cb2")
        
        stats = manager.get_all_stats()
        assert "cb1" in stats
        assert "cb2" in stats
        assert stats["cb1"]["name"] == "cb1"
        assert stats["cb2"]["name"] == "cb2"


class TestCircuitBreakerGlobals:
    """Testes para funções globais do circuit breaker"""
    
    def test_get_circuit_breaker_manager(self):
        """Testa obtenção do manager global"""
        manager = get_circuit_breaker_manager()
        assert isinstance(manager, CircuitBreakerManager)
    
    def test_circuit_breaker_call_helper(self):
        """Testa função helper de chamada"""
        def success_func():
            return "success"
        
        result = circuit_breaker_call("test_cb", success_func)
        assert result == "success"


class TestCircuitBreakerConfigurations:
    """Testes para configurações do circuit breaker"""
    
    def test_circuit_breaker_config_defaults(self):
        """Testa configurações padrão"""
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.recovery_timeout == 60
        assert config.success_threshold == 2
    
    def test_circuit_breaker_config_custom(self):
        """Testa configurações customizadas"""
        config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30, success_threshold=1)
        assert config.failure_threshold == 3
        assert config.recovery_timeout == 30
        assert config.success_threshold == 1
    
    def test_circuit_state_enum(self):
        """Testa enum de estados"""
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open" 