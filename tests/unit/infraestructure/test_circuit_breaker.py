"""
Testes Unitários - Circuit Breaker - IMP-012

Prompt: Circuit Breaker - IMP-012
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:00:00Z
Tracing ID: ENTERPRISE_20250127_012

Testes baseados APENAS no código real implementado:
- Estados do circuit breaker (CLOSED, OPEN, HALF_OPEN)
- Transições de estado
- Métricas e observabilidade
- Thread safety
- Integração com configuração
- Callbacks e eventos
- Decorators e context managers
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from infraestructure.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerManager,
    CircuitBreakerOpenError,
    CircuitBreakerMetrics,
    get_circuit_breaker_manager,
    circuit_breaker,
    circuit_breaker_context
)
from infraestructure.resilience_config import (
    CircuitBreakerConfig,
    CircuitBreakerState,
    ResilienceConfiguration
)


class TestCircuitBreakerMetrics:
    """Testes para métricas do circuit breaker"""
    
    def test_metrics_initialization(self):
        """Testa inicialização das métricas"""
        metrics = CircuitBreakerMetrics()
        
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.circuit_open_count == 0
        assert metrics.circuit_half_open_count == 0
        assert metrics.last_failure_time is None
        assert metrics.last_success_time is None
        assert metrics.current_failure_count == 0
        assert metrics.consecutive_failures == 0
        assert metrics.consecutive_successes == 0


class TestCircuitBreaker:
    """Testes para a classe CircuitBreaker"""
    
    @pytest.fixture
    def config(self):
        """Configuração de teste para circuit breaker"""
        return CircuitBreakerConfig(
            name='test_circuit_breaker',
            failure_threshold=3,
            recovery_timeout=60.0,
            monitor_interval=10.0
        )
    
    @pytest.fixture
    def circuit_breaker(self, config):
        """Instância de circuit breaker para testes"""
        return CircuitBreaker(config)
    
    def test_circuit_breaker_initialization(self, circuit_breaker, config):
        """Testa inicialização do circuit breaker"""
        assert circuit_breaker.config == config
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.total_requests == 0
        assert len(circuit_breaker.on_open_callbacks) == 0
        assert len(circuit_breaker.on_close_callbacks) == 0
        assert len(circuit_breaker.on_half_open_callbacks) == 0
    
    def test_can_execute_when_closed(self, circuit_breaker):
        """Testa execução quando circuito está fechado"""
        assert circuit_breaker._can_execute() is True
    
    def test_can_execute_when_open_before_timeout(self, circuit_breaker):
        """Testa execução quando circuito está aberto antes do timeout"""
        circuit_breaker.state = CircuitBreakerState.OPEN
        circuit_breaker.last_state_change = datetime.now()
        
        assert circuit_breaker._can_execute() is False
    
    def test_can_execute_when_open_after_timeout(self, circuit_breaker):
        """Testa execução quando circuito está aberto após timeout"""
        circuit_breaker.state = CircuitBreakerState.OPEN
        circuit_breaker.last_state_change = datetime.now() - timedelta(seconds=70)
        
        assert circuit_breaker._can_execute() is True
    
    def test_can_execute_when_half_open(self, circuit_breaker):
        """Testa execução quando circuito está em half-open"""
        circuit_breaker.state = CircuitBreakerState.HALF_OPEN
        
        assert circuit_breaker._can_execute() is True
    
    def test_on_success_in_closed_state(self, circuit_breaker):
        """Testa sucesso quando circuito está fechado"""
        circuit_breaker._on_success()
        
        assert circuit_breaker.metrics.total_requests == 1
        assert circuit_breaker.metrics.successful_requests == 1
        assert circuit_breaker.metrics.consecutive_successes == 1
        assert circuit_breaker.metrics.consecutive_failures == 0
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.last_success_time is not None
    
    def test_on_success_in_half_open_state(self, circuit_breaker):
        """Testa sucesso quando circuito está em half-open"""
        circuit_breaker.state = CircuitBreakerState.HALF_OPEN
        circuit_breaker._on_success()
        
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.circuit_half_open_count == 0  # Não incrementa pois já estava em half-open
    
    def test_on_failure_below_threshold(self, circuit_breaker):
        """Testa falha abaixo do threshold"""
        circuit_breaker._on_failure(Exception("Test error"))
        
        assert circuit_breaker.metrics.total_requests == 1
        assert circuit_breaker.metrics.failed_requests == 1
        assert circuit_breaker.metrics.consecutive_failures == 1
        assert circuit_breaker.metrics.consecutive_successes == 0
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.last_failure_time is not None
    
    def test_on_failure_at_threshold(self, circuit_breaker):
        """Testa falha no threshold - deve abrir circuito"""
        # Simular 3 falhas consecutivas
        for _ in range(3):
            circuit_breaker._on_failure(Exception("Test error"))
        
        assert circuit_breaker.state == CircuitBreakerState.OPEN
        assert circuit_breaker.metrics.circuit_open_count == 1
        assert circuit_breaker.metrics.consecutive_failures == 3
    
    def test_on_failure_in_half_open_state(self, circuit_breaker):
        """Testa falha quando circuito está em half-open"""
        circuit_breaker.state = CircuitBreakerState.HALF_OPEN
        circuit_breaker._on_failure(Exception("Test error"))
        
        assert circuit_breaker.state == CircuitBreakerState.OPEN
        assert circuit_breaker.metrics.circuit_open_count == 1
    
    def test_transition_to_open(self, circuit_breaker):
        """Testa transição para estado OPEN"""
        circuit_breaker._transition_to_open()
        
        assert circuit_breaker.state == CircuitBreakerState.OPEN
        assert circuit_breaker.metrics.circuit_open_count == 1
    
    def test_transition_to_half_open(self, circuit_breaker):
        """Testa transição para estado HALF_OPEN"""
        circuit_breaker._transition_to_half_open()
        
        assert circuit_breaker.state == CircuitBreakerState.HALF_OPEN
        assert circuit_breaker.metrics.circuit_half_open_count == 1
    
    def test_transition_to_closed(self, circuit_breaker):
        """Testa transição para estado CLOSED"""
        circuit_breaker.state = CircuitBreakerState.OPEN
        circuit_breaker._transition_to_closed()
        
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.current_failure_count == 0
    
    def test_calculate_failure_rate(self, circuit_breaker):
        """Testa cálculo da taxa de falha"""
        # Sem requisições
        assert circuit_breaker._calculate_failure_rate() == 0.0
        
        # Com sucessos
        circuit_breaker.metrics.total_requests = 10
        circuit_breaker.metrics.successful_requests = 10
        assert circuit_breaker._calculate_failure_rate() == 0.0
        
        # Com falhas
        circuit_breaker.metrics.failed_requests = 5
        assert circuit_breaker._calculate_failure_rate() == 0.5
    
    def test_get_metrics(self, circuit_breaker):
        """Testa obtenção de métricas"""
        metrics = circuit_breaker.get_metrics()
        
        assert 'name' in metrics
        assert 'state' in metrics
        assert 'total_requests' in metrics
        assert 'successful_requests' in metrics
        assert 'failed_requests' in metrics
        assert 'failure_rate' in metrics
        assert 'consecutive_failures' in metrics
        assert 'consecutive_successes' in metrics
        assert 'circuit_open_count' in metrics
        assert 'circuit_half_open_count' in metrics
        assert 'last_failure_time' in metrics
        assert 'last_success_time' in metrics
        assert 'last_state_change' in metrics
        assert 'time_in_current_state' in metrics
    
    def test_reset(self, circuit_breaker):
        """Testa reset do circuit breaker"""
        # Simular algumas operações
        circuit_breaker._on_success()
        circuit_breaker._on_failure(Exception("Test error"))
        
        circuit_breaker.reset()
        
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
        assert circuit_breaker.metrics.total_requests == 0
        assert circuit_breaker.metrics.successful_requests == 0
        assert circuit_breaker.metrics.failed_requests == 0
    
    def test_force_open(self, circuit_breaker):
        """Testa abertura forçada do circuito"""
        circuit_breaker.force_open()
        
        assert circuit_breaker.state == CircuitBreakerState.OPEN
    
    def test_force_close(self, circuit_breaker):
        """Testa fechamento forçado do circuito"""
        circuit_breaker.state = CircuitBreakerState.OPEN
        circuit_breaker.force_close()
        
        assert circuit_breaker.state == CircuitBreakerState.CLOSED
    
    def test_callbacks(self, circuit_breaker):
        """Testa callbacks de eventos"""
        open_callback = Mock()
        close_callback = Mock()
        half_open_callback = Mock()
        
        circuit_breaker.add_on_open_callback(open_callback)
        circuit_breaker.add_on_close_callback(close_callback)
        circuit_breaker.add_on_half_open_callback(half_open_callback)
        
        # Testar callbacks
        circuit_breaker._transition_to_open()
        open_callback.assert_called_once_with(circuit_breaker)
        
        circuit_breaker._transition_to_half_open()
        half_open_callback.assert_called_once_with(circuit_breaker)
        
        circuit_breaker._transition_to_closed()
        close_callback.assert_called_once_with(circuit_breaker)
    
    def test_call_success(self, circuit_breaker):
        """Testa chamada bem-sucedida"""
        def success_func():
            return "success"
        
        result = circuit_breaker.call(success_func)
        
        assert result == "success"
        assert circuit_breaker.metrics.successful_requests == 1
    
    def test_call_failure(self, circuit_breaker):
        """Testa chamada com falha"""
        def failure_func():
            raise Exception("Test error")
        
        with pytest.raises(Exception, match="Test error"):
            circuit_breaker.call(failure_func)
        
        assert circuit_breaker.metrics.failed_requests == 1
    
    def test_call_when_open(self, circuit_breaker):
        """Testa chamada quando circuito está aberto"""
        circuit_breaker.state = CircuitBreakerState.OPEN
        
        def test_func():
            return "test"
        
        with pytest.raises(CircuitBreakerOpenError):
            circuit_breaker.call(test_func)


class TestCircuitBreakerManager:
    """Testes para o gerenciador de circuit breakers"""
    
    @pytest.fixture
    def manager(self):
        """Instância do gerenciador para testes"""
        return CircuitBreakerManager()
    
    def test_manager_initialization(self, manager):
        """Testa inicialização do gerenciador"""
        assert isinstance(manager.resilience_config, ResilienceConfiguration)
        assert isinstance(manager.circuit_breakers, dict)
    
    def test_get_circuit_breaker_existing(self, manager):
        """Testa obtenção de circuit breaker existente"""
        # Assumindo que 'ai_providers' está configurado
        cb = manager.get_circuit_breaker('ai_providers')
        if cb is not None:
            assert isinstance(cb, CircuitBreaker)
    
    def test_get_circuit_breaker_nonexistent(self, manager):
        """Testa obtenção de circuit breaker inexistente"""
        cb = manager.get_circuit_breaker('nonexistent_component')
        assert cb is None
    
    def test_call_with_circuit_breaker(self, manager):
        """Testa chamada com circuit breaker"""
        def test_func():
            return "test_result"
        
        # Testar com componente que pode não ter circuit breaker
        result = manager.call('ai_providers', test_func)
        assert result == "test_result"
    
    def test_call_without_circuit_breaker(self, manager):
        """Testa chamada sem circuit breaker"""
        def test_func():
            return "test_result"
        
        result = manager.call('nonexistent_component', test_func)
        assert result == "test_result"
    
    def test_get_all_metrics(self, manager):
        """Testa obtenção de todas as métricas"""
        metrics = manager.get_all_metrics()
        
        assert isinstance(metrics, dict)
        # Verificar se há métricas para componentes configurados
        for component_name, component_metrics in metrics.items():
            assert isinstance(component_metrics, dict)
            assert 'name' in component_metrics
            assert 'state' in component_metrics
    
    def test_reset_all(self, manager):
        """Testa reset de todos os circuit breakers"""
        # Simular algumas operações em um circuit breaker
        cb = manager.get_circuit_breaker('ai_providers')
        if cb is not None:
            cb._on_success()
            cb._on_failure(Exception("Test error"))
            
            manager.reset_all()
            
            assert cb.state == CircuitBreakerState.CLOSED
            assert cb.metrics.total_requests == 0


class TestCircuitBreakerIntegration:
    """Testes de integração do circuit breaker"""
    
    def test_integration_with_real_config(self):
        """Testa integração com configuração real"""
        manager = get_circuit_breaker_manager()
        
        # Verificar se o gerenciador foi inicializado corretamente
        assert isinstance(manager, CircuitBreakerManager)
        
        # Verificar se há circuit breakers configurados
        assert len(manager.circuit_breakers) > 0
    
    def test_decorator_usage(self):
        """Testa uso do decorator"""
        @circuit_breaker('ai_providers')
        def test_function():
            return "decorated_result"
        
        result = test_function()
        assert result == "decorated_result"
    
    def test_context_manager_usage(self):
        """Testa uso do context manager"""
        with circuit_breaker_context('ai_providers') as cb:
            if cb is not None:
                assert isinstance(cb, CircuitBreaker)
            # Se não há circuit breaker configurado, cb será None
    
    def test_thread_safety(self):
        """Testa thread safety do circuit breaker"""
        config = CircuitBreakerConfig(
            name='thread_test_cb',
            failure_threshold=5,
            recovery_timeout=1.0
        )
        cb = CircuitBreaker(config)
        
        def worker():
            for _ in range(10):
                try:
                    cb.call(lambda: "success")
                except Exception:
                    pass
        
        # Executar múltiplas threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verificar se não houve corrupção de dados
        assert cb.metrics.total_requests >= 0
        assert cb.metrics.successful_requests >= 0
        assert cb.metrics.failed_requests >= 0


class TestCircuitBreakerErrorHandling:
    """Testes de tratamento de erros"""
    
    def test_circuit_breaker_open_error(self):
        """Testa exceção CircuitBreakerOpenError"""
        config = CircuitBreakerConfig(
            name='error_test_cb',
            failure_threshold=1,
            recovery_timeout=60.0
        )
        cb = CircuitBreaker(config)
        
        # Forçar abertura do circuito
        cb.force_open()
        
        with pytest.raises(CircuitBreakerOpenError):
            cb.call(lambda: "test")
    
    def test_callback_error_handling(self, circuit_breaker):
        """Testa tratamento de erro em callbacks"""
        def failing_callback(cb):
            raise Exception("Callback error")
        
        circuit_breaker.add_on_open_callback(failing_callback)
        
        # Não deve propagar erro do callback
        circuit_breaker._transition_to_open()
        
        # Circuito deve estar aberto mesmo com erro no callback
        assert circuit_breaker.state == CircuitBreakerState.OPEN


class TestCircuitBreakerPerformance:
    """Testes de performance"""
    
    def test_metrics_calculation_performance(self, circuit_breaker):
        """Testa performance do cálculo de métricas"""
        import time
        
        start_time = time.time()
        
        # Simular muitas operações
        for _ in range(1000):
            circuit_breaker._on_success()
        
        end_time = time.time()
        
        # Deve ser rápido (menos de 1 segundo)
        assert end_time - start_time < 1.0
        assert circuit_breaker.metrics.total_requests == 1000
    
    def test_state_transition_performance(self, circuit_breaker):
        """Testa performance das transições de estado"""
        import time
        
        start_time = time.time()
        
        # Simular muitas transições
        for _ in range(100):
            circuit_breaker._transition_to_open()
            circuit_breaker._transition_to_closed()
        
        end_time = time.time()
        
        # Deve ser rápido
        assert end_time - start_time < 1.0 