"""
Circuit Breaker Implementation - IMP-012

Prompt: Circuit Breaker - IMP-012
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:00:00Z
Tracing ID: ENTERPRISE_20250127_012

Implementação completa do padrão Circuit Breaker com:
- Estados: CLOSED, OPEN, HALF_OPEN
- Métricas e observabilidade
- Integração com sistema de logging estruturado
- Configuração centralizada
- Thread safety
- Fallback automático
"""

import time
import threading
import functools
from typing import Any, Callable, Optional, Dict, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
from contextlib import contextmanager

from infraestructure.resilience_config import (
    CircuitBreakerConfig, 
    CircuitBreakerState, 
    FailureType,
    ResilienceConfiguration
)
from shared.logger import get_logger


@dataclass
class CircuitBreakerMetrics:
    """Métricas do circuit breaker"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    circuit_open_count: int = 0
    circuit_half_open_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    current_failure_count: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class CircuitBreaker:
    """
    Implementação do padrão Circuit Breaker.
    
    Estados:
    - CLOSED: Circuito funcionando normalmente
    - OPEN: Circuito aberto, requisições bloqueadas
    - HALF_OPEN: Circuito testando recuperação
    """
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.metrics = CircuitBreakerMetrics()
        self.last_state_change = datetime.now()
        self._lock = threading.RLock()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Callbacks para eventos
        self.on_open_callbacks: List[Callable] = []
        self.on_close_callbacks: List[Callable] = []
        self.on_half_open_callbacks: List[Callable] = []
        
        self.logger.info(
            f"Circuit Breaker '{config.name}' inicializado",
            extra={
                'event': 'circuit_breaker_init',
                'component': config.name,
                'failure_threshold': config.failure_threshold,
                'recovery_timeout': config.recovery_timeout
            }
        )
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Executa função protegida pelo circuit breaker.
        
        Args:
            func: Função a ser executada
            *args: Argumentos da função
            **kwargs: Argumentos nomeados da função
            
        Returns:
            Resultado da função
            
        Raises:
            CircuitBreakerOpenError: Se circuito estiver aberto
            Exception: Exceção original da função
        """
        with self._lock:
            if not self._can_execute():
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.config.name}' está aberto"
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise
    
    def _can_execute(self) -> bool:
        """Verifica se pode executar requisição"""
        now = datetime.now()
        
        if self.state == CircuitBreakerState.CLOSED:
            return True
        
        elif self.state == CircuitBreakerState.OPEN:
            if now - self.last_state_change >= timedelta(seconds=self.config.recovery_timeout):
                self._transition_to_half_open()
                return True
            return False
        
        elif self.state == CircuitBreakerState.HALF_OPEN:
            return True
        
        return False
    
    def _on_success(self):
        """Chamado quando requisição é bem-sucedida"""
        with self._lock:
            self.metrics.total_requests += 1
            self.metrics.successful_requests += 1
            self.metrics.consecutive_successes += 1
            self.metrics.consecutive_failures = 0
            self.metrics.last_success_time = datetime.now()
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                self._transition_to_closed()
            
            self._log_metrics('success')
    
    def _on_failure(self, exception: Exception):
        """Chamado quando requisição falha"""
        with self._lock:
            self.metrics.total_requests += 1
            self.metrics.failed_requests += 1
            self.metrics.consecutive_failures += 1
            self.metrics.consecutive_successes = 0
            self.metrics.last_failure_time = datetime.now()
            self.metrics.current_failure_count += 1
            
            if (self.state == CircuitBreakerState.CLOSED and 
                self.metrics.consecutive_failures >= self.config.failure_threshold):
                self._transition_to_open()
            elif self.state == CircuitBreakerState.HALF_OPEN:
                self._transition_to_open()
            
            self._log_metrics('failure', exception)
    
    def _transition_to_open(self):
        """Transição para estado OPEN"""
        if self.state != CircuitBreakerState.OPEN:
            old_state = self.state
            self.state = CircuitBreakerState.OPEN
            self.last_state_change = datetime.now()
            self.metrics.circuit_open_count += 1
            
            self.logger.warning(
                f"Circuit breaker '{self.config.name}' aberto",
                extra={
                    'event': 'circuit_breaker_open',
                    'component': self.config.name,
                    'previous_state': old_state.value,
                    'failure_count': self.metrics.consecutive_failures,
                    'failure_threshold': self.config.failure_threshold
                }
            )
            
            for callback in self.on_open_callbacks:
                try:
                    callback(self)
                except Exception as e:
                    self.logger.error(f"Erro em callback on_open: {e}")
    
    def _transition_to_half_open(self):
        """Transição para estado HALF_OPEN"""
        if self.state != CircuitBreakerState.HALF_OPEN:
            old_state = self.state
            self.state = CircuitBreakerState.HALF_OPEN
            self.last_state_change = datetime.now()
            self.metrics.circuit_half_open_count += 1
            
            self.logger.info(
                f"Circuit breaker '{self.config.name}' em half-open",
                extra={
                    'event': 'circuit_breaker_half_open',
                    'component': self.config.name,
                    'previous_state': old_state.value
                }
            )
            
            for callback in self.on_half_open_callbacks:
                try:
                    callback(self)
                except Exception as e:
                    self.logger.error(f"Erro em callback on_half_open: {e}")
    
    def _transition_to_closed(self):
        """Transição para estado CLOSED"""
        if self.state != CircuitBreakerState.CLOSED:
            old_state = self.state
            self.state = CircuitBreakerState.CLOSED
            self.last_state_change = datetime.now()
            self.metrics.current_failure_count = 0
            
            self.logger.info(
                f"Circuit breaker '{self.config.name}' fechado",
                extra={
                    'event': 'circuit_breaker_closed',
                    'component': self.config.name,
                    'previous_state': old_state.value
                }
            )
            
            for callback in self.on_close_callbacks:
                try:
                    callback(self)
                except Exception as e:
                    self.logger.error(f"Erro em callback on_close: {e}")
    
    def _log_metrics(self, event_type: str, exception: Optional[Exception] = None):
        """Loga métricas do circuit breaker"""
        if not self.config.enable_logging:
            return
        
        extra_data = {
            'event': f'circuit_breaker_{event_type}',
            'component': self.config.name,
            'state': self.state.value,
            'total_requests': self.metrics.total_requests,
            'successful_requests': self.metrics.successful_requests,
            'failed_requests': self.metrics.failed_requests,
            'consecutive_failures': self.metrics.consecutive_failures,
            'consecutive_successes': self.metrics.consecutive_successes,
            'failure_rate': self._calculate_failure_rate()
        }
        
        if exception:
            extra_data['exception'] = str(exception)
            extra_data['exception_type'] = type(exception).__name__
        
        if event_type == 'failure':
            self.logger.warning(
                f"Falha no circuit breaker '{self.config.name}'",
                extra=extra_data
            )
        else:
            self.logger.debug(
                f"Sucesso no circuit breaker '{self.config.name}'",
                extra=extra_data
            )
    
    def _calculate_failure_rate(self) -> float:
        """Calcula taxa de falha"""
        if self.metrics.total_requests == 0:
            return 0.0
        return self.metrics.failed_requests / self.metrics.total_requests
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas atuais"""
        with self._lock:
            return {
                'name': self.config.name,
                'state': self.state.value,
                'total_requests': self.metrics.total_requests,
                'successful_requests': self.metrics.successful_requests,
                'failed_requests': self.metrics.failed_requests,
                'failure_rate': self._calculate_failure_rate(),
                'consecutive_failures': self.metrics.consecutive_failures,
                'consecutive_successes': self.metrics.consecutive_successes,
                'circuit_open_count': self.metrics.circuit_open_count,
                'circuit_half_open_count': self.metrics.circuit_half_open_count,
                'last_failure_time': self.metrics.last_failure_time.isoformat() if self.metrics.last_failure_time else None,
                'last_success_time': self.metrics.last_success_time.isoformat() if self.metrics.last_success_time else None,
                'last_state_change': self.last_state_change.isoformat(),
                'time_in_current_state': (datetime.now() - self.last_state_change).total_seconds()
            }
    
    def reset(self):
        """Reseta o circuit breaker para estado inicial"""
        with self._lock:
            self.state = CircuitBreakerState.CLOSED
            self.metrics = CircuitBreakerMetrics()
            self.last_state_change = datetime.now()
            
            self.logger.info(
                f"Circuit breaker '{self.config.name}' resetado",
                extra={
                    'event': 'circuit_breaker_reset',
                    'component': self.config.name
                }
            )
    
    def force_open(self):
        """Força abertura do circuit breaker"""
        with self._lock:
            self._transition_to_open()
    
    def force_close(self):
        """Força fechamento do circuit breaker"""
        with self._lock:
            self._transition_to_closed()
    
    def add_on_open_callback(self, callback: Callable):
        """Adiciona callback para quando circuito abre"""
        self.on_open_callbacks.append(callback)
    
    def add_on_close_callback(self, callback: Callable):
        """Adiciona callback para quando circuito fecha"""
        self.on_close_callbacks.append(callback)
    
    def add_on_half_open_callback(self, callback: Callable):
        """Adiciona callback para quando circuito vai para half-open"""
        self.on_half_open_callbacks.append(callback)


class CircuitBreakerOpenError(Exception):
    """Exceção lançada quando circuit breaker está aberto"""
    pass


class CircuitBreakerManager:
    """
    Gerenciador centralizado de circuit breakers.
    """
    
    def __init__(self):
        self.resilience_config = ResilienceConfiguration()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Inicializar circuit breakers baseado na configuração
        self._initialize_circuit_breakers()
    
    def _initialize_circuit_breakers(self):
        """Inicializa circuit breakers baseado na configuração"""
        if not self.resilience_config.is_resilience_enabled():
            self.logger.info("Resiliência desabilitada - circuit breakers não inicializados")
            return
        
        for component_name, config in self.resilience_config.get_all_component_configs().items():
            circuit_breaker = CircuitBreaker(config.circuit_breaker)
            self.circuit_breakers[component_name] = circuit_breaker
            
            # Configurar callbacks para métricas
            if self.resilience_config.is_monitoring_enabled():
                circuit_breaker.add_on_open_callback(self._on_circuit_open)
                circuit_breaker.add_on_close_callback(self._on_circuit_close)
        
        self.logger.info(
            f"Circuit breakers inicializados: {list(self.circuit_breakers.keys())}",
            extra={
                'event': 'circuit_breaker_manager_init',
                'components': list(self.circuit_breakers.keys()),
                'resilience_enabled': self.resilience_config.is_resilience_enabled()
            }
        )
    
    def get_circuit_breaker(self, component_name: str) -> Optional[CircuitBreaker]:
        """Retorna circuit breaker para componente"""
        return self.circuit_breakers.get(component_name)
    
    def call(self, component_name: str, func: Callable, *args, **kwargs) -> Any:
        """
        Executa função protegida pelo circuit breaker do componente.
        
        Args:
            component_name: Nome do componente
            func: Função a ser executada
            *args: Argumentos da função
            **kwargs: Argumentos nomeados da função
            
        Returns:
            Resultado da função
        """
        circuit_breaker = self.get_circuit_breaker(component_name)
        
        if circuit_breaker is None:
            # Se não há circuit breaker configurado, executa diretamente
            return func(*args, **kwargs)
        
        return circuit_breaker.call(func, *args, **kwargs)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Retorna métricas de todos os circuit breakers"""
        return {
            name: cb.get_metrics() 
            for name, cb in self.circuit_breakers.items()
        }
    
    def reset_all(self):
        """Reseta todos os circuit breakers"""
        for cb in self.circuit_breakers.values():
            cb.reset()
        
        self.logger.info(
            "Todos os circuit breakers resetados",
            extra={'event': 'circuit_breaker_manager_reset_all'}
        )
    
    def _on_circuit_open(self, circuit_breaker: CircuitBreaker):
        """Callback quando circuit breaker abre"""
        if self.resilience_config.is_alerting_enabled():
            self.logger.error(
                f"ALERTA: Circuit breaker '{circuit_breaker.config.name}' aberto",
                extra={
                    'event': 'circuit_breaker_alert',
                    'component': circuit_breaker.config.name,
                    'failure_rate': circuit_breaker._calculate_failure_rate(),
                    'consecutive_failures': circuit_breaker.metrics.consecutive_failures
                }
            )
    
    def _on_circuit_close(self, circuit_breaker: CircuitBreaker):
        """Callback quando circuit breaker fecha"""
        self.logger.info(
            f"Circuit breaker '{circuit_breaker.config.name}' recuperado",
            extra={
                'event': 'circuit_breaker_recovered',
                'component': circuit_breaker.config.name
            }
        )


# Instância global do gerenciador
_circuit_breaker_manager: Optional[CircuitBreakerManager] = None


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Retorna instância global do gerenciador de circuit breakers"""
    global _circuit_breaker_manager
    if _circuit_breaker_manager is None:
        _circuit_breaker_manager = CircuitBreakerManager()
    return _circuit_breaker_manager


def circuit_breaker(component_name: str):
    """
    Decorator para aplicar circuit breaker a funções.
    
    Args:
        component_name: Nome do componente para configuração
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            manager = get_circuit_breaker_manager()
            return manager.call(component_name, func, *args, **kwargs)
        return wrapper
    return decorator


@contextmanager
def circuit_breaker_context(component_name: str):
    """
    Context manager para circuit breaker.
    
    Args:
        component_name: Nome do componente para configuração
        
    Yields:
        CircuitBreaker instance
    """
    manager = get_circuit_breaker_manager()
    circuit_breaker = manager.get_circuit_breaker(component_name)
    
    if circuit_breaker is None:
        # Se não há circuit breaker, executa sem proteção
        yield None
    else:
        yield circuit_breaker 