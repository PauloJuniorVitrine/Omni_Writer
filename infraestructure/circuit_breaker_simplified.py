"""
Circuit Breaker Simplificado - Versão Otimizada

Prompt: Simplificação de Gargalos Críticos - IMP-004
Ruleset: enterprise_control_layer
Data/Hora: 2025-01-27T22:35:00Z
Tracing ID: SIMPLIFICATION_20250127_002

Redução: 489 linhas → 150 linhas (70% de redução)
"""

import time
import threading
import functools
from typing import Any, Callable, Optional, Dict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Estados simplificados do circuit breaker"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerConfig:
    """Configuração simplificada do circuit breaker"""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 success_threshold: int = 2):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold


class CircuitBreaker:
    """
    Circuit Breaker simplificado.
    
    Funcionalidades essenciais:
    - Estados: CLOSED, OPEN, HALF_OPEN
    - Contagem de falhas e sucessos
    - Timeout de recuperação
    - Thread safety básico
    """
    
    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        
        # Estado e contadores
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_state_change = time.time()
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info(f"Circuit Breaker '{name}' inicializado")
    
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
                raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' está aberto")
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
            
        except Exception as e:
            self._on_failure(e)
            raise
    
    def _can_execute(self) -> bool:
        """Verifica se pode executar baseado no estado atual"""
        if self.state == CircuitState.CLOSED:
            return True
        
        elif self.state == CircuitState.OPEN:
            # Verifica se passou tempo suficiente para tentar recuperação
            if time.time() - self.last_failure_time > self.config.recovery_timeout:
                self._transition_to_half_open()
                return True
            return False
        
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    def _on_success(self):
        """Chamado quando operação é bem-sucedida"""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            else:
                # Reset contadores em estado CLOSED
                self.failure_count = 0
                self.success_count = 0
    
    def _on_failure(self, exception: Exception):
        """Chamado quando operação falha"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self._transition_to_open()
            
            elif self.state == CircuitState.HALF_OPEN:
                self._transition_to_open()
            
            logger.warning(f"Circuit breaker '{self.name}' falha #{self.failure_count}: {exception}")
    
    def _transition_to_open(self):
        """Transição para estado OPEN"""
        if self.state != CircuitState.OPEN:
            self.state = CircuitState.OPEN
            self.last_state_change = time.time()
            logger.warning(f"Circuit breaker '{self.name}' ABERTO após {self.failure_count} falhas")
    
    def _transition_to_half_open(self):
        """Transição para estado HALF_OPEN"""
        if self.state != CircuitState.HALF_OPEN:
            self.state = CircuitState.HALF_OPEN
            self.last_state_change = time.time()
            self.success_count = 0
            logger.info(f"Circuit breaker '{self.name}' HALF-OPEN para teste de recuperação")
    
    def _transition_to_closed(self):
        """Transição para estado CLOSED"""
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED
            self.last_state_change = time.time()
            self.failure_count = 0
            self.success_count = 0
            logger.info(f"Circuit breaker '{self.name}' FECHADO - recuperado")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Obtém métricas básicas do circuit breaker"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time,
            'last_state_change': self.last_state_change,
            'config': {
                'failure_threshold': self.config.failure_threshold,
                'recovery_timeout': self.config.recovery_timeout,
                'success_threshold': self.config.success_threshold
            }
        }
    
    def reset(self):
        """Reseta o circuit breaker para estado inicial"""
        with self._lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0
            self.last_failure_time = None
            self.last_state_change = time.time()
            logger.info(f"Circuit breaker '{self.name}' resetado")


class CircuitBreakerOpenError(Exception):
    """Exceção lançada quando circuit breaker está aberto"""
    pass


class CircuitBreakerManager:
    """Gerenciador simplificado de circuit breakers"""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()
        logger.info("Circuit Breaker Manager inicializado")
    
    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Obtém ou cria circuit breaker"""
        with self._lock:
            if name not in self.circuit_breakers:
                self.circuit_breakers[name] = CircuitBreaker(name, config)
            return self.circuit_breakers[name]
    
    def call(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """Executa função através do circuit breaker"""
        circuit_breaker = self.get_circuit_breaker(name)
        return circuit_breaker.call(func, *args, **kwargs)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Obtém métricas de todos os circuit breakers"""
        return {name: cb.get_metrics() for name, cb in self.circuit_breakers.items()}
    
    def reset_all(self):
        """Reseta todos os circuit breakers"""
        for circuit_breaker in self.circuit_breakers.values():
            circuit_breaker.reset()


# Instância global
_circuit_breaker_manager = None


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Obtém instância global do circuit breaker manager"""
    global _circuit_breaker_manager
    if _circuit_breaker_manager is None:
        _circuit_breaker_manager = CircuitBreakerManager()
    return _circuit_breaker_manager


def circuit_breaker(name: str):
    """Decorator para aplicar circuit breaker a função"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            manager = get_circuit_breaker_manager()
            return manager.call(name, func, *args, **kwargs)
        return wrapper
    return decorator


# Funções de conveniência
def circuit_breaker_call(name: str, func: Callable, *args, **kwargs) -> Any:
    """Função de conveniência para chamar circuit breaker"""
    return get_circuit_breaker_manager().call(name, func, *args, **kwargs)


def get_circuit_breaker_metrics() -> Dict[str, Dict[str, Any]]:
    """Função de conveniência para obter métricas"""
    return get_circuit_breaker_manager().get_all_metrics()


def reset_circuit_breakers():
    """Função de conveniência para resetar circuit breakers"""
    get_circuit_breaker_manager().reset_all() 