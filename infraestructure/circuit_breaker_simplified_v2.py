"""
Circuit Breaker Simplificado - Versão 2.0

Prompt: Simplificação de Complexidade - Seção 2.2
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:35:00Z
Tracing ID: SIMPLIFICATION_20250127_002

Redução de 489 linhas para ~150 linhas mantendo apenas funcionalidades essenciais.
"""

import time
import threading
from typing import Any, Callable, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Estados do circuit breaker"""
    CLOSED = "closed"      # Funcionando normalmente
    OPEN = "open"          # Bloqueando requisições
    HALF_OPEN = "half_open"  # Testando recuperação


@dataclass
class CircuitBreakerConfig:
    """Configuração simplificada do circuit breaker"""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # segundos
    success_threshold: int = 2


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
        now = time.time()
        
        if self.state == CircuitState.CLOSED:
            return True
        
        elif self.state == CircuitState.OPEN:
            if now - self.last_state_change >= self.config.recovery_timeout:
                self._transition_to_half_open()
                return True
            return False
        
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    def _on_success(self):
        """Chamado quando função executa com sucesso"""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.config.success_threshold:
                    self._transition_to_closed()
            else:
                # Reset contadores em estado CLOSED
                self.failure_count = 0
    
    def _on_failure(self, error: Exception):
        """Chamado quando função falha"""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.CLOSED:
                if self.failure_count >= self.config.failure_threshold:
                    self._transition_to_open()
            
            elif self.state == CircuitState.HALF_OPEN:
                self._transition_to_open()
    
    def _transition_to_open(self):
        """Transição para estado OPEN"""
        if self.state != CircuitState.OPEN:
            self.state = CircuitState.OPEN
            self.last_state_change = time.time()
            self.success_count = 0
            logger.warning(f"Circuit breaker '{self.name}' aberto após {self.failure_count} falhas")
    
    def _transition_to_half_open(self):
        """Transição para estado HALF_OPEN"""
        if self.state == CircuitState.OPEN:
            self.state = CircuitState.HALF_OPEN
            self.last_state_change = time.time()
            self.success_count = 0
            logger.info(f"Circuit breaker '{self.name}' em half-open")
    
    def _transition_to_closed(self):
        """Transição para estado CLOSED"""
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED
            self.last_state_change = time.time()
            self.failure_count = 0
            self.success_count = 0
            logger.info(f"Circuit breaker '{self.name}' fechado")
    
    def get_state(self) -> CircuitState:
        """Retorna estado atual"""
        return self.state
    
    def get_stats(self) -> dict:
        """Retorna estatísticas básicas"""
        return {
            'name': self.name,
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time,
            'last_state_change': self.last_state_change
        }


class CircuitBreakerOpenError(Exception):
    """Exceção lançada quando circuit breaker está aberto"""
    pass


class CircuitBreakerManager:
    """Gerenciador simplificado de circuit breakers"""
    
    def __init__(self):
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        logger.info("Circuit Breaker Manager simplificado inicializado")
    
    def get_circuit_breaker(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Obtém ou cria circuit breaker"""
        if name not in self.circuit_breakers:
            self.circuit_breakers[name] = CircuitBreaker(name, config)
        return self.circuit_breakers[name]
    
    def call(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """Executa função através do circuit breaker"""
        circuit_breaker = self.get_circuit_breaker(name)
        return circuit_breaker.call(func, *args, **kwargs)
    
    def get_all_stats(self) -> dict:
        """Retorna estatísticas de todos os circuit breakers"""
        return {
            name: cb.get_stats() 
            for name, cb in self.circuit_breakers.items()
        }


# Instância global
_circuit_breaker_manager = CircuitBreakerManager()


def get_circuit_breaker_manager() -> CircuitBreakerManager:
    """Obtém instância global do circuit breaker manager"""
    return _circuit_breaker_manager


def circuit_breaker_call(name: str, func: Callable, *args, **kwargs) -> Any:
    """Helper para executar função através do circuit breaker"""
    return _circuit_breaker_manager.call(name, func, *args, **kwargs) 