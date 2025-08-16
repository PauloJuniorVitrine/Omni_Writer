"""
Sistema de Circuit Breakers Avançados - Omni Writer
==================================================

Implementação de circuit breakers robustos para 99% de confiabilidade.
Baseado em análise do código real e padrões enterprise.

Prompt: Circuit Breakers Avançados para 99% de Confiabilidade
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-28T10:15:00Z
Tracing ID: CIRCUIT_BREAKER_20250128_001
"""

import asyncio
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Callable, Any, List
from dataclasses import dataclass, field
from enum import Enum
import functools
import json
import os

# Configuração de logging estruturado
logger = logging.getLogger("circuit_breaker")
logger.setLevel(logging.INFO)

class CircuitState(Enum):
    CLOSED = "closed"      # Funcionando normalmente
    OPEN = "open"          # Falhas detectadas, bloqueando chamadas
    HALF_OPEN = "half_open"  # Testando se o serviço recuperou

@dataclass
class CircuitBreakerConfig:
    """Configuração do circuit breaker"""
    failure_threshold: int = 5        # Falhas para abrir
    recovery_timeout: int = 60        # Segundos para tentar recuperar
    expected_exception: type = Exception  # Exceção esperada
    success_threshold: int = 3        # Sucessos para fechar
    timeout: float = 30.0             # Timeout da operação
    max_failures_per_minute: int = 10  # Máximo de falhas por minuto

@dataclass
class CircuitBreakerMetrics:
    """Métricas do circuit breaker"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_requests: int = 0
    circuit_opens: int = 0
    circuit_closes: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    current_failure_count: int = 0
    consecutive_success_count: int = 0

class AdvancedCircuitBreaker:
    """
    Circuit breaker avançado com métricas e auto-healing.
    
    Funcionalidades:
    - Estados automáticos (CLOSED, OPEN, HALF_OPEN)
    - Timeout configurável
    - Métricas detalhadas
    - Auto-healing baseado em sucessos
    - Fallback functions
    - Logging estruturado
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.metrics = CircuitBreakerMetrics()
        self.last_state_change = datetime.utcnow()
        self.failure_timestamps: List[datetime] = []
        self.fallback_function: Optional[Callable] = None
        
        logger.info(f"Circuit breaker '{name}' inicializado com configuração: {self.config}")
    
    def set_fallback(self, fallback_func: Callable):
        """Define função de fallback"""
        self.fallback_function = fallback_func
        logger.info(f"Fallback function definida para circuit breaker '{self.name}'")
    
    def _should_attempt_reset(self) -> bool:
        """Verifica se deve tentar resetar o circuit breaker"""
        if self.state != CircuitState.OPEN:
            return False
        
        time_since_open = datetime.utcnow() - self.last_state_change
        return time_since_open.total_seconds() >= self.config.recovery_timeout
    
    def _on_success(self):
        """Chamado quando uma operação é bem-sucedida"""
        self.metrics.successful_requests += 1
        self.metrics.last_success_time = datetime.utcnow()
        self.metrics.consecutive_success_count += 1
        self.metrics.current_failure_count = 0
        
        # Limpa timestamps de falhas antigas
        cutoff_time = datetime.utcnow() - timedelta(minutes=1)
        self.failure_timestamps = [ts for ts in self.failure_timestamps if ts > cutoff_time]
        
        if self.state == CircuitState.HALF_OPEN:
            if self.metrics.consecutive_success_count >= self.config.success_threshold:
                self._close_circuit()
        elif self.state == CircuitState.OPEN:
            self._half_open_circuit()
    
    def _on_failure(self, exception: Exception):
        """Chamado quando uma operação falha"""
        self.metrics.failed_requests += 1
        self.metrics.last_failure_time = datetime.utcnow()
        self.metrics.current_failure_count += 1
        self.metrics.consecutive_success_count = 0
        
        # Adiciona timestamp da falha
        self.failure_timestamps.append(datetime.utcnow())
        
        # Limpa timestamps antigos
        cutoff_time = datetime.utcnow() - timedelta(minutes=1)
        self.failure_timestamps = [ts for ts in self.failure_timestamps if ts > cutoff_time]
        
        # Verifica se deve abrir o circuit breaker
        if (self.state == CircuitState.CLOSED and 
            len(self.failure_timestamps) >= self.config.failure_threshold):
            self._open_circuit()
        elif self.state == CircuitState.HALF_OPEN:
            self._open_circuit()
    
    def _on_timeout(self):
        """Chamado quando uma operação timeout"""
        self.metrics.timeout_requests += 1
        self._on_failure(Exception("Operation timeout"))
    
    def _open_circuit(self):
        """Abre o circuit breaker"""
        if self.state != CircuitState.OPEN:
            self.state = CircuitState.OPEN
            self.last_state_change = datetime.utcnow()
            self.metrics.circuit_opens += 1
            
            logger.warning(f"Circuit breaker '{self.name}' ABERTO - Falhas: {len(self.failure_timestamps)}")
    
    def _close_circuit(self):
        """Fecha o circuit breaker"""
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED
            self.last_state_change = datetime.utcnow()
            self.metrics.circuit_closes += 1
            
            logger.info(f"Circuit breaker '{self.name}' FECHADO - Recuperado com sucesso")
    
    def _half_open_circuit(self):
        """Coloca o circuit breaker em estado half-open"""
        if self.state != CircuitState.HALF_OPEN:
            self.state = CircuitState.HALF_OPEN
            self.last_state_change = datetime.utcnow()
            self.metrics.consecutive_success_count = 0
            
            logger.info(f"Circuit breaker '{self.name}' HALF-OPEN - Testando recuperação")
    
    def _can_execute(self) -> bool:
        """Verifica se pode executar a operação"""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._half_open_circuit()
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        
        return False
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """Executa função com proteção do circuit breaker"""
        self.metrics.total_requests += 1
        
        if not self._can_execute():
            logger.warning(f"Circuit breaker '{self.name}' bloqueando chamada")
            if self.fallback_function:
                return self.fallback_function(*args, **kwargs)
            raise Exception(f"Circuit breaker '{self.name}' is OPEN")
        
        try:
            # Executa com timeout
            if asyncio.iscoroutinefunction(func):
                # Função assíncrona
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(
                    asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
                )
            else:
                # Função síncrona
                result = func(*args, **kwargs)
            
            self._on_success()
            return result
            
        except asyncio.TimeoutError:
            self._on_timeout()
            if self.fallback_function:
                return self.fallback_function(*args, **kwargs)
            raise
        except self.config.expected_exception as e:
            self._on_failure(e)
            if self.fallback_function:
                return self.fallback_function(*args, **kwargs)
            raise
        except Exception as e:
            # Log de erro inesperado
            logger.error(f"Erro inesperado no circuit breaker '{self.name}': {e}")
            if self.fallback_function:
                return self.fallback_function(*args, **kwargs)
            raise
    
    async def call_async(self, func: Callable, *args, **kwargs) -> Any:
        """Executa função assíncrona com proteção do circuit breaker"""
        self.metrics.total_requests += 1
        
        if not self._can_execute():
            logger.warning(f"Circuit breaker '{self.name}' bloqueando chamada assíncrona")
            if self.fallback_function:
                if asyncio.iscoroutinefunction(self.fallback_function):
                    return await self.fallback_function(*args, **kwargs)
                else:
                    return self.fallback_function(*args, **kwargs)
            raise Exception(f"Circuit breaker '{self.name}' is OPEN")
        
        try:
            result = await asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
            self._on_success()
            return result
            
        except asyncio.TimeoutError:
            self._on_timeout()
            if self.fallback_function:
                if asyncio.iscoroutinefunction(self.fallback_function):
                    return await self.fallback_function(*args, **kwargs)
                else:
                    return self.fallback_function(*args, **kwargs)
            raise
        except self.config.expected_exception as e:
            self._on_failure(e)
            if self.fallback_function:
                if asyncio.iscoroutinefunction(self.fallback_function):
                    return await self.fallback_function(*args, **kwargs)
                else:
                    return self.fallback_function(*args, **kwargs)
            raise
        except Exception as e:
            logger.error(f"Erro inesperado no circuit breaker '{self.name}': {e}")
            if self.fallback_function:
                if asyncio.iscoroutinefunction(self.fallback_function):
                    return await self.fallback_function(*args, **kwargs)
                else:
                    return self.fallback_function(*args, **kwargs)
            raise
    
    def get_metrics(self) -> Dict:
        """Retorna métricas do circuit breaker"""
        return {
            'name': self.name,
            'state': self.state.value,
            'total_requests': self.metrics.total_requests,
            'successful_requests': self.metrics.successful_requests,
            'failed_requests': self.metrics.failed_requests,
            'timeout_requests': self.metrics.timeout_requests,
            'circuit_opens': self.metrics.circuit_opens,
            'circuit_closes': self.metrics.circuit_closes,
            'current_failure_count': self.metrics.current_failure_count,
            'consecutive_success_count': self.metrics.consecutive_success_count,
            'failure_rate': (self.metrics.failed_requests / max(self.metrics.total_requests, 1)) * 100,
            'last_failure_time': self.metrics.last_failure_time.isoformat() if self.metrics.last_failure_time else None,
            'last_success_time': self.metrics.last_success_time.isoformat() if self.metrics.last_success_time else None,
            'last_state_change': self.last_state_change.isoformat(),
            'failures_last_minute': len(self.failure_timestamps)
        }
    
    def reset(self):
        """Reseta o circuit breaker manualmente"""
        self.state = CircuitState.CLOSED
        self.last_state_change = datetime.utcnow()
        self.metrics = CircuitBreakerMetrics()
        self.failure_timestamps.clear()
        logger.info(f"Circuit breaker '{self.name}' resetado manualmente")

class CircuitBreakerManager:
    """
    Gerenciador centralizado de circuit breakers.
    
    Funcionalidades:
    - Gerenciamento de múltiplos circuit breakers
    - Configurações centralizadas
    - Métricas agregadas
    - Auto-healing global
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, AdvancedCircuitBreaker] = {}
        self.default_config = CircuitBreakerConfig()
        
        # Configurações específicas por serviço
        self.service_configs = {
            'openai_api': CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=120,
                timeout=30.0,
                max_failures_per_minute=5
            ),
            'deepseek_api': CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=120,
                timeout=30.0,
                max_failures_per_minute=5
            ),
            'database': CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=60,
                timeout=10.0,
                max_failures_per_minute=10
            ),
            'redis': CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=30,
                timeout=5.0,
                max_failures_per_minute=20
            ),
            'file_system': CircuitBreakerConfig(
                failure_threshold=3,
                recovery_timeout=60,
                timeout=10.0,
                max_failures_per_minute=5
            )
        }
        
        logger.info("Circuit Breaker Manager inicializado")
    
    def get_circuit_breaker(self, name: str) -> AdvancedCircuitBreaker:
        """Obtém ou cria circuit breaker"""
        if name not in self.circuit_breakers:
            config = self.service_configs.get(name, self.default_config)
            self.circuit_breakers[name] = AdvancedCircuitBreaker(name, config)
            logger.info(f"Circuit breaker '{name}' criado com configuração específica")
        
        return self.circuit_breakers[name]
    
    def set_fallback(self, name: str, fallback_func: Callable):
        """Define fallback para circuit breaker específico"""
        cb = self.get_circuit_breaker(name)
        cb.set_fallback(fallback_func)
    
    def get_all_metrics(self) -> Dict:
        """Retorna métricas de todos os circuit breakers"""
        metrics = {
            'total_circuit_breakers': len(self.circuit_breakers),
            'open_circuit_breakers': 0,
            'half_open_circuit_breakers': 0,
            'closed_circuit_breakers': 0,
            'circuit_breakers': {}
        }
        
        for name, cb in self.circuit_breakers.items():
            cb_metrics = cb.get_metrics()
            metrics['circuit_breakers'][name] = cb_metrics
            
            if cb.state == CircuitState.OPEN:
                metrics['open_circuit_breakers'] += 1
            elif cb.state == CircuitState.HALF_OPEN:
                metrics['half_open_circuit_breakers'] += 1
            else:
                metrics['closed_circuit_breakers'] += 1
        
        return metrics
    
    def reset_all(self):
        """Reseta todos os circuit breakers"""
        for cb in self.circuit_breakers.values():
            cb.reset()
        logger.info("Todos os circuit breakers foram resetados")
    
    def get_health_status(self) -> Dict:
        """Retorna status de saúde dos circuit breakers"""
        open_cbs = [name for name, cb in self.circuit_breakers.items() if cb.state == CircuitState.OPEN]
        half_open_cbs = [name for name, cb in self.circuit_breakers.items() if cb.state == CircuitState.HALF_OPEN]
        
        return {
            'status': 'healthy' if not open_cbs else 'degraded' if not half_open_cbs else 'critical',
            'open_circuit_breakers': open_cbs,
            'half_open_circuit_breakers': half_open_cbs,
            'total_circuit_breakers': len(self.circuit_breakers)
        }

# Instância global
circuit_breaker_manager = CircuitBreakerManager()

# Decorators para facilitar uso
def circuit_breaker(name: str, fallback_func: Optional[Callable] = None):
    """Decorator para aplicar circuit breaker a funções"""
    def decorator(func):
        cb = circuit_breaker_manager.get_circuit_breaker(name)
        if fallback_func:
            cb.set_fallback(fallback_func)
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return cb.call(func, *args, **kwargs)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await cb.call_async(func, *args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator

# Funções de fallback padrão
def default_openai_fallback(*args, **kwargs):
    """Fallback padrão para OpenAI API"""
    logger.warning("Usando fallback para OpenAI API")
    return {
        'content': 'Serviço temporariamente indisponível. Tente novamente em alguns minutos.',
        'model': 'fallback',
        'usage': {'total_tokens': 0}
    }

def default_database_fallback(*args, **kwargs):
    """Fallback padrão para banco de dados"""
    logger.warning("Usando fallback para banco de dados")
    return None

def default_redis_fallback(*args, **kwargs):
    """Fallback padrão para Redis"""
    logger.warning("Usando fallback para Redis")
    return None

# Configuração automática de fallbacks
circuit_breaker_manager.set_fallback('openai_api', default_openai_fallback)
circuit_breaker_manager.set_fallback('database', default_database_fallback)
circuit_breaker_manager.set_fallback('redis', default_redis_fallback)

if __name__ == "__main__":
    # Exemplo de uso
    import time
    
    # Simula função que pode falhar
    def unreliable_function(success_rate=0.7):
        if time.time() % 10 < 7:  # 70% de sucesso
            return "Success"
        else:
            raise Exception("Simulated failure")
    
    # Aplica circuit breaker
    @circuit_breaker('test_service', lambda: "Fallback response")
    def test_function():
        return unreliable_function()
    
    # Testa
    for i in range(10):
        try:
            result = test_function()
            print(f"Call {i+1}: {result}")
        except Exception as e:
            print(f"Call {i+1}: {e}")
        time.sleep(1)
    
    # Mostra métricas
    metrics = circuit_breaker_manager.get_all_metrics()
    print(f"\nMétricas: {json.dumps(metrics, indent=2)}") 