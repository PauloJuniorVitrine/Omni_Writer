"""
Sistema de Retry Inteligente - Omni Writer
==========================================

Implementa retry inteligente com:
- Retry exponencial com backoff adaptativo
- Detecção automática de falhas temporárias vs permanentes
- Circuit breaker para APIs externas
- Fallback automático entre provedores (OpenAI → DeepSeek)
- Logs detalhados de tentativas e falhas
- Métricas de sucesso/falha por provedor

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque
import random

logger = logging.getLogger("domain.smart_retry")

class FailureType(Enum):
    """Tipos de falha"""
    TEMPORARY = "temporary"  # Falha temporária (rate limit, timeout)
    PERMANENT = "permanent"  # Falha permanente (auth, invalid request)
    UNKNOWN = "unknown"      # Tipo desconhecido

class CircuitState(Enum):
    """Estados do circuit breaker"""
    CLOSED = "closed"      # Funcionando normalmente
    OPEN = "open"          # Circuito aberto (falhas)
    HALF_OPEN = "half_open"  # Testando se recuperou

@dataclass
class RetryConfig:
    """Configuração de retry por provedor"""
    provider_name: str
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1
    timeout: float = 30.0

@dataclass
class CircuitBreakerConfig:
    """Configuração do circuit breaker"""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # segundos
    expected_exception: type = Exception
    monitor_interval: float = 10.0

@dataclass
class RetryAttempt:
    """Registro de tentativa de retry"""
    attempt_number: int
    provider: str
    start_time: datetime
    end_time: Optional[datetime] = None
    success: bool = False
    failure_type: FailureType = FailureType.UNKNOWN
    error_message: str = ""
    response_time: float = 0.0

class CircuitBreaker:
    """Implementa circuit breaker para proteção contra falhas"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.lock = threading.Lock()
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'circuit_opens': 0,
            'circuit_closes': 0
        }
    
    def can_execute(self) -> bool:
        """Verifica se pode executar a operação"""
        with self.lock:
            if self.state == CircuitState.CLOSED:
                return True
            
            if self.state == CircuitState.OPEN:
                # Verifica se já passou tempo suficiente para tentar recuperar
                if (self.last_failure_time and 
                    datetime.now() - self.last_failure_time > timedelta(seconds=self.config.recovery_timeout)):
                    self.state = CircuitState.HALF_OPEN
                    logger.info("Circuit breaker mudou para HALF_OPEN")
                    return True
                return False
            
            # HALF_OPEN - permite uma tentativa
            return True
    
    def on_success(self):
        """Registra sucesso"""
        with self.lock:
            self.metrics['total_requests'] += 1
            self.metrics['successful_requests'] += 1
            
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.metrics['circuit_closes'] += 1
                logger.info("Circuit breaker fechado após recuperação")
    
    def on_failure(self, exception: Exception):
        """Registra falha"""
        with self.lock:
            self.metrics['total_requests'] += 1
            self.metrics['failed_requests'] += 1
            self.failure_count += 1
            self.last_failure_time = datetime.now()
            
            if self.failure_count >= self.config.failure_threshold:
                if self.state != CircuitState.OPEN:
                    self.state = CircuitState.OPEN
                    self.metrics['circuit_opens'] += 1
                    logger.warning(f"Circuit breaker aberto após {self.failure_count} falhas")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas do circuit breaker"""
        with self.lock:
            return {
                'state': self.state.value,
                'failure_count': self.failure_count,
                'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
                **self.metrics
            }

class SmartRetry:
    """
    Sistema de retry inteligente com fallback entre provedores
    """
    
    def __init__(self):
        self.retry_configs = self._get_default_retry_configs()
        self.circuit_breakers = {}
        self.fallback_providers = {
            'openai': ['deepseek', 'gemini'],
            'deepseek': ['openai', 'gemini'],
            'gemini': ['openai', 'deepseek'],
            'claude': ['openai', 'deepseek']
        }
        self.attempt_history = []
        self.metrics = defaultdict(lambda: {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'retry_attempts': 0,
            'fallback_attempts': 0,
            'avg_response_time': 0.0
        })
        self.lock = threading.Lock()
        
        # Inicializa circuit breakers
        for provider in self.retry_configs:
            config = CircuitBreakerConfig()
            self.circuit_breakers[provider] = CircuitBreaker(config)
        
        logger.info("SmartRetry inicializado")
    
    def _get_default_retry_configs(self) -> Dict[str, RetryConfig]:
        """Retorna configurações padrão de retry"""
        return {
            'openai': RetryConfig(
                provider_name='openai',
                max_retries=3,
                base_delay=1.0,
                max_delay=30.0,
                backoff_multiplier=2.0,
                jitter_factor=0.1,
                timeout=30.0
            ),
            'deepseek': RetryConfig(
                provider_name='deepseek',
                max_retries=3,
                base_delay=2.0,
                max_delay=45.0,
                backoff_multiplier=2.0,
                jitter_factor=0.15,
                timeout=45.0
            ),
            'gemini': RetryConfig(
                provider_name='gemini',
                max_retries=2,
                base_delay=3.0,
                max_delay=60.0,
                backoff_multiplier=1.5,
                jitter_factor=0.2,
                timeout=60.0
            ),
            'claude': RetryConfig(
                provider_name='claude',
                max_retries=3,
                base_delay=2.0,
                max_delay=40.0,
                backoff_multiplier=2.0,
                jitter_factor=0.1,
                timeout=40.0
            )
        }
    
    def execute_with_retry(self, operation: Callable, provider: str, *args, **kwargs) -> Any:
        """
        Executa operação com retry inteligente e fallback
        """
        start_time = time.time()
        original_provider = provider
        providers_to_try = [provider] + self.fallback_providers.get(provider, [])
        
        for current_provider in providers_to_try:
            try:
                # Verifica circuit breaker
                circuit_breaker = self.circuit_breakers.get(current_provider)
                if circuit_breaker and not circuit_breaker.can_execute():
                    logger.warning(f"Circuit breaker aberto para {current_provider}, tentando próximo provedor")
                    continue
                
                # Executa com retry
                result = self._execute_with_retry_for_provider(
                    operation, current_provider, *args, **kwargs
                )
                
                # Registra sucesso
                if circuit_breaker:
                    circuit_breaker.on_success()
                
                # Atualiza métricas
                with self.lock:
                    self.metrics[current_provider]['successful_attempts'] += 1
                    if current_provider != original_provider:
                        self.metrics[current_provider]['fallback_attempts'] += 1
                
                logger.info(f"Operação executada com sucesso via {current_provider}")
                return result
                
            except Exception as e:
                # Registra falha
                if circuit_breaker:
                    circuit_breaker.on_failure(e)
                
                with self.lock:
                    self.metrics[current_provider]['failed_attempts'] += 1
                
                logger.error(f"Falha na operação via {current_provider}: {e}")
                
                # Se é o último provedor, re-levanta a exceção
                if current_provider == providers_to_try[-1]:
                    raise e
        
        # Nunca deve chegar aqui
        raise RuntimeError("Todos os provedores falharam")
    
    def _execute_with_retry_for_provider(self, operation: Callable, provider: str, *args, **kwargs) -> Any:
        """
        Executa operação com retry para um provedor específico
        """
        config = self.retry_configs.get(provider)
        if not config:
            # Sem configuração, executa sem retry
            return operation(*args, **kwargs)
        
        last_exception = None
        
        for attempt in range(config.max_retries + 1):
            attempt_start = time.time()
            
            try:
                # Executa operação
                result = operation(*args, **kwargs)
                
                # Registra tentativa bem-sucedida
                attempt_time = time.time() - attempt_start
                self._record_attempt(provider, attempt, True, attempt_time)
                
                return result
                
            except Exception as e:
                attempt_time = time.time() - attempt_start
                last_exception = e
                
                # Determina tipo de falha
                failure_type = self._classify_failure(e)
                
                # Registra tentativa falhada
                self._record_attempt(provider, attempt, False, attempt_time, failure_type, str(e))
                
                # Se é falha permanente, não tenta novamente
                if failure_type == FailureType.PERMANENT:
                    logger.error(f"Falha permanente detectada para {provider}: {e}")
                    break
                
                # Se é a última tentativa, para
                if attempt == config.max_retries:
                    logger.error(f"Máximo de tentativas atingido para {provider}: {e}")
                    break
                
                # Calcula delay para próxima tentativa
                delay = self._calculate_delay(config, attempt)
                logger.info(f"Tentativa {attempt + 1} falhou para {provider}. Aguardando {delay:.2f}s antes da próxima tentativa")
                
                time.sleep(delay)
        
        # Se chegou aqui, todas as tentativas falharam
        raise last_exception or RuntimeError(f"Operação falhou para {provider}")
    
    def _classify_failure(self, exception: Exception) -> FailureType:
        """
        Classifica o tipo de falha baseado na exceção
        """
        error_message = str(exception).lower()
        
        # Falhas temporárias
        temporary_indicators = [
            'rate limit', 'too many requests', 'timeout', 'connection',
            'temporary', 'service unavailable', 'gateway timeout',
            'request timeout', 'network', 'dns'
        ]
        
        # Falhas permanentes
        permanent_indicators = [
            'authentication', 'unauthorized', 'forbidden', 'invalid',
            'bad request', 'not found', 'malformed', 'syntax error'
        ]
        
        for indicator in temporary_indicators:
            if indicator in error_message:
                return FailureType.TEMPORARY
        
        for indicator in permanent_indicators:
            if indicator in error_message:
                return FailureType.PERMANENT
        
        return FailureType.UNKNOWN
    
    def _calculate_delay(self, config: RetryConfig, attempt: int) -> float:
        """
        Calcula delay para próxima tentativa com backoff exponencial e jitter
        """
        # Backoff exponencial
        delay = config.base_delay * (config.backoff_multiplier ** attempt)
        
        # Limita ao máximo
        delay = min(delay, config.max_delay)
        
        # Adiciona jitter para evitar thundering herd
        jitter = delay * config.jitter_factor * random.uniform(-1, 1)
        delay += jitter
        
        return max(0.1, delay)  # Mínimo de 0.1s
    
    def _record_attempt(self, provider: str, attempt: int, success: bool, 
                       response_time: float, failure_type: FailureType = FailureType.UNKNOWN, 
                       error_message: str = ""):
        """
        Registra tentativa de retry
        """
        attempt_record = RetryAttempt(
            attempt_number=attempt,
            provider=provider,
            start_time=datetime.now(),
            end_time=datetime.now(),
            success=success,
            failure_type=failure_type,
            error_message=error_message,
            response_time=response_time
        )
        
        with self.lock:
            self.attempt_history.append(attempt_record)
            self.metrics[provider]['total_attempts'] += 1
            
            if attempt > 0:
                self.metrics[provider]['retry_attempts'] += 1
            
            # Atualiza tempo médio de resposta
            current_avg = self.metrics[provider]['avg_response_time']
            total_attempts = self.metrics[provider]['total_attempts']
            self.metrics[provider]['avg_response_time'] = (
                (current_avg * (total_attempts - 1) + response_time) / total_attempts
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas de retry"""
        with self.lock:
            return {
                'providers': dict(self.metrics),
                'circuit_breakers': {
                    provider: cb.get_metrics() 
                    for provider, cb in self.circuit_breakers.items()
                },
                'total_attempts': len(self.attempt_history),
                'recent_attempts': [
                    {
                        'provider': attempt.provider,
                        'attempt': attempt.attempt_number,
                        'success': attempt.success,
                        'response_time': attempt.response_time,
                        'failure_type': attempt.failure_type.value,
                        'timestamp': attempt.start_time.isoformat()
                    }
                    for attempt in self.attempt_history[-10:]  # Últimas 10 tentativas
                ]
            }
    
    def reset_circuit_breaker(self, provider: str):
        """Reseta circuit breaker de um provedor"""
        if provider in self.circuit_breakers:
            circuit_breaker = self.circuit_breakers[provider]
            with circuit_breaker.lock:
                circuit_breaker.state = CircuitState.CLOSED
                circuit_breaker.failure_count = 0
                circuit_breaker.last_failure_time = None
            logger.info(f"Circuit breaker resetado para {provider}")
    
    def clear_history(self):
        """Limpa histórico de tentativas"""
        with self.lock:
            self.attempt_history.clear()
            logger.info("Histórico de tentativas limpo") 