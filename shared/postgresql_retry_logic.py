"""
Retry Logic para PostgreSQL - Omni Writer
========================================

Implementa retry logic robusta para falhas de conexão PostgreSQL.
Prompt: Retry logic para PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional
from sqlalchemy.exc import OperationalError, DisconnectionError

# Configuração de logging
logger = logging.getLogger("postgresql_retry")

# Configurações de retry
RETRY_CONFIG = {
    "max_attempts": 3,
    "base_delay": 1.0,
    "max_delay": 10.0,
    "backoff_factor": 2.0
}

def exponential_backoff(attempt: int, base_delay: float = 1.0, max_delay: float = 10.0, backoff_factor: float = 2.0) -> float:
    """
    Calcula delay exponencial para retry.
    
    Args:
        attempt: Número da tentativa
        base_delay: Delay base em segundos
        max_delay: Delay máximo em segundos
        backoff_factor: Fator de backoff
        
    Returns:
        Delay em segundos
    """
    delay = base_delay * (backoff_factor ** (attempt - 1))
    return min(delay, max_delay)

def postgresql_retry(max_attempts: Optional[int] = None, base_delay: Optional[float] = None, max_delay: Optional[float] = None, backoff_factor: Optional[float] = None):
    """
    Decorator para retry logic em operações PostgreSQL.
    
    Args:
        max_attempts: Número máximo de tentativas
        base_delay: Delay base em segundos
        max_delay: Delay máximo em segundos
        backoff_factor: Fator de backoff
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            attempts = max_attempts or RETRY_CONFIG["max_attempts"]
            base = base_delay or RETRY_CONFIG["base_delay"]
            max_d = max_delay or RETRY_CONFIG["max_delay"]
            backoff = backoff_factor or RETRY_CONFIG["backoff_factor"]
            
            last_exception = None
            
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                    
                except (OperationalError, DisconnectionError) as e:
                    last_exception = e
                    
                    if attempt == attempts:
                        logger.error(f"Falha após {attempts} tentativas: {e}")
                        raise
                    
                    delay = exponential_backoff(attempt, base, max_d, backoff)
                    logger.warning(f"Tentativa {attempt} falhou, aguardando {delay}s: {e}")
                    time.sleep(delay)
                    
                except Exception as e:
                    # Não retry para outros tipos de erro
                    logger.error(f"Erro não recuperável: {e}")
                    raise
            
            # Nunca deve chegar aqui
            raise last_exception
            
        return wrapper
    return decorator

class PostgreSQLRetryHandler:
    """
    Handler para retry logic em operações PostgreSQL.
    """
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = 2.0
    
    def execute_with_retry(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Executa operação com retry logic.
        
        Args:
            operation: Função a ser executada
            *args: Argumentos posicionais
            **kwargs: Argumentos nomeados
            
        Returns:
            Resultado da operação
        """
        last_exception = None
        
        for attempt in range(1, self.max_attempts + 1):
            try:
                return operation(*args, **kwargs)
                
            except (OperationalError, DisconnectionError) as e:
                last_exception = e
                
                if attempt == self.max_attempts:
                    logger.error(f"Falha após {self.max_attempts} tentativas: {e}")
                    raise
                
                delay = exponential_backoff(attempt, self.base_delay, self.max_delay, self.backoff_factor)
                logger.warning(f"Tentativa {attempt} falhou, aguardando {delay}s: {e}")
                time.sleep(delay)
        
        raise last_exception 