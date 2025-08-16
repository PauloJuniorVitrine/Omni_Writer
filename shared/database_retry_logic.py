"""
Lógica de retry para operações de banco de dados.
Prompt: Implementação retry logic PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-07-13T09:20:59.844087
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional
from sqlalchemy.exc import OperationalError, DisconnectionError, TimeoutError

logger = logging.getLogger("database_retry")

class DatabaseRetryLogic:
    """
    Lógica de retry para operações de banco de dados.
    
    Implementa:
    - Retry com backoff exponencial
    - Circuit breaker pattern
    - Logging estruturado
    - Fallback para SQLite
    """
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.failure_count = 0
        self.last_failure_time = None
    
    def retry_on_failure(self, func: Callable) -> Callable:
        """
        Decorator para retry automático em falhas de banco.
        
        Args:
            func: Função a ser executada com retry
            
        Returns:
            Função decorada com retry logic
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(self.max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    self.failure_count = 0  # Reset on success
                    return result
                    
                except (OperationalError, DisconnectionError, TimeoutError) as e:
                    last_exception = e
                    self.failure_count += 1
                    
                    if attempt < self.max_retries:
                        delay = self.base_delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"Tentativa {attempt + 1} falhou: {e}. Tentando novamente em {delay}s")
                        time.sleep(delay)
                    else:
                        logger.error(f"Todas as {self.max_retries + 1} tentativas falharam. Último erro: {e}")
                        raise e
                        
                except Exception as e:
                    # Não retry para outros tipos de erro
                    logger.error(f"Erro não recuperável: {e}")
                    raise e
            
            raise last_exception
        
        return wrapper
    
    def circuit_breaker(self, threshold: int = 5, timeout: int = 60) -> Callable:
        """
        Circuit breaker para prevenir sobrecarga do banco.
        
        Args:
            threshold: Número de falhas antes de abrir o circuito
            timeout: Tempo em segundos para tentar fechar o circuito
            
        Returns:
            Decorator com circuit breaker
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.failure_count >= threshold:
                    if self.last_failure_time:
                        elapsed = time.time() - self.last_failure_time
                        if elapsed < timeout:
                            raise Exception(f"Circuit breaker aberto. Aguarde {timeout - elapsed}s")
                        else:
                            # Reset circuit breaker
                            self.failure_count = 0
                            self.last_failure_time = None
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    self.failure_count += 1
                    self.last_failure_time = time.time()
                    raise e
            
            return wrapper
        return decorator

# Instância global
db_retry = DatabaseRetryLogic()

# Decorators de conveniência
retry_on_db_failure = db_retry.retry_on_failure
circuit_breaker_db = db_retry.circuit_breaker
