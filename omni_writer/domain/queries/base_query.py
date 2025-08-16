"""
Classe base para queries CQRS.

Baseada no código real existente do domínio Omni Writer.
Implementa padrão Query com validação e logging estruturado.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List
from datetime import datetime
import uuid

logger = logging.getLogger("domain.queries.base")

@dataclass
class QueryResult:
    """
    Resultado de execução de uma query.
    Baseado no código real de consultas e validação.
    """
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    query_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_time_ms: Optional[float] = None
    total_count: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte resultado para dicionário para logging estruturado."""
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'query_id': self.query_id,
            'timestamp': self.timestamp.isoformat(),
            'execution_time_ms': self.execution_time_ms,
            'total_count': self.total_count
        }

class BaseQuery(ABC):
    """
    Classe base para todas as queries CQRS.
    
    Baseada nos padrões de validação e logging do código real:
    - Validação rigorosa como em data_models.py
    - Logging estruturado como em generate_articles.py
    - Tratamento de erros como em validation_service.py
    """
    
    def __init__(self, **kwargs):
        self.query_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        self._validate_input(kwargs)
        self._data = kwargs
        
    def _validate_input(self, data: Dict[str, Any]) -> None:
        """
        Valida dados de entrada da query.
        Baseado no padrão de validação de data_models.py.
        """
        if not isinstance(data, dict):
            logger.error(f"Validação falhou: dados inválidos em {self.__class__.__name__}")
            raise ValueError("Dados de entrada devem ser um dicionário")
        
        # Validação específica implementada nas subclasses
        self._validate_query_data(data)
    
    @abstractmethod
    def _validate_query_data(self, data: Dict[str, Any]) -> None:
        """
        Validação específica da query.
        Deve ser implementada pelas subclasses.
        """
        pass
    
    @abstractmethod
    def execute(self, session) -> QueryResult:
        """
        Executa a query.
        Deve ser implementada pelas subclasses.
        
        Args:
            session: Sessão do banco de dados (SQLAlchemy)
            
        Returns:
            QueryResult: Resultado da execução
        """
        pass
    
    def _log_execution_start(self) -> None:
        """Log do início da execução da query."""
        logger.info(f"Executando query {self.__class__.__name__}", extra={
            'query_id': self.query_id,
            'timestamp': self.timestamp.isoformat(),
            'data': self._data
        })
    
    def _log_execution_success(self, result: QueryResult) -> None:
        """Log de sucesso na execução da query."""
        logger.info(f"Query {self.__class__.__name__} executada com sucesso", extra={
            'query_id': self.query_id,
            'result': result.to_dict()
        })
    
    def _log_execution_error(self, error: Exception) -> None:
        """Log de erro na execução da query."""
        logger.error(f"Erro na execução da query {self.__class__.__name__}: {error}", extra={
            'query_id': self.query_id,
            'error': str(error),
            'error_type': type(error).__name__
        })
    
    def _create_error_result(self, error: Exception) -> QueryResult:
        """Cria resultado de erro padronizado."""
        return QueryResult(
            success=False,
            error=str(error),
            query_id=self.query_id,
            timestamp=datetime.utcnow()
        )
    
    def _create_success_result(self, data: Any = None, total_count: Optional[int] = None) -> QueryResult:
        """Cria resultado de sucesso padronizado."""
        return QueryResult(
            success=True,
            data=data,
            query_id=self.query_id,
            timestamp=datetime.utcnow(),
            total_count=total_count
        ) 