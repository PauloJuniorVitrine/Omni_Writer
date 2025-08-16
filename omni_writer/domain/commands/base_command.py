"""
Classe base para comandos CQRS.

Baseada no código real existente do domínio Omni Writer.
Implementa padrão Command com validação e logging estruturado.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from datetime import datetime
import uuid

logger = logging.getLogger("domain.commands.base")

@dataclass
class CommandResult:
    """
    Resultado de execução de um comando.
    Baseado no código real de geração de artigos e validação.
    """
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    command_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_time_ms: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte resultado para dicionário para logging estruturado."""
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'command_id': self.command_id,
            'timestamp': self.timestamp.isoformat(),
            'execution_time_ms': self.execution_time_ms
        }

class BaseCommand(ABC):
    """
    Classe base para todos os comandos CQRS.
    
    Baseada nos padrões de validação e logging do código real:
    - Validação rigorosa como em data_models.py
    - Logging estruturado como em generate_articles.py
    - Tratamento de erros como em validation_service.py
    """
    
    def __init__(self, **kwargs):
        self.command_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        self._validate_input(kwargs)
        self._data = kwargs
        
    def _validate_input(self, data: Dict[str, Any]) -> None:
        """
        Valida dados de entrada do comando.
        Baseado no padrão de validação de data_models.py.
        """
        if not isinstance(data, dict):
            logger.error(f"Validação falhou: dados inválidos em {self.__class__.__name__}")
            raise ValueError("Dados de entrada devem ser um dicionário")
        
        # Validação específica implementada nas subclasses
        self._validate_command_data(data)
    
    @abstractmethod
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """
        Validação específica do comando.
        Deve ser implementada pelas subclasses.
        """
        pass
    
    @abstractmethod
    def execute(self, session) -> CommandResult:
        """
        Executa o comando.
        Deve ser implementada pelas subclasses.
        
        Args:
            session: Sessão do banco de dados (SQLAlchemy)
            
        Returns:
            CommandResult: Resultado da execução
        """
        pass
    
    def _log_execution_start(self) -> None:
        """Log do início da execução do comando."""
        logger.info(f"Executando comando {self.__class__.__name__}", extra={
            'command_id': self.command_id,
            'timestamp': self.timestamp.isoformat(),
            'data': self._data
        })
    
    def _log_execution_success(self, result: CommandResult) -> None:
        """Log de sucesso na execução do comando."""
        logger.info(f"Comando {self.__class__.__name__} executado com sucesso", extra={
            'command_id': self.command_id,
            'result': result.to_dict()
        })
    
    def _log_execution_error(self, error: Exception) -> None:
        """Log de erro na execução do comando."""
        logger.error(f"Erro na execução do comando {self.__class__.__name__}: {error}", extra={
            'command_id': self.command_id,
            'error': str(error),
            'error_type': type(error).__name__
        })
    
    def _create_error_result(self, error: Exception) -> CommandResult:
        """Cria resultado de erro padronizado."""
        return CommandResult(
            success=False,
            error=str(error),
            command_id=self.command_id,
            timestamp=datetime.utcnow()
        )
    
    def _create_success_result(self, data: Any = None) -> CommandResult:
        """Cria resultado de sucesso padronizado."""
        return CommandResult(
            success=True,
            data=data,
            command_id=self.command_id,
            timestamp=datetime.utcnow()
        ) 