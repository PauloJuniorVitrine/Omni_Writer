"""
Configuração centralizada para logging estruturado.

Prompt: Logging Estruturado - IMP-005
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:25:00Z
Tracing ID: ENTERPRISE_20250127_005
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class StructuredJsonFormatter(logging.Formatter):
    """
    Formatter estruturado para logs JSON com metadados completos.
    Inclui trace_id, span_id, contexto e métricas.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log record como JSON estruturado."""
        
        # Base do log estruturado
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Adicionar trace_id se disponível
        if hasattr(record, 'trace_id'):
            log_data['trace_id'] = record.trace_id
            
        # Adicionar span_id se disponível
        if hasattr(record, 'span_id'):
            log_data['span_id'] = record.span_id
            
        # Adicionar contexto se disponível
        if hasattr(record, 'context'):
            log_data['context'] = record.context
            
        # Adicionar métricas se disponível
        if hasattr(record, 'metrics'):
            log_data['metrics'] = record.metrics
            
        # Adicionar dados extras se disponível
        if hasattr(record, 'extra_data'):
            log_data['extra_data'] = record.extra_data
            
        # Adicionar exceção se disponível
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        return json.dumps(log_data, ensure_ascii=False, default=str)


class HumanReadableFormatter(logging.Formatter):
    """
    Formatter legível para humanos com informações estruturadas.
    Útil para desenvolvimento e debugging local.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log record de forma legível para humanos."""
        
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        level = record.levelname.ljust(8)
        logger = record.name.ljust(25)
        message = record.getMessage()
        
        # Base do log
        log_line = f"[{timestamp}] {level} [{logger}] {message}"
        
        # Adicionar trace_id se disponível
        if hasattr(record, 'trace_id'):
            log_line += f" | trace_id={record.trace_id}"
            
        # Adicionar contexto se disponível
        if hasattr(record, 'context'):
            log_line += f" | context={record.context}"
            
        # Adicionar exceção se disponível
        if record.exc_info:
            log_line += f" | exception={record.exc_info[0].__name__}: {record.exc_info[1]}"
            
        return log_line


class LoggingConfig:
    """
    Configuração centralizada para logging estruturado.
    Gerencia diferentes formatos, níveis e handlers.
    """
    
    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.handlers: Dict[str, logging.Handler] = {}
        self.formatters: Dict[str, logging.Formatter] = {}
        
        # Criar diretório de logs se não existir
        self.logs_dir = Path("logs")
        self.logs_dir.mkdir(exist_ok=True)
        
        # Configurar formatters
        self._setup_formatters()
        
        # Configurar handlers
        self._setup_handlers()
        
    def _setup_formatters(self):
        """Configura os formatters disponíveis."""
        self.formatters['json'] = StructuredJsonFormatter()
        self.formatters['human'] = HumanReadableFormatter()
        
    def _setup_handlers(self):
        """Configura os handlers disponíveis."""
        
        # Handler para console (formato legível)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.formatters['human'])
        console_handler.setLevel(logging.INFO)
        self.handlers['console'] = console_handler
        
        # Handler para arquivo JSON (formato estruturado)
        json_file_handler = logging.FileHandler(
            self.logs_dir / "structured_logs.json",
            mode='a',
            encoding='utf-8'
        )
        json_file_handler.setFormatter(self.formatters['json'])
        json_file_handler.setLevel(logging.DEBUG)
        self.handlers['json_file'] = json_file_handler
        
        # Handler para arquivo de erros
        error_file_handler = logging.FileHandler(
            self.logs_dir / "errors.log",
            mode='a',
            encoding='utf-8'
        )
        error_file_handler.setFormatter(self.formatters['human'])
        error_file_handler.setLevel(logging.ERROR)
        self.handlers['error_file'] = error_file_handler
        
        # Handler para métricas
        metrics_file_handler = logging.FileHandler(
            self.logs_dir / "metrics.log",
            mode='a',
            encoding='utf-8'
        )
        metrics_file_handler.setFormatter(self.formatters['json'])
        metrics_file_handler.setLevel(logging.INFO)
        self.handlers['metrics'] = metrics_file_handler
        
    def get_logger(self, name: str, level: str = "INFO") -> logging.Logger:
        """
        Retorna logger configurado com handlers apropriados.
        
        Args:
            name: Nome do logger
            level: Nível de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            
        Returns:
            Logger configurado
        """
        if name in self.loggers:
            return self.loggers[name]
            
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        
        # Adicionar handlers
        logger.addHandler(self.handlers['console'])
        logger.addHandler(self.handlers['json_file'])
        logger.addHandler(self.handlers['error_file'])
        
        # Configurar para não propagar para logger pai
        logger.propagate = False
        
        self.loggers[name] = logger
        return logger
        
    def get_metrics_logger(self, name: str) -> logging.Logger:
        """
        Retorna logger específico para métricas.
        
        Args:
            name: Nome do logger de métricas
            
        Returns:
            Logger configurado para métricas
        """
        logger = logging.getLogger(f"{name}.metrics")
        logger.setLevel(logging.INFO)
        logger.addHandler(self.handlers['metrics'])
        logger.propagate = False
        return logger
        
    def log_with_context(
        self,
        logger: logging.Logger,
        level: str,
        message: str,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        metrics: Optional[Dict[str, Any]] = None,
        extra_data: Optional[Dict[str, Any]] = None
    ):
        """
        Log estruturado com contexto completo.
        
        Args:
            logger: Logger instance
            level: Nível de logging
            message: Mensagem principal
            trace_id: ID de rastreamento
            span_id: ID do span
            context: Contexto adicional
            metrics: Métricas relacionadas
            extra_data: Dados extras
        """
        extra = {}
        
        if trace_id:
            extra['trace_id'] = trace_id
        if span_id:
            extra['span_id'] = span_id
        if context:
            extra['context'] = context
        if metrics:
            extra['metrics'] = metrics
        if extra_data:
            extra['extra_data'] = extra_data
            
        log_method = getattr(logger, level.lower())
        log_method(message, extra=extra)
        
    def cleanup(self):
        """Limpa recursos de logging."""
        for handler in self.handlers.values():
            handler.close()
            
        for logger in self.loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)


# Instância global da configuração
logging_config = LoggingConfig()


def get_structured_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Função de conveniência para obter logger estruturado.
    
    Args:
        name: Nome do logger
        level: Nível de logging
        
    Returns:
        Logger configurado
    """
    return logging_config.get_logger(name, level)


def log_event(
    logger: logging.Logger,
    event: str,
    status: str = "INFO",
    trace_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    metrics: Optional[Dict[str, Any]] = None
):
    """
    Log de evento estruturado.
    
    Args:
        logger: Logger instance
        event: Nome do evento
        status: Status do evento (INFO, SUCCESS, ERROR, WARNING)
        trace_id: ID de rastreamento
        context: Contexto do evento
        metrics: Métricas do evento
    """
    logging_config.log_with_context(
        logger=logger,
        level="info",
        message=f"Event: {event} | Status: {status}",
        trace_id=trace_id,
        context=context,
        metrics=metrics
    ) 