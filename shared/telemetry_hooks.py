"""
Telemetry Hooks - Omni Writer
=============================

Hooks e decorators para integração transparente do OpenTelemetry
com o sistema existente de logging e tracing.

Prompt: Hooks de Telemetria - ETAPA 8
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:15:00Z
Tracing ID: TELEMETRY_HOOKS_20250127_001
"""

import functools
import time
import logging
from typing import Dict, Any, Optional, Callable, TypeVar, ParamSpec
from contextlib import contextmanager
from opentelemetry import trace, context as otel_context
from opentelemetry.trace import Status, StatusCode

from .opentelemetry_config import get_tracer, get_meter, record_metric

# Type variables para decorators
T = TypeVar('T')
P = ParamSpec('P')

# Logger
logger = logging.getLogger(__name__)

class TelemetryHooks:
    """
    Hooks para integração transparente de telemetria.
    
    Funcionalidades:
    - Decorators para tracing automático
    - Context managers para spans
    - Integração com sistema de logging existente
    - Métricas automáticas
    """
    
    def __init__(self):
        self.tracer = get_tracer()
        self.meter = get_meter()
    
    def trace_function(self, 
                      name: Optional[str] = None,
                      attributes: Optional[Dict[str, Any]] = None,
                      record_metrics: bool = True,
                      record_exceptions: bool = True):
        """
        Decorator para tracing automático de funções.
        
        Args:
            name: Nome do span (padrão: nome da função)
            attributes: Atributos do span
            record_metrics: Se deve registrar métricas de duração
            record_exceptions: Se deve registrar exceções
        """
        
        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            span_name = name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                start_time = time.time()
                
                # Criar span
                with self.tracer.start_as_current_span(span_name, attributes=attributes or {}) as span:
                    try:
                        # Adicionar argumentos como atributos (se não sensíveis)
                        if not span_name.lower().contains('password') and not span_name.lower().contains('token'):
                            span.set_attributes({
                                "function.args_count": len(args),
                                "function.kwargs_count": len(kwargs),
                                "function.module": func.__module__,
                                "function.name": func.__name__
                            })
                        
                        # Executar função
                        result = func(*args, **kwargs)
                        
                        # Registrar sucesso
                        span.set_status(Status(StatusCode.OK))
                        
                        # Registrar métricas se habilitado
                        if record_metrics:
                            duration = time.time() - start_time
                            record_metric(
                                f"{span_name}.duration",
                                duration,
                                {"status": "success"}
                            )
                            record_metric(
                                f"{span_name}.calls",
                                1,
                                {"status": "success"}
                            )
                        
                        return result
                        
                    except Exception as e:
                        # Registrar erro
                        if record_exceptions:
                            span.set_status(Status(StatusCode.ERROR, str(e)))
                            span.record_exception(e)
                            
                            # Registrar métricas de erro
                            if record_metrics:
                                duration = time.time() - start_time
                                record_metric(
                                    f"{span_name}.duration",
                                    duration,
                                    {"status": "error", "error_type": type(e).__name__}
                                )
                                record_metric(
                                    f"{span_name}.calls",
                                    1,
                                    {"status": "error", "error_type": type(e).__name__}
                                )
                        
                        raise
            
            return wrapper
        return decorator
    
    def trace_api_endpoint(self, 
                          endpoint: str,
                          method: str = "GET",
                          attributes: Optional[Dict[str, Any]] = None):
        """
        Decorator específico para endpoints de API.
        
        Args:
            endpoint: Caminho do endpoint
            method: Método HTTP
            attributes: Atributos adicionais
        """
        
        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            span_name = f"api.{method}.{endpoint}"
            api_attributes = {
                "http.route": endpoint,
                "http.method": method,
                "span.kind": "server"
            }
            
            if attributes:
                api_attributes.update(attributes)
            
            @functools.wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                start_time = time.time()
                
                with self.tracer.start_as_current_span(span_name, attributes=api_attributes) as span:
                    try:
                        # Adicionar contexto de request se disponível
                        if args and hasattr(args[0], 'headers'):
                            request = args[0]
                            span.set_attributes({
                                "http.user_agent": request.headers.get('User-Agent', 'unknown'),
                                "http.request_id": request.headers.get('X-Request-ID', 'unknown'),
                                "http.client_ip": request.headers.get('X-Forwarded-For', 'unknown')
                            })
                        
                        result = func(*args, **kwargs)
                        
                        # Registrar sucesso
                        span.set_status(Status(StatusCode.OK))
                        
                        # Métricas de API
                        duration = time.time() - start_time
                        record_metric(
                            f"api.{method.lower()}.{endpoint.replace('/', '_')}.duration",
                            duration,
                            {"status": "success"}
                        )
                        record_metric(
                            f"api.{method.lower()}.{endpoint.replace('/', '_')}.calls",
                            1,
                            {"status": "success"}
                        )
                        
                        return result
                        
                    except Exception as e:
                        span.set_status(Status(StatusCode.ERROR, str(e)))
                        span.record_exception(e)
                        
                        # Métricas de erro
                        duration = time.time() - start_time
                        record_metric(
                            f"api.{method.lower()}.{endpoint.replace('/', '_')}.duration",
                            duration,
                            {"status": "error", "error_type": type(e).__name__}
                        )
                        record_metric(
                            f"api.{method.lower()}.{endpoint.replace('/', '_')}.calls",
                            1,
                            {"status": "error", "error_type": type(e).__name__}
                        )
                        
                        raise
            
            return wrapper
        return decorator
    
    @contextmanager
    def database_span(self, operation: str, table: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Context manager para operações de banco de dados.
        
        Args:
            operation: Tipo de operação (SELECT, INSERT, UPDATE, DELETE)
            table: Nome da tabela
            attributes: Atributos adicionais
        """
        
        span_name = f"db.{operation.lower()}.{table}"
        db_attributes = {
            "db.operation": operation,
            "db.table": table,
            "span.kind": "client"
        }
        
        if attributes:
            db_attributes.update(attributes)
        
        start_time = time.time()
        
        with self.tracer.start_as_current_span(span_name, attributes=db_attributes) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
                
                # Métricas de banco
                duration = time.time() - start_time
                record_metric(
                    f"db.{operation.lower()}.{table}.duration",
                    duration,
                    {"status": "success"}
                )
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                
                # Métricas de erro
                duration = time.time() - start_time
                record_metric(
                    f"db.{operation.lower()}.{table}.duration",
                    duration,
                    {"status": "error", "error_type": type(e).__name__}
                )
                raise
    
    @contextmanager
    def external_service_span(self, service: str, operation: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Context manager para chamadas de serviços externos.
        
        Args:
            service: Nome do serviço externo
            operation: Operação sendo executada
            attributes: Atributos adicionais
        """
        
        span_name = f"external.{service}.{operation}"
        service_attributes = {
            "service.name": service,
            "service.operation": operation,
            "span.kind": "client"
        }
        
        if attributes:
            service_attributes.update(attributes)
        
        start_time = time.time()
        
        with self.tracer.start_as_current_span(span_name, attributes=service_attributes) as span:
            try:
                yield span
                span.set_status(Status(StatusCode.OK))
                
                # Métricas de serviço externo
                duration = time.time() - start_time
                record_metric(
                    f"external.{service}.{operation}.duration",
                    duration,
                    {"status": "success"}
                )
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                span.record_exception(e)
                
                # Métricas de erro
                duration = time.time() - start_time
                record_metric(
                    f"external.{service}.{operation}.duration",
                    duration,
                    {"status": "error", "error_type": type(e).__name__}
                )
                raise
    
    def log_with_trace(self, logger_instance: logging.Logger, level: str, message: str, **kwargs):
        """
        Função para logging com contexto de trace.
        
        Args:
            logger_instance: Instância do logger
            level: Nível do log (DEBUG, INFO, WARNING, ERROR)
            message: Mensagem do log
            **kwargs: Atributos adicionais
        """
        
        # Obter contexto atual
        current_span = trace.get_current_span()
        if current_span:
            # Adicionar trace_id e span_id ao log
            trace_id = current_span.get_span_context().trace_id
            span_id = current_span.get_span_context().span_id
            
            kwargs.update({
                'trace_id': format(trace_id, '032x'),
                'span_id': format(span_id, '016x')
            })
        
        # Logar com contexto
        log_method = getattr(logger_instance, level.lower(), logger_instance.info)
        log_method(message, extra=kwargs)

# Instância global
telemetry_hooks = TelemetryHooks()

# Funções de conveniência
def trace_function(name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None, **kwargs):
    """Decorator de conveniência para tracing de funções."""
    return telemetry_hooks.trace_function(name, attributes, **kwargs)

def trace_api_endpoint(endpoint: str, method: str = "GET", attributes: Optional[Dict[str, Any]] = None):
    """Decorator de conveniência para tracing de endpoints."""
    return telemetry_hooks.trace_api_endpoint(endpoint, method, attributes)

def database_span(operation: str, table: str, attributes: Optional[Dict[str, Any]] = None):
    """Context manager de conveniência para operações de banco."""
    return telemetry_hooks.database_span(operation, table, attributes)

def external_service_span(service: str, operation: str, attributes: Optional[Dict[str, Any]] = None):
    """Context manager de conveniência para serviços externos."""
    return telemetry_hooks.external_service_span(service, operation, attributes)

def log_with_trace(logger_instance: logging.Logger, level: str, message: str, **kwargs):
    """Função de conveniência para logging com trace."""
    return telemetry_hooks.log_with_trace(logger_instance, level, message, **kwargs) 