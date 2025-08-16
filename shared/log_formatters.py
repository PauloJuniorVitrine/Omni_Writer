"""
Formatters específicos para diferentes tipos de logging.

Prompt: Logging Estruturado - IMP-005
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:30:00Z
Tracing ID: ENTERPRISE_20250127_005
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional


class SecurityFormatter(logging.Formatter):
    """
    Formatter específico para logs de segurança.
    Inclui informações sensíveis de auditoria e compliance.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log de segurança com informações de auditoria."""
        
        security_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': 'security',
            'level': record.levelname,
            'logger': record.name,
            'event': getattr(record, 'security_event', record.getMessage()),
            'user_id': getattr(record, 'user_id', None),
            'ip_address': getattr(record, 'ip_address', None),
            'user_agent': getattr(record, 'user_agent', None),
            'action': getattr(record, 'security_action', None),
            'resource': getattr(record, 'resource', None),
            'outcome': getattr(record, 'outcome', 'unknown'),
            'risk_level': getattr(record, 'risk_level', 'low'),
            'trace_id': getattr(record, 'trace_id', None),
            'session_id': getattr(record, 'session_id', None),
        }
        
        # Adicionar contexto de segurança se disponível
        if hasattr(record, 'security_context'):
            security_data['security_context'] = record.security_context
            
        # Adicionar exceção se disponível
        if record.exc_info:
            security_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1])
            }
            
        return json.dumps(security_data, ensure_ascii=False, default=str)


class PerformanceFormatter(logging.Formatter):
    """
    Formatter específico para logs de performance.
    Inclui métricas de tempo, recursos e throughput.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log de performance com métricas detalhadas."""
        
        performance_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': 'performance',
            'level': record.levelname,
            'logger': record.name,
            'operation': getattr(record, 'operation', record.getMessage()),
            'duration_ms': getattr(record, 'duration_ms', None),
            'cpu_usage': getattr(record, 'cpu_usage', None),
            'memory_usage': getattr(record, 'memory_usage', None),
            'throughput': getattr(record, 'throughput', None),
            'queue_size': getattr(record, 'queue_size', None),
            'cache_hit_rate': getattr(record, 'cache_hit_rate', None),
            'database_queries': getattr(record, 'database_queries', None),
            'external_calls': getattr(record, 'external_calls', None),
            'trace_id': getattr(record, 'trace_id', None),
            'span_id': getattr(record, 'span_id', None),
        }
        
        # Adicionar métricas de performance se disponível
        if hasattr(record, 'performance_metrics'):
            performance_data['performance_metrics'] = record.performance_metrics
            
        # Adicionar contexto de performance se disponível
        if hasattr(record, 'performance_context'):
            performance_data['performance_context'] = record.performance_context
            
        return json.dumps(performance_data, ensure_ascii=False, default=str)


class AuditFormatter(logging.Formatter):
    """
    Formatter específico para logs de auditoria.
    Inclui informações completas para compliance e auditoria.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log de auditoria com informações completas."""
        
        audit_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': 'audit',
            'level': record.levelname,
            'logger': record.name,
            'event': getattr(record, 'audit_event', record.getMessage()),
            'user_id': getattr(record, 'user_id', None),
            'user_role': getattr(record, 'user_role', None),
            'action': getattr(record, 'audit_action', None),
            'resource_type': getattr(record, 'resource_type', None),
            'resource_id': getattr(record, 'resource_id', None),
            'old_value': getattr(record, 'old_value', None),
            'new_value': getattr(record, 'new_value', None),
            'reason': getattr(record, 'reason', None),
            'ip_address': getattr(record, 'ip_address', None),
            'user_agent': getattr(record, 'user_agent', None),
            'trace_id': getattr(record, 'trace_id', None),
            'session_id': getattr(record, 'session_id', None),
            'compliance_tags': getattr(record, 'compliance_tags', []),
        }
        
        # Adicionar contexto de auditoria se disponível
        if hasattr(record, 'audit_context'):
            audit_data['audit_context'] = record.audit_context
            
        # Adicionar metadados de compliance se disponível
        if hasattr(record, 'compliance_metadata'):
            audit_data['compliance_metadata'] = record.compliance_metadata
            
        return json.dumps(audit_data, ensure_ascii=False, default=str)


class BusinessFormatter(logging.Formatter):
    """
    Formatter específico para logs de negócio.
    Inclui informações relevantes para análise de negócio.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log de negócio com informações relevantes."""
        
        business_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': 'business',
            'level': record.levelname,
            'logger': record.name,
            'event': getattr(record, 'business_event', record.getMessage()),
            'user_id': getattr(record, 'user_id', None),
            'customer_id': getattr(record, 'customer_id', None),
            'transaction_id': getattr(record, 'transaction_id', None),
            'product_id': getattr(record, 'product_id', None),
            'amount': getattr(record, 'amount', None),
            'currency': getattr(record, 'currency', None),
            'channel': getattr(record, 'channel', None),
            'campaign': getattr(record, 'campaign', None),
            'conversion': getattr(record, 'conversion', None),
            'trace_id': getattr(record, 'trace_id', None),
            'business_unit': getattr(record, 'business_unit', None),
        }
        
        # Adicionar contexto de negócio se disponível
        if hasattr(record, 'business_context'):
            business_data['business_context'] = record.business_context
            
        # Adicionar métricas de negócio se disponível
        if hasattr(record, 'business_metrics'):
            business_data['business_metrics'] = record.business_metrics
            
        return json.dumps(business_data, ensure_ascii=False, default=str)


class ErrorFormatter(logging.Formatter):
    """
    Formatter específico para logs de erro.
    Inclui informações detalhadas para debugging e análise.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Formata log de erro com informações detalhadas."""
        
        error_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': 'error',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'error_code': getattr(record, 'error_code', None),
            'error_category': getattr(record, 'error_category', None),
            'user_id': getattr(record, 'user_id', None),
            'request_id': getattr(record, 'request_id', None),
            'trace_id': getattr(record, 'trace_id', None),
            'span_id': getattr(record, 'span_id', None),
            'environment': getattr(record, 'environment', 'production'),
            'version': getattr(record, 'version', None),
        }
        
        # Adicionar exceção se disponível
        if record.exc_info:
            error_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        # Adicionar contexto de erro se disponível
        if hasattr(record, 'error_context'):
            error_data['error_context'] = record.error_context
            
        # Adicionar stack trace se disponível
        if hasattr(record, 'stack_trace'):
            error_data['stack_trace'] = record.stack_trace
            
        return json.dumps(error_data, ensure_ascii=False, default=str)


def create_formatter(formatter_type: str) -> logging.Formatter:
    """
    Factory para criar formatters específicos.
    
    Args:
        formatter_type: Tipo de formatter (security, performance, audit, business, error)
        
    Returns:
        Formatter configurado
    """
    formatters = {
        'security': SecurityFormatter(),
        'performance': PerformanceFormatter(),
        'audit': AuditFormatter(),
        'business': BusinessFormatter(),
        'error': ErrorFormatter(),
    }
    
    return formatters.get(formatter_type, logging.Formatter())


def log_security_event(
    logger: logging.Logger,
    event: str,
    action: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    outcome: str = "success",
    risk_level: str = "low",
    **kwargs
):
    """
    Log de evento de segurança estruturado.
    
    Args:
        logger: Logger instance
        event: Nome do evento de segurança
        action: Ação realizada
        user_id: ID do usuário
        ip_address: Endereço IP
        outcome: Resultado da ação
        risk_level: Nível de risco
        **kwargs: Dados extras
    """
    extra = {
        'security_event': event,
        'security_action': action,
        'user_id': user_id,
        'ip_address': ip_address,
        'outcome': outcome,
        'risk_level': risk_level,
        **kwargs
    }
    
    logger.info(f"Security Event: {event}", extra=extra)


def log_performance_event(
    logger: logging.Logger,
    operation: str,
    duration_ms: float,
    **kwargs
):
    """
    Log de evento de performance estruturado.
    
    Args:
        logger: Logger instance
        operation: Nome da operação
        duration_ms: Duração em milissegundos
        **kwargs: Dados extras
    """
    extra = {
        'operation': operation,
        'duration_ms': duration_ms,
        **kwargs
    }
    
    logger.info(f"Performance: {operation} took {duration_ms}ms", extra=extra)


def log_audit_event(
    logger: logging.Logger,
    event: str,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    **kwargs
):
    """
    Log de evento de auditoria estruturado.
    
    Args:
        logger: Logger instance
        event: Nome do evento de auditoria
        action: Ação realizada
        user_id: ID do usuário
        resource_type: Tipo do recurso
        resource_id: ID do recurso
        **kwargs: Dados extras
    """
    extra = {
        'audit_event': event,
        'audit_action': action,
        'user_id': user_id,
        'resource_type': resource_type,
        'resource_id': resource_id,
        **kwargs
    }
    
    logger.info(f"Audit Event: {event}", extra=extra) 