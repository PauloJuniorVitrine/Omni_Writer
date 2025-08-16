"""
Testes unitários para sistema de logging estruturado.

Prompt: Logging Estruturado - IMP-005
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:35:00Z
Tracing ID: ENTERPRISE_20250127_005
"""

import pytest
import json
import logging
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from shared.logging_config import (
    LoggingConfig,
    StructuredJsonFormatter,
    HumanReadableFormatter,
    get_structured_logger,
    log_event,
    logging_config
)
from shared.log_formatters import (
    SecurityFormatter,
    PerformanceFormatter,
    AuditFormatter,
    BusinessFormatter,
    ErrorFormatter,
    log_security_event,
    log_performance_event,
    log_audit_event
)


class TestLoggingConfig:
    """Testes para configuração centralizada de logging."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = LoggingConfig()
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.config.cleanup()
        
    def test_logging_config_initialization(self):
        """Testa inicialização da configuração de logging."""
        assert self.config.loggers == {}
        assert self.config.handlers == {}
        assert self.config.formatters == {}
        assert self.config.logs_dir.exists()
        
    def test_get_logger_creation(self):
        """Testa criação de logger configurado."""
        logger = self.config.get_logger("test_logger")
        
        assert logger.name == "test_logger"
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 3  # console, json_file, error_file
        assert not logger.propagate
        
    def test_get_logger_caching(self):
        """Testa que logger é reutilizado quando solicitado novamente."""
        logger1 = self.config.get_logger("test_logger")
        logger2 = self.config.get_logger("test_logger")
        
        assert logger1 is logger2
        assert "test_logger" in self.config.loggers
        
    def test_get_logger_different_levels(self):
        """Testa criação de logger com diferentes níveis."""
        debug_logger = self.config.get_logger("debug_logger", "DEBUG")
        error_logger = self.config.get_logger("error_logger", "ERROR")
        
        assert debug_logger.level == logging.DEBUG
        assert error_logger.level == logging.ERROR
        
    def test_get_metrics_logger(self):
        """Testa criação de logger específico para métricas."""
        metrics_logger = self.config.get_metrics_logger("test")
        
        assert metrics_logger.name == "test.metrics"
        assert metrics_logger.level == logging.INFO
        assert len(metrics_logger.handlers) == 1  # apenas metrics handler
        assert not metrics_logger.propagate
        
    def test_log_with_context(self):
        """Testa logging com contexto completo."""
        logger = self.config.get_logger("test_logger")
        
        with patch.object(logger, 'info') as mock_info:
            self.config.log_with_context(
                logger=logger,
                level="info",
                message="Test message",
                trace_id="trace-123",
                span_id="span-456",
                context={"user_id": "user-123"},
                metrics={"duration": 100}
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert call_args[0][0] == "Test message"
            assert call_args[1]['extra']['trace_id'] == "trace-123"
            assert call_args[1]['extra']['span_id'] == "span-456"
            assert call_args[1]['extra']['context']['user_id'] == "user-123"
            assert call_args[1]['extra']['metrics']['duration'] == 100


class TestStructuredJsonFormatter:
    """Testes para formatter JSON estruturado."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = StructuredJsonFormatter()
        
    def test_format_basic_log(self):
        """Testa formatação básica de log."""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'test_logger'
        assert log_data['message'] == 'Test message'
        assert log_data['module'] == 'test'
        assert log_data['function'] == 'test_format_basic_log'
        assert log_data['line'] == 10
        assert 'timestamp' in log_data
        
    def test_format_with_trace_id(self):
        """Testa formatação com trace_id."""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.trace_id = "trace-123"
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['trace_id'] == "trace-123"
        
    def test_format_with_exception(self):
        """Testa formatação com exceção."""
        try:
            raise ValueError("Test error")
        except ValueError:
            record = logging.LogRecord(
                name="test_logger",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Test error",
                args=(),
                exc_info=sys.exc_info()
            )
            
            result = self.formatter.format(record)
            log_data = json.loads(result)
            
            assert log_data['level'] == 'ERROR'
            assert 'exception' in log_data
            assert log_data['exception']['type'] == 'ValueError'
            assert log_data['exception']['message'] == 'Test error'
            assert 'traceback' in log_data['exception']


class TestHumanReadableFormatter:
    """Testes para formatter legível para humanos."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = HumanReadableFormatter()
        
    def test_format_basic_log(self):
        """Testa formatação básica legível."""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        
        assert "[INFO" in result
        assert "[test_logger" in result
        assert "Test message" in result
        assert "UTC" in result
        
    def test_format_with_trace_id(self):
        """Testa formatação com trace_id."""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.trace_id = "trace-123"
        
        result = self.formatter.format(record)
        
        assert "trace_id=trace-123" in result


class TestSecurityFormatter:
    """Testes para formatter de segurança."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = SecurityFormatter()
        
    def test_format_security_log(self):
        """Testa formatação de log de segurança."""
        record = logging.LogRecord(
            name="security_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Login attempt",
            args=(),
            exc_info=None
        )
        record.security_event = "user_login"
        record.security_action = "authentication"
        record.user_id = "user-123"
        record.ip_address = "192.168.1.1"
        record.outcome = "success"
        record.risk_level = "low"
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'security'
        assert log_data['event'] == 'user_login'
        assert log_data['action'] == 'authentication'
        assert log_data['user_id'] == 'user-123'
        assert log_data['ip_address'] == '192.168.1.1'
        assert log_data['outcome'] == 'success'
        assert log_data['risk_level'] == 'low'


class TestPerformanceFormatter:
    """Testes para formatter de performance."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = PerformanceFormatter()
        
    def test_format_performance_log(self):
        """Testa formatação de log de performance."""
        record = logging.LogRecord(
            name="performance_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Database query",
            args=(),
            exc_info=None
        )
        record.operation = "database_query"
        record.duration_ms = 150.5
        record.cpu_usage = 25.0
        record.memory_usage = 512.0
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'performance'
        assert log_data['operation'] == 'database_query'
        assert log_data['duration_ms'] == 150.5
        assert log_data['cpu_usage'] == 25.0
        assert log_data['memory_usage'] == 512.0


class TestAuditFormatter:
    """Testes para formatter de auditoria."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = AuditFormatter()
        
    def test_format_audit_log(self):
        """Testa formatação de log de auditoria."""
        record = logging.LogRecord(
            name="audit_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="User data update",
            args=(),
            exc_info=None
        )
        record.audit_event = "user_update"
        record.audit_action = "modify"
        record.user_id = "user-123"
        record.user_role = "admin"
        record.resource_type = "user"
        record.resource_id = "user-456"
        record.old_value = {"name": "John"}
        record.new_value = {"name": "John Doe"}
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'audit'
        assert log_data['event'] == 'user_update'
        assert log_data['action'] == 'modify'
        assert log_data['user_id'] == 'user-123'
        assert log_data['user_role'] == 'admin'
        assert log_data['resource_type'] == 'user'
        assert log_data['resource_id'] == 'user-456'
        assert log_data['old_value']['name'] == 'John'
        assert log_data['new_value']['name'] == 'John Doe'


class TestBusinessFormatter:
    """Testes para formatter de negócio."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = BusinessFormatter()
        
    def test_format_business_log(self):
        """Testa formatação de log de negócio."""
        record = logging.LogRecord(
            name="business_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Article generation",
            args=(),
            exc_info=None
        )
        record.business_event = "article_generation"
        record.user_id = "user-123"
        record.customer_id = "customer-456"
        record.transaction_id = "txn-789"
        record.product_id = "article-gen"
        record.amount = 10.50
        record.currency = "USD"
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'business'
        assert log_data['event'] == 'article_generation'
        assert log_data['user_id'] == 'user-123'
        assert log_data['customer_id'] == 'customer-456'
        assert log_data['transaction_id'] == 'txn-789'
        assert log_data['product_id'] == 'article-gen'
        assert log_data['amount'] == 10.50
        assert log_data['currency'] == 'USD'


class TestErrorFormatter:
    """Testes para formatter de erro."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = ErrorFormatter()
        
    def test_format_error_log(self):
        """Testa formatação de log de erro."""
        record = logging.LogRecord(
            name="error_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="API call failed",
            args=(),
            exc_info=None
        )
        record.error_code = "API_001"
        record.error_category = "external_service"
        record.user_id = "user-123"
        record.request_id = "req-456"
        record.environment = "production"
        record.version = "1.0.0"
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'error'
        assert log_data['level'] == 'ERROR'
        assert log_data['error_code'] == 'API_001'
        assert log_data['error_category'] == 'external_service'
        assert log_data['user_id'] == 'user-123'
        assert log_data['request_id'] == 'req-456'
        assert log_data['environment'] == 'production'
        assert log_data['version'] == '1.0.0'


class TestLoggingFunctions:
    """Testes para funções de logging de conveniência."""
    
    def test_log_security_event(self):
        """Testa função de log de evento de segurança."""
        logger = MagicMock()
        
        log_security_event(
            logger=logger,
            event="user_login",
            action="authentication",
            user_id="user-123",
            ip_address="192.168.1.1",
            outcome="success",
            risk_level="low"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Security Event: user_login" in call_args[0][0]
        assert call_args[1]['extra']['security_event'] == 'user_login'
        assert call_args[1]['extra']['security_action'] == 'authentication'
        assert call_args[1]['extra']['user_id'] == 'user-123'
        assert call_args[1]['extra']['ip_address'] == '192.168.1.1'
        assert call_args[1]['extra']['outcome'] == 'success'
        assert call_args[1]['extra']['risk_level'] == 'low'
        
    def test_log_performance_event(self):
        """Testa função de log de evento de performance."""
        logger = MagicMock()
        
        log_performance_event(
            logger=logger,
            operation="database_query",
            duration_ms=150.5,
            cpu_usage=25.0
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Performance: database_query took 150.5ms" in call_args[0][0]
        assert call_args[1]['extra']['operation'] == 'database_query'
        assert call_args[1]['extra']['duration_ms'] == 150.5
        assert call_args[1]['extra']['cpu_usage'] == 25.0
        
    def test_log_audit_event(self):
        """Testa função de log de evento de auditoria."""
        logger = MagicMock()
        
        log_audit_event(
            logger=logger,
            event="user_update",
            action="modify",
            user_id="user-123",
            resource_type="user",
            resource_id="user-456"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Audit Event: user_update" in call_args[0][0]
        assert call_args[1]['extra']['audit_event'] == 'user_update'
        assert call_args[1]['extra']['audit_action'] == 'modify'
        assert call_args[1]['extra']['user_id'] == 'user-123'
        assert call_args[1]['extra']['resource_type'] == 'user'
        assert call_args[1]['extra']['resource_id'] == 'user-456'


class TestIntegrationLogging:
    """Testes de integração para sistema de logging."""
    
    def test_get_structured_logger_integration(self):
        """Testa integração da função get_structured_logger."""
        logger = get_structured_logger("integration_test")
        
        assert logger.name == "integration_test"
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 3
        
    def test_log_event_integration(self):
        """Testa integração da função log_event."""
        logger = get_structured_logger("integration_test")
        
        with patch.object(logger, 'info') as mock_info:
            log_event(
                logger=logger,
                event="test_event",
                status="SUCCESS",
                trace_id="trace-123",
                context={"test": "data"},
                metrics={"duration": 100}
            )
            
            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "Event: test_event | Status: SUCCESS" in call_args[0][0]
            assert call_args[1]['extra']['trace_id'] == 'trace-123'
            assert call_args[1]['extra']['context']['test'] == 'data'
            assert call_args[1]['extra']['metrics']['duration'] == 100


# Import necessário para teste de exceção
import sys 