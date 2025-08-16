"""
Testes unitários para formatters específicos de logging.

Prompt: Logging Estruturado - IMP-005
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:40:00Z
Tracing ID: ENTERPRISE_20250127_005
"""

import pytest
import json
import logging
import sys
from unittest.mock import MagicMock

from shared.log_formatters import (
    SecurityFormatter,
    PerformanceFormatter,
    AuditFormatter,
    BusinessFormatter,
    ErrorFormatter,
    create_formatter,
    log_security_event,
    log_performance_event,
    log_audit_event
)


class TestSecurityFormatter:
    """Testes para formatter de segurança."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = SecurityFormatter()
        
    def test_format_security_log_basic(self):
        """Testa formatação básica de log de segurança."""
        record = logging.LogRecord(
            name="security_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Login attempt",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'security'
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'security_logger'
        assert log_data['event'] == 'Login attempt'
        assert log_data['outcome'] == 'unknown'
        assert log_data['risk_level'] == 'low'
        assert 'timestamp' in log_data
        
    def test_format_security_log_complete(self):
        """Testa formatação completa de log de segurança."""
        record = logging.LogRecord(
            name="security_logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=10,
            msg="Failed login attempt",
            args=(),
            exc_info=None
        )
        record.security_event = "user_login"
        record.security_action = "authentication"
        record.user_id = "user-123"
        record.ip_address = "192.168.1.1"
        record.user_agent = "Mozilla/5.0"
        record.resource = "/api/login"
        record.outcome = "failure"
        record.risk_level = "medium"
        record.trace_id = "trace-123"
        record.session_id = "session-456"
        record.security_context = {
            "attempt_count": 3,
            "blocked": False
        }
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'security'
        assert log_data['level'] == 'WARNING'
        assert log_data['event'] == 'user_login'
        assert log_data['action'] == 'authentication'
        assert log_data['user_id'] == 'user-123'
        assert log_data['ip_address'] == '192.168.1.1'
        assert log_data['user_agent'] == 'Mozilla/5.0'
        assert log_data['resource'] == '/api/login'
        assert log_data['outcome'] == 'failure'
        assert log_data['risk_level'] == 'medium'
        assert log_data['trace_id'] == 'trace-123'
        assert log_data['session_id'] == 'session-456'
        assert log_data['security_context']['attempt_count'] == 3
        assert log_data['security_context']['blocked'] is False
        
    def test_format_security_log_with_exception(self):
        """Testa formatação de log de segurança com exceção."""
        try:
            raise ValueError("Invalid credentials")
        except ValueError:
            record = logging.LogRecord(
                name="security_logger",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Authentication error",
                args=(),
                exc_info=sys.exc_info()
            )
            record.security_event = "auth_error"
            record.security_action = "authentication"
            record.user_id = "user-123"
            record.ip_address = "192.168.1.1"
            record.outcome = "error"
            record.risk_level = "high"
            
            result = self.formatter.format(record)
            log_data = json.loads(result)
            
            assert log_data['type'] == 'security'
            assert log_data['level'] == 'ERROR'
            assert log_data['event'] == 'auth_error'
            assert log_data['outcome'] == 'error'
            assert log_data['risk_level'] == 'high'
            assert 'exception' in log_data
            assert log_data['exception']['type'] == 'ValueError'
            assert log_data['exception']['message'] == 'Invalid credentials'


class TestPerformanceFormatter:
    """Testes para formatter de performance."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = PerformanceFormatter()
        
    def test_format_performance_log_basic(self):
        """Testa formatação básica de log de performance."""
        record = logging.LogRecord(
            name="performance_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Database query",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'performance'
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'performance_logger'
        assert log_data['operation'] == 'Database query'
        assert 'timestamp' in log_data
        
    def test_format_performance_log_complete(self):
        """Testa formatação completa de log de performance."""
        record = logging.LogRecord(
            name="performance_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="API call completed",
            args=(),
            exc_info=None
        )
        record.operation = "external_api_call"
        record.duration_ms = 250.5
        record.cpu_usage = 15.2
        record.memory_usage = 1024.0
        record.throughput = 100.0
        record.queue_size = 5
        record.cache_hit_rate = 0.85
        record.database_queries = 3
        record.external_calls = 1
        record.trace_id = "trace-123"
        record.span_id = "span-456"
        record.performance_metrics = {
            "response_time_p95": 300.0,
            "error_rate": 0.01
        }
        record.performance_context = {
            "endpoint": "/api/articles",
            "method": "POST"
        }
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'performance'
        assert log_data['operation'] == 'external_api_call'
        assert log_data['duration_ms'] == 250.5
        assert log_data['cpu_usage'] == 15.2
        assert log_data['memory_usage'] == 1024.0
        assert log_data['throughput'] == 100.0
        assert log_data['queue_size'] == 5
        assert log_data['cache_hit_rate'] == 0.85
        assert log_data['database_queries'] == 3
        assert log_data['external_calls'] == 1
        assert log_data['trace_id'] == 'trace-123'
        assert log_data['span_id'] == 'span-456'
        assert log_data['performance_metrics']['response_time_p95'] == 300.0
        assert log_data['performance_metrics']['error_rate'] == 0.01
        assert log_data['performance_context']['endpoint'] == '/api/articles'
        assert log_data['performance_context']['method'] == 'POST'


class TestAuditFormatter:
    """Testes para formatter de auditoria."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = AuditFormatter()
        
    def test_format_audit_log_basic(self):
        """Testa formatação básica de log de auditoria."""
        record = logging.LogRecord(
            name="audit_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="User data update",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'audit'
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'audit_logger'
        assert log_data['event'] == 'User data update'
        assert log_data['compliance_tags'] == []
        assert 'timestamp' in log_data
        
    def test_format_audit_log_complete(self):
        """Testa formatação completa de log de auditoria."""
        record = logging.LogRecord(
            name="audit_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="User profile modification",
            args=(),
            exc_info=None
        )
        record.audit_event = "user_profile_update"
        record.audit_action = "modify"
        record.user_id = "user-123"
        record.user_role = "admin"
        record.resource_type = "user_profile"
        record.resource_id = "profile-456"
        record.old_value = {
            "name": "John Doe",
            "email": "john@example.com"
        }
        record.new_value = {
            "name": "John Smith",
            "email": "john.smith@example.com"
        }
        record.reason = "User requested name change"
        record.ip_address = "192.168.1.1"
        record.user_agent = "Mozilla/5.0"
        record.trace_id = "trace-123"
        record.session_id = "session-456"
        record.compliance_tags = ["gdpr", "sox"]
        record.audit_context = {
            "change_source": "web_interface",
            "approval_required": False
        }
        record.compliance_metadata = {
            "data_classification": "personal",
            "retention_period": "7_years"
        }
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'audit'
        assert log_data['event'] == 'user_profile_update'
        assert log_data['action'] == 'modify'
        assert log_data['user_id'] == 'user-123'
        assert log_data['user_role'] == 'admin'
        assert log_data['resource_type'] == 'user_profile'
        assert log_data['resource_id'] == 'profile-456'
        assert log_data['old_value']['name'] == 'John Doe'
        assert log_data['new_value']['name'] == 'John Smith'
        assert log_data['reason'] == 'User requested name change'
        assert log_data['ip_address'] == '192.168.1.1'
        assert log_data['user_agent'] == 'Mozilla/5.0'
        assert log_data['trace_id'] == 'trace-123'
        assert log_data['session_id'] == 'session-456'
        assert 'gdpr' in log_data['compliance_tags']
        assert 'sox' in log_data['compliance_tags']
        assert log_data['audit_context']['change_source'] == 'web_interface'
        assert log_data['audit_context']['approval_required'] is False
        assert log_data['compliance_metadata']['data_classification'] == 'personal'
        assert log_data['compliance_metadata']['retention_period'] == '7_years'


class TestBusinessFormatter:
    """Testes para formatter de negócio."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = BusinessFormatter()
        
    def test_format_business_log_basic(self):
        """Testa formatação básica de log de negócio."""
        record = logging.LogRecord(
            name="business_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Article generation",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'business'
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'business_logger'
        assert log_data['event'] == 'Article generation'
        assert 'timestamp' in log_data
        
    def test_format_business_log_complete(self):
        """Testa formatação completa de log de negócio."""
        record = logging.LogRecord(
            name="business_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Premium article generation",
            args=(),
            exc_info=None
        )
        record.business_event = "premium_article_generation"
        record.user_id = "user-123"
        record.customer_id = "customer-456"
        record.transaction_id = "txn-789"
        record.product_id = "premium_article_gen"
        record.amount = 25.00
        record.currency = "USD"
        record.channel = "web"
        record.campaign = "summer_promotion"
        record.conversion = True
        record.trace_id = "trace-123"
        record.business_unit = "content_generation"
        record.business_context = {
            "article_length": "long",
            "topic": "technology",
            "language": "en"
        }
        record.business_metrics = {
            "generation_time": 45.2,
            "quality_score": 0.92,
            "user_satisfaction": 4.8
        }
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'business'
        assert log_data['event'] == 'premium_article_generation'
        assert log_data['user_id'] == 'user-123'
        assert log_data['customer_id'] == 'customer-456'
        assert log_data['transaction_id'] == 'txn-789'
        assert log_data['product_id'] == 'premium_article_gen'
        assert log_data['amount'] == 25.00
        assert log_data['currency'] == 'USD'
        assert log_data['channel'] == 'web'
        assert log_data['campaign'] == 'summer_promotion'
        assert log_data['conversion'] is True
        assert log_data['trace_id'] == 'trace-123'
        assert log_data['business_unit'] == 'content_generation'
        assert log_data['business_context']['article_length'] == 'long'
        assert log_data['business_context']['topic'] == 'technology'
        assert log_data['business_context']['language'] == 'en'
        assert log_data['business_metrics']['generation_time'] == 45.2
        assert log_data['business_metrics']['quality_score'] == 0.92
        assert log_data['business_metrics']['user_satisfaction'] == 4.8


class TestErrorFormatter:
    """Testes para formatter de erro."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.formatter = ErrorFormatter()
        
    def test_format_error_log_basic(self):
        """Testa formatação básica de log de erro."""
        record = logging.LogRecord(
            name="error_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="API call failed",
            args=(),
            exc_info=None
        )
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'error'
        assert log_data['level'] == 'ERROR'
        assert log_data['logger'] == 'error_logger'
        assert log_data['message'] == 'API call failed'
        assert log_data['module'] == 'test'
        assert log_data['function'] == 'test_format_error_log_basic'
        assert log_data['line'] == 10
        assert log_data['environment'] == 'production'
        assert 'timestamp' in log_data
        
    def test_format_error_log_complete(self):
        """Testa formatação completa de log de erro."""
        record = logging.LogRecord(
            name="error_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Database connection failed",
            args=(),
            exc_info=None
        )
        record.error_code = "DB_001"
        record.error_category = "database"
        record.user_id = "user-123"
        record.request_id = "req-456"
        record.trace_id = "trace-123"
        record.span_id = "span-456"
        record.environment = "staging"
        record.version = "1.2.3"
        record.error_context = {
            "database": "postgresql",
            "connection_pool_size": 10,
            "timeout": 30
        }
        record.stack_trace = [
            "File 'app.py', line 25, in main",
            "File 'database.py', line 15, in connect"
        ]
        
        result = self.formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['type'] == 'error'
        assert log_data['level'] == 'ERROR'
        assert log_data['message'] == 'Database connection failed'
        assert log_data['error_code'] == 'DB_001'
        assert log_data['error_category'] == 'database'
        assert log_data['user_id'] == 'user-123'
        assert log_data['request_id'] == 'req-456'
        assert log_data['trace_id'] == 'trace-123'
        assert log_data['span_id'] == 'span-456'
        assert log_data['environment'] == 'staging'
        assert log_data['version'] == '1.2.3'
        assert log_data['error_context']['database'] == 'postgresql'
        assert log_data['error_context']['connection_pool_size'] == 10
        assert log_data['error_context']['timeout'] == 30
        assert len(log_data['stack_trace']) == 2
        assert 'app.py' in log_data['stack_trace'][0]
        assert 'database.py' in log_data['stack_trace'][1]
        
    def test_format_error_log_with_exception(self):
        """Testa formatação de log de erro com exceção."""
        try:
            raise ConnectionError("Database connection timeout")
        except ConnectionError:
            record = logging.LogRecord(
                name="error_logger",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Database connection error",
                args=(),
                exc_info=sys.exc_info()
            )
            record.error_code = "DB_002"
            record.error_category = "connection"
            record.user_id = "user-123"
            record.environment = "production"
            
            result = self.formatter.format(record)
            log_data = json.loads(result)
            
            assert log_data['type'] == 'error'
            assert log_data['level'] == 'ERROR'
            assert log_data['error_code'] == 'DB_002'
            assert log_data['error_category'] == 'connection'
            assert log_data['user_id'] == 'user-123'
            assert log_data['environment'] == 'production'
            assert 'exception' in log_data
            assert log_data['exception']['type'] == 'ConnectionError'
            assert log_data['exception']['message'] == 'Database connection timeout'
            assert 'traceback' in log_data['exception']


class TestFormatterFactory:
    """Testes para factory de formatters."""
    
    def test_create_formatter_security(self):
        """Testa criação de formatter de segurança."""
        formatter = create_formatter('security')
        assert isinstance(formatter, SecurityFormatter)
        
    def test_create_formatter_performance(self):
        """Testa criação de formatter de performance."""
        formatter = create_formatter('performance')
        assert isinstance(formatter, PerformanceFormatter)
        
    def test_create_formatter_audit(self):
        """Testa criação de formatter de auditoria."""
        formatter = create_formatter('audit')
        assert isinstance(formatter, AuditFormatter)
        
    def test_create_formatter_business(self):
        """Testa criação de formatter de negócio."""
        formatter = create_formatter('business')
        assert isinstance(formatter, BusinessFormatter)
        
    def test_create_formatter_error(self):
        """Testa criação de formatter de erro."""
        formatter = create_formatter('error')
        assert isinstance(formatter, ErrorFormatter)
        
    def test_create_formatter_unknown(self):
        """Testa criação de formatter desconhecido."""
        formatter = create_formatter('unknown')
        assert isinstance(formatter, logging.Formatter)


class TestLoggingFunctions:
    """Testes para funções de logging de conveniência."""
    
    def test_log_security_event_basic(self):
        """Testa função básica de log de evento de segurança."""
        logger = MagicMock()
        
        log_security_event(
            logger=logger,
            event="user_login",
            action="authentication"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Security Event: user_login" in call_args[0][0]
        assert call_args[1]['extra']['security_event'] == 'user_login'
        assert call_args[1]['extra']['security_action'] == 'authentication'
        assert call_args[1]['extra']['outcome'] == 'success'
        assert call_args[1]['extra']['risk_level'] == 'low'
        
    def test_log_security_event_complete(self):
        """Testa função completa de log de evento de segurança."""
        logger = MagicMock()
        
        log_security_event(
            logger=logger,
            event="failed_login",
            action="authentication",
            user_id="user-123",
            ip_address="192.168.1.1",
            outcome="failure",
            risk_level="medium",
            user_agent="Mozilla/5.0",
            resource="/api/login"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Security Event: failed_login" in call_args[0][0]
        assert call_args[1]['extra']['security_event'] == 'failed_login'
        assert call_args[1]['extra']['security_action'] == 'authentication'
        assert call_args[1]['extra']['user_id'] == 'user-123'
        assert call_args[1]['extra']['ip_address'] == '192.168.1.1'
        assert call_args[1]['extra']['outcome'] == 'failure'
        assert call_args[1]['extra']['risk_level'] == 'medium'
        assert call_args[1]['extra']['user_agent'] == 'Mozilla/5.0'
        assert call_args[1]['extra']['resource'] == '/api/login'
        
    def test_log_performance_event_basic(self):
        """Testa função básica de log de evento de performance."""
        logger = MagicMock()
        
        log_performance_event(
            logger=logger,
            operation="database_query",
            duration_ms=100.5
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Performance: database_query took 100.5ms" in call_args[0][0]
        assert call_args[1]['extra']['operation'] == 'database_query'
        assert call_args[1]['extra']['duration_ms'] == 100.5
        
    def test_log_performance_event_with_metrics(self):
        """Testa função de log de evento de performance com métricas."""
        logger = MagicMock()
        
        log_performance_event(
            logger=logger,
            operation="api_call",
            duration_ms=250.0,
            cpu_usage=15.2,
            memory_usage=1024.0,
            throughput=100.0
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Performance: api_call took 250.0ms" in call_args[0][0]
        assert call_args[1]['extra']['operation'] == 'api_call'
        assert call_args[1]['extra']['duration_ms'] == 250.0
        assert call_args[1]['extra']['cpu_usage'] == 15.2
        assert call_args[1]['extra']['memory_usage'] == 1024.0
        assert call_args[1]['extra']['throughput'] == 100.0
        
    def test_log_audit_event_basic(self):
        """Testa função básica de log de evento de auditoria."""
        logger = MagicMock()
        
        log_audit_event(
            logger=logger,
            event="user_update",
            action="modify"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Audit Event: user_update" in call_args[0][0]
        assert call_args[1]['extra']['audit_event'] == 'user_update'
        assert call_args[1]['extra']['audit_action'] == 'modify'
        
    def test_log_audit_event_complete(self):
        """Testa função completa de log de evento de auditoria."""
        logger = MagicMock()
        
        log_audit_event(
            logger=logger,
            event="user_delete",
            action="delete",
            user_id="user-123",
            resource_type="user",
            resource_id="user-456",
            user_role="admin",
            reason="Account termination"
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert "Audit Event: user_delete" in call_args[0][0]
        assert call_args[1]['extra']['audit_event'] == 'user_delete'
        assert call_args[1]['extra']['audit_action'] == 'delete'
        assert call_args[1]['extra']['user_id'] == 'user-123'
        assert call_args[1]['extra']['resource_type'] == 'user'
        assert call_args[1]['extra']['resource_id'] == 'user-456'
        assert call_args[1]['extra']['user_role'] == 'admin'
        assert call_args[1]['extra']['reason'] == 'Account termination' 