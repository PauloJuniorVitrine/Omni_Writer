"""
Testes Unitários - Header Sensitivity Auditor
============================================

Testes baseados em código real para o sistema de auditoria de headers.
Testa funcionalidades específicas implementadas no header_sensitivity_auditor.py.

Prompt: Header Sensitivity Audit - Item 9
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T20:35:00Z
Tracing ID: HEADER_SENSITIVITY_AUDIT_TEST_20250127_009

Regras de Teste:
- ✅ Baseado em código real implementado
- ✅ Testa funcionalidades específicas
- ❌ Proibido: dados fictícios, testes genéricos
- ❌ Proibido: foo, bar, lorem, random
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from scripts.header_sensitivity_auditor import (
    HeaderSensitivityAuditor,
    HeaderViolation,
    HeaderAuditResult,
    HeaderSensitivityLevel,
    HeaderViolationType,
    audit_headers,
    audit_endpoint
)


class TestHeaderSensitivityAuditor:
    """Testes para a classe HeaderSensitivityAuditor."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.auditor = HeaderSensitivityAuditor()
        self.sample_context = {
            'endpoint': '/api/generate',
            'method': 'POST',
            'status_code': 200,
            'environment': 'production'
        }
    
    def test_auditor_initialization(self):
        """Testa inicialização correta do auditor."""
        assert self.auditor.tracing_id.startswith("HEADER_AUDIT_")
        assert len(self.auditor.sensitive_headers) > 0
        assert len(self.auditor.sensitive_patterns) > 0
        assert len(self.auditor.allowed_in_context) > 0
    
    def test_detect_server_info_leak(self):
        """Testa detecção de vazamento de informações do servidor."""
        headers = {
            'server': 'nginx/1.18.0',
            'x-powered-by': 'PHP/7.4.0',
            'content-type': 'application/json'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve detectar headers de servidor
        server_violations = [v for v in result.violations if v.violation_type == HeaderViolationType.SERVER_INFO_LEAK]
        assert len(server_violations) >= 2
        
        # Verifica headers específicos
        server_header_violation = next((v for v in server_violations if v.header_name == 'server'), None)
        assert server_header_violation is not None
        assert server_header_violation.sensitivity_level == HeaderSensitivityLevel.HIGH
    
    def test_detect_debug_info_leak(self):
        """Testa detecção de vazamento de informações de debug."""
        headers = {
            'x-debug': 'true',
            'x-debug-info': 'stack trace available',
            'x-debug-token': 'abc123',
            'content-type': 'application/json'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve detectar headers de debug
        debug_violations = [v for v in result.violations if v.violation_type == HeaderViolationType.DEBUG_INFO_LEAK]
        assert len(debug_violations) >= 3
        
        # Verifica que são críticos
        for violation in debug_violations:
            assert violation.sensitivity_level == HeaderSensitivityLevel.CRITICAL
    
    def test_detect_sensitive_data_exposure(self):
        """Testa detecção de exposição de dados sensíveis."""
        headers = {
            'x-file-path': '/var/www/html/config.php',
            'x-real-path': '/home/user/app/secret.txt',
            'x-database': 'mysql://user:password@localhost/db',
            'content-type': 'application/json'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve detectar exposição de dados sensíveis
        sensitive_violations = [v for v in result.violations if v.violation_type == HeaderViolationType.SENSITIVE_DATA_EXPOSURE]
        assert len(sensitive_violations) >= 3
        
        # Verifica padrões específicos
        path_violations = [v for v in sensitive_violations if '/var/www/' in v.header_value or '/home/' in v.header_value]
        assert len(path_violations) >= 2
    
    def test_false_positive_validation_monitoring_context(self):
        """Testa validação de falso positivo em contexto de monitoramento."""
        headers = {
            'x-request-id': 'req-123',
            'x-correlation-id': 'corr-456',
            'x-response-time': '150ms'
        }
        
        monitoring_context = {
            'endpoint': '/metrics',
            'method': 'GET',
            'status_code': 200,
            'context_type': 'monitoring'
        }
        
        result = self.auditor.audit_headers(headers, monitoring_context)
        
        # Headers de monitoramento devem ser permitidos
        monitoring_violations = [v for v in result.violations if v.header_name in ['x-request-id', 'x-correlation-id', 'x-response-time']]
        for violation in monitoring_violations:
            assert violation.is_false_positive
            assert "monitoring" in violation.false_positive_reason
    
    def test_false_positive_validation_tracing_context(self):
        """Testa validação de falso positivo em contexto de tracing."""
        headers = {
            'x-trace-id': 'trace-789',
            'x-span-id': 'span-012',
            'x-request-id': 'req-345'
        }
        
        tracing_context = {
            'endpoint': '/trace',
            'method': 'GET',
            'status_code': 200,
            'context_type': 'tracing'
        }
        
        result = self.auditor.audit_headers(headers, tracing_context)
        
        # Headers de tracing devem ser permitidos
        tracing_violations = [v for v in result.violations if v.header_name in ['x-trace-id', 'x-span-id', 'x-request-id']]
        for violation in tracing_violations:
            assert violation.is_false_positive
            assert "tracing" in violation.false_positive_reason
    
    def test_false_positive_validation_development_environment(self):
        """Testa validação de falso positivo em ambiente de desenvolvimento."""
        headers = {
            'x-debug': 'true',
            'x-debug-info': 'stack trace available'
        }
        
        dev_context = {
            'endpoint': '/api/test',
            'method': 'GET',
            'status_code': 200,
            'environment': 'development'
        }
        
        result = self.auditor.audit_headers(headers, dev_context)
        
        # Headers de debug devem ser permitidos em desenvolvimento
        debug_violations = [v for v in result.violations if v.violation_type == HeaderViolationType.DEBUG_INFO_LEAK]
        for violation in debug_violations:
            assert violation.is_false_positive
            assert "desenvolvimento" in violation.false_positive_reason
    
    def test_risk_score_calculation(self):
        """Testa cálculo de score de risco."""
        headers = {
            'server': 'nginx/1.18.0',
            'x-debug': 'true',
            'x-file-path': '/var/www/config.php'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve ter score de risco > 0
        assert result.risk_score > 0
        assert result.risk_score <= 1.0
        
        # Score deve ser baseado nas violações reais
        real_violations = [v for v in result.violations if not v.is_false_positive]
        if real_violations:
            assert result.risk_score > 0.1
    
    def test_recommendations_generation(self):
        """Testa geração de recomendações."""
        headers = {
            'x-debug': 'true',
            'server': 'nginx/1.18.0',
            'x-file-path': '/var/www/config.php'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve gerar recomendações
        assert len(result.recommendations) > 0
        
        # Verifica recomendações específicas
        recommendations_text = ' '.join(result.recommendations).lower()
        if any('debug' in v.header_name for v in result.violations if not v.is_false_positive):
            assert 'debug' in recommendations_text or 'desenvolvimento' in recommendations_text
    
    def test_content_pattern_detection(self):
        """Testa detecção de padrões de conteúdo sensível."""
        headers = {
            'x-config': 'database_url=mysql://user:password@192.168.1.100/db',
            'x-error': 'stack trace: /var/log/app/error.log',
            'x-path': '/home/user/app/secret/config.json'
        }
        
        result = self.auditor.audit_headers(headers, self.sample_context)
        
        # Deve detectar padrões sensíveis
        sensitive_violations = [v for v in result.violations if v.violation_type == HeaderViolationType.SENSITIVE_DATA_EXPOSURE]
        assert len(sensitive_violations) >= 3
        
        # Verifica padrões específicos
        ip_violations = [v for v in sensitive_violations if '192.168.' in v.header_value]
        path_violations = [v for v in sensitive_violations if '/home/' in v.header_value]
        
        assert len(ip_violations) >= 1
        assert len(path_violations) >= 1
    
    def test_environment_detection(self):
        """Testa detecção de ambiente baseado na URL."""
        # Testa ambiente de desenvolvimento
        dev_env = self.auditor._detect_environment('http://localhost:3000/api/test')
        assert dev_env == 'development'
        
        # Testa ambiente de staging
        staging_env = self.auditor._detect_environment('https://staging.example.com/api/test')
        assert staging_env == 'staging'
        
        # Testa ambiente de produção
        prod_env = self.auditor._detect_environment('https://prod.example.com/api/test')
        assert prod_env == 'production'
        
        # Testa ambiente desconhecido
        unknown_env = self.auditor._detect_environment('https://example.com/api/test')
        assert unknown_env == 'unknown'


class TestHeaderViolation:
    """Testes para a classe HeaderViolation."""
    
    def test_header_violation_creation(self):
        """Testa criação de violação de header."""
        context = {'endpoint': '/test', 'method': 'GET'}
        
        violation = HeaderViolation(
            header_name='server',
            header_value='nginx/1.18.0',
            violation_type=HeaderViolationType.SERVER_INFO_LEAK,
            sensitivity_level=HeaderSensitivityLevel.HIGH,
            description='Header vaza informações do servidor',
            risk_score=0.8,
            recommendation='Usar valor genérico',
            context=context,
            timestamp=datetime.now()
        )
        
        assert violation.header_name == 'server'
        assert violation.violation_type == HeaderViolationType.SERVER_INFO_LEAK
        assert violation.sensitivity_level == HeaderSensitivityLevel.HIGH
        assert violation.risk_score == 0.8
        assert not violation.is_false_positive
    
    def test_header_violation_false_positive(self):
        """Testa violação marcada como falso positivo."""
        context = {'endpoint': '/metrics', 'context_type': 'monitoring'}
        
        violation = HeaderViolation(
            header_name='x-request-id',
            header_value='req-123',
            violation_type=HeaderViolationType.INTERNAL_INFO_LEAK,
            sensitivity_level=HeaderSensitivityLevel.LOW,
            description='Header de request ID',
            risk_score=0.2,
            recommendation='Permitido em contexto de monitoramento',
            context=context,
            timestamp=datetime.now(),
            is_false_positive=True,
            false_positive_reason='Header permitido no contexto: monitoring'
        )
        
        assert violation.is_false_positive
        assert 'monitoring' in violation.false_positive_reason


class TestHeaderAuditResult:
    """Testes para a classe HeaderAuditResult."""
    
    def test_header_audit_result_creation(self):
        """Testa criação de resultado de auditoria."""
        violations = [
            HeaderViolation(
                header_name='server',
                header_value='nginx/1.18.0',
                violation_type=HeaderViolationType.SERVER_INFO_LEAK,
                sensitivity_level=HeaderSensitivityLevel.HIGH,
                description='Header vaza informações do servidor',
                risk_score=0.8,
                recommendation='Usar valor genérico',
                context={},
                timestamp=datetime.now()
            )
        ]
        
        result = HeaderAuditResult(
            total_headers=5,
            violations=violations,
            risk_score=0.8,
            recommendations=['Remover header server'],
            audit_timestamp=datetime.now(),
            endpoint='/api/test',
            method='GET',
            status_code=200
        )
        
        assert result.total_headers == 5
        assert len(result.violations) == 1
        assert result.risk_score == 0.8
        assert len(result.recommendations) == 1
        assert result.endpoint == '/api/test'
        assert result.method == 'GET'
        assert result.status_code == 200


class TestFunctions:
    """Testes para funções de conveniência."""
    
    def test_audit_headers_function(self):
        """Testa função de conveniência audit_headers."""
        headers = {
            'server': 'nginx/1.18.0',
            'x-debug': 'true'
        }
        
        context = {'endpoint': '/api/test', 'method': 'GET'}
        
        result = audit_headers(headers, context)
        
        assert isinstance(result, HeaderAuditResult)
        assert result.total_headers == 2
        assert len(result.violations) >= 2
    
    @patch('scripts.header_sensitivity_auditor.requests.request')
    def test_audit_endpoint_function(self, mock_request):
        """Testa função de conveniência audit_endpoint."""
        # Mock da resposta HTTP
        mock_response = Mock()
        mock_response.headers = {
            'server': 'nginx/1.18.0',
            'content-type': 'application/json'
        }
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        result = audit_endpoint('http://localhost:3000/api/test')
        
        assert isinstance(result, HeaderAuditResult)
        assert result.total_headers == 2
        assert result.status_code == 200
        assert result.endpoint == '/api/test'
        
        # Verifica que a requisição foi feita
        mock_request.assert_called_once()
    
    @patch('scripts.header_sensitivity_auditor.requests.request')
    def test_audit_endpoint_error_handling(self, mock_request):
        """Testa tratamento de erro na função audit_endpoint."""
        # Mock de erro na requisição
        mock_request.side_effect = Exception("Connection error")
        
        result = audit_endpoint('http://invalid-url.com/api/test')
        
        assert isinstance(result, HeaderAuditResult)
        assert result.total_headers == 0
        assert result.status_code == 0
        assert len(result.recommendations) == 1
        assert "Erro" in result.recommendations[0]


class TestReportGeneration:
    """Testes para geração de relatórios."""
    
    def test_generate_report(self):
        """Testa geração de relatório consolidado."""
        auditor = HeaderSensitivityAuditor()
        
        # Cria resultados de teste
        violations = [
            HeaderViolation(
                header_name='server',
                header_value='nginx/1.18.0',
                violation_type=HeaderViolationType.SERVER_INFO_LEAK,
                sensitivity_level=HeaderSensitivityLevel.HIGH,
                description='Header vaza informações do servidor',
                risk_score=0.8,
                recommendation='Usar valor genérico',
                context={},
                timestamp=datetime.now()
            )
        ]
        
        results = [
            HeaderAuditResult(
                total_headers=5,
                violations=violations,
                risk_score=0.8,
                recommendations=['Remover header server'],
                audit_timestamp=datetime.now(),
                endpoint='/api/test1',
                method='GET',
                status_code=200
            ),
            HeaderAuditResult(
                total_headers=3,
                violations=violations,
                risk_score=0.8,
                recommendations=['Remover header server'],
                audit_timestamp=datetime.now(),
                endpoint='/api/test2',
                method='POST',
                status_code=200
            )
        ]
        
        report = auditor.generate_report(results)
        
        # Verifica estrutura do relatório
        assert 'audit_summary' in report
        assert 'violation_types' in report
        assert 'problematic_headers' in report
        assert 'recommendations' in report
        assert 'detailed_results' in report
        
        # Verifica dados do resumo
        summary = report['audit_summary']
        assert summary['total_endpoints'] == 2
        assert summary['total_violations'] == 2
        assert summary['real_violations'] == 2
        assert summary['false_positives'] == 0
        assert summary['average_risk_score'] == 0.8
        
        # Verifica tipos de violação
        violation_types = report['violation_types']
        assert HeaderViolationType.SERVER_INFO_LEAK.value in violation_types
        assert violation_types[HeaderViolationType.SERVER_INFO_LEAK.value] == 2
        
        # Verifica headers problemáticos
        problematic_headers = report['problematic_headers']
        assert 'server' in problematic_headers
        assert problematic_headers['server'] == 2


class TestIntegration:
    """Testes de integração."""
    
    def test_full_audit_workflow(self):
        """Testa workflow completo de auditoria."""
        auditor = HeaderSensitivityAuditor()
        
        # Headers com diferentes tipos de problemas
        headers = {
            'server': 'nginx/1.18.0',
            'x-debug': 'true',
            'x-file-path': '/var/www/config.php',
            'x-request-id': 'req-123',
            'content-type': 'application/json'
        }
        
        # Contexto de produção
        prod_context = {
            'endpoint': '/api/generate',
            'method': 'POST',
            'status_code': 200,
            'environment': 'production'
        }
        
        # Executa auditoria
        result = auditor.audit_headers(headers, prod_context)
        
        # Verifica resultados
        assert result.total_headers == 5
        assert len(result.violations) >= 3  # server, x-debug, x-file-path
        
        # Verifica que x-request-id pode ser falso positivo
        request_id_violations = [v for v in result.violations if v.header_name == 'x-request-id']
        if request_id_violations:
            # Pode ser falso positivo dependendo do contexto
            assert request_id_violations[0].is_false_positive or request_id_violations[0].sensitivity_level == HeaderSensitivityLevel.LOW
        
        # Verifica score de risco
        assert result.risk_score > 0
        assert result.risk_score <= 1.0
        
        # Verifica recomendações
        assert len(result.recommendations) > 0
    
    def test_multiple_endpoints_audit(self):
        """Testa auditoria de múltiplos endpoints."""
        auditor = HeaderSensitivityAuditor()
        
        # Simula headers de diferentes endpoints
        endpoints_data = [
            {
                'headers': {'server': 'nginx/1.18.0', 'x-debug': 'true'},
                'context': {'endpoint': '/api/generate', 'environment': 'production'}
            },
            {
                'headers': {'x-request-id': 'req-123', 'x-response-time': '150ms'},
                'context': {'endpoint': '/metrics', 'context_type': 'monitoring'}
            },
            {
                'headers': {'x-file-path': '/var/www/config.php'},
                'context': {'endpoint': '/api/config', 'environment': 'production'}
            }
        ]
        
        results = []
        for data in endpoints_data:
            result = auditor.audit_headers(data['headers'], data['context'])
            results.append(result)
        
        # Gera relatório consolidado
        report = auditor.generate_report(results)
        
        # Verifica relatório
        assert report['audit_summary']['total_endpoints'] == 3
        assert report['audit_summary']['total_violations'] >= 3
        
        # Verifica que há violações reais e falsos positivos
        assert report['audit_summary']['real_violations'] >= 2
        assert report['audit_summary']['false_positives'] >= 1
        
        # Verifica recomendações globais
        assert len(report['recommendations']) > 0


if __name__ == "__main__":
    pytest.main([__file__]) 