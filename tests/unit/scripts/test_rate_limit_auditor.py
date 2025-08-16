"""
Testes Unitários - Rate Limit Auditor
====================================

Testes para o sistema de auditoria de rate limits baseados em código real.

Prompt: Rate Limits & Throttling Audit - Item 7
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T19:40:00Z
Tracing ID: RATE_LIMIT_AUDIT_TEST_20250127_007

Análise CoCoT:
- Comprovação: Baseado em Test-Driven Development e Security Testing
- Causalidade: Valida funcionalidades reais do sistema de auditoria de rate limits
- Contexto: Testa integração com sistema de rate limiting existente e monitoring
- Tendência: Usa mocks realistas e cenários de produção

Decisões ToT:
- Abordagem 1: Testes de integração completos (realista, mas lento)
- Abordagem 2: Mocks simples (rápido, mas não realista)
- Abordagem 3: Mocks realistas + testes de unidade (equilibrado)
- Escolha: Abordagem 3 - mocks que simulam comportamento real

Simulação ReAct:
- Antes: Configurações de rate limiting não validadas
- Durante: Testes validam auditoria automática de configurações
- Depois: Rate limiting otimizado e seguro

Validação de Falsos Positivos:
- Regra: Teste pode falhar por configuração legítima específica
- Validação: Verificar se teste reflete funcionalidade real
- Log: Registrar configurações válidas mas diferentes do padrão
"""

import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, mock_open
from typing import Dict, Any, List

from scripts.rate_limit_auditor import (
    RateLimitAuditor,
    RateLimitConfig,
    RateLimitViolation,
    AuditResult,
    AuditSeverity,
    RateLimitType,
    get_rate_limit_auditor,
    run_rate_limit_audit
)


class TestRateLimitAuditor:
    """Testes para o auditor de rate limits."""

    def setup_method(self):
        """Configuração para cada teste."""
        # Mock das dependências
        with patch('scripts.rate_limit_auditor.is_feature_enabled') as mock_feature:
            mock_feature.return_value = True
            
            with patch('scripts.rate_limit_auditor.get_structured_logger') as mock_logger:
                mock_logger.return_value = Mock()
                
                with patch('scripts.rate_limit_auditor.metrics_collector') as mock_metrics:
                    mock_metrics.record_request = Mock()
                    mock_metrics.record_error = Mock()
                    
                    self.auditor = RateLimitAuditor()
    
    def test_rate_limit_auditor_initialization(self):
        """Testa inicialização do auditor de rate limits."""
        # Verifica se o auditor foi inicializado corretamente
        assert self.auditor.enabled is True
        assert self.auditor.auto_fix is True
        
        # Verifica se as configurações foram carregadas
        assert len(self.auditor.rate_limit_configs) > 0
        
        # Verifica se os thresholds de segurança foram definidos
        assert 'min_rate_limit_per_minute' in self.auditor.security_thresholds
        assert 'max_rate_limit_per_minute' in self.auditor.security_thresholds
        assert 'max_concurrent_requests' in self.auditor.security_thresholds
    
    def test_rate_limit_configs_loaded(self):
        """Testa se as configurações de rate limiting foram carregadas."""
        # Verifica endpoints principais
        assert '/generate' in self.auditor.rate_limit_configs
        assert '/feedback' in self.auditor.rate_limit_configs
        assert '/download' in self.auditor.rate_limit_configs
        assert '/export' in self.auditor.rate_limit_configs
        assert '/token/rotate' in self.auditor.rate_limit_configs
        assert '/metrics' in self.auditor.rate_limit_configs
        assert '/health' in self.auditor.rate_limit_configs
        assert 'global' in self.auditor.rate_limit_configs
        
        # Verifica configurações específicas
        generate_config = self.auditor.rate_limit_configs['/generate']
        assert generate_config.endpoint == '/generate'
        assert generate_config.limit_type == RateLimitType.PER_MINUTE
        assert generate_config.limit_value == 10
        assert generate_config.window_seconds == 60
        assert generate_config.user_specific is True
        assert generate_config.ip_specific is True
        assert "Geração de artigos" in generate_config.description
    
    def test_feedback_config_loaded(self):
        """Testa configuração do endpoint de feedback."""
        feedback_config = self.auditor.rate_limit_configs['/feedback']
        
        assert feedback_config.endpoint == '/feedback'
        assert feedback_config.limit_type == RateLimitType.PER_MINUTE
        assert feedback_config.limit_value == 20
        assert feedback_config.window_seconds == 60
        assert feedback_config.user_specific is True
        assert feedback_config.ip_specific is True
        assert "Envio de feedback" in feedback_config.description
    
    def test_download_config_loaded(self):
        """Testa configuração do endpoint de download."""
        download_config = self.auditor.rate_limit_configs['/download']
        
        assert download_config.endpoint == '/download'
        assert download_config.limit_type == RateLimitType.PER_MINUTE
        assert download_config.limit_value == 20
        assert download_config.window_seconds == 60
        assert download_config.user_specific is True
        assert download_config.ip_specific is True
        assert "Download de arquivos" in download_config.description
    
    def test_export_config_loaded(self):
        """Testa configuração do endpoint de export."""
        export_config = self.auditor.rate_limit_configs['/export']
        
        assert export_config.endpoint == '/export'
        assert export_config.limit_type == RateLimitType.PER_MINUTE
        assert export_config.limit_value == 30
        assert export_config.window_seconds == 60
        assert export_config.user_specific is True
        assert export_config.ip_specific is True
        assert "Exportação de dados" in export_config.description
    
    def test_token_rotate_config_loaded(self):
        """Testa configuração do endpoint de rotação de tokens."""
        token_config = self.auditor.rate_limit_configs['/token/rotate']
        
        assert token_config.endpoint == '/token/rotate'
        assert token_config.limit_type == RateLimitType.PER_MINUTE
        assert token_config.limit_value == 5
        assert token_config.window_seconds == 60
        assert token_config.user_specific is True
        assert token_config.ip_specific is True
        assert "Rotação de tokens" in token_config.description
    
    def test_metrics_config_loaded(self):
        """Testa configuração do endpoint de métricas."""
        metrics_config = self.auditor.rate_limit_configs['/metrics']
        
        assert metrics_config.endpoint == '/metrics'
        assert metrics_config.limit_type == RateLimitType.PER_MINUTE
        assert metrics_config.limit_value == 60
        assert metrics_config.window_seconds == 60
        assert metrics_config.user_specific is False
        assert metrics_config.ip_specific is True
        assert "Métricas do sistema" in metrics_config.description
    
    def test_health_config_loaded(self):
        """Testa configuração do endpoint de health check."""
        health_config = self.auditor.rate_limit_configs['/health']
        
        assert health_config.endpoint == '/health'
        assert health_config.limit_type == RateLimitType.PER_MINUTE
        assert health_config.limit_value == 60
        assert health_config.window_seconds == 60
        assert health_config.user_specific is False
        assert health_config.ip_specific is True
        assert "Health check" in health_config.description
    
    def test_global_config_loaded(self):
        """Testa configuração global de rate limiting."""
        global_config = self.auditor.rate_limit_configs['global']
        
        assert global_config.endpoint == 'global'
        assert global_config.limit_type == RateLimitType.PER_MINUTE
        assert global_config.limit_value == 100
        assert global_config.window_seconds == 60
        assert global_config.user_specific is False
        assert global_config.ip_specific is True
        assert "Limite global por IP" in global_config.description
    
    def test_security_thresholds_defined(self):
        """Testa se os thresholds de segurança estão definidos."""
        thresholds = self.auditor.security_thresholds
        
        assert thresholds['min_rate_limit_per_minute'] == 10
        assert thresholds['max_rate_limit_per_minute'] == 1000
        assert thresholds['min_rate_limit_per_hour'] == 100
        assert thresholds['max_rate_limit_per_hour'] == 10000
        assert thresholds['max_concurrent_requests'] == 50
        assert thresholds['max_burst_limit'] == 100
    
    def test_default_limits_defined(self):
        """Testa se os limites padrão estão definidos."""
        default_limits = self.auditor.default_limits
        
        assert 'generate' in default_limits
        assert 'feedback' in default_limits
        assert 'download' in default_limits
        assert 'export' in default_limits
        assert 'token' in default_limits
        assert 'metrics' in default_limits
        assert 'health' in default_limits
        assert 'default' in default_limits
        
        # Verifica valores específicos
        assert default_limits['generate']['per_minute'] == 10
        assert default_limits['generate']['per_hour'] == 100
        assert default_limits['feedback']['per_minute'] == 20
        assert default_limits['feedback']['per_hour'] == 200
        assert default_limits['download']['per_minute'] == 20
        assert default_limits['download']['per_hour'] == 200
        assert default_limits['export']['per_minute'] == 30
        assert default_limits['export']['per_hour'] == 300
        assert default_limits['token']['per_minute'] == 5
        assert default_limits['token']['per_hour'] == 50
        assert default_limits['metrics']['per_minute'] == 60
        assert default_limits['metrics']['per_hour'] == 1000
        assert default_limits['health']['per_minute'] == 60
        assert default_limits['health']['per_hour'] == 1000
        assert default_limits['default']['per_minute'] == 100
        assert default_limits['default']['per_hour'] == 1000
    
    def test_audit_rate_limit_configs(self):
        """Testa auditoria de configurações de rate limiting."""
        result = self.auditor.audit_rate_limit_configs()
        
        assert isinstance(result, AuditResult)
        assert result.audit_id.startswith("rate_limit_audit_config_audit_")
        assert result.timestamp > datetime.now() - timedelta(seconds=5)
        assert result.total_endpoints == len(self.auditor.rate_limit_configs)
        assert isinstance(result.total_violations, int)
        assert isinstance(result.violations_by_severity, dict)
        assert isinstance(result.recommendations, list)
        assert isinstance(result.summary, str)
        assert isinstance(result.details, list)
        
        # Verifica se o resultado foi adicionado à lista
        assert len(self.auditor.audit_results) == 1
        assert self.auditor.audit_results[0] == result
    
    def test_validate_consistency(self):
        """Testa validação de consistência entre endpoints."""
        violations = []
        
        # Simula configurações inconsistentes
        self.auditor.rate_limit_configs['/test1'] = RateLimitConfig(
            endpoint='/test1',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=10,
            window_seconds=60,
            description="Test endpoint 1"
        )
        
        self.auditor.rate_limit_configs['/test2'] = RateLimitConfig(
            endpoint='/test2',
            limit_type=RateLimitType.PER_MINUTE,
            limit_value=50,  # 5x maior que test1
            window_seconds=60,
            description="Test endpoint 2"
        )
        
        # Executa validação
        self.auditor._validate_consistency(violations)
        
        # Verifica se violação foi detectada
        assert len(violations) > 0
        
        # Verifica se a violação é do tipo correto
        consistency_violations = [v for v in violations if v.violation_type == 'inconsistency']
        assert len(consistency_violations) > 0
    
    def test_generate_audit_result(self):
        """Testa geração de resultado de auditoria."""
        # Cria violações de teste
        violations = [
            RateLimitViolation(
                endpoint='/test',
                violation_type='security_threshold',
                severity=AuditSeverity.CRITICAL,
                description='Test violation',
                current_value=5,
                expected_value=10,
                recommendation='Fix this',
                timestamp=datetime.now(),
                metadata={}
            ),
            RateLimitViolation(
                endpoint='/test2',
                violation_type='missing_user_specific',
                severity=AuditSeverity.WARNING,
                description='Test violation 2',
                current_value=False,
                expected_value=True,
                recommendation='Fix this too',
                timestamp=datetime.now(),
                metadata={}
            )
        ]
        
        result = self.auditor._generate_audit_result(violations, 'test_audit')
        
        assert result.audit_id.startswith("rate_limit_audit_test_audit_")
        assert result.timestamp > datetime.now() - timedelta(seconds=5)
        assert result.total_endpoints == len(self.auditor.rate_limit_configs)
        assert result.total_violations == 2
        assert result.violations_by_severity['critical'] == 1
        assert result.violations_by_severity['warning'] == 1
        assert len(result.recommendations) > 0
        assert "violações encontradas" in result.summary
        assert result.details == violations
    
    def test_generate_audit_result_no_violations(self):
        """Testa geração de resultado sem violações."""
        result = self.auditor._generate_audit_result([], 'test_audit')
        
        assert result.total_violations == 0
        assert result.summary == "✅ Auditoria passou sem violações"
        assert len(result.recommendations) == 0
    
    def test_generate_global_recommendations(self):
        """Testa geração de recomendações globais."""
        # Cria violações de diferentes tipos
        violations = [
            RateLimitViolation(
                endpoint='/test1',
                violation_type='security_threshold',
                severity=AuditSeverity.CRITICAL,
                description='Test',
                current_value=5,
                expected_value=10,
                recommendation='Fix',
                timestamp=datetime.now(),
                metadata={}
            ),
            RateLimitViolation(
                endpoint='/test2',
                violation_type='rate_limit_not_enforced',
                severity=AuditSeverity.CRITICAL,
                description='Test',
                current_value=15,
                expected_value=10,
                recommendation='Fix',
                timestamp=datetime.now(),
                metadata={}
            ),
            RateLimitViolation(
                endpoint='/test3',
                violation_type='suspicious_ip',
                severity=AuditSeverity.WARNING,
                description='Test',
                current_value=20,
                expected_value=10,
                recommendation='Fix',
                timestamp=datetime.now(),
                metadata={}
            )
        ]
        
        recommendations = self.auditor._generate_global_recommendations(violations)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Verifica se recomendações específicas foram geradas
        recommendation_texts = [r.lower() for r in recommendations]
        assert any('security' in r for r in recommendation_texts)
        assert any('flask-limiter' in r for r in recommendation_texts)
        assert any('blacklist' in r for r in recommendation_texts)
        assert any('monitor' in r for r in recommendation_texts)
    
    def test_parse_rate_limit_logs(self):
        """Testa parse de logs de rate limiting."""
        # Cria log de teste
        test_logs = [
            '{"timestamp": "2025-01-27T19:40:00Z", "ip": "127.0.0.1", "endpoint": "/generate", "status_code": 429}',
            '{"timestamp": "2025-01-27T19:40:01Z", "ip": "127.0.0.1", "endpoint": "/feedback", "status_code": 200}',
            '{"timestamp": "2025-01-27T19:40:02Z", "ip": "192.168.1.1", "endpoint": "/generate", "status_code": 429}'
        ]
        
        with patch('builtins.open', mock_open(read_data='\n'.join(test_logs))):
            events = self.auditor._parse_rate_limit_logs('test.log')
        
        assert len(events) == 3
        assert events[0]['ip'] == '127.0.0.1'
        assert events[0]['endpoint'] == '/generate'
        assert events[0]['status_code'] == 429
        assert events[1]['status_code'] == 200
        assert events[2]['ip'] == '192.168.1.1'
    
    def test_parse_rate_limit_logs_with_raw_lines(self):
        """Testa parse de logs com linhas não-JSON."""
        # Cria log misto (JSON + texto)
        test_logs = [
            '{"timestamp": "2025-01-27T19:40:00Z", "ip": "127.0.0.1", "status_code": 429}',
            'Rate limit exceeded for IP 127.0.0.1',
            '{"timestamp": "2025-01-27T19:40:01Z", "ip": "127.0.0.1", "status_code": 200}',
            'Normal request processed'
        ]
        
        with patch('builtins.open', mock_open(read_data='\n'.join(test_logs))):
            events = self.auditor._parse_rate_limit_logs('test.log')
        
        # Deve processar apenas linhas JSON válidas
        assert len(events) == 2
        assert events[0]['status_code'] == 429
        assert events[1]['status_code'] == 200
    
    def test_detect_suspicious_patterns(self):
        """Testa detecção de padrões suspeitos."""
        # Cria eventos de teste
        events = [
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:00Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:01Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:02Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:03Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:04Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:05Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:06Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:07Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:08Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:09Z'},
            {'ip': '127.0.0.1', 'status_code': 429, 'timestamp': '2025-01-27T19:40:10Z'},
            {'ip': '192.168.1.1', 'status_code': 200, 'timestamp': '2025-01-27T19:40:00Z'}
        ]
        
        violations = self.auditor._detect_suspicious_patterns(events)
        
        # Deve detectar IP suspeito com muitas violações
        assert len(violations) > 0
        
        suspicious_violations = [v for v in violations if v.violation_type == 'suspicious_ip']
        assert len(suspicious_violations) > 0
        
        # Verifica se o IP correto foi detectado
        ip_violations = [v for v in suspicious_violations if '127.0.0.1' in v.endpoint]
        assert len(ip_violations) > 0
    
    def test_analyze_request_distribution(self):
        """Testa análise de distribuição de requests."""
        # Cria eventos de teste com alta taxa de violação
        events = [
            {'endpoint': '/generate', 'status_code': 429, 'timestamp': '2025-01-27T19:40:00Z'},
            {'endpoint': '/generate', 'status_code': 429, 'timestamp': '2025-01-27T19:40:01Z'},
            {'endpoint': '/generate', 'status_code': 429, 'timestamp': '2025-01-27T19:40:02Z'},
            {'endpoint': '/generate', 'status_code': 429, 'timestamp': '2025-01-27T19:40:03Z'},
            {'endpoint': '/generate', 'status_code': 429, 'timestamp': '2025-01-27T19:40:04Z'},
            {'endpoint': '/generate', 'status_code': 200, 'timestamp': '2025-01-27T19:40:05Z'},
            {'endpoint': '/generate', 'status_code': 200, 'timestamp': '2025-01-27T19:40:06Z'},
            {'endpoint': '/generate', 'status_code': 200, 'timestamp': '2025-01-27T19:40:07Z'},
            {'endpoint': '/generate', 'status_code': 200, 'timestamp': '2025-01-27T19:40:08Z'},
            {'endpoint': '/generate', 'status_code': 200, 'timestamp': '2025-01-27T19:40:09Z'},
            {'endpoint': '/feedback', 'status_code': 200, 'timestamp': '2025-01-27T19:40:00Z'},
            {'endpoint': '/feedback', 'status_code': 200, 'timestamp': '2025-01-27T19:40:01Z'}
        ]
        
        violations = self.auditor._analyze_request_distribution(events)
        
        # Deve detectar alta taxa de violação no endpoint /generate
        assert len(violations) > 0
        
        high_violation_violations = [v for v in violations if v.violation_type == 'high_violation_rate']
        assert len(high_violation_violations) > 0
        
        # Verifica se o endpoint correto foi detectado
        generate_violations = [v for v in high_violation_violations if '/generate' in v.endpoint]
        assert len(generate_violations) > 0
    
    def test_generate_audit_report(self):
        """Testa geração de relatório de auditoria."""
        # Cria violações de teste
        violations = [
            RateLimitViolation(
                endpoint='/test',
                violation_type='security_threshold',
                severity=AuditSeverity.CRITICAL,
                description='Test violation',
                current_value=5,
                expected_value=10,
                recommendation='Fix this',
                timestamp=datetime.now(),
                metadata={}
            )
        ]
        
        # Gera resultado
        result = self.auditor._generate_audit_result(violations, 'test_audit')
        
        # Gera relatório
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_file = f.name
        
        try:
            output_file = self.auditor.generate_audit_report(report_file)
            
            # Verifica se arquivo foi criado
            assert os.path.exists(output_file)
            
            # Verifica conteúdo do relatório
            with open(output_file, 'r') as f:
                report = json.load(f)
            
            assert 'audit_info' in report
            assert 'summary' in report
            assert 'violations' in report
            assert 'recommendations' in report
            assert 'configurations' in report
            
            assert report['summary']['total_violations'] == 1
            assert report['summary']['violations_by_severity']['critical'] == 1
            
        finally:
            # Limpa arquivo temporário
            if os.path.exists(report_file):
                os.unlink(report_file)


class TestRateLimitAuditorFunctions:
    """Testes para funções utilitárias do rate limit auditor."""

    def test_get_rate_limit_auditor_function(self):
        """Testa função get_rate_limit_auditor."""
        auditor = get_rate_limit_auditor()
        assert isinstance(auditor, RateLimitAuditor)
    
    def test_run_rate_limit_audit_function(self):
        """Testa função run_rate_limit_audit."""
        with patch('scripts.rate_limit_auditor.get_rate_limit_auditor') as mock_get_auditor:
            mock_auditor = Mock()
            mock_auditor.run_full_audit.return_value = Mock()
            mock_get_auditor.return_value = mock_auditor
            
            result = run_rate_limit_audit('http://test.com')
            
            mock_auditor.run_full_audit.assert_called_once_with('http://test.com')
            assert result == mock_auditor.run_full_audit.return_value


class TestRateLimitAuditorIntegration:
    """Testes de integração do rate limit auditor."""

    def test_integration_with_feature_flags(self):
        """Testa integração com feature flags."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled') as mock_feature:
            # Testa com feature habilitada
            mock_feature.return_value = True
            
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                assert auditor.enabled is True
            
            # Testa com feature desabilitada
            mock_feature.return_value = False
            
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                assert auditor.enabled is False
    
    def test_integration_with_logging(self):
        """Testa integração com sistema de logging."""
        mock_logger = Mock()
        
        with patch('scripts.rate_limit_auditor.get_structured_logger', return_value=mock_logger):
            with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
                auditor = RateLimitAuditor()
                
                # Verifica se logger foi chamado na inicialização
                mock_logger.info.assert_called()
                
                # Verifica se o call inclui tracing_id
                call_args = mock_logger.info.call_args
                assert 'tracing_id' in call_args[1]['extra']
                assert call_args[1]['extra']['tracing_id'] == 'RATE_LIMIT_AUDIT_20250127_007'
    
    def test_integration_with_metrics_collector(self):
        """Testa integração com metrics collector."""
        mock_metrics = Mock()
        mock_metrics.record_request = Mock()
        mock_metrics.record_error = Mock()
        
        with patch('scripts.rate_limit_auditor.metrics_collector', mock_metrics):
            with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
                with patch('scripts.rate_limit_auditor.get_structured_logger'):
                    auditor = RateLimitAuditor()
                    
                    # Executa auditoria
                    result = auditor.audit_rate_limit_configs()
                    
                    # Verifica se métricas foram registradas (se aplicável)
                    # O auditor pode registrar métricas durante a execução
                    assert isinstance(result, AuditResult)


class TestRateLimitAuditorEdgeCases:
    """Testes para casos extremos do rate limit auditor."""

    def test_auditor_with_empty_configs(self):
        """Testa auditor com configurações vazias."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                
                # Limpa configurações
                auditor.rate_limit_configs = {}
                
                # Executa auditoria
                result = auditor.audit_rate_limit_configs()
                
                assert result.total_endpoints == 0
                assert result.total_violations == 0
                assert result.summary == "✅ Auditoria passou sem violações"
    
    def test_auditor_with_invalid_log_file(self):
        """Testa auditor com arquivo de log inválido."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                
                # Testa com arquivo inexistente
                result = auditor.analyze_rate_limit_logs('nonexistent.log')
                
                assert result.total_violations == 1
                assert result.details[0].violation_type == 'log_file_missing'
    
    def test_auditor_with_malformed_logs(self):
        """Testa auditor com logs malformados."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                
                # Cria logs malformados
                malformed_logs = [
                    '{"invalid": json}',
                    'not json at all',
                    '{"timestamp": "2025-01-27T19:40:00Z", "status_code": 429}',
                    '{"timestamp": "2025-01-27T19:40:01Z", "status_code": 200}'
                ]
                
                with patch('builtins.open', mock_open(read_data='\n'.join(malformed_logs))):
                    events = auditor._parse_rate_limit_logs('test.log')
                
                # Deve processar apenas linhas JSON válidas
                assert len(events) == 2
                assert events[0]['status_code'] == 429
                assert events[1]['status_code'] == 200
    
    def test_auditor_with_high_threshold_violations(self):
        """Testa auditor com violações de threshold alto."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                
                # Cria configuração com limite muito alto
                auditor.rate_limit_configs['/test'] = RateLimitConfig(
                    endpoint='/test',
                    limit_type=RateLimitType.PER_MINUTE,
                    limit_value=2000,  # Acima do threshold máximo
                    window_seconds=60,
                    description="Test endpoint"
                )
                
                # Executa auditoria
                result = auditor.audit_rate_limit_configs()
                
                # Deve detectar violação de threshold
                assert result.total_violations > 0
                
                threshold_violations = [v for v in result.details if v.violation_type == 'security_threshold']
                assert len(threshold_violations) > 0
    
    def test_auditor_with_low_threshold_violations(self):
        """Testa auditor com violações de threshold baixo."""
        with patch('scripts.rate_limit_auditor.is_feature_enabled', return_value=True):
            with patch('scripts.rate_limit_auditor.get_structured_logger'):
                auditor = RateLimitAuditor()
                
                # Cria configuração com limite muito baixo
                auditor.rate_limit_configs['/test'] = RateLimitConfig(
                    endpoint='/test',
                    limit_type=RateLimitType.PER_MINUTE,
                    limit_value=5,  # Abaixo do threshold mínimo
                    window_seconds=60,
                    description="Test endpoint"
                )
                
                # Executa auditoria
                result = auditor.audit_rate_limit_configs()
                
                # Deve detectar violação de threshold
                assert result.total_violations > 0
                
                threshold_violations = [v for v in result.details if v.violation_type == 'security_threshold']
                assert len(threshold_violations) > 0 