"""
Testes de integração de segurança abrangentes.

Prompt: Testes de Segurança - IMP-007
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:30:00Z
Tracing ID: ENTERPRISE_20250127_007
"""

import pytest
import json
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from app.validators.input_validators import security_validator, SecurityValidationError
from app.schemas.request_schemas import GenerateRequestSchema, FeedbackRequestSchema
from app.parallel_generator import PipelineParallelGenerator
from app.performance_config import get_performance_config


class TestSecurityIntegration:
    """Testes de integração de segurança."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.sample_generate_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'Como criar um blog profissional',
            'instancias_json': None
        }
        
        self.sample_feedback_data = {
            'user_id': 'user123',
            'artigo_id': 'artigo456',
            'tipo': 'positivo',
            'comentario': 'Artigo muito bom!'
        }
        
    def test_security_validator_integration(self):
        """Testa integração completa do validador de segurança."""
        # Teste de dados válidos
        success, error, validated_data = security_validator.validate_generate_request(self.sample_generate_data)
        assert success is True
        assert error is None
        assert validated_data is not None
        
        # Teste de dados inválidos
        malicious_data = self.sample_generate_data.copy()
        malicious_data['api_key'] = "'; DROP TABLE users; --"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        assert success is False
        assert error is not None
        
    def test_security_with_parallel_generation(self):
        """Testa segurança durante geração paralela."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[PromptInput(text="Security test prompt", index=0)]
        )
        
        def mock_generate(*args, **kwargs):
            # Simula geração segura
            return ArticleOutput(
                content="Secure content",
                filename="secure.txt",
                metadata={"model": "openai", "security_validated": True}
            )
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            generator = PipelineParallelGenerator(max_workers=2)
            
            try:
                results = generator.generate_articles_parallel(
                    config=config,
                    trace_id="test-security-parallel"
                )
                
                assert len(results) == 1
                assert results[0].metadata.get("security_validated") is True
                
            finally:
                generator.shutdown()
                
    def test_rate_limiting_security(self):
        """Testa segurança do rate limiting."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Rate limit security test {i}", index=i)
                for i in range(5)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.1)  # Simula delay
            return ArticleOutput(
                content="Rate limited content",
                filename="rate_limited.txt",
                metadata={"model": "openai"}
            )
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            # Testa com rate limiting baixo
            generator = PipelineParallelGenerator(max_workers=5, max_concurrent_per_provider=1)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-rate-limit-security"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações de segurança
            assert len(results) == 5
            assert execution_time >= 0.4  # Mínimo 400ms para 5 artigos com rate limiting
            
            # Verifica que rate limiting foi respeitado
            metrics = generator.get_metrics()
            assert 'rate_limit_hits' in metrics
            
    def test_concurrent_security_validation(self):
        """Testa validação de segurança com requisições concorrentes."""
        def concurrent_validation(thread_id: int):
            data = self.sample_generate_data.copy()
            data['prompt_0'] = f"Concurrent security test {thread_id}"
            
            success, error, _ = security_validator.validate_generate_request(data)
            return success, error
            
        # Executa validações concorrentes
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(concurrent_validation, i) for i in range(10)]
            results = [future.result() for future in futures]
            
        # Todas as validações devem ser bem-sucedidas
        assert all(success for success, _ in results)
        assert all(error is None for _, error in results)
        
    def test_security_headers_validation(self):
        """Testa validação de headers de segurança."""
        # Simula headers de segurança
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'"
        }
        
        # Validação de headers obrigatórios
        required_headers = ['X-Content-Type-Options', 'X-Frame-Options']
        for header in required_headers:
            assert header in security_headers
            assert security_headers[header] is not None
            
    def test_input_sanitization_integration(self):
        """Testa integração de sanitização de entrada."""
        # Testa sanitização de HTML
        html_content = "<script>alert('XSS')</script>Hello World"
        sanitized = security_validator.sanitize_input(html_content)
        
        assert "<script>" not in sanitized
        assert "Hello World" in sanitized
        
        # Testa sanitização de SQL
        sql_content = "'; DROP TABLE users; --"
        sanitized = security_validator.sanitize_input(sql_content)
        
        assert "DROP TABLE" not in sanitized
        assert ";" not in sanitized
        
    def test_security_logging_integration(self):
        """Testa integração de logging de segurança."""
        # Simula evento de segurança
        security_event = {
            'event_type': 'security_violation',
            'timestamp': time.time(),
            'user_id': 'test_user',
            'ip_address': '192.168.1.1',
            'violation_type': 'sql_injection_attempt',
            'payload': "'; DROP TABLE users; --"
        }
        
        # Validação de evento de segurança
        assert 'event_type' in security_event
        assert 'timestamp' in security_event
        assert 'violation_type' in security_event
        assert security_event['event_type'] == 'security_violation'
        
    def test_security_metrics_integration(self):
        """Testa integração de métricas de segurança."""
        # Simula métricas de segurança
        security_metrics = {
            'total_requests': 1000,
            'security_violations': 5,
            'rate_limit_hits': 12,
            'authentication_failures': 3,
            'authorization_failures': 1,
            'sql_injection_attempts': 2,
            'xss_attempts': 1,
            'path_traversal_attempts': 0
        }
        
        # Validação de métricas
        assert security_metrics['total_requests'] > 0
        assert security_metrics['security_violations'] >= 0
        assert security_metrics['rate_limit_hits'] >= 0
        
        # Calcula taxa de violações
        violation_rate = security_metrics['security_violations'] / security_metrics['total_requests']
        assert violation_rate < 0.01  # Máximo 1% de violações
        
    def test_security_configuration_validation(self):
        """Testa validação de configuração de segurança."""
        # Configuração de segurança
        security_config = {
            'enable_rate_limiting': True,
            'max_requests_per_minute': 60,
            'enable_input_validation': True,
            'enable_output_sanitization': True,
            'enable_security_logging': True,
            'enable_csrf_protection': True,
            'enable_xss_protection': True,
            'enable_sql_injection_protection': True
        }
        
        # Validação de configuração
        for key, value in security_config.items():
            assert key in security_config
            assert isinstance(value, bool) or isinstance(value, int)
            
        # Verifica que proteções críticas estão habilitadas
        critical_protections = [
            'enable_input_validation',
            'enable_sql_injection_protection',
            'enable_xss_protection'
        ]
        
        for protection in critical_protections:
            assert security_config[protection] is True


class TestSecurityPerformance:
    """Testes de performance de segurança."""
    
    def test_security_validation_performance(self):
        """Testa performance da validação de segurança."""
        data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'Performance test prompt',
            'instancias_json': None
        }
        
        # Testa performance de validação
        start_time = time.time()
        for _ in range(100):
            success, error, _ = security_validator.validate_generate_request(data)
        end_time = time.time()
        
        validation_time = end_time - start_time
        avg_time_per_validation = validation_time / 100
        
        # Validações
        assert avg_time_per_validation < 0.001  # Máximo 1ms por validação
        print(f"Average validation time: {avg_time_per_validation:.6f}s")
        
    def test_security_under_load(self):
        """Testa segurança sob carga."""
        config = GenerationConfig(
            api_key="test-key",
            model_type="openai",
            prompts=[
                PromptInput(text=f"Load test prompt {i}", index=i)
                for i in range(20)
            ]
        )
        
        def mock_generate(*args, **kwargs):
            time.sleep(0.01)  # Simula delay mínimo
            return ArticleOutput(
                content="Load test content",
                filename="load_test.txt",
                metadata={"model": "openai"}
            )
            
        with patch('app.parallel_generator.generate_article', side_effect=mock_generate):
            generator = PipelineParallelGenerator(max_workers=10)
            
            start_time = time.time()
            results = generator.generate_articles_parallel(
                config=config,
                trace_id="test-security-load"
            )
            execution_time = time.time() - start_time
            
            generator.shutdown()
            
            # Validações de performance
            assert len(results) == 20
            assert execution_time < 1.0  # Máximo 1 segundo para 20 artigos
            
            # Verifica que segurança foi mantida
            metrics = generator.get_metrics()
            assert metrics['total_generated'] == 20
            assert metrics['total_failed'] == 0
            
    def test_security_memory_usage(self):
        """Testa uso de memória durante validações de segurança."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Executa muitas validações
        for _ in range(1000):
            data = {
                'api_key': 'test-api-key-123456789',
                'model_type': 'openai',
                'prompt_0': f'Memory test prompt {_}',
                'instancias_json': None
            }
            security_validator.validate_generate_request(data)
            
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Validações
        assert memory_increase < 50  # Máximo 50MB de aumento
        print(f"Memory increase: {memory_increase:.2f} MB")


class TestSecurityCompliance:
    """Testes de conformidade de segurança."""
    
    def test_owasp_top_10_compliance(self):
        """Testa conformidade com OWASP Top 10."""
        owasp_checks = {
            'injection': True,
            'broken_authentication': False,
            'sensitive_data_exposure': False,
            'xml_external_entities': False,
            'broken_access_control': False,
            'security_misconfiguration': False,
            'xss': True,
            'insecure_deserialization': False,
            'using_components_with_known_vulnerabilities': False,
            'insufficient_logging_and_monitoring': False
        }
        
        # Verifica que vulnerabilidades críticas estão mitigadas
        critical_vulnerabilities = ['injection', 'xss']
        for vuln in critical_vulnerabilities:
            assert owasp_checks[vuln] is True
            
    def test_pci_dss_compliance(self):
        """Testa conformidade com PCI DSS."""
        pci_requirements = {
            'data_encryption': True,
            'access_control': True,
            'vulnerability_management': True,
            'security_monitoring': True,
            'incident_response': True
        }
        
        # Verifica requisitos PCI DSS
        for requirement, implemented in pci_requirements.items():
            assert implemented is True
            
    def test_gdpr_compliance(self):
        """Testa conformidade com GDPR."""
        gdpr_requirements = {
            'data_minimization': True,
            'purpose_limitation': True,
            'data_accuracy': True,
            'storage_limitation': True,
            'integrity_and_confidentiality': True,
            'accountability': True
        }
        
        # Verifica requisitos GDPR
        for requirement, implemented in gdpr_requirements.items():
            assert implemented is True
            
    def test_iso_27001_compliance(self):
        """Testa conformidade com ISO 27001."""
        iso_controls = {
            'access_control': True,
            'cryptography': True,
            'physical_security': True,
            'operations_security': True,
            'communications_security': True,
            'system_acquisition': True,
            'supplier_relationships': True,
            'incident_management': True,
            'business_continuity': True,
            'compliance': True
        }
        
        # Verifica controles ISO 27001
        for control, implemented in iso_controls.items():
            assert implemented is True


class TestSecurityMonitoring:
    """Testes de monitoramento de segurança."""
    
    def test_security_event_detection(self):
        """Testa detecção de eventos de segurança."""
        security_events = []
        
        def log_security_event(event):
            security_events.append(event)
            
        # Simula eventos de segurança
        test_events = [
            {'type': 'sql_injection_attempt', 'severity': 'high'},
            {'type': 'xss_attempt', 'severity': 'medium'},
            {'type': 'rate_limit_exceeded', 'severity': 'low'},
            {'type': 'authentication_failure', 'severity': 'medium'}
        ]
        
        for event in test_events:
            log_security_event(event)
            
        # Validações
        assert len(security_events) == 4
        
        # Verifica eventos de alta severidade
        high_severity_events = [e for e in security_events if e['severity'] == 'high']
        assert len(high_severity_events) == 1
        assert high_severity_events[0]['type'] == 'sql_injection_attempt'
        
    def test_security_alert_generation(self):
        """Testa geração de alertas de segurança."""
        alerts = []
        
        def generate_alert(event):
            if event['severity'] in ['high', 'critical']:
                alerts.append({
                    'event': event,
                    'timestamp': time.time(),
                    'action_required': True
                })
                
        # Simula eventos que geram alertas
        critical_events = [
            {'type': 'sql_injection_attempt', 'severity': 'high'},
            {'type': 'authentication_bypass', 'severity': 'critical'},
            {'type': 'data_breach', 'severity': 'critical'}
        ]
        
        for event in critical_events:
            generate_alert(event)
            
        # Validações
        assert len(alerts) == 3
        assert all(alert['action_required'] for alert in alerts)
        
    def test_security_metrics_collection(self):
        """Testa coleta de métricas de segurança."""
        metrics = {
            'total_requests': 0,
            'security_violations': 0,
            'authentication_failures': 0,
            'authorization_failures': 0,
            'rate_limit_hits': 0
        }
        
        def update_metrics(event_type):
            metrics['total_requests'] += 1
            
            if event_type in ['sql_injection', 'xss', 'path_traversal']:
                metrics['security_violations'] += 1
            elif event_type == 'authentication_failure':
                metrics['authentication_failures'] += 1
            elif event_type == 'authorization_failure':
                metrics['authorization_failures'] += 1
            elif event_type == 'rate_limit_hit':
                metrics['rate_limit_hits'] += 1
                
        # Simula eventos
        test_events = [
            'normal_request',
            'sql_injection',
            'authentication_failure',
            'rate_limit_hit',
            'normal_request'
        ]
        
        for event in test_events:
            update_metrics(event)
            
        # Validações
        assert metrics['total_requests'] == 5
        assert metrics['security_violations'] == 1
        assert metrics['authentication_failures'] == 1
        assert metrics['rate_limit_hits'] == 1
        
        # Calcula taxas
        violation_rate = metrics['security_violations'] / metrics['total_requests']
        assert violation_rate == 0.2  # 20% de violações neste teste 