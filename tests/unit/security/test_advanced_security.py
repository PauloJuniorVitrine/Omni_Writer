"""
Testes de Segurança Avançada - Omni Writer
==========================================

Implementa testes para cenários de segurança avançada:
- Prevenção de ataques de timing
- Injeção de tokens maliciosos
- Validação de assinaturas criptográficas
- Headers de segurança de webhooks
- Rate limiting sob ataque

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import time
import hmac
import hashlib
import secrets
import json
from unittest.mock import Mock, patch, MagicMock
import requests
from datetime import datetime, timedelta

# Importações do sistema real
from shared.token_rotation import TokenRotation, validate_token_security
from infraestructure.webhook_security_v1 import validate_webhook_request, generate_hmac_signature
from shared.security_headers import SecurityHeadersManager
from app.validators.input_validators import SecurityValidator
from shared.rate_limiter import RateLimiter


class TestTimingAttackPrevention:
    """Testa prevenção de ataques de timing."""
    
    def test_timing_attack_prevention(self):
        """Testa prevenção de ataques de timing."""
        # Setup baseado no código real
        token_rotation = TokenRotation()
        
        # Tokens válidos e inválidos
        valid_tokens = [
            "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "sk-deepseek-1234567890abcdef1234567890abcdef",
            "sk-claude-1234567890abcdef1234567890abcdef"
        ]
        
        invalid_tokens = [
            "invalid-token",
            "sk-",
            "sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "",
            "sk-invalid-format"
        ]
        
        # Testa validação com timing constante
        timing_results = []
        
        # Valida tokens válidos
        for token in valid_tokens:
            start_time = time.time()
            result = validate_token_security(token)
            end_time = time.time()
            timing_results.append({
                "token": token,
                "valid": result,
                "time": end_time - start_time
            })
        
        # Valida tokens inválidos
        for token in invalid_tokens:
            start_time = time.time()
            result = validate_token_security(token)
            end_time = time.time()
            timing_results.append({
                "token": token,
                "valid": result,
                "time": end_time - start_time
            })
        
        # Analisa timing
        valid_times = [r["time"] for r in timing_results if r["valid"]]
        invalid_times = [r["time"] for r in timing_results if not r["valid"]]
        
        # Calcula estatísticas de timing
        if valid_times and invalid_times:
            avg_valid_time = sum(valid_times) / len(valid_times)
            avg_invalid_time = sum(invalid_times) / len(invalid_times)
            time_diff = abs(avg_valid_time - avg_invalid_time)
            
            # Timing deve ser similar (diferença < 10ms)
            assert time_diff < 0.01, f"Diferença de timing muito alta: {time_diff}s"
        
        # Valida que tokens válidos foram aceitos
        valid_count = sum(1 for r in timing_results if r["valid"])
        assert valid_count == len(valid_tokens)
        
        # Valida que tokens inválidos foram rejeitados
        invalid_count = sum(1 for r in timing_results if not r["valid"])
        assert invalid_count == len(invalid_tokens)
    
    def test_constant_time_comparison(self):
        """Testa comparação em tempo constante."""
        # Setup
        secret_key = "test-secret-key"
        
        # Função que simula comparação em tempo constante
        def constant_time_compare(a, b):
            """Comparação em tempo constante para prevenir timing attacks."""
            if len(a) != len(b):
                return False
            
            result = 0
            for x, y in zip(a, b):
                result |= ord(x) ^ ord(y)
            
            return result == 0
        
        # Testa com diferentes inputs
        test_cases = [
            ("correct", "correct", True),
            ("correct", "incorrect", False),
            ("short", "longer", False),
            ("", "", True),
            ("a", "b", False),
            ("same", "same", True)
        ]
        
        timing_results = []
        
        for input_a, input_b, expected in test_cases:
            start_time = time.time()
            result = constant_time_compare(input_a, input_b)
            end_time = time.time()
            
            timing_results.append({
                "input_a": input_a,
                "input_b": input_b,
                "expected": expected,
                "result": result,
                "time": end_time - start_time
            })
        
        # Valida resultados
        for case in timing_results:
            assert case["result"] == case["expected"]
        
        # Valida que timing é similar
        times = [case["time"] for case in timing_results]
        max_time = max(times)
        min_time = min(times)
        time_variance = max_time - min_time
        
        # Variação de tempo deve ser pequena
        assert time_variance < 0.001  # Menos de 1ms de variação
    
    def test_hmac_timing_attack_prevention(self):
        """Testa prevenção de timing attacks em HMAC."""
        # Setup
        secret_key = "test-secret-key"
        test_data = "test-data-for-hmac"
        
        # Gera HMAC válido
        valid_hmac = hmac.new(
            secret_key.encode(),
            test_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Gera HMACs inválidos
        invalid_hmacs = [
            "a" * 64,  # HMAC falso
            valid_hmac[:-1] + "0",  # Último caractere diferente
            valid_hmac[1:] + "0",   # Primeiro caractere diferente
            "0" + valid_hmac[1:],   # Primeiro caractere diferente
            valid_hmac[:32] + "0" * 32  # Metade diferente
        ]
        
        # Testa validação com timing constante
        timing_results = []
        
        # Valida HMAC válido
        start_time = time.time()
        valid_result = hmac.compare_digest(valid_hmac, valid_hmac)
        end_time = time.time()
        timing_results.append({
            "hmac": "valid",
            "result": valid_result,
            "time": end_time - start_time
        })
        
        # Valida HMACs inválidos
        for invalid_hmac in invalid_hmacs:
            start_time = time.time()
            invalid_result = hmac.compare_digest(valid_hmac, invalid_hmac)
            end_time = time.time()
            timing_results.append({
                "hmac": "invalid",
                "result": invalid_result,
                "time": end_time - start_time
            })
        
        # Valida resultados
        valid_case = next(r for r in timing_results if r["hmac"] == "valid")
        invalid_cases = [r for r in timing_results if r["hmac"] == "invalid"]
        
        assert valid_case["result"] is True
        assert all(case["result"] is False for case in invalid_cases)
        
        # Valida timing similar
        valid_time = valid_case["time"]
        invalid_times = [case["time"] for case in invalid_cases]
        
        for invalid_time in invalid_times:
            time_diff = abs(valid_time - invalid_time)
            assert time_diff < 0.001  # Diferença deve ser < 1ms


class TestMaliciousTokenInjection:
    """Testa injeção de tokens maliciosos."""
    
    def test_malicious_token_injection(self):
        """Testa injeção de tokens maliciosos."""
        # Setup
        token_rotation = TokenRotation()
        
        # Tokens maliciosos com diferentes padrões de ataque
        malicious_tokens = [
            # SQL Injection
            "sk-'; DROP TABLE users; --",
            "sk-' OR 1=1; --",
            "sk-' UNION SELECT * FROM tokens; --",
            
            # XSS
            "sk-<script>alert('xss')</script>",
            "sk-javascript:alert('xss')",
            "sk-onload=alert('xss')",
            
            # Command Injection
            "sk-; rm -rf /",
            "sk- && rm -rf /",
            "sk- | cat /etc/passwd",
            
            # Path Traversal
            "sk-../../../etc/passwd",
            "sk-..\\..\\..\\windows\\system32\\config\\sam",
            
            # Null Byte Injection
            "sk-\x00malicious",
            "sk-malicious\x00",
            
            # Unicode Normalization
            "sk-ｍａｌｉｃｉｏｕｓ",  # Full-width characters
            "sk-malicious\u0000",
            
            # Overlong UTF-8
            "sk-\xc0\xafetc\xc0\xafpasswd",
            
            # Control Characters
            "sk-\x01\x02\x03malicious",
            "sk-malicious\x7f\x80\x81"
        ]
        
        # Testa validação de tokens maliciosos
        validation_results = []
        
        for token in malicious_tokens:
            try:
                result = validate_token_security(token)
                validation_results.append({
                    "token": token,
                    "valid": result,
                    "error": None
                })
            except Exception as e:
                validation_results.append({
                    "token": token,
                    "valid": False,
                    "error": str(e)
                })
        
        # Valida que todos os tokens maliciosos foram rejeitados
        malicious_accepted = [r for r in validation_results if r["valid"]]
        assert len(malicious_accepted) == 0, f"Tokens maliciosos aceitos: {malicious_accepted}"
        
        # Valida que erros foram capturados adequadamente
        error_count = sum(1 for r in validation_results if r["error"] is not None)
        assert error_count > 0  # Pelo menos alguns devem ter gerado erros
    
    def test_token_format_validation(self):
        """Testa validação de formato de token."""
        # Setup
        token_rotation = TokenRotation()
        
        # Testa diferentes formatos de token
        test_cases = [
            # Formatos válidos
            ("sk-1234567890abcdef1234567890abcdef1234567890abcdef", True),
            ("sk-deepseek-1234567890abcdef1234567890abcdef", True),
            ("sk-claude-1234567890abcdef1234567890abcdef", True),
            
            # Formatos inválidos
            ("invalid-token", False),
            ("sk-", False),
            ("sk-123", False),  # Muito curto
            ("sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", False),  # Muito longo
            ("", False),
            ("sk-invalid-format", False),
            ("sk_1234567890abcdef1234567890abcdef1234567890abcdef", False),  # Underscore em vez de hífen
            ("SK-1234567890abcdef1234567890abcdef1234567890abcdef", False),  # Maiúsculas
        ]
        
        for token, expected_valid in test_cases:
            result = validate_token_security(token)
            assert result == expected_valid, f"Token '{token}' deveria ser {expected_valid}, mas foi {result}"
    
    def test_token_entropy_validation(self):
        """Testa validação de entropia de token."""
        # Setup
        token_rotation = TokenRotation()
        
        # Tokens com baixa entropia
        low_entropy_tokens = [
            "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sk-123456789012345678901234567890123456789012345678",
            "sk-000000000000000000000000000000000000000000000000",
            "sk-111111111111111111111111111111111111111111111111",
            "sk-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
        ]
        
        # Tokens com alta entropia (válidos)
        high_entropy_tokens = [
            "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "sk-deepseek-1234567890abcdef1234567890abcdef",
            "sk-claude-1234567890abcdef1234567890abcdef"
        ]
        
        # Testa validação de entropia
        for token in low_entropy_tokens:
            result = validate_token_security(token)
            # Tokens com baixa entropia podem ser rejeitados
            assert result is False or "entropy" in str(result).lower()
        
        for token in high_entropy_tokens:
            result = validate_token_security(token)
            assert result is True


class TestCryptographicSignatureValidation:
    """Testa validação de assinaturas criptográficas."""
    
    def test_cryptographic_signature_validation(self):
        """Testa validação de assinaturas criptográficas."""
        # Setup
        secret_key = "test-secret-key"
        test_data = "test-data-for-signature"
        
        # Gera assinatura válida
        valid_signature = generate_hmac_signature(test_data, secret_key)
        
        # Gera assinaturas inválidas
        invalid_signatures = [
            "invalid-signature",
            valid_signature[:-1] + "0",  # Último caractere diferente
            valid_signature[1:] + "0",   # Primeiro caractere diferente
            "0" + valid_signature[1:],   # Primeiro caractere diferente
            valid_signature[:32] + "0" * 32,  # Metade diferente
            "",  # Assinatura vazia
            "a" * 64,  # Assinatura falsa
        ]
        
        # Testa validação de assinaturas
        validation_results = []
        
        # Valida assinatura válida
        expected_valid = generate_hmac_signature(test_data, secret_key)
        is_valid = hmac.compare_digest(valid_signature, expected_valid)
        validation_results.append({
            "signature": "valid",
            "is_valid": is_valid
        })
        
        # Valida assinaturas inválidas
        for invalid_signature in invalid_signatures:
            is_valid = hmac.compare_digest(invalid_signature, expected_valid)
            validation_results.append({
                "signature": "invalid",
                "is_valid": is_valid
            })
        
        # Valida resultados
        valid_case = next(r for r in validation_results if r["signature"] == "valid")
        invalid_cases = [r for r in validation_results if r["signature"] == "invalid"]
        
        assert valid_case["is_valid"] is True
        assert all(case["is_valid"] is False for case in invalid_cases)
    
    def test_signature_tampering_detection(self):
        """Testa detecção de adulteração de assinatura."""
        # Setup
        secret_key = "test-secret-key"
        original_data = "original-data"
        
        # Gera assinatura original
        original_signature = generate_hmac_signature(original_data, secret_key)
        
        # Simula adulteração de dados
        tampered_data = "tampered-data"
        tampered_signature = generate_hmac_signature(tampered_data, secret_key)
        
        # Testa validação com dados adulterados
        # Assinatura original com dados adulterados deve falhar
        is_valid_original_with_tampered = hmac.compare_digest(
            original_signature,
            generate_hmac_signature(tampered_data, secret_key)
        )
        
        # Assinatura adulterada com dados originais deve falhar
        is_valid_tampered_with_original = hmac.compare_digest(
            tampered_signature,
            generate_hmac_signature(original_data, secret_key)
        )
        
        # Ambas devem falhar
        assert is_valid_original_with_tampered is False
        assert is_valid_tampered_with_original is False
    
    def test_signature_replay_attack_prevention(self):
        """Testa prevenção de ataques de replay de assinatura."""
        # Setup
        secret_key = "test-secret-key"
        
        # Simula dados com timestamp
        timestamp = int(time.time())
        data_with_timestamp = f"data-{timestamp}"
        
        # Gera assinatura
        signature = generate_hmac_signature(data_with_timestamp, secret_key)
        
        # Simula replay attack (mesma assinatura com timestamp antigo)
        old_timestamp = timestamp - 3600  # 1 hora atrás
        old_data = f"data-{old_timestamp}"
        
        # Assinatura antiga deve ser rejeitada
        is_valid_old = hmac.compare_digest(
            signature,
            generate_hmac_signature(old_data, secret_key)
        )
        
        # Assinatura atual deve ser válida
        is_valid_current = hmac.compare_digest(
            signature,
            generate_hmac_signature(data_with_timestamp, secret_key)
        )
        
        assert is_valid_old is False
        assert is_valid_current is True


class TestWebhookSecurityHeaders:
    """Testa headers de segurança de webhooks."""
    
    def test_webhook_security_headers(self):
        """Testa headers de segurança de webhooks."""
        # Setup
        secret_key = "test-secret-key"
        test_data = '{"test": "data"}'
        timestamp = str(int(time.time()))
        
        # Gera assinatura válida
        valid_signature = generate_hmac_signature(test_data, secret_key)
        
        # Cria request válido
        class ValidRequest:
            def __init__(self):
                self.data = test_data.encode()
                self.headers = {
                    'X-Timestamp': timestamp,
                    'X-Signature': valid_signature
                }
                self.remote_addr = '127.0.0.1'
        
        # Cria request inválido (sem headers)
        class InvalidRequest:
            def __init__(self):
                self.data = test_data.encode()
                self.headers = {}
                self.remote_addr = '127.0.0.1'
        
        # Testa validação de request válido
        valid_request = ValidRequest()
        valid_result = validate_webhook_request(valid_request, secret_key)
        assert valid_result['valid'] is True
        
        # Testa validação de request inválido
        invalid_request = InvalidRequest()
        invalid_result = validate_webhook_request(invalid_request, secret_key)
        assert invalid_result['valid'] is False
    
    def test_webhook_ip_whitelist_validation(self):
        """Testa validação de whitelist de IPs."""
        # Setup
        secret_key = "test-secret-key"
        test_data = '{"test": "data"}'
        timestamp = str(int(time.time()))
        signature = generate_hmac_signature(test_data, secret_key)
        
        # IPs válidos e inválidos
        valid_ips = ['127.0.0.1', '192.168.1.100', '10.0.0.50']
        invalid_ips = ['192.168.1.200', '10.0.0.100', '172.16.0.50']
        
        # Testa IPs válidos
        for ip in valid_ips:
            class ValidIPRequest:
                def __init__(self, ip_addr):
                    self.data = test_data.encode()
                    self.headers = {
                        'X-Timestamp': timestamp,
                        'X-Signature': signature
                    }
                    self.remote_addr = ip_addr
            
            request = ValidIPRequest(ip)
            result = validate_webhook_request(request, secret_key)
            # Pode falhar por outros motivos, mas não por IP
            if not result['valid']:
                assert 'ip' not in result['reason'].lower()
        
        # Testa IPs inválidos
        for ip in invalid_ips:
            class InvalidIPRequest:
                def __init__(self, ip_addr):
                    self.data = test_data.encode()
                    self.headers = {
                        'X-Timestamp': timestamp,
                        'X-Signature': signature
                    }
                    self.remote_addr = ip_addr
            
            request = InvalidIPRequest(ip)
            result = validate_webhook_request(request, secret_key)
            # Deve falhar por IP inválido
            assert result['valid'] is False
            assert 'ip' in result['reason'].lower() or 'permitido' in result['reason'].lower()
    
    def test_webhook_timestamp_validation(self):
        """Testa validação de timestamp de webhook."""
        # Setup
        secret_key = "test-secret-key"
        test_data = '{"test": "data"}'
        signature = generate_hmac_signature(test_data, secret_key)
        
        # Timestamps válidos e inválidos
        current_time = int(time.time())
        valid_timestamps = [
            str(current_time),  # Agora
            str(current_time - 60),  # 1 minuto atrás
            str(current_time - 300)  # 5 minutos atrás
        ]
        
        invalid_timestamps = [
            str(current_time - 3600),  # 1 hora atrás (muito antigo)
            str(current_time + 3600),  # 1 hora no futuro
            "invalid-timestamp",
            "",
            "0"
        ]
        
        # Testa timestamps válidos
        for timestamp in valid_timestamps:
            class ValidTimestampRequest:
                def __init__(self, ts):
                    self.data = test_data.encode()
                    self.headers = {
                        'X-Timestamp': ts,
                        'X-Signature': signature
                    }
                    self.remote_addr = '127.0.0.1'
            
            request = ValidTimestampRequest(timestamp)
            result = validate_webhook_request(request, secret_key)
            # Pode falhar por outros motivos, mas não por timestamp
            if not result['valid']:
                assert 'timestamp' not in result['reason'].lower()
        
        # Testa timestamps inválidos
        for timestamp in invalid_timestamps:
            class InvalidTimestampRequest:
                def __init__(self, ts):
                    self.data = test_data.encode()
                    self.headers = {
                        'X-Timestamp': ts,
                        'X-Signature': signature
                    }
                    self.remote_addr = '127.0.0.1'
            
            request = InvalidTimestampRequest(timestamp)
            result = validate_webhook_request(request, secret_key)
            # Deve falhar por timestamp inválido
            assert result['valid'] is False
            assert 'timestamp' in result['reason'].lower() or 'tempo' in result['reason'].lower()


class TestRateLimitingUnderAttack:
    """Testa rate limiting sob ataque."""
    
    def test_rate_limiting_under_attack(self):
        """Testa rate limiting sob ataque."""
        # Setup
        rate_limiter = RateLimiter(
            max_requests=10,
            window_seconds=60
        )
        
        # Simula ataque de força bruta
        attack_results = []
        
        # Ataque com muitas requisições rápidas
        for i in range(50):
            start_time = time.time()
            is_allowed = rate_limiter.is_allowed("attacker_ip")
            end_time = time.time()
            
            attack_results.append({
                "request": i,
                "allowed": is_allowed,
                "time": end_time - start_time
            })
        
        # Analisa resultados do ataque
        allowed_requests = [r for r in attack_results if r["allowed"]]
        blocked_requests = [r for r in attack_results if not r["allowed"]]
        
        # Deve bloquear a maioria das requisições após o limite
        assert len(allowed_requests) <= 10  # Máximo permitido
        assert len(blocked_requests) >= 40  # Pelo menos 40 devem ser bloqueadas
        
        # Testa rate limiting com diferentes IPs
        ip_results = {}
        
        for ip in ["ip1", "ip2", "ip3", "ip4", "ip5"]:
            ip_results[ip] = []
            for i in range(15):
                is_allowed = rate_limiter.is_allowed(ip)
                ip_results[ip].append(is_allowed)
        
        # Cada IP deve ter seu próprio limite
        for ip, results in ip_results.items():
            allowed_count = sum(results)
            assert allowed_count <= 10  # Cada IP deve respeitar o limite
    
    def test_ddos_protection(self):
        """Testa proteção contra DDoS."""
        # Setup
        rate_limiter = RateLimiter(
            max_requests=5,
            window_seconds=10
        )
        
        # Simula ataque DDoS com múltiplos IPs
        ddos_results = {}
        
        # 100 IPs diferentes fazendo requisições simultâneas
        for ip_num in range(100):
            ip = f"ddos_ip_{ip_num}"
            ddos_results[ip] = []
            
            # Cada IP faz 10 requisições
            for req_num in range(10):
                is_allowed = rate_limiter.is_allowed(ip)
                ddos_results[ip].append(is_allowed)
        
        # Analisa proteção DDoS
        total_requests = sum(len(results) for results in ddos_results.values())
        total_allowed = sum(sum(results) for results in ddos_results.values())
        total_blocked = total_requests - total_allowed
        
        # Deve bloquear a maioria das requisições
        assert total_blocked > total_allowed  # Mais bloqueadas que permitidas
        
        # Cada IP deve ter seu próprio limite
        for ip, results in ddos_results.items():
            allowed_count = sum(results)
            assert allowed_count <= 5  # Máximo por IP
    
    def test_rate_limiting_recovery(self):
        """Testa recuperação do rate limiting."""
        # Setup
        rate_limiter = RateLimiter(
            max_requests=3,
            window_seconds=5
        )
        
        # Esgota o limite
        for i in range(5):
            rate_limiter.is_allowed("test_ip")
        
        # Verifica que está bloqueado
        is_blocked = not rate_limiter.is_allowed("test_ip")
        assert is_blocked is True
        
        # Aguarda recuperação
        time.sleep(6)  # Mais que window_seconds
        
        # Verifica que recuperou
        is_allowed = rate_limiter.is_allowed("test_ip")
        assert is_allowed is True 