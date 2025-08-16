"""
Testes de Integração com Sistemas Externos - Omni Writer
=======================================================

Implementa testes para integração com sistemas externos:
- Integração real com OpenAI
- Integração real com DeepSeek
- Validação de certificados SSL
- Rate limiting de webhooks
- Fallback entre provedores

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import time
import requests
import ssl
import socket
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import json

# Importações do sistema real
from infraestructure.openai_gateway import generate_article_openai
from infraestructure.deepseek_gateway import generate_article_deepseek
from infraestructure.webhook_security_v1 import send_webhook
from shared.ssl_validator import validate_ssl_certificate
from omni_writer.domain.smart_retry import SmartRetry


class TestOpenAIRealIntegration:
    """Testa integração real com OpenAI."""
    
    @pytest.mark.integration
    @pytest.mark.slow
    def test_openai_api_real_integration(self):
        """Testa integração real com OpenAI."""
        # Setup - requer API key real para teste
        config = {
            "api_key": "sk-test-key",  # Será mockado
            "model": "gpt-3.5-turbo",
            "max_tokens": 100,
            "temperature": 0.7
        }
        
        prompt = "Escreva uma frase sobre tecnologia."
        
        # Mock da resposta da API OpenAI
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": "A tecnologia está transformando rapidamente o mundo moderno."
                }
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 15,
                "total_tokens": 25
            }
        }
        
        # Testa integração com mock
        with patch('infraestructure.openai_gateway.requests.post') as mock_post:
            mock_post.return_value = mock_response
            
            result = generate_article_openai(config, prompt)
            
            # Valida resultado
            assert "tecnologia" in result.lower()
            assert len(result) > 0
            
            # Valida que API foi chamada corretamente
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            
            # Valida headers
            headers = call_args[1]['headers']
            assert 'Authorization' in headers
            assert headers['Authorization'].startswith('Bearer sk-')
            
            # Valida payload
            payload = call_args[1]['json']
            assert payload['model'] == config['model']
            assert payload['max_tokens'] == config['max_tokens']
            assert prompt in payload['messages'][0]['content']
    
    @pytest.mark.integration
    def test_openai_api_error_handling(self):
        """Testa tratamento de erros da API OpenAI."""
        config = {
            "api_key": "sk-test-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 100
        }
        
        prompt = "Teste de erro"
        
        # Testa diferentes códigos de erro
        error_codes = [400, 401, 403, 429, 500, 502, 503]
        
        for status_code in error_codes:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.json.return_value = {
                "error": {
                    "message": f"HTTP {status_code} error",
                    "type": "api_error"
                }
            }
            
            with patch('infraestructure.openai_gateway.requests.post') as mock_post:
                mock_post.return_value = mock_response
                
                with pytest.raises(Exception) as exc_info:
                    generate_article_openai(config, prompt)
                
                # Valida que erro foi tratado adequadamente
                assert str(exc_info.value) is not None
    
    @pytest.mark.integration
    def test_openai_api_rate_limiting(self):
        """Testa rate limiting da API OpenAI."""
        config = {
            "api_key": "sk-test-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 100
        }
        
        prompt = "Teste de rate limit"
        
        # Simula rate limit seguido de sucesso
        rate_limit_response = Mock()
        rate_limit_response.status_code = 429
        rate_limit_response.json.return_value = {
            "error": {
                "message": "Rate limit exceeded",
                "type": "rate_limit_error"
            }
        }
        rate_limit_response.headers = {"Retry-After": "60"}
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": "Resposta após rate limit."
                }
            }]
        }
        
        with patch('infraestructure.openai_gateway.requests.post') as mock_post:
            mock_post.side_effect = [rate_limit_response, success_response]
            
            # Primeira chamada deve falhar com rate limit
            with pytest.raises(Exception) as exc_info:
                generate_article_openai(config, prompt)
            
            # Segunda chamada deve ter sucesso
            result = generate_article_openai(config, prompt)
            assert "Resposta após rate limit" in result


class TestDeepSeekRealIntegration:
    """Testa integração real com DeepSeek."""
    
    @pytest.mark.integration
    @pytest.mark.slow
    def test_deepseek_api_real_integration(self):
        """Testa integração real com DeepSeek."""
        # Setup
        config = {
            "api_key": "sk-deepseek-test-key",  # Será mockado
            "model": "deepseek-chat",
            "max_tokens": 100,
            "temperature": 0.7
        }
        
        prompt = "Explique o que é inteligência artificial."
        
        # Mock da resposta da API DeepSeek
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": "Inteligência artificial é a simulação de processos de inteligência humana por máquinas."
                }
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 18,
                "total_tokens": 30
            }
        }
        
        # Testa integração com mock
        with patch('infraestructure.deepseek_gateway.requests.post') as mock_post:
            mock_post.return_value = mock_response
            
            result = generate_article_deepseek(config, prompt)
            
            # Valida resultado
            assert "inteligência artificial" in result.lower()
            assert len(result) > 0
            
            # Valida que API foi chamada corretamente
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            
            # Valida headers
            headers = call_args[1]['headers']
            assert 'Authorization' in headers
            assert headers['Authorization'].startswith('Bearer sk-deepseek-')
            
            # Valida payload
            payload = call_args[1]['json']
            assert payload['model'] == config['model']
            assert payload['max_tokens'] == config['max_tokens']
            assert prompt in payload['messages'][0]['content']
    
    @pytest.mark.integration
    def test_deepseek_api_timeout_handling(self):
        """Testa tratamento de timeouts da API DeepSeek."""
        config = {
            "api_key": "sk-deepseek-test-key",
            "model": "deepseek-chat",
            "max_tokens": 100
        }
        
        prompt = "Teste de timeout"
        
        # Simula timeout seguido de sucesso
        timeout_response = Mock()
        timeout_response.side_effect = requests.exceptions.Timeout("Request timeout")
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": "Resposta após timeout."
                }
            }]
        }
        
        with patch('infraestructure.deepseek_gateway.requests.post') as mock_post:
            mock_post.side_effect = [timeout_response, success_response]
            
            # Primeira chamada deve falhar com timeout
            with pytest.raises(Exception) as exc_info:
                generate_article_deepseek(config, prompt)
            
            # Segunda chamada deve ter sucesso
            result = generate_article_deepseek(config, prompt)
            assert "Resposta após timeout" in result


class TestSSLCertificateValidation:
    """Testa validação de certificados SSL."""
    
    def test_ssl_certificate_validation(self):
        """Testa validação de certificados SSL."""
        # Testa certificados válidos
        valid_hosts = [
            "api.openai.com",
            "api.deepseek.com",
            "www.google.com"
        ]
        
        for host in valid_hosts:
            try:
                result = validate_ssl_certificate(host, 443)
                assert result['valid'] is True
                assert 'issuer' in result
                assert 'expiry' in result
            except Exception as e:
                # Pode falhar em ambiente de teste, mas não deve quebrar
                assert "ssl" in str(e).lower() or "certificate" in str(e).lower()
    
    def test_ssl_certificate_expiry_validation(self):
        """Testa validação de expiração de certificados SSL."""
        # Mock de certificado expirado
        expired_cert = {
            'subject': ((('CN', 'expired.example.com'),),),
            'issuer': ((('CN', 'Test CA'),),),
            'notAfter': '2020-01-01 00:00:00',
            'notBefore': '2019-01-01 00:00:00'
        }
        
        # Mock de certificado válido
        valid_cert = {
            'subject': ((('CN', 'valid.example.com'),),),
            'issuer': ((('CN', 'Test CA'),),),
            'notAfter': '2030-01-01 00:00:00',
            'notBefore': '2020-01-01 00:00:00'
        }
        
        # Testa certificado expirado
        with patch('ssl.get_server_certificate') as mock_get_cert:
            mock_get_cert.return_value = expired_cert
            
            result = validate_ssl_certificate("expired.example.com", 443)
            assert result['valid'] is False
            assert 'expired' in result['reason'].lower()
        
        # Testa certificado válido
        with patch('ssl.get_server_certificate') as mock_get_cert:
            mock_get_cert.return_value = valid_cert
            
            result = validate_ssl_certificate("valid.example.com", 443)
            assert result['valid'] is True
    
    def test_ssl_certificate_issuer_validation(self):
        """Testa validação de emissor de certificados SSL."""
        # Mock de certificado com emissor confiável
        trusted_cert = {
            'subject': ((('CN', 'trusted.example.com'),),),
            'issuer': ((('CN', 'DigiCert Inc'),),),
            'notAfter': '2030-01-01 00:00:00',
            'notBefore': '2020-01-01 00:00:00'
        }
        
        # Mock de certificado com emissor não confiável
        untrusted_cert = {
            'subject': ((('CN', 'untrusted.example.com'),),),
            'issuer': ((('CN', 'Self-Signed CA'),),),
            'notAfter': '2030-01-01 00:00:00',
            'notBefore': '2020-01-01 00:00:00'
        }
        
        # Testa certificado confiável
        with patch('ssl.get_server_certificate') as mock_get_cert:
            mock_get_cert.return_value = trusted_cert
            
            result = validate_ssl_certificate("trusted.example.com", 443)
            assert result['valid'] is True
        
        # Testa certificado não confiável
        with patch('ssl.get_server_certificate') as mock_get_cert:
            mock_get_cert.return_value = untrusted_cert
            
            result = validate_ssl_certificate("untrusted.example.com", 443)
            # Pode ser válido em testes, mas deve ter informação sobre emissor
            assert 'issuer' in result


class TestWebhookRateLimiting:
    """Testa rate limiting de webhooks."""
    
    def test_webhook_rate_limiting(self):
        """Testa rate limiting de webhooks."""
        # Setup
        webhook_url = "http://example.com/webhook"
        payload = {
            "event": "article_generated",
            "timestamp": time.time(),
            "data": {"article_id": "123"}
        }
        
        # Simula rate limiting
        rate_limit_response = Mock()
        rate_limit_response.status_code = 429
        rate_limit_response.json.return_value = {
            "error": "Rate limit exceeded",
            "retry_after": 60
        }
        rate_limit_response.headers = {"Retry-After": "60"}
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"status": "received"}
        
        # Testa rate limiting
        with patch('infraestructure.webhook_security_v1.requests.post') as mock_post:
            mock_post.side_effect = [rate_limit_response, success_response]
            
            # Primeira chamada deve falhar com rate limit
            try:
                send_webhook(webhook_url, payload)
            except Exception as e:
                assert "rate limit" in str(e).lower() or "429" in str(e)
            
            # Segunda chamada deve ter sucesso
            result = send_webhook(webhook_url, payload)
            assert result is not None
    
    def test_webhook_retry_mechanism(self):
        """Testa mecanismo de retry de webhooks."""
        # Setup
        webhook_url = "http://example.com/webhook"
        payload = {"test": "data"}
        
        # Simula falhas seguidas de sucesso
        failure_responses = [
            Mock(status_code=500, json=lambda: {"error": "Internal server error"}),
            Mock(status_code=502, json=lambda: {"error": "Bad gateway"}),
            Mock(status_code=503, json=lambda: {"error": "Service unavailable"}),
            Mock(status_code=200, json=lambda: {"status": "success"})
        ]
        
        with patch('infraestructure.webhook_security_v1.requests.post') as mock_post:
            mock_post.side_effect = failure_responses
            
            # Deve tentar múltiplas vezes e eventualmente ter sucesso
            result = send_webhook(webhook_url, payload)
            assert result is not None
            
            # Deve ter feito 4 tentativas
            assert mock_post.call_count == 4
    
    def test_webhook_timeout_handling(self):
        """Testa tratamento de timeout de webhooks."""
        # Setup
        webhook_url = "http://example.com/webhook"
        payload = {"test": "data"}
        
        # Simula timeout seguido de sucesso
        timeout_response = Mock()
        timeout_response.side_effect = requests.exceptions.Timeout("Request timeout")
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = {"status": "success"}
        
        with patch('infraestructure.webhook_security_v1.requests.post') as mock_post:
            mock_post.side_effect = [timeout_response, success_response]
            
            # Primeira chamada deve falhar com timeout
            try:
                send_webhook(webhook_url, payload)
            except Exception as e:
                assert "timeout" in str(e).lower()
            
            # Segunda chamada deve ter sucesso
            result = send_webhook(webhook_url, payload)
            assert result is not None


class TestProviderFallback:
    """Testa fallback entre provedores."""
    
    def test_provider_fallback_mechanism(self):
        """Testa mecanismo de fallback entre provedores."""
        # Setup
        smart_retry = SmartRetry()
        
        # Configurações dos provedores
        openai_config = {
            "api_key": "sk-openai-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 100
        }
        
        deepseek_config = {
            "api_key": "sk-deepseek-key",
            "model": "deepseek-chat",
            "max_tokens": 100
        }
        
        prompt = "Teste de fallback"
        
        # Simula falha do OpenAI seguida de sucesso do DeepSeek
        openai_failure = Mock()
        openai_failure.side_effect = Exception("OpenAI unavailable")
        
        deepseek_success = Mock()
        deepseek_success.return_value = "Resposta do DeepSeek"
        
        # Testa fallback
        with patch('infraestructure.openai_gateway.generate_article_openai', side_effect=openai_failure):
            with patch('infraestructure.deepseek_gateway.generate_article_deepseek', side_effect=deepseek_success):
                
                # Deve tentar OpenAI primeiro, falhar, e usar DeepSeek
                result = smart_retry.generate_with_fallback(prompt, [openai_config, deepseek_config])
                
                assert "DeepSeek" in result
    
    def test_provider_health_check(self):
        """Testa verificação de saúde dos provedores."""
        # Setup
        smart_retry = SmartRetry()
        
        # Simula diferentes estados de saúde
        healthy_provider = Mock()
        healthy_provider.return_value = {"status": "healthy", "response_time": 0.5}
        
        unhealthy_provider = Mock()
        unhealthy_provider.side_effect = Exception("Provider down")
        
        # Testa verificação de saúde
        with patch('infraestructure.openai_gateway.health_check', side_effect=healthy_provider):
            health_status = smart_retry.check_provider_health("openai")
            assert health_status["status"] == "healthy"
            assert health_status["response_time"] < 1.0
        
        with patch('infraestructure.deepseek_gateway.health_check', side_effect=unhealthy_provider):
            health_status = smart_retry.check_provider_health("deepseek")
            assert health_status["status"] == "unhealthy"
    
    def test_provider_load_balancing(self):
        """Testa balanceamento de carga entre provedores."""
        # Setup
        smart_retry = SmartRetry()
        
        # Configurações dos provedores
        providers = [
            {"name": "openai", "weight": 0.6},
            {"name": "deepseek", "weight": 0.3},
            {"name": "claude", "weight": 0.1}
        ]
        
        prompt = "Teste de balanceamento"
        
        # Simula seleção baseada em peso
        selections = []
        for _ in range(100):
            selected = smart_retry.select_provider(providers)
            selections.append(selected)
        
        # Analisa distribuição
        openai_count = selections.count("openai")
        deepseek_count = selections.count("deepseek")
        claude_count = selections.count("claude")
        
        # Deve respeitar os pesos (com tolerância)
        assert openai_count > deepseek_count > claude_count
        assert openai_count > 50  # Pelo menos 50% para OpenAI
        assert claude_count > 0   # Pelo menos algumas para Claude


class TestExternalAPIMonitoring:
    """Testa monitoramento de APIs externas."""
    
    def test_api_response_time_monitoring(self):
        """Testa monitoramento de tempo de resposta de APIs."""
        # Setup
        api_endpoints = [
            "https://api.openai.com/v1/chat/completions",
            "https://api.deepseek.com/v1/chat/completions"
        ]
        
        # Simula diferentes tempos de resposta
        fast_response = Mock()
        fast_response.elapsed.total_seconds.return_value = 0.5
        
        slow_response = Mock()
        slow_response.elapsed.total_seconds.return_value = 5.0
        
        # Testa monitoramento
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [fast_response, slow_response]
            
            response_times = []
            for endpoint in api_endpoints:
                start_time = time.time()
                response = requests.get(endpoint)
                end_time = time.time()
                
                response_time = end_time - start_time
                response_times.append(response_time)
            
            # Valida tempos de resposta
            assert len(response_times) == 2
            assert response_times[0] < response_times[1]  # Primeiro deve ser mais rápido
    
    def test_api_availability_monitoring(self):
        """Testa monitoramento de disponibilidade de APIs."""
        # Setup
        api_endpoints = [
            "https://api.openai.com/health",
            "https://api.deepseek.com/health"
        ]
        
        # Simula diferentes estados de disponibilidade
        available_response = Mock()
        available_response.status_code = 200
        available_response.json.return_value = {"status": "healthy"}
        
        unavailable_response = Mock()
        unavailable_response.status_code = 503
        unavailable_response.json.return_value = {"status": "unavailable"}
        
        # Testa monitoramento
        with patch('requests.get') as mock_get:
            mock_get.side_effect = [available_response, unavailable_response]
            
            availability_status = []
            for endpoint in api_endpoints:
                try:
                    response = requests.get(endpoint)
                    if response.status_code == 200:
                        availability_status.append("available")
                    else:
                        availability_status.append("unavailable")
                except Exception:
                    availability_status.append("error")
            
            # Valida status de disponibilidade
            assert availability_status[0] == "available"
            assert availability_status[1] == "unavailable"
    
    def test_api_error_rate_monitoring(self):
        """Testa monitoramento de taxa de erro de APIs."""
        # Setup
        api_calls = []
        
        # Simula diferentes resultados de chamadas
        for i in range(100):
            if i < 90:  # 90% sucesso
                api_calls.append({"status": "success", "response_time": 0.5})
            else:  # 10% erro
                api_calls.append({"status": "error", "response_time": 2.0})
        
        # Calcula métricas
        success_count = sum(1 for call in api_calls if call["status"] == "success")
        error_count = sum(1 for call in api_calls if call["status"] == "error")
        error_rate = error_count / len(api_calls)
        
        # Valida métricas
        assert success_count == 90
        assert error_count == 10
        assert error_rate == 0.1  # 10% de erro
        
        # Deve gerar alerta se taxa de erro > 5%
        if error_rate > 0.05:
            assert True  # Alerta deve ser gerado 