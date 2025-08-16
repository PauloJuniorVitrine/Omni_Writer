"""
Testes de Validação de Entrada - Omni Writer
============================================

Implementa testes para validação de entrada robusta:
- Validação de prompts (XSS, injeção, tamanho)
- Validação de configurações de API
- Validação de dados de entrada
- Sanitização de conteúdo
- Validação de formatos

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import json
import re
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Importações do sistema real
from app.validators.input_validators import (
    SecurityValidator,
    GenerateRequestValidator,
    SecurityValidationError,
    validate_prompt_security,
    sanitize_input,
    validate_api_config
)
from app.schemas.request_schemas import (
    GenerateRequestSchema,
    WebhookRequestSchema
)
from shared.config import get_config


class TestPromptValidation:
    """Testa validação de prompts."""
    
    def test_valid_prompt_validation(self):
        """Testa prompt válido."""
        # Prompts válidos baseados no sistema real
        valid_prompts = [
            "Como criar um blog profissional sobre tecnologia",
            "Dicas de SEO para iniciantes em marketing digital",
            "Estratégias de conteúdo para redes sociais",
            "Guia completo de copywriting para vendas online",
            "Como otimizar um site para conversão"
        ]
        
        for prompt in valid_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is True
            assert result['sanitized_prompt'] == prompt
    
    def test_xss_prompt_detection(self):
        """Testa detecção de XSS em prompts."""
        # Prompts maliciosos com XSS
        malicious_prompts = [
            "<script>alert('xss')</script>Como criar um blog",
            "javascript:alert('xss')",
            "onload=alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "data:text/html,<script>alert('xss')</script>",
            "<iframe src=javascript:alert('xss')></iframe>",
            "prompt<script>alert('xss')</script>",
            "prompt onmouseover=alert('xss')",
            "prompt onfocus=alert('xss')",
            "prompt onblur=alert('xss')"
        ]
        
        for prompt in malicious_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is False
            assert 'xss' in result['reason'].lower() or 'malicious' in result['reason'].lower()
    
    def test_sql_injection_detection(self):
        """Testa detecção de injeção SQL."""
        # Prompts com tentativas de injeção SQL
        sql_injection_prompts = [
            "'; DROP TABLE users; --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "'; UPDATE users SET password='hacked'; --",
            "'; SELECT * FROM users WHERE id=1; --",
            "'; EXEC xp_cmdshell('dir'); --",
            "'; UNION SELECT * FROM users; --",
            "'; OR 1=1; --",
            "'; AND 1=1; --",
            "'; WAITFOR DELAY '00:00:10'; --",
            "'; DECLARE @cmd VARCHAR(100); SET @cmd='dir'; EXEC(@cmd); --"
        ]
        
        for prompt in sql_injection_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is False
            assert 'injection' in result['reason'].lower() or 'malicious' in result['reason'].lower()
    
    def test_command_injection_detection(self):
        """Testa detecção de injeção de comandos."""
        # Prompts com tentativas de injeção de comandos
        command_injection_prompts = [
            "prompt; rm -rf /",
            "prompt && rm -rf /",
            "prompt | rm -rf /",
            "prompt || rm -rf /",
            "prompt; cat /etc/passwd",
            "prompt && cat /etc/passwd",
            "prompt | cat /etc/passwd",
            "prompt; whoami",
            "prompt && whoami",
            "prompt | whoami"
        ]
        
        for prompt in command_injection_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is False
            assert 'injection' in result['reason'].lower() or 'malicious' in result['reason'].lower()
    
    def test_prompt_length_validation(self):
        """Testa validação de tamanho de prompt."""
        # Prompt muito longo
        long_prompt = "A" * 10001  # Mais de 10.000 caracteres
        
        result = validate_prompt_security(long_prompt)
        assert result['valid'] is False
        assert 'length' in result['reason'].lower() or 'size' in result['reason'].lower()
        
        # Prompt vazio
        empty_prompt = ""
        result = validate_prompt_security(empty_prompt)
        assert result['valid'] is False
        assert 'empty' in result['reason'].lower() or 'required' in result['reason'].lower()
        
        # Prompt apenas com espaços
        whitespace_prompt = "   \n\t   "
        result = validate_prompt_security(whitespace_prompt)
        assert result['valid'] is False
        assert 'empty' in result['reason'].lower() or 'whitespace' in result['reason'].lower()
    
    def test_prompt_sanitization(self):
        """Testa sanitização de prompts."""
        # Prompts que devem ser sanitizados
        test_cases = [
            {
                "input": "prompt<script>alert('xss')</script>",
                "expected_contains": "prompt",
                "expected_not_contains": "<script>"
            },
            {
                "input": "prompt; rm -rf /",
                "expected_contains": "prompt",
                "expected_not_contains": "; rm -rf /"
            },
            {
                "input": "prompt' OR 1=1; --",
                "expected_contains": "prompt",
                "expected_not_contains": "OR 1=1"
            }
        ]
        
        for case in test_cases:
            sanitized = sanitize_input(case["input"])
            assert case["expected_contains"] in sanitized
            assert case["expected_not_contains"] not in sanitized


class TestAPIConfigValidation:
    """Testa validação de configurações de API."""
    
    def test_valid_api_config(self):
        """Testa configuração de API válida."""
        valid_configs = [
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000,
                "temperature": 0.7
            },
            {
                "api_key": "sk-deepseek-1234567890abcdef1234567890abcdef",
                "model_type": "deepseek",
                "max_tokens": 2000,
                "temperature": 0.5
            }
        ]
        
        for config in valid_configs:
            result = validate_api_config(config)
            assert result['valid'] is True
    
    def test_invalid_api_key_format(self):
        """Testa formato inválido de API key."""
        invalid_configs = [
            {
                "api_key": "invalid-key",
                "model_type": "openai",
                "max_tokens": 1000
            },
            {
                "api_key": "sk-",
                "model_type": "openai",
                "max_tokens": 1000
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000
            },
            {
                "api_key": "",
                "model_type": "openai",
                "max_tokens": 1000
            }
        ]
        
        for config in invalid_configs:
            result = validate_api_config(config)
            assert result['valid'] is False
            assert 'api_key' in result['reason'].lower()
    
    def test_invalid_model_type(self):
        """Testa tipo de modelo inválido."""
        invalid_configs = [
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "invalid_model",
                "max_tokens": 1000
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "",
                "max_tokens": 1000
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "gpt-5",  # Modelo inexistente
                "max_tokens": 1000
            }
        ]
        
        for config in invalid_configs:
            result = validate_api_config(config)
            assert result['valid'] is False
            assert 'model' in result['reason'].lower()
    
    def test_invalid_max_tokens(self):
        """Testa valor inválido de max_tokens."""
        invalid_configs = [
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 0
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": -1
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 100000  # Muito alto
            }
        ]
        
        for config in invalid_configs:
            result = validate_api_config(config)
            assert result['valid'] is False
            assert 'tokens' in result['reason'].lower() or 'max_tokens' in result['reason'].lower()
    
    def test_invalid_temperature(self):
        """Testa valor inválido de temperature."""
        invalid_configs = [
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000,
                "temperature": -0.1
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000,
                "temperature": 2.1
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000,
                "temperature": "invalid"
            }
        ]
        
        for config in invalid_configs:
            result = validate_api_config(config)
            assert result['valid'] is False
            assert 'temperature' in result['reason'].lower()


class TestRequestSchemaValidation:
    """Testa validação de schemas de requisição."""
    
    def test_valid_generate_request(self):
        """Testa requisição de geração válida."""
        valid_requests = [
            {
                "prompts": ["Como criar um blog profissional"],
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai",
                "max_tokens": 1000,
                "temperature": 0.7
            },
            {
                "prompts": ["Dicas de SEO", "Marketing digital"],
                "api_key": "sk-deepseek-1234567890abcdef1234567890abcdef",
                "model_type": "deepseek",
                "max_tokens": 2000,
                "temperature": 0.5
            }
        ]
        
        for request_data in valid_requests:
            try:
                validated = GenerateRequestSchema(**request_data)
                assert validated.prompts == request_data["prompts"]
                assert validated.api_key == request_data["api_key"]
                assert validated.model_type == request_data["model_type"]
            except Exception as e:
                pytest.fail(f"Validação falhou para dados válidos: {e}")
    
    def test_invalid_generate_request(self):
        """Testa requisição de geração inválida."""
        invalid_requests = [
            {
                "prompts": [],  # Lista vazia
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai"
            },
            {
                "prompts": [""],  # Prompt vazio
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                "model_type": "openai"
            },
            {
                "prompts": ["Valid prompt"],
                # api_key ausente
                "model_type": "openai"
            },
            {
                "prompts": ["Valid prompt"],
                "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
                # model_type ausente
            }
        ]
        
        for request_data in invalid_requests:
            with pytest.raises(Exception):
                GenerateRequestSchema(**request_data)
    
    def test_valid_webhook_request(self):
        """Testa requisição de webhook válida."""
        valid_webhooks = [
            {
                "url": "https://example.com/webhook"
            },
            {
                "url": "http://localhost:3000/webhook"
            },
            {
                "url": "https://api.example.com/webhook/notify"
            }
        ]
        
        for webhook_data in valid_webhooks:
            try:
                validated = WebhookRequestSchema(**webhook_data)
                assert validated.url == webhook_data["url"]
            except Exception as e:
                pytest.fail(f"Validação falhou para webhook válido: {e}")
    
    def test_invalid_webhook_request(self):
        """Testa requisição de webhook inválida."""
        invalid_webhooks = [
            {
                "url": "invalid-url"  # URL inválida
            },
            {
                "url": "ftp://example.com/webhook"  # Protocolo não permitido
            },
            {
                "url": "http://"  # URL incompleta
            },
            {
                "url": ""  # URL vazia
            }
        ]
        
        for webhook_data in invalid_webhooks:
            with pytest.raises(Exception):
                WebhookRequestSchema(**webhook_data)


class TestSecurityValidator:
    """Testa o validador de segurança principal."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.validator = SecurityValidator()
    
    def test_validate_generate_request_success(self):
        """Testa validação bem-sucedida de requisição de geração."""
        valid_request = {
            "prompts": ["Como criar um blog profissional"],
            "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "model_type": "openai",
            "max_tokens": 1000,
            "temperature": 0.7
        }
        
        success, error, validated_data = self.validator.validate_generate_request(valid_request)
        
        assert success is True
        assert error is None
        assert validated_data is not None
        assert validated_data["prompts"] == valid_request["prompts"]
    
    def test_validate_generate_request_malicious_prompt(self):
        """Testa validação com prompt malicioso."""
        malicious_request = {
            "prompts": ["<script>alert('xss')</script>Como criar um blog"],
            "api_key": "sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "model_type": "openai",
            "max_tokens": 1000
        }
        
        success, error, validated_data = self.validator.validate_generate_request(malicious_request)
        
        assert success is False
        assert error is not None
        assert "malicious" in error.lower() or "xss" in error.lower()
        assert validated_data is None
    
    def test_validate_generate_request_invalid_config(self):
        """Testa validação com configuração inválida."""
        invalid_request = {
            "prompts": ["Como criar um blog profissional"],
            "api_key": "invalid-key",
            "model_type": "openai",
            "max_tokens": 1000
        }
        
        success, error, validated_data = self.validator.validate_generate_request(invalid_request)
        
        assert success is False
        assert error is not None
        assert "api_key" in error.lower() or "invalid" in error.lower()
        assert validated_data is None
    
    def test_validate_generate_request_missing_fields(self):
        """Testa validação com campos ausentes."""
        incomplete_request = {
            "prompts": ["Como criar um blog profissional"]
            # api_key e model_type ausentes
        }
        
        success, error, validated_data = self.validator.validate_generate_request(incomplete_request)
        
        assert success is False
        assert error is not None
        assert validated_data is None


class TestInputSanitization:
    """Testa sanitização de entrada."""
    
    def test_html_sanitization(self):
        """Testa sanitização de HTML."""
        test_cases = [
            {
                "input": "<script>alert('xss')</script>prompt",
                "expected": "prompt"
            },
            {
                "input": "prompt<img src=x onerror=alert('xss')>",
                "expected": "prompt"
            },
            {
                "input": "prompt<iframe src=javascript:alert('xss')></iframe>",
                "expected": "prompt"
            },
            {
                "input": "prompt<style>body{background:red}</style>",
                "expected": "prompt"
            }
        ]
        
        for case in test_cases:
            sanitized = sanitize_input(case["input"])
            assert case["expected"] in sanitized
            assert "<script>" not in sanitized
            assert "<img" not in sanitized
            assert "<iframe" not in sanitized
            assert "<style>" not in sanitized
    
    def test_sql_injection_sanitization(self):
        """Testa sanitização de injeção SQL."""
        test_cases = [
            {
                "input": "prompt'; DROP TABLE users; --",
                "expected": "prompt"
            },
            {
                "input": "prompt' OR 1=1; --",
                "expected": "prompt"
            },
            {
                "input": "prompt' UNION SELECT * FROM users; --",
                "expected": "prompt"
            }
        ]
        
        for case in test_cases:
            sanitized = sanitize_input(case["input"])
            assert case["expected"] in sanitized
            assert "DROP TABLE" not in sanitized
            assert "OR 1=1" not in sanitized
            assert "UNION SELECT" not in sanitized
    
    def test_command_injection_sanitization(self):
        """Testa sanitização de injeção de comandos."""
        test_cases = [
            {
                "input": "prompt; rm -rf /",
                "expected": "prompt"
            },
            {
                "input": "prompt && rm -rf /",
                "expected": "prompt"
            },
            {
                "input": "prompt | cat /etc/passwd",
                "expected": "prompt"
            }
        ]
        
        for case in test_cases:
            sanitized = sanitize_input(case["input"])
            assert case["expected"] in sanitized
            assert "; rm -rf /" not in sanitized
            assert "&& rm -rf /" not in sanitized
            assert "| cat /etc/passwd" not in sanitized
    
    def test_whitespace_normalization(self):
        """Testa normalização de espaços em branco."""
        test_cases = [
            {
                "input": "  prompt  with  extra  spaces  ",
                "expected": "prompt with extra spaces"
            },
            {
                "input": "prompt\nwith\nnewlines",
                "expected": "prompt with newlines"
            },
            {
                "input": "prompt\twith\ttabs",
                "expected": "prompt with tabs"
            }
        ]
        
        for case in test_cases:
            sanitized = sanitize_input(case["input"])
            assert sanitized == case["expected"]


class TestEdgeCases:
    """Testa casos extremos de validação."""
    
    def test_unicode_characters(self):
        """Testa caracteres Unicode."""
        unicode_prompts = [
            "Como criar um blog com emojis 🚀📱💻",
            "Dicas de SEO com acentos: ação, coração, situação",
            "Marketing digital com caracteres especiais: ©®™",
            "Conteúdo com símbolos: €$¥£¢"
        ]
        
        for prompt in unicode_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is True
    
    def test_very_long_valid_prompt(self):
        """Testa prompt válido muito longo."""
        long_prompt = "Como criar um blog profissional sobre tecnologia " * 200  # ~10.000 caracteres
        
        result = validate_prompt_security(long_prompt)
        assert result['valid'] is True
    
    def test_special_characters(self):
        """Testa caracteres especiais válidos."""
        special_prompts = [
            "Como criar um blog com markdown: **negrito**, *itálico*, `código`",
            "Dicas de SEO com URLs: https://example.com",
            "Marketing digital com hashtags: #marketing #digital #seo",
            "Conteúdo com parênteses: (exemplo) e [referência]"
        ]
        
        for prompt in special_prompts:
            result = validate_prompt_security(prompt)
            assert result['valid'] is True
    
    def test_empty_and_none_values(self):
        """Testa valores vazios e None."""
        empty_values = [None, "", "   ", "\n\t"]
        
        for value in empty_values:
            result = validate_prompt_security(value)
            assert result['valid'] is False 