"""
Testes de segurança para prevenção de SQL injection.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:10:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

import pytest
import json
from unittest.mock import Mock, patch
from app.validators.input_validators import security_validator, SecurityValidationError
from app.schemas.request_schemas import GenerateRequestSchema, FeedbackRequestSchema


class TestSQLInjectionPrevention:
    """Testes para prevenir SQL injection em entradas de usuário."""
    
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
    
    def test_sql_injection_in_api_key_generate(self):
        """Testa prevenção de SQL injection na API key."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['api_key'] = "'; DROP TABLE users; --"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "caracteres inválidos" in error or "padrão suspeito" in error
    
    def test_sql_injection_in_prompt_generate(self):
        """Testa prevenção de SQL injection nos prompts."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['prompt_0'] = "'; INSERT INTO articles VALUES ('hacked'); --"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_sql_injection_in_instancias_json(self):
        """Testa prevenção de SQL injection no JSON de instâncias."""
        malicious_data = self.sample_generate_data.copy()
        malicious_instances = [{
            'api_key': "'; DROP TABLE articles; --",
            'modelo': 'openai',
            'prompts': ["'; DELETE FROM users; --"]
        }]
        malicious_data['instancias_json'] = json.dumps(malicious_instances)
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "caracteres inválidos" in error or "conteúdo suspeito" in error
    
    def test_sql_injection_in_user_id_feedback(self):
        """Testa prevenção de SQL injection no user_id do feedback."""
        malicious_data = self.sample_feedback_data.copy()
        malicious_data['user_id'] = "'; UPDATE users SET role='admin'; --"
        
        success, error, _ = security_validator.validate_feedback_request(malicious_data)
        
        assert success is False
        assert "caracteres inválidos" in error
    
    def test_sql_injection_in_artigo_id_feedback(self):
        """Testa prevenção de SQL injection no artigo_id do feedback."""
        malicious_data = self.sample_feedback_data.copy()
        malicious_data['artigo_id'] = "'; DROP TABLE feedback; --"
        
        success, error, _ = security_validator.validate_feedback_request(malicious_data)
        
        assert success is False
        assert "caracteres inválidos" in error
    
    def test_sql_injection_in_comentario_feedback(self):
        """Testa prevenção de SQL injection no comentário do feedback."""
        malicious_data = self.sample_feedback_data.copy()
        malicious_data['comentario'] = "'; INSERT INTO admin_users VALUES ('hacker'); --"
        
        success, error, _ = security_validator.validate_feedback_request(malicious_data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_union_sql_injection_in_prompt(self):
        """Testa prevenção de UNION SQL injection."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['prompt_0'] = "' UNION SELECT * FROM users --"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_comment_sql_injection_in_api_key(self):
        """Testa prevenção de SQL injection com comentários."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['api_key'] = "admin/* */--"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "caracteres inválidos" in error
    
    def test_stored_procedure_injection(self):
        """Testa prevenção de injeção de stored procedures."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['prompt_0'] = "'; EXEC xp_cmdshell 'dir'; --"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_legitimate_data_passes_validation(self):
        """Testa que dados legítimos passam na validação."""
        success, error, validated_data = security_validator.validate_generate_request(self.sample_generate_data)
        
        assert success is True
        assert error is None
        assert validated_data is not None
    
    def test_legitimate_feedback_passes_validation(self):
        """Testa que feedback legítimo passa na validação."""
        success, error, validated_data = security_validator.validate_feedback_request(self.sample_feedback_data)
        
        assert success is True
        assert error is None
        assert validated_data is not None


class TestXSSPrevention:
    """Testes para prevenir XSS em entradas de usuário."""
    
    def test_xss_script_tag_in_prompt(self):
        """Testa prevenção de XSS com tag script."""
        data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': '<script>alert("XSS")</script>',
            'instancias_json': None
        }
        
        success, error, _ = security_validator.validate_generate_request(data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_xss_javascript_protocol_in_prompt(self):
        """Testa prevenção de XSS com protocolo javascript."""
        data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'javascript:alert("XSS")',
            'instancias_json': None
        }
        
        success, error, _ = security_validator.validate_generate_request(data)
        
        assert success is False
        assert "conteúdo suspeito" in error
    
    def test_xss_onload_event_in_comentario(self):
        """Testa prevenção de XSS com evento onload."""
        data = {
            'user_id': 'user123',
            'artigo_id': 'artigo456',
            'tipo': 'positivo',
            'comentario': '<img src="x" onload="alert(\'XSS\')">'
        }
        
        success, error, _ = security_validator.validate_feedback_request(data)
        
        assert success is False
        assert "conteúdo suspeito" in error


class TestPathTraversalPrevention:
    """Testes para prevenir path traversal."""
    
    def test_path_traversal_in_api_key(self):
        """Testa prevenção de path traversal na API key."""
        data = {
            'api_key': '../../../etc/passwd',
            'model_type': 'openai',
            'prompt_0': 'Test prompt',
            'instancias_json': None
        }
        
        success, error, _ = security_validator.validate_generate_request(data)
        
        assert success is False
        assert "caracteres inválidos" in error
    
    def test_path_traversal_in_user_id(self):
        """Testa prevenção de path traversal no user_id."""
        data = {
            'user_id': '../../config/database.yml',
            'artigo_id': 'artigo456',
            'tipo': 'positivo',
            'comentario': 'Test comment'
        }
        
        success, error, _ = security_validator.validate_feedback_request(data)
        
        assert success is False
        assert "caracteres inválidos" in error


class TestInputSanitization:
    """Testes para sanitização de entrada."""
    
    def test_sanitize_html_entities(self):
        """Testa sanitização de entidades HTML."""
        malicious_input = "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        sanitized = security_validator.sanitize_input(malicious_input)
        
        # Deve escapar as entidades HTML
        assert "&amp;lt;" in sanitized or "&lt;" not in sanitized
    
    def test_sanitize_control_characters(self):
        """Testa sanitização de caracteres de controle."""
        malicious_input = "test\x00\x01\x02string"
        sanitized = security_validator.sanitize_input(malicious_input)
        
        # Deve remover caracteres de controle
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized
        assert "\x02" not in sanitized
    
    def test_sanitize_script_tags(self):
        """Testa sanitização de tags script."""
        malicious_input = "<script>alert('XSS')</script>"
        sanitized = security_validator.sanitize_input(malicious_input)
        
        # Deve remover ou escapar tags script
        assert "<script>" not in sanitized.lower() 