"""
Testes unitários para validador de entrada.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:35:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

import pytest
import json
from app.validators.input_validators import (
    security_validator, SecurityValidationError,
    GenerateRequestValidator, FeedbackRequestValidator
)
from app.schemas.request_schemas import GenerateRequestSchema, FeedbackRequestSchema


class TestInputValidators:
    """Testes unitários para validadores de entrada."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.valid_generate_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'Como criar um blog profissional',
            'instancias_json': None
        }
        
        self.valid_feedback_data = {
            'user_id': 'user123',
            'artigo_id': 'artigo456',
            'tipo': 'positivo',
            'comentario': 'Artigo muito bom!'
        }
    
    def test_validate_generate_request_success(self):
        """Testa validação bem-sucedida de requisição de geração."""
        success, error, validated_data = security_validator.validate_generate_request(self.valid_generate_data)
        
        assert success is True
        assert error is None
        assert validated_data is not None
        assert validated_data['api_key'] == 'test-api-key-123456789'
        assert validated_data['model_type'] == 'openai'
    
    def test_validate_feedback_request_success(self):
        """Testa validação bem-sucedida de requisição de feedback."""
        success, error, validated_data = security_validator.validate_feedback_request(self.valid_feedback_data)
        
        assert success is True
        assert error is None
        assert validated_data is not None
        assert validated_data['user_id'] == 'user123'
        assert validated_data['tipo'] == 'positivo'
    
    def test_validate_generate_request_missing_api_key(self):
        """Testa falha na validação sem API key."""
        invalid_data = self.valid_generate_data.copy()
        del invalid_data['api_key']
        
        success, error, _ = security_validator.validate_generate_request(invalid_data)
        
        assert success is False
        assert error and "Dados inválidos" in error
    
    def test_validate_feedback_request_missing_user_id(self):
        """Testa falha na validação sem user_id."""
        invalid_data = self.valid_feedback_data.copy()
        del invalid_data['user_id']
        
        success, error, _ = security_validator.validate_feedback_request(invalid_data)
        
        assert success is False
        assert error and "Dados inválidos" in error
    
    def test_validate_generate_request_invalid_model_type(self):
        """Testa falha na validação com tipo de modelo inválido."""
        invalid_data = self.valid_generate_data.copy()
        invalid_data['model_type'] = 'invalid-model'
        
        success, error, _ = security_validator.validate_generate_request(invalid_data)
        
        assert success is False
        assert error and "modelo não suportado" in error
    
    def test_validate_feedback_request_invalid_type(self):
        """Testa falha na validação com tipo de feedback inválido."""
        invalid_data = self.valid_feedback_data.copy()
        invalid_data['tipo'] = 'invalido'
        
        success, error, _ = security_validator.validate_feedback_request(invalid_data)
        
        assert success is False
        assert error and "tipo de feedback inválido" in error
    
    def test_validate_generate_request_with_instances(self):
        """Testa validação com instâncias JSON válidas."""
        instances = [{
            'api_key': 'instance-api-key-123',
            'modelo': 'openai',
            'prompts': ['Prompt 1', 'Prompt 2']
        }]
        
        data_with_instances = self.valid_generate_data.copy()
        data_with_instances['instancias_json'] = json.dumps(instances)
        
        success, error, validated_data = security_validator.validate_generate_request(data_with_instances)
        
        assert success is True
        assert error is None
        assert validated_data is not None
    
    def test_validate_generate_request_invalid_instances_json(self):
        """Testa falha na validação com JSON de instâncias inválido."""
        data_with_invalid_json = self.valid_generate_data.copy()
        data_with_invalid_json['instancias_json'] = 'invalid-json'
        
        success, error, _ = security_validator.validate_generate_request(data_with_invalid_json)
        
        assert success is False
        assert error and "JSON de instâncias inválido" in error
    
    def test_sanitize_input_removes_control_characters(self):
        """Testa sanitização de caracteres de controle."""
        malicious_input = "test\x00\x01\x02string"
        sanitized = security_validator.sanitize_input(malicious_input)
        
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized
        assert "\x02" not in sanitized
        assert "test" in sanitized
        assert "string" in sanitized
    
    def test_sanitize_input_escapes_html(self):
        """Testa escape de HTML na sanitização."""
        malicious_input = "<script>alert('XSS')</script>"
        sanitized = security_validator.sanitize_input(malicious_input)
        
        assert "<script>" not in sanitized
        assert "&lt;" in sanitized or sanitized != malicious_input
    
    def test_sanitize_input_empty_string(self):
        """Testa sanitização de string vazia."""
        sanitized = security_validator.sanitize_input("")
        assert sanitized == ""
    
    def test_sanitize_input_none_value(self):
        """Testa sanitização de valor None."""
        sanitized = security_validator.sanitize_input(None)
        assert sanitized is None 