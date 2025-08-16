"""
Testes de segurança para prevenção de path traversal.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:15:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

import pytest
from app.validators.input_validators import security_validator


class TestPathTraversalPrevention:
    """Testes para prevenir path traversal em entradas de usuário."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.sample_generate_data = {
            'api_key': 'test-api-key-123456789',
            'model_type': 'openai',
            'prompt_0': 'Como criar um blog profissional',
            'instancias_json': None
        }
    
    def test_path_traversal_in_api_key(self):
        """Testa prevenção de path traversal na API key."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['api_key'] = "../../../etc/passwd"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert error and ("caracteres inválidos" in error or "padrão suspeito" in error)
    
    def test_path_traversal_in_prompt(self):
        """Testa prevenção de path traversal nos prompts."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['prompt_0'] = "../../../config/database.yml"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert error and "conteúdo suspeito" in error
    
    def test_absolute_path_in_api_key(self):
        """Testa prevenção de caminhos absolutos na API key."""
        malicious_data = self.sample_generate_data.copy()
        malicious_data['api_key'] = "/etc/passwd"
        
        success, error, _ = security_validator.validate_generate_request(malicious_data)
        
        assert success is False
        assert error and ("caracteres inválidos" in error or "padrão suspeito" in error)
    
    def test_legitimate_data_passes_validation(self):
        """Testa que dados legítimos passam na validação."""
        success, error, validated_data = security_validator.validate_generate_request(self.sample_generate_data)
        
        assert success is True
        assert error is None
        assert validated_data is not None 