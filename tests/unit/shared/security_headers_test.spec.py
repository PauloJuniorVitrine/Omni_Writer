"""
Testes Unitários - Security Headers System
=========================================

Testes para o sistema de headers de segurança hardenizados.
Baseados exclusivamente no código real implementado.

Prompt: Testes para headers de segurança hardenizados
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:45:00Z
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os
import sys
from datetime import datetime, timedelta

# Adiciona o diretório raiz ao path para importar módulos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared.security_headers import (
    SecurityHeadersManager,
    apply_security_headers,
    get_security_headers,
    validate_security_headers
)

class TestSecurityHeadersManager:
    """Testes para o gerenciador de headers de segurança."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.manager = SecurityHeadersManager()
    
    def test_generate_nonce(self):
        """Testa geração de nonce."""
        # Act
        nonce1 = self.manager.generate_nonce()
        nonce2 = self.manager.generate_nonce()
        
        # Assert
        assert len(nonce1) > 0
        assert len(nonce2) > 0
        assert nonce1 != nonce2  # Nonces devem ser únicos
    
    def test_rotate_nonces(self):
        """Testa rotação de nonces."""
        # Arrange
        self.manager.last_nonce_rotation = datetime.utcnow() - timedelta(hours=2)
        self.manager.nonce_cache['test'] = 'value'
        
        # Act
        self.manager.rotate_nonces()
        
        # Assert
        assert len(self.manager.nonce_cache) == 0
    
    def test_get_csp_policy_with_nonce(self):
        """Testa geração de política CSP com nonce."""
        # Arrange
        nonce = "test_nonce_123"
        
        # Act
        csp_policy = self.manager.get_csp_policy(nonce)
        
        # Assert
        assert "default-src 'self'" in csp_policy
        assert f"script-src 'self' 'nonce-{nonce}'" in csp_policy
        assert "object-src 'none'" in csp_policy
        assert "frame-ancestors 'none'" in csp_policy
    
    def test_get_csp_policy_without_nonce(self):
        """Testa geração de política CSP sem nonce."""
        # Act
        csp_policy = self.manager.get_csp_policy()
        
        # Assert
        assert "default-src 'self'" in csp_policy
        assert "script-src 'self' 'nonce-" in csp_policy
        assert "object-src 'none'" in csp_policy
    
    def test_get_permissions_policy(self):
        """Testa geração de Permissions-Policy."""
        # Act
        permissions_policy = self.manager.get_permissions_policy()
        
        # Assert
        assert "camera=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "geolocation=()" in permissions_policy
        assert "push=()" in permissions_policy
        assert "payment=()" in permissions_policy
    
    def test_get_referrer_policy(self):
        """Testa geração de Referrer-Policy."""
        # Act
        referrer_policy = self.manager.get_referrer_policy()
        
        # Assert
        assert referrer_policy == "strict-origin-when-cross-origin"
    
    def test_get_all_security_headers(self):
        """Testa geração de todos os headers de segurança."""
        # Act
        headers = self.manager.get_all_security_headers()
        
        # Assert
        assert 'X-Content-Type-Options' in headers
        assert 'X-Frame-Options' in headers
        assert 'Strict-Transport-Security' in headers
        assert 'Content-Security-Policy' in headers
        assert 'Permissions-Policy' in headers
        assert 'Referrer-Policy' in headers
        assert 'X-XSS-Protection' in headers
        assert 'X-Download-Options' in headers
        assert 'X-Permitted-Cross-Domain-Policies' in headers
        assert 'Cache-Control' in headers
        assert 'X-DNS-Prefetch-Control' in headers
        assert 'X-Robots-Tag' in headers
    
    def test_get_all_security_headers_with_nonce(self):
        """Testa geração de headers com nonce específico."""
        # Arrange
        nonce = "custom_nonce_456"
        
        # Act
        headers = self.manager.get_all_security_headers(nonce)
        
        # Assert
        assert f"'nonce-{nonce}'" in headers['Content-Security-Policy']
    
    def test_apply_headers_to_response(self):
        """Testa aplicação de headers a uma resposta."""
        # Arrange
        mock_response = Mock()
        mock_response.headers = {}
        
        # Act
        result = self.manager.apply_headers_to_response(mock_response)
        
        # Assert
        assert result == mock_response
        assert len(mock_response.headers) > 0
        assert 'X-Content-Type-Options' in mock_response.headers
        assert 'Content-Security-Policy' in mock_response.headers
    
    def test_get_csp_report_only_policy(self):
        """Testa geração de política CSP report-only."""
        # Act
        csp_policy = self.manager.get_csp_report_only_policy()
        
        # Assert
        assert "default-src 'self'" in csp_policy
        assert "'unsafe-inline'" in csp_policy
        assert "'unsafe-eval'" in csp_policy
        assert "report-uri" in csp_policy
    
    def test_validate_headers_with_valid_headers(self):
        """Testa validação de headers válidos."""
        # Arrange
        valid_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=63072000',
            'Content-Security-Policy': "default-src 'self'",
            'Permissions-Policy': 'camera=()',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        # Act
        result = self.manager.validate_headers(valid_headers)
        
        # Assert
        assert result['valid'] == True
        assert len(result['missing_headers']) == 0
        assert result['total_headers'] == 6
        assert 'validation_timestamp' in result
    
    def test_validate_headers_with_missing_headers(self):
        """Testa validação de headers com headers faltando."""
        # Arrange
        incomplete_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        }
        
        # Act
        result = self.manager.validate_headers(incomplete_headers)
        
        # Assert
        assert result['valid'] == False
        assert len(result['missing_headers']) > 0
        assert 'Strict-Transport-Security' in result['missing_headers']
        assert 'Content-Security-Policy' in result['missing_headers']
        assert 'Permissions-Policy' in result['missing_headers']
        assert 'Referrer-Policy' in result['missing_headers']

class TestSecurityHeadersIntegration:
    """Testes de integração para o sistema de headers de segurança."""
    
    def test_apply_security_headers_function(self):
        """Testa função de conveniência apply_security_headers."""
        # Arrange
        mock_response = Mock()
        mock_response.headers = {}
        
        # Act
        result = apply_security_headers(mock_response)
        
        # Assert
        assert result == mock_response
        assert len(mock_response.headers) > 0
        assert 'X-Content-Type-Options' in mock_response.headers
    
    def test_get_security_headers_function(self):
        """Testa função de conveniência get_security_headers."""
        # Act
        headers = get_security_headers()
        
        # Assert
        assert 'X-Content-Type-Options' in headers
        assert 'Content-Security-Policy' in headers
        assert 'Permissions-Policy' in headers
    
    def test_get_security_headers_with_nonce(self):
        """Testa função get_security_headers com nonce."""
        # Arrange
        nonce = "test_nonce_function"
        
        # Act
        headers = get_security_headers(nonce)
        
        # Assert
        assert f"'nonce-{nonce}'" in headers['Content-Security-Policy']
    
    def test_validate_security_headers_function(self):
        """Testa função de conveniência validate_security_headers."""
        # Arrange
        valid_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=63072000',
            'Content-Security-Policy': "default-src 'self'",
            'Permissions-Policy': 'camera=()',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        # Act
        result = validate_security_headers(valid_headers)
        
        # Assert
        assert result['valid'] == True
        assert len(result['missing_headers']) == 0

class TestSecurityHeadersConfiguration:
    """Testes para configurações do sistema de headers de segurança."""
    
    def test_csp_directives_structure(self):
        """Testa estrutura das diretivas CSP."""
        # Arrange
        manager = SecurityHeadersManager()
        nonce = "test_nonce"
        
        # Act
        csp_policy = manager.get_csp_policy(nonce)
        
        # Assert
        # Verifica se todas as diretivas importantes estão presentes
        required_directives = [
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'font-src',
            'connect-src',
            'object-src',
            'frame-src',
            'frame-ancestors',
            'base-uri',
            'form-action'
        ]
        
        for directive in required_directives:
            assert directive in csp_policy
    
    def test_permissions_policy_structure(self):
        """Testa estrutura da política de permissões."""
        # Arrange
        manager = SecurityHeadersManager()
        
        # Act
        permissions_policy = manager.get_permissions_policy()
        
        # Assert
        # Verifica se todas as permissões importantes estão presentes
        required_permissions = [
            'camera',
            'microphone',
            'geolocation',
            'push',
            'payment',
            'fullscreen',
            'usb'
        ]
        
        for permission in required_permissions:
            assert f"{permission}=" in permissions_policy
    
    def test_header_values(self):
        """Testa valores específicos dos headers."""
        # Arrange
        manager = SecurityHeadersManager()
        
        # Act
        headers = manager.get_all_security_headers()
        
        # Assert
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert headers['X-Frame-Options'] == 'DENY'
        assert headers['X-XSS-Protection'] == '1; mode=block'
        assert 'max-age=63072000' in headers['Strict-Transport-Security']
        assert headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        assert headers['X-Download-Options'] == 'noopen'
        assert headers['X-Permitted-Cross-Domain-Policies'] == 'none'
        assert 'no-store' in headers['Cache-Control']
        assert headers['X-DNS-Prefetch-Control'] == 'off'
        assert 'noindex' in headers['X-Robots-Tag']

class TestSecurityHeadersErrorHandling:
    """Testes para tratamento de erros."""
    
    def test_apply_headers_with_invalid_response(self):
        """Testa aplicação de headers com resposta inválida."""
        # Arrange
        invalid_response = None
        
        # Act & Assert
        with pytest.raises(AttributeError):
            apply_security_headers(invalid_response)
    
    def test_validate_headers_with_empty_dict(self):
        """Testa validação de headers vazio."""
        # Arrange
        empty_headers = {}
        
        # Act
        result = validate_security_headers(empty_headers)
        
        # Assert
        assert result['valid'] == False
        assert len(result['missing_headers']) > 0
        assert result['total_headers'] == 0
    
    def test_validate_headers_with_none(self):
        """Testa validação de headers None."""
        # Arrange
        none_headers = None
        
        # Act & Assert
        with pytest.raises(TypeError):
            validate_security_headers(none_headers)

class TestSecurityHeadersLogging:
    """Testes para logging do sistema de headers de segurança."""
    
    def test_security_headers_logger_configuration(self):
        """Testa configuração do logger de headers de segurança."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("security_headers")
        
        # Assert
        assert logger.name == "security_headers"
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0
    
    def test_security_headers_logger_handler(self):
        """Testa handler do logger de headers de segurança."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("security_headers")
        
        # Assert
        assert len(logger.handlers) > 0
        assert isinstance(logger.handlers[0], logging.FileHandler)
        assert "security_headers.log" in logger.handlers[0].baseFilename

class TestSecurityHeadersNonceManagement:
    """Testes para gerenciamento de nonces."""
    
    def test_nonce_uniqueness(self):
        """Testa unicidade dos nonces gerados."""
        # Arrange
        manager = SecurityHeadersManager()
        nonces = set()
        
        # Act
        for _ in range(100):
            nonce = manager.generate_nonce()
            nonces.add(nonce)
        
        # Assert
        assert len(nonces) == 100  # Todos os nonces devem ser únicos
    
    def test_nonce_format(self):
        """Testa formato dos nonces gerados."""
        # Arrange
        manager = SecurityHeadersManager()
        
        # Act
        nonce = manager.generate_nonce()
        
        # Assert
        assert len(nonce) >= 16  # Nonce deve ter pelo menos 16 caracteres
        assert nonce.isalnum() or '-' in nonce or '_' in nonce  # Formato URL-safe
    
    def test_nonce_in_csp(self):
        """Testa inclusão de nonce na política CSP."""
        # Arrange
        manager = SecurityHeadersManager()
        nonce = "test_nonce_csp"
        
        # Act
        csp_policy = manager.get_csp_policy(nonce)
        
        # Assert
        assert f"'nonce-{nonce}'" in csp_policy
        assert "script-src" in csp_policy
        assert "style-src" in csp_policy 