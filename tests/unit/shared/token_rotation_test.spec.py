"""
Testes Unitários - Token Rotation System
========================================

Testes para o sistema de rotação automática de tokens.
Baseados exclusivamente no código real implementado.

Prompt: Testes para rotação automática de tokens
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:00:00Z
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import os
import sys

# Adiciona o diretório raiz ao path para importar módulos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared.token_rotation import (
    TokenRotationService,
    init_token_rotation,
    stop_token_rotation,
    ROTATION_INTERVAL_DAYS,
    FORCE_EXPIRATION_DAYS
)

class TestTokenRotationService:
    """Testes para o serviço de rotação de tokens."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.service = TokenRotationService()
        self.mock_session = Mock()
        self.service.session_factory = Mock(return_value=self.mock_session)
    
    def test_token_rotation_service_initialization(self):
        """Testa inicialização do serviço de rotação."""
        # Arrange & Act
        service = TokenRotationService()
        
        # Assert
        assert service.scheduler is not None
        assert service.session_factory is not None
    
    def test_rotate_expired_tokens_with_expired_tokens(self):
        """Testa rotação de tokens expirados."""
        # Arrange
        mock_token = Mock()
        mock_token.user_id = "user123"
        mock_token.token = "expired_token_123"
        mock_token.expires_at = datetime.utcnow() - timedelta(days=1)
        mock_token.active = True
        
        self.mock_session.query.return_value.filter.return_value.all.return_value = [mock_token]
        
        with patch.object(self.service, '_create_new_token', return_value="new_token_456"):
            # Act
            self.service.rotate_expired_tokens()
            
            # Assert
            assert mock_token.active == False
            self.mock_session.commit.assert_called_once()
            self.mock_session.close.assert_called_once()
    
    def test_rotate_expired_tokens_with_no_expired_tokens(self):
        """Testa rotação quando não há tokens expirados."""
        # Arrange
        self.mock_session.query.return_value.filter.return_value.all.return_value = []
        
        # Act
        self.service.rotate_expired_tokens()
        
        # Assert
        self.mock_session.commit.assert_called_once()
        self.mock_session.close.assert_called_once()
    
    def test_force_expire_old_tokens(self):
        """Testa expiração forçada de tokens antigos."""
        # Arrange
        mock_token = Mock()
        mock_token.user_id = "user123"
        mock_token.token = "old_token_123"
        mock_token.expires_at = datetime.utcnow() - timedelta(days=FORCE_EXPIRATION_DAYS + 1)
        mock_token.active = True
        
        self.mock_session.query.return_value.filter.return_value.all.return_value = [mock_token]
        
        # Act
        self.service.force_expire_old_tokens()
        
        # Assert
        assert mock_token.active == False
        self.mock_session.commit.assert_called_once()
        self.mock_session.close.assert_called_once()
    
    def test_create_new_token(self):
        """Testa criação de novo token."""
        # Arrange
        user_id = "user123"
        
        # Act
        with patch('secrets.token_urlsafe', return_value="new_secret_token"):
            with patch('shared.token_rotation.datetime') as mock_datetime:
                mock_datetime.utcnow.return_value = datetime(2025, 1, 27, 10, 0, 0)
                new_token = self.service._create_new_token(user_id)
        
        # Assert
        assert new_token == "new_secret_token"
        self.mock_session.add.assert_called_once()
        self.mock_session.commit.assert_called_once()
        self.mock_session.close.assert_called_once()
    
    def test_get_rotation_stats(self):
        """Testa obtenção de estatísticas de rotação."""
        # Arrange
        self.mock_session.query.return_value.filter.return_value.count.side_effect = [5, 2, 1]
        
        with patch('shared.token_rotation.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2025, 1, 27, 10, 0, 0)
            
            # Act
            stats = self.service.get_rotation_stats()
            
            # Assert
            assert stats["active_tokens"] == 5
            assert stats["expired_tokens"] == 2
            assert stats["old_tokens"] == 1
            assert stats["rotation_interval_days"] == ROTATION_INTERVAL_DAYS
            assert stats["force_expiration_days"] == FORCE_EXPIRATION_DAYS
            assert "last_check" in stats
            self.mock_session.close.assert_called_once()
    
    def test_get_rotation_stats_with_error(self):
        """Testa obtenção de estatísticas com erro."""
        # Arrange
        self.mock_session.query.side_effect = Exception("Database error")
        
        # Act
        stats = self.service.get_rotation_stats()
        
        # Assert
        assert "error" in stats
        assert "Database error" in stats["error"]

class TestTokenRotationIntegration:
    """Testes de integração para o sistema de rotação."""
    
    def test_init_token_rotation(self):
        """Testa inicialização do sistema de rotação."""
        # Arrange
        mock_service = Mock()
        
        with patch('shared.token_rotation.token_rotation_service', mock_service):
            # Act
            init_token_rotation()
            
            # Assert
            mock_service.start_scheduler.assert_called_once()
            mock_service.get_rotation_stats.assert_called_once()
    
    def test_stop_token_rotation(self):
        """Testa parada do sistema de rotação."""
        # Arrange
        mock_service = Mock()
        
        with patch('shared.token_rotation.token_rotation_service', mock_service):
            # Act
            stop_token_rotation()
            
            # Assert
            mock_service.stop_scheduler.assert_called_once()

class TestTokenRotationConfiguration:
    """Testes para configurações do sistema de rotação."""
    
    def test_rotation_interval_configuration(self):
        """Testa configuração do intervalo de rotação."""
        # Assert
        assert ROTATION_INTERVAL_DAYS == 7  # Valor padrão
        assert FORCE_EXPIRATION_DAYS == 30  # Valor padrão
    
    def test_rotation_scheduler_configuration(self):
        """Testa configuração do agendador."""
        # Arrange
        service = TokenRotationService()
        
        # Act & Assert
        assert service.scheduler is not None
        assert hasattr(service, 'start_scheduler')
        assert hasattr(service, 'stop_scheduler')

class TestTokenRotationErrorHandling:
    """Testes para tratamento de erros."""
    
    def test_rotate_expired_tokens_with_database_error(self):
        """Testa tratamento de erro de banco na rotação."""
        # Arrange
        service = TokenRotationService()
        service.session_factory = Mock(side_effect=Exception("Database connection failed"))
        
        # Act & Assert
        with pytest.raises(Exception):
            service.rotate_expired_tokens()
    
    def test_force_expire_old_tokens_with_database_error(self):
        """Testa tratamento de erro de banco na expiração forçada."""
        # Arrange
        service = TokenRotationService()
        service.session_factory = Mock(side_effect=Exception("Database connection failed"))
        
        # Act & Assert
        with pytest.raises(Exception):
            service.force_expire_old_tokens()
    
    def test_create_new_token_with_database_error(self):
        """Testa tratamento de erro de banco na criação de token."""
        # Arrange
        service = TokenRotationService()
        service.session_factory = Mock(side_effect=Exception("Database connection failed"))
        
        # Act & Assert
        with pytest.raises(Exception):
            service._create_new_token("user123")

class TestTokenRotationLogging:
    """Testes para logging do sistema de rotação."""
    
    def test_rotation_logging_structure(self):
        """Testa estrutura de logging."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("token_rotation")
        
        # Assert
        assert logger.name == "token_rotation"
        assert logger.level == logging.INFO
    
    def test_rotation_logging_handler(self):
        """Testa handler de logging."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("token_rotation")
        
        # Assert
        assert len(logger.handlers) > 0
        assert isinstance(logger.handlers[0], logging.FileHandler)
        assert "token_rotation.log" in logger.handlers[0].baseFilename 