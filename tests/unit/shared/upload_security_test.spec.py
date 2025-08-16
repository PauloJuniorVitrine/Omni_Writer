"""
Testes Unitários - Upload Security System
========================================

Testes para o sistema de proteção contra uploads maliciosos.
Baseados exclusivamente no código real implementado.

Prompt: Testes para proteção contra uploads maliciosos
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:30:00Z
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os
import tempfile
from io import BytesIO
from werkzeug.datastructures import FileStorage

# Adiciona o diretório raiz ao path para importar módulos
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared.upload_security import (
    UploadSecurityValidator,
    validate_upload,
    get_upload_stats,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    MAX_LINES_PER_FILE,
    MAX_CHARS_PER_LINE
)

class TestUploadSecurityValidator:
    """Testes para o validador de segurança de uploads."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.validator = UploadSecurityValidator()
        self.client_ip = "192.168.1.100"
    
    def test_validate_basic_file_with_valid_file(self):
        """Testa validação básica com arquivo válido."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.txt"
        
        # Act
        is_valid, error = self.validator._validate_basic_file(mock_file)
        
        # Assert
        assert is_valid == True
        assert error == ""
    
    def test_validate_basic_file_with_no_file(self):
        """Testa validação básica sem arquivo."""
        # Arrange
        mock_file = None
        
        # Act
        is_valid, error = self.validator._validate_basic_file(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Arquivo não fornecido" in error
    
    def test_validate_basic_file_with_empty_filename(self):
        """Testa validação básica com nome vazio."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = ""
        
        # Act
        is_valid, error = self.validator._validate_basic_file(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Nome do arquivo vazio" in error
    
    def test_validate_file_extension_with_valid_extension(self):
        """Testa validação de extensão válida."""
        # Arrange
        filename = "test.txt"
        
        # Act
        is_valid, error = self.validator._validate_file_extension(filename)
        
        # Assert
        assert is_valid == True
        assert error == ""
    
    def test_validate_file_extension_with_invalid_extension(self):
        """Testa validação de extensão inválida."""
        # Arrange
        filename = "test.exe"
        
        # Act
        is_valid, error = self.validator._validate_file_extension(filename)
        
        # Assert
        assert is_valid == False
        assert "Extensão não permitida" in error
    
    def test_validate_file_extension_with_no_filename(self):
        """Testa validação de extensão sem nome."""
        # Arrange
        filename = None
        
        # Act
        is_valid, error = self.validator._validate_file_extension(filename)
        
        # Assert
        assert is_valid == False
        assert "Nome do arquivo não fornecido" in error
    
    def test_validate_file_size_with_valid_size(self):
        """Testa validação de tamanho válido."""
        # Arrange
        mock_file = Mock()
        mock_file.content_length = 1024  # 1KB
        
        # Act
        is_valid, error = self.validator._validate_file_size(mock_file)
        
        # Assert
        assert is_valid == True
        assert error == ""
    
    def test_validate_file_size_with_too_large(self):
        """Testa validação de tamanho muito grande."""
        # Arrange
        mock_file = Mock()
        mock_file.content_length = MAX_FILE_SIZE + 1024
        
        # Act
        is_valid, error = self.validator._validate_file_size(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Arquivo muito grande" in error
    
    def test_validate_file_size_with_no_file(self):
        """Testa validação de tamanho sem arquivo."""
        # Arrange
        mock_file = None
        
        # Act
        is_valid, error = self.validator._validate_file_size(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Arquivo não fornecido" in error
    
    def test_validate_file_content_with_valid_content(self):
        """Testa validação de conteúdo válido."""
        # Arrange
        mock_file = Mock()
        mock_file.read.return_value = b"Linha 1\nLinha 2\nLinha 3"
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == True
        assert error == ""
        assert content == "Linha 1\nLinha 2\nLinha 3"
    
    def test_validate_file_content_with_empty_content(self):
        """Testa validação de conteúdo vazio."""
        # Arrange
        mock_file = Mock()
        mock_file.read.return_value = b""
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Arquivo vazio" in error
    
    def test_validate_file_content_with_too_many_lines(self):
        """Testa validação de conteúdo com muitas linhas."""
        # Arrange
        mock_file = Mock()
        # Cria conteúdo com mais linhas que o permitido
        content = "\n".join([f"Linha {i}" for i in range(MAX_LINES_PER_FILE + 10)])
        mock_file.read.return_value = content.encode('utf-8')
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Arquivo com muitas linhas" in error
    
    def test_validate_file_content_with_too_long_line(self):
        """Testa validação de conteúdo com linha muito longa."""
        # Arrange
        mock_file = Mock()
        long_line = "a" * (MAX_CHARS_PER_LINE + 10)
        content = f"Linha normal\n{long_line}\nOutra linha"
        mock_file.read.return_value = content.encode('utf-8')
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Linha 2 muito longa" in error
    
    def test_validate_file_content_with_malicious_content(self):
        """Testa validação de conteúdo malicioso."""
        # Arrange
        mock_file = Mock()
        malicious_content = "Texto normal <script>alert('xss')</script> mais texto"
        mock_file.read.return_value = malicious_content.encode('utf-8')
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Conteúdo malicioso detectado" in error
    
    def test_detect_malicious_content_with_script_tag(self):
        """Testa detecção de tag script maliciosa."""
        # Arrange
        content = "Texto normal <script>alert('xss')</script> mais texto"
        
        # Act
        result = self.validator._detect_malicious_content(content)
        
        # Assert
        assert result is not None
        assert "Padrão malicioso detectado" in result
    
    def test_detect_malicious_content_with_javascript_protocol(self):
        """Testa detecção de protocolo javascript malicioso."""
        # Arrange
        content = "Texto normal javascript:alert('xss') mais texto"
        
        # Act
        result = self.validator._detect_malicious_content(content)
        
        # Assert
        assert result is not None
        assert "Padrão malicioso detectado" in result
    
    def test_detect_malicious_content_with_safe_content(self):
        """Testa detecção com conteúdo seguro."""
        # Arrange
        content = "Texto normal sem conteúdo malicioso"
        
        # Act
        result = self.validator._detect_malicious_content(content)
        
        # Assert
        assert result is None
    
    def test_sanitize_content_with_html_tags(self):
        """Testa sanitização de tags HTML."""
        # Arrange
        content = "Texto <b>negrito</b> e <script>malicioso</script>"
        
        # Act
        sanitized = self.validator._sanitize_content(content)
        
        # Assert
        assert "<b>" not in sanitized
        assert "<script>" not in sanitized
        assert "negrito" in sanitized
        assert "malicioso" in sanitized
    
    def test_sanitize_content_with_control_characters(self):
        """Testa sanitização de caracteres de controle."""
        # Arrange
        content = "Texto\x00normal\x01com\x02caracteres\x03de\x04controle"
        
        # Act
        sanitized = self.validator._sanitize_content(content)
        
        # Assert
        assert "\x00" not in sanitized
        assert "\x01" not in sanitized
        assert "\x02" not in sanitized
        assert "\x03" not in sanitized
        assert "\x04" not in sanitized
        assert "Texto" in sanitized
        assert "normal" in sanitized
    
    def test_generate_metadata(self):
        """Testa geração de metadados."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.txt"
        original_content = "Linha 1\nLinha 2\nLinha 3"
        sanitized_content = "Linha 1\nLinha 2\nLinha 3"
        
        # Act
        metadata = self.validator._generate_metadata(mock_file, original_content, sanitized_content, self.client_ip)
        
        # Assert
        assert metadata['filename'] == "test.txt"
        assert metadata['original_filename'] == "test.txt"
        assert metadata['file_size'] == len(original_content)
        assert metadata['line_count'] == 3
        assert 'content_hash' in metadata
        assert 'sanitized_hash' in metadata
        assert metadata['client_ip'] == self.client_ip
        assert 'upload_timestamp' in metadata
        assert metadata['was_sanitized'] == False

class TestUploadSecurityIntegration:
    """Testes de integração para o sistema de segurança de uploads."""
    
    def test_validate_upload_with_valid_file(self):
        """Testa validação completa com arquivo válido."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.txt"
        mock_file.content_length = 1024
        mock_file.read.return_value = b"Linha 1\nLinha 2\nLinha 3"
        mock_file.seek = Mock()
        
        with patch('shared.upload_security.magic') as mock_magic:
            mock_magic.from_buffer.return_value = "text/plain"
            
            # Act
            is_valid, error, metadata = validate_upload(mock_file, "192.168.1.100")
            
            # Assert
            assert is_valid == True
            assert error == ""
            assert metadata['filename'] == "test.txt"
            assert metadata['line_count'] == 3
    
    def test_validate_upload_with_malicious_file(self):
        """Testa validação completa com arquivo malicioso."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.txt"
        mock_file.content_length = 1024
        mock_file.read.return_value = b"Texto <script>alert('xss')</script>"
        mock_file.seek = Mock()
        
        with patch('shared.upload_security.magic') as mock_magic:
            mock_magic.from_buffer.return_value = "text/plain"
            
            # Act
            is_valid, error, metadata = validate_upload(mock_file, "192.168.1.100")
            
            # Assert
            assert is_valid == False
            assert "Conteúdo malicioso detectado" in error
    
    def test_validate_upload_with_invalid_extension(self):
        """Testa validação completa com extensão inválida."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.exe"
        mock_file.content_length = 1024
        
        # Act
        is_valid, error, metadata = validate_upload(mock_file, "192.168.1.100")
        
        # Assert
        assert is_valid == False
        assert "Extensão não permitida" in error
    
    def test_validate_upload_with_too_large_file(self):
        """Testa validação completa com arquivo muito grande."""
        # Arrange
        mock_file = Mock()
        mock_file.filename = "test.txt"
        mock_file.content_length = MAX_FILE_SIZE + 1024
        
        # Act
        is_valid, error, metadata = validate_upload(mock_file, "192.168.1.100")
        
        # Assert
        assert is_valid == False
        assert "Arquivo muito grande" in error

class TestUploadSecurityConfiguration:
    """Testes para configurações do sistema de segurança de uploads."""
    
    def test_allowed_extensions_configuration(self):
        """Testa configuração de extensões permitidas."""
        # Assert
        assert '.txt' in ALLOWED_EXTENSIONS
        assert '.csv' in ALLOWED_EXTENSIONS
        assert '.exe' not in ALLOWED_EXTENSIONS
        assert '.js' not in ALLOWED_EXTENSIONS
    
    def test_file_size_limits_configuration(self):
        """Testa configuração de limites de tamanho."""
        # Assert
        assert MAX_FILE_SIZE == 1024 * 1024  # 1MB
        assert MAX_LINES_PER_FILE == 1000
        assert MAX_CHARS_PER_LINE == 500
    
    def test_get_upload_stats(self):
        """Testa obtenção de estatísticas de upload."""
        # Act
        stats = get_upload_stats()
        
        # Assert
        assert stats['max_file_size'] == MAX_FILE_SIZE
        assert '.txt' in stats['allowed_extensions']
        assert '.csv' in stats['allowed_extensions']
        assert stats['max_lines_per_file'] == MAX_LINES_PER_FILE
        assert stats['max_chars_per_line'] == MAX_CHARS_PER_LINE
        assert 'malicious_patterns_count' in stats

class TestUploadSecurityErrorHandling:
    """Testes para tratamento de erros."""
    
    def test_validate_file_content_with_unicode_error(self):
        """Testa tratamento de erro de codificação Unicode."""
        # Arrange
        mock_file = Mock()
        mock_file.read.side_effect = UnicodeDecodeError('utf-8', b'\xff\xfe', 0, 1, 'invalid utf-8')
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "não é texto UTF-8 válido" in error
    
    def test_validate_file_content_with_read_error(self):
        """Testa tratamento de erro de leitura."""
        # Arrange
        mock_file = Mock()
        mock_file.read.side_effect = Exception("Erro de leitura")
        mock_file.seek = Mock()
        
        # Act
        content, is_valid, error = self.validator._validate_file_content(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Erro ao ler conteúdo" in error
    
    def test_validate_file_size_with_read_error(self):
        """Testa tratamento de erro de leitura no tamanho."""
        # Arrange
        mock_file = Mock()
        mock_file.seek.side_effect = Exception("Erro de leitura")
        
        # Act
        is_valid, error = self.validator._validate_file_size(mock_file)
        
        # Assert
        assert is_valid == False
        assert "Erro ao verificar tamanho" in error

class TestUploadSecurityLogging:
    """Testes para logging do sistema de segurança de uploads."""
    
    def test_upload_security_logger_configuration(self):
        """Testa configuração do logger de segurança de uploads."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("upload_security")
        
        # Assert
        assert logger.name == "upload_security"
        assert logger.level == logging.INFO
        assert len(logger.handlers) > 0
    
    def test_upload_security_logger_handler(self):
        """Testa handler do logger de segurança de uploads."""
        # Arrange
        import logging
        
        # Act
        logger = logging.getLogger("upload_security")
        
        # Assert
        assert len(logger.handlers) > 0
        assert isinstance(logger.handlers[0], logging.FileHandler)
        assert "upload_security.log" in logger.handlers[0].baseFilename 