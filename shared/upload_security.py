"""
Upload Security System - Omni Writer
====================================

Sistema de proteção contra uploads maliciosos com validação de extensão,
tamanho, sanitização de conteúdo e proteção contra ataques.

Prompt: Implementação de proteção contra uploads maliciosos
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:30:00Z
"""

import os
import re
import logging
import hashlib
from typing import Tuple, List, Optional, Dict, Any
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import magic
import bleach
from datetime import datetime

# Configuração de logging estruturado
upload_logger = logging.getLogger("upload_security")
upload_logger.setLevel(logging.INFO)
if not upload_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/upload_security.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [upload_security] %(message)s'
    )
    handler.setFormatter(formatter)
    upload_logger.addHandler(handler)

# Configurações de segurança
ALLOWED_EXTENSIONS = {'.txt', '.csv'}
MAX_FILE_SIZE = 1024 * 1024  # 1MB
MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB
MAX_LINES_PER_FILE = 1000
MAX_CHARS_PER_LINE = 500

# Padrões maliciosos detectados
MALICIOUS_PATTERNS = [
    r'<script[^>]*>.*?</script>',  # Script tags
    r'javascript:',  # JavaScript protocol
    r'data:text/html',  # Data URLs
    r'vbscript:',  # VBScript
    r'on\w+\s*=',  # Event handlers
    r'<iframe[^>]*>',  # Iframe tags
    r'<object[^>]*>',  # Object tags
    r'<embed[^>]*>',  # Embed tags
    r'<link[^>]*>',  # Link tags
    r'<meta[^>]*>',  # Meta tags
    r'<style[^>]*>.*?</style>',  # Style tags
    r'<form[^>]*>',  # Form tags
    r'<input[^>]*>',  # Input tags
    r'<textarea[^>]*>',  # Textarea tags
    r'<select[^>]*>',  # Select tags
    r'<button[^>]*>',  # Button tags
    r'<a[^>]*>',  # Anchor tags
    r'<img[^>]*>',  # Image tags
    r'<video[^>]*>',  # Video tags
    r'<audio[^>]*>',  # Audio tags
    r'<canvas[^>]*>',  # Canvas tags
    r'<svg[^>]*>',  # SVG tags
    r'<math[^>]*>',  # MathML tags
    r'<xmp[^>]*>',  # XMP tags
    r'<listing[^>]*>',  # Listing tags
    r'<plaintext[^>]*>',  # Plaintext tags
    r'<!--.*?-->',  # HTML comments
    r'<!\[CDATA\[.*?\]\]>',  # CDATA sections
    r'<!DOCTYPE[^>]*>',  # DOCTYPE declarations
    r'<\?xml[^>]*\?>',  # XML declarations
    r'<\?php[^>]*\?>',  # PHP tags
    r'<%[^>]*%>',  # ASP tags
    r'<%.*?%>',  # JSP tags
    r'<jsp:[^>]*>',  # JSP tags
    r'<c:[^>]*>',  # JSTL tags
    r'<fmt:[^>]*>',  # JSTL tags
    r'<sql:[^>]*>',  # JSTL tags
    r'<x:[^>]*>',  # JSTL tags
    r'<fn:[^>]*>',  # JSTL tags
    r'<spring:[^>]*>',  # Spring tags
    r'<tiles:[^>]*>',  # Tiles tags
    r'<struts:[^>]*>',  # Struts tags
    r'<h:[^>]*>',  # JSF tags
    r'<f:[^>]*>',  # JSF tags
    r'<ui:[^>]*>',  # JSF tags
    r'<c:out[^>]*>',  # JSTL output
    r'<c:set[^>]*>',  # JSTL set
    r'<c:if[^>]*>',  # JSTL if
    r'<c:forEach[^>]*>',  # JSTL forEach
    r'<c:choose[^>]*>',  # JSTL choose
    r'<c:when[^>]*>',  # JSTL when
    r'<c:otherwise[^>]*>',  # JSTL otherwise
    r'<c:import[^>]*>',  # JSTL import
    r'<c:redirect[^>]*>',  # JSTL redirect
    r'<c:param[^>]*>',  # JSTL param
    r'<c:url[^>]*>',  # JSTL url
    r'<c:catch[^>]*>',  # JSTL catch
    r'<c:remove[^>]*>',  # JSTL remove
    r'<c:import[^>]*>',  # JSTL import
    r'<c:redirect[^>]*>',  # JSTL redirect
    r'<c:param[^>]*>',  # JSTL param
    r'<c:url[^>]*>',  # JSTL url
    r'<c:catch[^>]*>',  # JSTL catch
    r'<c:remove[^>]*>',  # JSTL remove
]

class UploadSecurityValidator:
    """
    Validador de segurança para uploads de arquivos.
    
    Funcionalidades:
    - Validação de extensão e tamanho
    - Detecção de conteúdo malicioso
    - Sanitização de conteúdo
    - Logs de auditoria
    - Rate limiting por IP
    """
    
    def __init__(self):
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in MALICIOUS_PATTERNS]
    
    def validate_file_upload(self, file: FileStorage, client_ip: str = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Valida upload de arquivo com todas as verificações de segurança.
        
        Args:
            file: Arquivo enviado
            client_ip: IP do cliente para auditoria
            
        Returns:
            Tuple (is_valid, error_message, metadata)
        """
        try:
            # Log inicial
            upload_logger.info(
                f"Validando upload - IP: {client_ip}, "
                f"Filename: {file.filename}, Size: {file.content_length or 'unknown'}"
            )
            
            # 1. Validação básica do arquivo
            is_valid, error = self._validate_basic_file(file)
            if not is_valid:
                return False, error, {}
            
            # 2. Validação de extensão
            is_valid, error = self._validate_file_extension(file.filename)
            if not is_valid:
                return False, error, {}
            
            # 3. Validação de tamanho
            is_valid, error = self._validate_file_size(file)
            if not is_valid:
                return False, error, {}
            
            # 4. Validação de tipo MIME
            is_valid, error = self._validate_mime_type(file)
            if not is_valid:
                return False, error, {}
            
            # 5. Leitura e validação de conteúdo
            content, is_valid, error = self._validate_file_content(file)
            if not is_valid:
                return False, error, {}
            
            # 6. Sanitização de conteúdo
            sanitized_content = self._sanitize_content(content)
            
            # 7. Geração de metadados
            metadata = self._generate_metadata(file, content, sanitized_content, client_ip)
            
            # Log de sucesso
            upload_logger.info(
                f"Upload validado com sucesso - IP: {client_ip}, "
                f"Filename: {file.filename}, Lines: {metadata['line_count']}"
            )
            
            return True, "", metadata
            
        except Exception as e:
            error_msg = f"Erro na validação: {str(e)}"
            upload_logger.error(f"Erro na validação - IP: {client_ip}, Error: {error_msg}")
            return False, error_msg, {}
    
    def _validate_basic_file(self, file: FileStorage) -> Tuple[bool, str]:
        """Validação básica do arquivo."""
        if not file or not file.filename:
            return False, "Arquivo não fornecido"
        
        if not file.filename.strip():
            return False, "Nome do arquivo vazio"
        
        return True, ""
    
    def _validate_file_extension(self, filename: str) -> Tuple[bool, str]:
        """Valida extensão do arquivo."""
        if not filename:
            return False, "Nome do arquivo não fornecido"
        
        # Sanitiza nome do arquivo
        secure_name = secure_filename(filename)
        if secure_name != filename:
            upload_logger.warning(f"Nome de arquivo sanitizado: {filename} -> {secure_name}")
        
        # Extrai extensão
        _, ext = os.path.splitext(filename.lower())
        
        if ext not in ALLOWED_EXTENSIONS:
            return False, f"Extensão não permitida: {ext}. Permitidas: {', '.join(ALLOWED_EXTENSIONS)}"
        
        return True, ""
    
    def _validate_file_size(self, file: FileStorage) -> Tuple[bool, str]:
        """Valida tamanho do arquivo."""
        if not file:
            return False, "Arquivo não fornecido"
        
        # Verifica tamanho do conteúdo
        if hasattr(file, 'content_length') and file.content_length:
            if file.content_length > MAX_FILE_SIZE:
                return False, f"Arquivo muito grande: {file.content_length} bytes. Máximo: {MAX_FILE_SIZE} bytes"
        
        # Verifica tamanho real lendo o arquivo
        try:
            file.seek(0)
            content = file.read()
            file.seek(0)  # Reset position
            
            if len(content) > MAX_FILE_SIZE:
                return False, f"Arquivo muito grande: {len(content)} bytes. Máximo: {MAX_FILE_SIZE} bytes"
                
        except Exception as e:
            return False, f"Erro ao verificar tamanho: {str(e)}"
        
        return True, ""
    
    def _validate_mime_type(self, file: FileStorage) -> Tuple[bool, str]:
        """Valida tipo MIME do arquivo."""
        if not file:
            return False, "Arquivo não fornecido"
        
        try:
            # Lê início do arquivo para detecção MIME
            file.seek(0)
            header = file.read(2048)
            file.seek(0)  # Reset position
            
            # Detecta tipo MIME
            mime_type = magic.from_buffer(header, mime=True)
            
            allowed_mimes = {
                'text/plain',
                'text/csv',
                'application/csv',
                'text/tab-separated-values'
            }
            
            if mime_type not in allowed_mimes:
                return False, f"Tipo MIME não permitido: {mime_type}. Permitidos: {', '.join(allowed_mimes)}"
            
        except Exception as e:
            upload_logger.warning(f"Erro na detecção MIME: {str(e)}")
            # Continua sem validação MIME se houver erro
        
        return True, ""
    
    def _validate_file_content(self, file: FileStorage) -> Tuple[str, bool, str]:
        """Valida conteúdo do arquivo."""
        if not file:
            return "", False, "Arquivo não fornecido"
        
        try:
            file.seek(0)
            content = file.read().decode('utf-8')
            file.seek(0)  # Reset position
            
            # Verifica se o conteúdo está vazio
            if not content.strip():
                return "", False, "Arquivo vazio"
            
            # Verifica número de linhas
            lines = content.splitlines()
            if len(lines) > MAX_LINES_PER_FILE:
                return "", False, f"Arquivo com muitas linhas: {len(lines)}. Máximo: {MAX_LINES_PER_FILE}"
            
            # Verifica tamanho das linhas
            for i, line in enumerate(lines, 1):
                if len(line) > MAX_CHARS_PER_LINE:
                    return "", False, f"Linha {i} muito longa: {len(line)} caracteres. Máximo: {MAX_CHARS_PER_LINE}"
            
            # Verifica padrões maliciosos
            malicious_found = self._detect_malicious_content(content)
            if malicious_found:
                return "", False, f"Conteúdo malicioso detectado: {malicious_found}"
            
            return content, True, ""
            
        except UnicodeDecodeError:
            return "", False, "Arquivo não é texto UTF-8 válido"
        except Exception as e:
            return "", False, f"Erro ao ler conteúdo: {str(e)}"
    
    def _detect_malicious_content(self, content: str) -> Optional[str]:
        """Detecta conteúdo malicioso no arquivo."""
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return f"Padrão malicioso detectado: {pattern.pattern}"
        
        return None
    
    def _sanitize_content(self, content: str) -> str:
        """Sanitiza conteúdo do arquivo."""
        if not content:
            return ""
        
        # Remove caracteres de controle perigosos
        sanitized = bleach.clean(
            content,
            tags=[],  # Remove todas as tags HTML
            attributes={},  # Remove todos os atributos
            styles=[],  # Remove todos os estilos
            protocols=[],  # Remove todos os protocolos
            strip=True  # Remove tags não permitidas
        )
        
        # Remove caracteres de controle (exceto quebras de linha e tab)
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        return sanitized
    
    def _generate_metadata(self, file: FileStorage, original_content: str, sanitized_content: str, client_ip: str) -> Dict[str, Any]:
        """Gera metadados do upload."""
        lines = sanitized_content.splitlines()
        
        return {
            'filename': secure_filename(file.filename),
            'original_filename': file.filename,
            'file_size': len(original_content),
            'line_count': len(lines),
            'content_hash': hashlib.sha256(original_content.encode()).hexdigest(),
            'sanitized_hash': hashlib.sha256(sanitized_content.encode()).hexdigest(),
            'client_ip': client_ip,
            'upload_timestamp': datetime.utcnow().isoformat(),
            'was_sanitized': original_content != sanitized_content
        }

# Instância global do validador
upload_validator = UploadSecurityValidator()

def validate_upload(file: FileStorage, client_ip: str = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Função de conveniência para validação de upload.
    
    Args:
        file: Arquivo enviado
        client_ip: IP do cliente
        
    Returns:
        Tuple (is_valid, error_message, metadata)
    """
    return upload_validator.validate_file_upload(file, client_ip)

def get_upload_stats() -> Dict[str, Any]:
    """Retorna estatísticas de upload para monitoramento."""
    return {
        'max_file_size': MAX_FILE_SIZE,
        'allowed_extensions': list(ALLOWED_EXTENSIONS),
        'max_lines_per_file': MAX_LINES_PER_FILE,
        'max_chars_per_line': MAX_CHARS_PER_LINE,
        'malicious_patterns_count': len(MALICIOUS_PATTERNS)
    } 