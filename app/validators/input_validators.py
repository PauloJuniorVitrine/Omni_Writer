"""
Sistema de validação de entrada robusto para prevenção de ataques de segurança.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:00:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from pydantic import BaseModel, Field, validator, ValidationError
from pydantic.types import constr
import html
from urllib.parse import unquote
from shared.messages import get_message

logger = logging.getLogger(__name__)


class SecurityValidationError(Exception):
    """Exceção customizada para erros de validação de segurança."""
    
    def __init__(self, message: str, error_code: str, details: Optional[Dict] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class GenerateRequestValidator(BaseModel):
    """
    Validador Pydantic para requisições de geração de artigos.
    Implementa validação rigorosa para prevenir ataques.
    """
    
    api_key: constr(min_length=8, max_length=100) = Field(
        ..., description="API key do usuário"
    )
    model_type: str = Field(..., description="Tipo do modelo")
    instancias_json: Optional[str] = Field(None, description="JSON de instâncias")
    
    # Campos de prompt (máximo 10)
    prompt_0: Optional[str] = Field(None, max_length=2000)
    prompt_1: Optional[str] = Field(None, max_length=2000)
    prompt_2: Optional[str] = Field(None, max_length=2000)
    prompt_3: Optional[str] = Field(None, max_length=2000)
    prompt_4: Optional[str] = Field(None, max_length=2000)
    prompt_5: Optional[str] = Field(None, max_length=2000)
    prompt_6: Optional[str] = Field(None, max_length=2000)
    prompt_7: Optional[str] = Field(None, max_length=2000)
    prompt_8: Optional[str] = Field(None, max_length=2000)
    prompt_9: Optional[str] = Field(None, max_length=2000)
    
    @validator('api_key')
    def validate_api_key(cls, v):
        """Valida formato e segurança da API key."""
        if not v or not v.strip():
            raise ValueError(get_message('erro_api_key_vazia'))
        
        # Verifica se não contém caracteres suspeitos
        suspicious_patterns = [
            r'<script', r'javascript:', r'vbscript:', r'onload=',
            r'<iframe', r'<object', r'<embed', r'<form',
            r'--', r'/*', r'*/', r'xp_', r'sp_'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                logger.warning(f"API key com padrão suspeito detectado: {pattern}")
                raise SecurityValidationError(
                    "API key contém caracteres inválidos",
                    "INVALID_API_KEY_FORMAT"
                )
        
        return v.strip()
    
    @validator('model_type')
    def validate_model_type(cls, v):
        """Valida tipo do modelo."""
        allowed_models = {'openai', 'deepseek', 'gpt-4', 'gpt-3.5-turbo'}
        
        if not v or v.lower() not in allowed_models:
            raise ValueError(get_message('modelo_nao_suportado', modelo=v))
        
        return v.lower()
    
    @validator('instancias_json')
    def validate_instancias_json(cls, v):
        """Valida JSON de instâncias contra ataques."""
        if not v:
            return v
        
        try:
            # Decodifica URL encoding se necessário
            decoded = unquote(v)
            
            # Valida JSON
            instances = json.loads(decoded)
            
            if not isinstance(instances, list):
                raise ValueError("Instâncias devem ser uma lista")
            
            # Valida cada instância
            for i, instance in enumerate(instances):
                if not isinstance(instance, dict):
                    raise ValueError(f"Instância {i} deve ser um objeto")
                
                # Valida campos obrigatórios
                required_fields = ['api_key', 'modelo', 'prompts']
                for field in required_fields:
                    if field not in instance:
                        raise ValueError(f"Campo obrigatório '{field}' ausente na instância {i}")
                
                # Valida API key da instância
                if not instance['api_key'] or len(instance['api_key']) < 8:
                    raise ValueError(f"API key inválida na instância {i}")
                
                # Valida prompts
                if not isinstance(instance['prompts'], list):
                    raise ValueError(f"Prompts devem ser uma lista na instância {i}")
                
                for j, prompt in enumerate(instance['prompts']):
                    if not isinstance(prompt, str) or len(prompt) > 2000:
                        raise ValueError(f"Prompt {j} inválido na instância {i}")
            
            return v
            
        except json.JSONDecodeError:
            raise SecurityValidationError(
                "JSON de instâncias inválido",
                "INVALID_JSON_FORMAT"
            )
        except Exception as e:
            raise SecurityValidationError(
                f"Erro na validação de instâncias: {str(e)}",
                "INSTANCE_VALIDATION_ERROR"
            )
    
    @validator('prompt_0', 'prompt_1', 'prompt_2', 'prompt_3', 'prompt_4',
               'prompt_5', 'prompt_6', 'prompt_7', 'prompt_8', 'prompt_9')
    def validate_prompt(cls, v):
        """Valida prompts contra ataques XSS e injeção."""
        if not v:
            return v
        
        # Sanitização básica
        sanitized = html.escape(v.strip())
        
        # Verifica padrões suspeitos
        suspicious_patterns = [
            r'<script[^>]*>', r'javascript:', r'vbscript:', r'onload=',
            r'<iframe[^>]*>', r'<object[^>]*>', r'<embed[^>]*>',
            r'<form[^>]*>', r'<input[^>]*>', r'<textarea[^>]*>',
            r'--', r'/*', r'*/', r'xp_', r'sp_', r'exec\s*\(', r'eval\s*\(',
            r'<.*?>', r'&[a-zA-Z]+;', r'&#[0-9]+;'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                logger.warning(f"Prompt com padrão suspeito detectado: {pattern}")
                raise SecurityValidationError(
                    "Prompt contém conteúdo suspeito",
                    "SUSPICIOUS_PROMPT_CONTENT"
                )
        
        # Verifica tamanho
        if len(v) > 2000:
            raise SecurityValidationError(
                "Prompt muito longo (máximo 2000 caracteres)",
                "PROMPT_TOO_LONG"
            )
        
        return sanitized


class FeedbackRequestValidator(BaseModel):
    """
    Validador Pydantic para requisições de feedback.
    """
    
    user_id: constr(min_length=3, max_length=64) = Field(..., description="ID do usuário")
    artigo_id: constr(min_length=3, max_length=64) = Field(..., description="ID do artigo")
    tipo: str = Field(..., description="Tipo de feedback")
    comentario: constr(min_length=3, max_length=1024) = Field(..., description="Comentário")
    
    @validator('user_id', 'artigo_id')
    def validate_id_fields(cls, v):
        """Valida campos de ID."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise SecurityValidationError(
                "ID contém caracteres inválidos",
                "INVALID_ID_FORMAT"
            )
        return v
    
    @validator('tipo')
    def validate_tipo(cls, v):
        """Valida tipo de feedback."""
        tipos_permitidos = {'positivo', 'negativo', 'neutro'}
        
        if v.lower() not in tipos_permitidos:
            raise SecurityValidationError(
                "Tipo de feedback inválido",
                "INVALID_FEEDBACK_TYPE"
            )
        
        return v.lower()
    
    @validator('comentario')
    def validate_comentario(cls, v):
        """Valida comentário contra ataques."""
        # Sanitização
        sanitized = html.escape(v.strip())
        
        # Verifica padrões suspeitos
        suspicious_patterns = [
            r'<script[^>]*>', r'javascript:', r'vbscript:', r'onload=',
            r'<iframe[^>]*>', r'<object[^>]*>', r'<embed[^>]*>',
            r'--', r'/*', r'*/', r'xp_', r'sp_', r'exec\s*\(', r'eval\s*\('
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                logger.warning(f"Comentário com padrão suspeito detectado: {pattern}")
                raise SecurityValidationError(
                    "Comentário contém conteúdo suspeito",
                    "SUSPICIOUS_COMMENT_CONTENT"
                )
        
        return sanitized


class SecurityValidator:
    """
    Classe principal para validação de segurança.
    Implementa validação em camadas para máxima proteção.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def validate_generate_request(self, request_data: Dict) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Valida requisição de geração de artigos.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            Tuple[bool, Optional[str], Optional[Dict]]: (sucesso, erro, dados_validados)
        """
        try:
            # Validação Pydantic
            validated_data = GenerateRequestValidator(**request_data)
            
            # Validação adicional de segurança
            security_check = self._perform_security_checks(request_data)
            if not security_check['valid']:
                return False, security_check['error'], None
            
            return True, None, validated_data.dict()
            
        except ValidationError as e:
            self.logger.warning(f"Erro de validação Pydantic: {e}")
            return False, f"Dados inválidos: {e}", None
            
        except SecurityValidationError as e:
            self.logger.warning(f"Erro de segurança: {e}")
            return False, e.message, None
            
        except Exception as e:
            self.logger.error(f"Erro inesperado na validação: {e}")
            return False, "Erro interno de validação", None
    
    def validate_feedback_request(self, request_data: Dict) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Valida requisição de feedback.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            Tuple[bool, Optional[str], Optional[Dict]]: (sucesso, erro, dados_validados)
        """
        try:
            # Validação Pydantic
            validated_data = FeedbackRequestValidator(**request_data)
            
            return True, None, validated_data.dict()
            
        except ValidationError as e:
            self.logger.warning(f"Erro de validação Pydantic: {e}")
            return False, f"Dados inválidos: {e}", None
            
        except SecurityValidationError as e:
            self.logger.warning(f"Erro de segurança: {e}")
            return False, e.message, None
            
        except Exception as e:
            self.logger.error(f"Erro inesperado na validação: {e}")
            return False, "Erro interno de validação", None
    
    def _perform_security_checks(self, request_data: Dict) -> Dict:
        """
        Realiza verificações adicionais de segurança.
        
        Args:
            request_data: Dados da requisição
            
        Returns:
            Dict: Resultado das verificações
        """
        try:
            # Verifica rate limiting (implementado no middleware)
            
            # Verifica tamanho total da requisição
            total_size = len(str(request_data))
            if total_size > 10000:  # 10KB limite
                return {
                    'valid': False,
                    'error': 'Requisição muito grande'
                }
            
            # Verifica profundidade de JSON
            if 'instancias_json' in request_data and request_data['instancias_json']:
                try:
                    instances = json.loads(request_data['instancias_json'])
                    if len(instances) > 50:  # Máximo 50 instâncias
                        return {
                            'valid': False,
                            'error': 'Muitas instâncias (máximo 50)'
                        }
                except:
                    pass
            
            # Verifica número de prompts
            prompt_count = 0
            for i in range(10):
                if f'prompt_{i}' in request_data and request_data[f'prompt_{i}']:
                    prompt_count += 1
            
            if prompt_count > 10:
                return {
                    'valid': False,
                    'error': 'Muitos prompts (máximo 10)'
                }
            
            return {'valid': True}
            
        except Exception as e:
            self.logger.error(f"Erro nas verificações de segurança: {e}")
            return {
                'valid': False,
                'error': 'Erro nas verificações de segurança'
            }
    
    def sanitize_input(self, input_data: str) -> str:
        """
        Sanitiza entrada de dados.
        
        Args:
            input_data: Dados de entrada
            
        Returns:
            str: Dados sanitizados
        """
        if not input_data:
            return input_data
        
        # Remove caracteres de controle
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_data)
        
        # Escape HTML
        sanitized = html.escape(sanitized)
        
        # Remove scripts
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized.strip()


# Instância global do validador
security_validator = SecurityValidator() 