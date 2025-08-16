"""
Schemas Pydantic para validação de requisições.

Prompt: Validação de Segurança - IMP-003
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:05:00Z
Tracing ID: ENTERPRISE_20250127_003
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator
from pydantic.types import constr
from enum import Enum


class ModelType(str, Enum):
    """Tipos de modelo suportados."""
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    GPT4 = "gpt-4"
    GPT35 = "gpt-3.5-turbo"


class FeedbackType(str, Enum):
    """Tipos de feedback suportados."""
    POSITIVO = "positivo"
    NEGATIVO = "negativo"
    NEUTRO = "neutro"


class InstanceSchema(BaseModel):
    """
    Schema para uma instância de geração.
    """
    api_key: constr(min_length=8, max_length=100) = Field(
        ..., description="API key para a instância"
    )
    modelo: str = Field(..., description="Tipo do modelo")
    prompts: List[str] = Field(..., description="Lista de prompts")
    
    @validator('modelo')
    def validate_modelo(cls, v):
        """Valida tipo do modelo."""
        allowed_models = {model.value for model in ModelType}
        if v.lower() not in allowed_models:
            raise ValueError(f"Modelo não suportado: {v}")
        return v.lower()
    
    @validator('prompts')
    def validate_prompts(cls, v):
        """Valida lista de prompts."""
        if not v or len(v) == 0:
            raise ValueError("Lista de prompts não pode estar vazia")
        
        if len(v) > 10:
            raise ValueError("Máximo 10 prompts por instância")
        
        for i, prompt in enumerate(v):
            if not isinstance(prompt, str):
                raise ValueError(f"Prompt {i} deve ser string")
            
            if len(prompt) > 2000:
                raise ValueError(f"Prompt {i} muito longo (máximo 2000 caracteres)")
        
        return v


class GenerateRequestSchema(BaseModel):
    """
    Schema para requisição de geração de artigos.
    """
    api_key: constr(min_length=8, max_length=100) = Field(
        ..., description="API key do usuário"
    )
    model_type: ModelType = Field(..., description="Tipo do modelo")
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
    
    class Config:
        """Configuração do modelo."""
        use_enum_values = True
        extra = "forbid"  # Rejeita campos extras


class FeedbackRequestSchema(BaseModel):
    """
    Schema para requisição de feedback.
    """
    user_id: constr(min_length=3, max_length=64, regex=r'^[a-zA-Z0-9_-]+$') = Field(
        ..., description="ID do usuário"
    )
    artigo_id: constr(min_length=3, max_length=64, regex=r'^[a-zA-Z0-9_-]+$') = Field(
        ..., description="ID do artigo"
    )
    tipo: FeedbackType = Field(..., description="Tipo de feedback")
    comentario: constr(min_length=3, max_length=1024) = Field(
        ..., description="Comentário do feedback"
    )
    
    class Config:
        """Configuração do modelo."""
        use_enum_values = True
        extra = "forbid"


class WebhookRequestSchema(BaseModel):
    """
    Schema para requisição de webhook.
    """
    url: constr(min_length=10, max_length=500) = Field(
        ..., description="URL do webhook"
    )
    
    @validator('url')
    def validate_url(cls, v):
        """Valida formato da URL."""
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL deve começar com http:// ou https://")
        return v


class TokenRotateRequestSchema(BaseModel):
    """
    Schema para requisição de rotação de token.
    """
    user_id: constr(min_length=3, max_length=64, regex=r'^[a-zA-Z0-9_-]+$') = Field(
        ..., description="ID do usuário"
    )


class ErrorResponseSchema(BaseModel):
    """
    Schema para respostas de erro padronizadas.
    """
    error: str = Field(..., description="Mensagem de erro")
    code: Optional[str] = Field(None, description="Código de erro")
    details: Optional[Dict[str, Any]] = Field(None, description="Detalhes do erro")
    trace_id: Optional[str] = Field(None, description="ID de rastreamento")


class SuccessResponseSchema(BaseModel):
    """
    Schema para respostas de sucesso padronizadas.
    """
    status: str = Field(..., description="Status da operação")
    message: Optional[str] = Field(None, description="Mensagem de sucesso")
    data: Optional[Dict[str, Any]] = Field(None, description="Dados da resposta")
    trace_id: Optional[str] = Field(None, description="ID de rastreamento")


class ValidationErrorSchema(BaseModel):
    """
    Schema para erros de validação Pydantic.
    """
    field: str = Field(..., description="Campo com erro")
    message: str = Field(..., description="Mensagem de erro")
    value: Optional[Any] = Field(None, description="Valor inválido")


class SecurityHeadersSchema(BaseModel):
    """
    Schema para headers de segurança.
    """
    x_content_type_options: str = Field(default="nosniff", description="X-Content-Type-Options")
    x_frame_options: str = Field(default="DENY", description="X-Frame-Options")
    strict_transport_security: str = Field(
        default="max-age=63072000; includeSubDomains; preload",
        description="Strict-Transport-Security"
    )
    content_security_policy: str = Field(
        default="default-src 'self'",
        description="Content-Security-Policy"
    )
    x_xss_protection: str = Field(default="1; mode=block", description="X-XSS-Protection")
    referrer_policy: str = Field(default="strict-origin-when-cross-origin", description="Referrer-Policy") 