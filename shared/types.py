"""
Tipos compartilhados entre Python e TypeScript
Baseado no código real do sistema Omni Writer
"""

from typing import TypedDict, Optional, List, Union, Literal
from dataclasses import dataclass
from datetime import datetime
import json

# ============================================================================
# TIPOS BASEADOS NO CÓDIGO REAL
# ============================================================================

@dataclass
class Blog:
    """Tipo Blog baseado em app/main.py"""
    id: int
    nome: str
    desc: Optional[str] = None

@dataclass
class Prompt:
    """Tipo Prompt baseado em app/main.py"""
    id: int
    text: str

@dataclass
class GenerationRequest:
    """Tipo GenerationRequest baseado em app/main.py"""
    api_key: str
    model_type: Literal['openai', 'deepseek']
    prompts: List[str]
    temperature: float = 0.7
    max_tokens: int = 4096
    language: str = 'pt-BR'

@dataclass
class GenerationResponse:
    """Tipo GenerationResponse baseado em app/main.py"""
    download_link: str
    trace_id: Optional[str] = None

@dataclass
class StatusResponse:
    """Tipo StatusResponse baseado em app/main.py"""
    trace_id: str
    status: Literal['pending', 'processing', 'completed', 'failed']
    total: int
    current: int

@dataclass
class ErrorResponse:
    """Tipo ErrorResponse baseado em app/main.py"""
    error: str

@dataclass
class WebhookRequest:
    """Tipo WebhookRequest baseado em app/main.py"""
    url: str

@dataclass
class WebhookResponse:
    """Tipo WebhookResponse baseado em app/main.py"""
    status: Literal['ok']

# ============================================================================
# TIPOS PARA VERSIONAMENTO
# ============================================================================

@dataclass
class ApiVersion:
    """Informações sobre versão da API"""
    version: str
    status: Literal['stable', 'beta', 'deprecated']
    deprecated: bool
    sunset_date: Optional[str] = None

@dataclass
class ApiVersionsResponse:
    """Resposta com informações de versões"""
    versions: dict[str, ApiVersion]
    current_stable: str
    latest: str

# ============================================================================
# TIPOS PARA VALIDAÇÃO
# ============================================================================

class ValidationError(TypedDict):
    """Erro de validação"""
    field: str
    message: str
    code: str

class ValidationResult(TypedDict):
    """Resultado de validação"""
    valid: bool
    errors: List[ValidationError]

# ============================================================================
# FUNÇÕES DE VALIDAÇÃO
# ============================================================================

def validate_blog(data: dict) -> ValidationResult:
    """Valida dados de Blog"""
    errors = []
    
    if not isinstance(data.get('id'), int) or data.get('id') <= 0:
        errors.append({
            'field': 'id',
            'message': 'ID deve ser um número inteiro positivo',
            'code': 'INVALID_ID'
        })
    
    if not isinstance(data.get('nome'), str) or len(data.get('nome', '')) == 0:
        errors.append({
            'field': 'nome',
            'message': 'Nome é obrigatório e deve ser uma string',
            'code': 'INVALID_NAME'
        })
    
    if len(data.get('nome', '')) > 40:
        errors.append({
            'field': 'nome',
            'message': 'Nome deve ter no máximo 40 caracteres',
            'code': 'NAME_TOO_LONG'
        })
    
    if 'desc' in data and data['desc'] is not None:
        if not isinstance(data['desc'], str) or len(data['desc']) > 80:
            errors.append({
                'field': 'desc',
                'message': 'Descrição deve ser uma string com no máximo 80 caracteres',
                'code': 'INVALID_DESC'
            })
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

def validate_generation_request(data: dict) -> ValidationResult:
    """Valida dados de GenerationRequest"""
    errors = []
    
    if not isinstance(data.get('api_key'), str) or len(data.get('api_key', '')) == 0:
        errors.append({
            'field': 'api_key',
            'message': 'API key é obrigatória',
            'code': 'MISSING_API_KEY'
        })
    
    if data.get('model_type') not in ['openai', 'deepseek']:
        errors.append({
            'field': 'model_type',
            'message': 'Model type deve ser "openai" ou "deepseek"',
            'code': 'INVALID_MODEL_TYPE'
        })
    
    if not isinstance(data.get('prompts'), list) or len(data.get('prompts', [])) == 0:
        errors.append({
            'field': 'prompts',
            'message': 'Prompts deve ser uma lista não vazia',
            'code': 'INVALID_PROMPTS'
        })
    
    for i, prompt in enumerate(data.get('prompts', [])):
        if not isinstance(prompt, str) or len(prompt) == 0:
            errors.append({
                'field': f'prompts[{i}]',
                'message': 'Cada prompt deve ser uma string não vazia',
                'code': 'INVALID_PROMPT_ITEM'
            })
        elif len(prompt) > 500:
            errors.append({
                'field': f'prompts[{i}]',
                'message': 'Cada prompt deve ter no máximo 500 caracteres',
                'code': 'PROMPT_TOO_LONG'
            })
    
    temperature = data.get('temperature', 0.7)
    if not isinstance(temperature, (int, float)) or temperature < 0.0 or temperature > 2.0:
        errors.append({
            'field': 'temperature',
            'message': 'Temperature deve ser um número entre 0.0 e 2.0',
            'code': 'INVALID_TEMPERATURE'
        })
    
    max_tokens = data.get('max_tokens', 4096)
    if not isinstance(max_tokens, int) or max_tokens < 256 or max_tokens > 8192:
        errors.append({
            'field': 'max_tokens',
            'message': 'Max tokens deve ser um número entre 256 e 8192',
            'code': 'INVALID_MAX_TOKENS'
        })
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

# ============================================================================
# SERIALIZAÇÃO PARA JSON
# ============================================================================

def blog_to_dict(blog: Blog) -> dict:
    """Converte Blog para dict"""
    return {
        'id': blog.id,
        'nome': blog.nome,
        'desc': blog.desc
    }

def blog_from_dict(data: dict) -> Blog:
    """Converte dict para Blog"""
    return Blog(
        id=data['id'],
        nome=data['nome'],
        desc=data.get('desc')
    )

def generation_request_to_dict(req: GenerationRequest) -> dict:
    """Converte GenerationRequest para dict"""
    return {
        'api_key': req.api_key,
        'model_type': req.model_type,
        'prompts': req.prompts,
        'temperature': req.temperature,
        'max_tokens': req.max_tokens,
        'language': req.language
    }

def generation_request_from_dict(data: dict) -> GenerationRequest:
    """Converte dict para GenerationRequest"""
    return GenerationRequest(
        api_key=data['api_key'],
        model_type=data['model_type'],
        prompts=data['prompts'],
        temperature=data.get('temperature', 0.7),
        max_tokens=data.get('max_tokens', 4096),
        language=data.get('language', 'pt-BR')
    )

# ============================================================================
# GERAÇÃO DE TIPOS TYPESCRIPT
# ============================================================================

def generate_typescript_types() -> str:
    """Gera tipos TypeScript baseados nos tipos Python"""
    typescript_code = """// Tipos gerados automaticamente a partir de shared/types.py
// Não edite manualmente - use o script de geração

export interface Blog {
  id: number;
  nome: string;
  desc?: string;
}

export interface Prompt {
  id: number;
  text: string;
}

export interface GenerationRequest {
  api_key: string;
  model_type: 'openai' | 'deepseek';
  prompts: string[];
  temperature?: number;
  max_tokens?: number;
  language?: string;
}

export interface GenerationResponse {
  download_link: string;
  trace_id?: string;
}

export interface StatusResponse {
  trace_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  total: number;
  current: number;
}

export interface ErrorResponse {
  error: string;
}

export interface WebhookRequest {
  url: string;
}

export interface WebhookResponse {
  status: 'ok';
}

export interface ApiVersion {
  version: string;
  status: 'stable' | 'beta' | 'deprecated';
  deprecated: boolean;
  sunset_date?: string;
}

export interface ApiVersionsResponse {
  versions: Record<string, ApiVersion>;
  current_stable: string;
  latest: string;
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}
"""
    return typescript_code

# ============================================================================
# UTILITÁRIOS
# ============================================================================

def save_typescript_types(output_file: str = 'ui/generated/shared-types.ts'):
    """Salva tipos TypeScript em arquivo"""
    import os
    
    # Cria diretório se não existir
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Gera e salva tipos
    typescript_code = generate_typescript_types()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(typescript_code)
    
    print(f"Tipos TypeScript salvos em: {output_file}")

if __name__ == '__main__':
    # Gera tipos TypeScript quando executado diretamente
    save_typescript_types() 