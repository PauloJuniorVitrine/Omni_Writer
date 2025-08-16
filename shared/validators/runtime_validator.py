#!/usr/bin/env python3
"""
Sistema de validação de runtime para Omni Writer
Tracing ID: RUNTIME_VALIDATOR_20250127_001

Implementa validação de runtime similar ao Zod/io-ts do TypeScript
para garantir integridade dos dados entre frontend e backend.
"""

import json
import re
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Union, Type, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Exceção para erros de validação"""
    
    def __init__(self, field: str, message: str, code: str, value: Any = None):
        self.field = field
        self.message = message
        self.code = code
        self.value = value
        super().__init__(f"Validation error in {field}: {message}")

@dataclass
class ValidationResult:
    """Resultado de validação"""
    valid: bool
    errors: List[Dict[str, Any]]
    data: Optional[Any] = None

class BaseValidator:
    """Classe base para validadores"""
    
    def __init__(self, field_name: str = "root"):
        self.field_name = field_name
        self.errors = []
    
    def validate(self, data: Any) -> ValidationResult:
        """Valida dados e retorna resultado"""
        self.errors = []
        try:
            validated_data = self._validate(data)
            return ValidationResult(
                valid=len(self.errors) == 0,
                errors=self.errors,
                data=validated_data
            )
        except Exception as e:
            self.errors.append({
                "field": self.field_name,
                "message": str(e),
                "code": "validation_exception",
                "value": data
            })
            return ValidationResult(
                valid=False,
                errors=self.errors,
                data=None
            )
    
    def _validate(self, data: Any) -> Any:
        """Implementação específica de validação"""
        raise NotImplementedError
    
    def _add_error(self, message: str, code: str, value: Any = None):
        """Adiciona erro à lista"""
        self.errors.append({
            "field": self.field_name,
            "message": message,
            "code": code,
            "value": value
        })

class StringValidator(BaseValidator):
    """Validador para strings"""
    
    def __init__(self, field_name: str = "root", min_length: int = 0, max_length: Optional[int] = None, pattern: Optional[str] = None, required: bool = True):
        super().__init__(field_name)
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.required = required
    
    def _validate(self, data: Any) -> str:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if not isinstance(data, str):
            self._add_error("Deve ser uma string", "type_error", data)
            return None
        
        if len(data) < self.min_length:
            self._add_error(f"Deve ter pelo menos {self.min_length} caracteres", "min_length", data)
        
        if self.max_length and len(data) > self.max_length:
            self._add_error(f"Deve ter no máximo {self.max_length} caracteres", "max_length", data)
        
        if self.pattern and not re.match(self.pattern, data):
            self._add_error(f"Deve seguir o padrão: {self.pattern}", "pattern", data)
        
        return data

class NumberValidator(BaseValidator):
    """Validador para números"""
    
    def __init__(self, field_name: str = "root", min_value: Optional[float] = None, max_value: Optional[float] = None, required: bool = True):
        super().__init__(field_name)
        self.min_value = min_value
        self.max_value = max_value
        self.required = required
    
    def _validate(self, data: Any) -> float:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        try:
            number = float(data)
        except (ValueError, TypeError):
            self._add_error("Deve ser um número", "type_error", data)
            return None
        
        if self.min_value is not None and number < self.min_value:
            self._add_error(f"Deve ser maior ou igual a {self.min_value}", "min_value", data)
        
        if self.max_value is not None and number > self.max_value:
            self._add_error(f"Deve ser menor ou igual a {self.max_value}", "max_value", data)
        
        return number

class IntegerValidator(NumberValidator):
    """Validador para inteiros"""
    
    def _validate(self, data: Any) -> int:
        result = super()._validate(data)
        if result is not None:
            if not isinstance(result, int) and result != int(result):
                self._add_error("Deve ser um número inteiro", "type_error", data)
                return None
            return int(result)
        return None

class BooleanValidator(BaseValidator):
    """Validador para booleanos"""
    
    def __init__(self, field_name: str = "root", required: bool = True):
        super().__init__(field_name)
        self.required = required
    
    def _validate(self, data: Any) -> bool:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if isinstance(data, bool):
            return data
        elif isinstance(data, str):
            if data.lower() in ['true', '1', 'yes', 'on']:
                return True
            elif data.lower() in ['false', '0', 'no', 'off']:
                return False
        
        self._add_error("Deve ser um valor booleano", "type_error", data)
        return None

class ArrayValidator(BaseValidator):
    """Validador para arrays"""
    
    def __init__(self, field_name: str = "root", item_validator: Optional[BaseValidator] = None, min_items: int = 0, max_items: Optional[int] = None, required: bool = True):
        super().__init__(field_name)
        self.item_validator = item_validator
        self.min_items = min_items
        self.max_items = max_items
        self.required = required
    
    def _validate(self, data: Any) -> List[Any]:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if not isinstance(data, list):
            self._add_error("Deve ser uma lista", "type_error", data)
            return None
        
        if len(data) < self.min_items:
            self._add_error(f"Deve ter pelo menos {self.min_items} itens", "min_items", data)
        
        if self.max_items and len(data) > self.max_items:
            self._add_error(f"Deve ter no máximo {self.max_items} itens", "max_items", data)
        
        if self.item_validator:
            validated_items = []
            for i, item in enumerate(data):
                item_validator = type(self.item_validator)(f"{self.field_name}[{i}]")
                result = item_validator.validate(item)
                if not result.valid:
                    self.errors.extend(result.errors)
                else:
                    validated_items.append(result.data)
            return validated_items
        
        return data

class ObjectValidator(BaseValidator):
    """Validador para objetos"""
    
    def __init__(self, field_name: str = "root", schema: Optional[Dict[str, BaseValidator]] = None, required_fields: Optional[List[str]] = None, required: bool = True):
        super().__init__(field_name)
        self.schema = schema or {}
        self.required_fields = required_fields or []
        self.required = required
    
    def _validate(self, data: Any) -> Dict[str, Any]:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if not isinstance(data, dict):
            self._add_error("Deve ser um objeto", "type_error", data)
            return None
        
        validated_data = {}
        
        # Validar campos obrigatórios
        for field in self.required_fields:
            if field not in data:
                self._add_error(f"Campo obrigatório: {field}", "required_field", data)
        
        # Validar campos do schema
        for field_name, validator in self.schema.items():
            if field_name in data:
                field_validator = type(validator)(field_name)
                result = field_validator.validate(data[field_name])
                if not result.valid:
                    self.errors.extend(result.errors)
                else:
                    validated_data[field_name] = result.data
            elif field_name in self.required_fields:
                self._add_error(f"Campo obrigatório: {field_name}", "required_field", data)
        
        return validated_data

class EnumValidator(BaseValidator):
    """Validador para enums"""
    
    def __init__(self, field_name: str = "root", allowed_values: List[Any], required: bool = True):
        super().__init__(field_name)
        self.allowed_values = allowed_values
        self.required = required
    
    def _validate(self, data: Any) -> Any:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if data not in self.allowed_values:
            self._add_error(f"Deve ser um dos valores: {self.allowed_values}", "enum", data)
            return None
        
        return data

class DateTimeValidator(BaseValidator):
    """Validador para datas"""
    
    def __init__(self, field_name: str = "root", format: str = "%Y-%m-%dT%H:%M:%S", required: bool = True):
        super().__init__(field_name)
        self.format = format
        self.required = required
    
    def _validate(self, data: Any) -> datetime:
        if data is None:
            if self.required:
                self._add_error("Campo obrigatório", "required")
                return None
            return None
        
        if isinstance(data, datetime):
            return data
        elif isinstance(data, str):
            try:
                return datetime.strptime(data, self.format)
            except ValueError:
                self._add_error(f"Deve ser uma data válida no formato {self.format}", "date_format", data)
                return None
        
        self._add_error("Deve ser uma data válida", "type_error", data)
        return None

class EmailValidator(StringValidator):
    """Validador para emails"""
    
    def __init__(self, field_name: str = "root", required: bool = True):
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        super().__init__(field_name, pattern=email_pattern, required=required)

class URLValidator(StringValidator):
    """Validador para URLs"""
    
    def __init__(self, field_name: str = "root", required: bool = True):
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        super().__init__(field_name, pattern=url_pattern, required=required)

# ============================================================================
# SCHEMAS PREDEFINIDOS
# ============================================================================

class BlogSchema:
    """Schema para validação de Blog"""
    
    @staticmethod
    def create() -> ObjectValidator:
        return ObjectValidator(
            schema={
                "title": StringValidator("title", min_length=1, max_length=200),
                "content": StringValidator("content", min_length=1),
                "author_id": StringValidator("author_id", required=False),
                "tags": ArrayValidator("tags", StringValidator(), required=False),
                "metadata": ObjectValidator("metadata", required=False)
            },
            required_fields=["title", "content"]
        )
    
    @staticmethod
    def update() -> ObjectValidator:
        return ObjectValidator(
            schema={
                "title": StringValidator("title", min_length=1, max_length=200, required=False),
                "content": StringValidator("content", min_length=1, required=False),
                "status": EnumValidator("status", ["draft", "published", "archived"], required=False),
                "tags": ArrayValidator("tags", StringValidator(), required=False),
                "metadata": ObjectValidator("metadata", required=False)
            }
        )

class GenerationRequestSchema:
    """Schema para validação de GenerationRequest"""
    
    @staticmethod
    def validate() -> ObjectValidator:
        return ObjectValidator(
            schema={
                "prompt": StringValidator("prompt", min_length=1),
                "max_tokens": IntegerValidator("max_tokens", min_value=1, max_value=4000, required=False),
                "temperature": NumberValidator("temperature", min_value=0.0, max_value=2.0, required=False),
                "top_p": NumberValidator("top_p", min_value=0.0, max_value=1.0, required=False),
                "frequency_penalty": NumberValidator("frequency_penalty", min_value=-2.0, max_value=2.0, required=False),
                "presence_penalty": NumberValidator("presence_penalty", min_value=-2.0, max_value=2.0, required=False),
                "stop_sequences": ArrayValidator("stop_sequences", StringValidator(), required=False),
                "model": StringValidator("model", required=False),
                "stream": BooleanValidator("stream", required=False)
            },
            required_fields=["prompt"]
        )

class AuthRequestSchema:
    """Schema para validação de AuthRequest"""
    
    @staticmethod
    def validate() -> ObjectValidator:
        return ObjectValidator(
            schema={
                "email": EmailValidator("email"),
                "password": StringValidator("password", min_length=6)
            },
            required_fields=["email", "password"]
        )

# ============================================================================
# FUNÇÕES UTILITÁRIAS
# ============================================================================

def validate_api_request(data: Dict[str, Any], schema: BaseValidator) -> ValidationResult:
    """Valida requisição da API"""
    return schema.validate(data)

def validate_api_response(data: Any, schema: BaseValidator) -> ValidationResult:
    """Valida resposta da API"""
    return schema.validate(data)

def format_validation_errors(errors: List[Dict[str, Any]]) -> str:
    """Formata erros de validação para log"""
    if not errors:
        return "No validation errors"
    
    error_messages = []
    for error in errors:
        error_messages.append(f"{error['field']}: {error['message']} (code: {error['code']})")
    
    return "; ".join(error_messages)

def log_validation_result(result: ValidationResult, context: str = ""):
    """Loga resultado de validação"""
    if result.valid:
        logger.info(f"✅ Validation passed {context}")
    else:
        logger.warning(f"❌ Validation failed {context}: {format_validation_errors(result.errors)}")

# ============================================================================
# DECORATOR PARA VALIDAÇÃO AUTOMÁTICA
# ============================================================================

def validate_request(schema: BaseValidator):
    """Decorator para validar requisições automaticamente"""
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            # Assumir que o primeiro argumento é a requisição
            if args and hasattr(args[0], 'get_json'):
                request_data = args[0].get_json()
                result = validate_api_request(request_data, schema)
                
                if not result.valid:
                    return {
                        "success": False,
                        "errors": result.errors,
                        "message": "Dados de entrada inválidos"
                    }, 400
                
                # Substituir dados originais pelos validados
                if hasattr(args[0], '_validated_data'):
                    args[0]._validated_data = result.data
                
            return func(*args, **kwargs)
        return wrapper
    return decorator

def validate_response(schema: BaseValidator):
    """Decorator para validar respostas automaticamente"""
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)
            
            if isinstance(response, tuple):
                data, status_code = response
            else:
                data, status_code = response, 200
            
            if status_code == 200 and data:
                result = validate_api_response(data, schema)
                log_validation_result(result, "response")
                
                if not result.valid:
                    logger.error(f"Response validation failed: {format_validation_errors(result.errors)}")
            
            return response
        return wrapper
    return decorator 