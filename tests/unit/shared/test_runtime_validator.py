#!/usr/bin/env python3
"""
Testes para sistema de validação de runtime
Tracing ID: RUNTIME_VALIDATOR_TESTS_20250127_001

Testes baseados em código real do sistema Omni Writer
"""

import pytest
import sys
from pathlib import Path

# Adicionar o diretório raiz ao path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.validators.runtime_validator import (
    StringValidator,
    NumberValidator,
    IntegerValidator,
    BooleanValidator,
    ArrayValidator,
    ObjectValidator,
    EnumValidator,
    DateTimeValidator,
    EmailValidator,
    URLValidator,
    BlogSchema,
    GenerationRequestSchema,
    AuthRequestSchema,
    validate_api_request,
    validate_api_response,
    format_validation_errors,
    ValidationResult
)

class TestStringValidator:
    """Testes para StringValidator"""
    
    def test_valid_string(self):
        """Testa string válida"""
        validator = StringValidator("title", min_length=1, max_length=200)
        result = validator.validate("Título do blog")
        
        assert result.valid is True
        assert result.data == "Título do blog"
        assert len(result.errors) == 0
    
    def test_empty_string_with_min_length(self):
        """Testa string vazia com comprimento mínimo"""
        validator = StringValidator("title", min_length=1)
        result = validator.validate("")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "min_length"
    
    def test_string_too_long(self):
        """Testa string muito longa"""
        long_string = "a" * 300
        validator = StringValidator("title", max_length=200)
        result = validator.validate(long_string)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "max_length"
    
    def test_invalid_type(self):
        """Testa tipo inválido"""
        validator = StringValidator("title")
        result = validator.validate(123)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "type_error"
    
    def test_optional_string(self):
        """Testa string opcional"""
        validator = StringValidator("description", required=False)
        result = validator.validate(None)
        
        assert result.valid is True
        assert result.data is None

class TestNumberValidator:
    """Testes para NumberValidator"""
    
    def test_valid_number(self):
        """Testa número válido"""
        validator = NumberValidator("temperature", min_value=0.0, max_value=2.0)
        result = validator.validate(1.5)
        
        assert result.valid is True
        assert result.data == 1.5
    
    def test_number_below_min(self):
        """Testa número abaixo do mínimo"""
        validator = NumberValidator("temperature", min_value=0.0)
        result = validator.validate(-1.0)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "min_value"
    
    def test_number_above_max(self):
        """Testa número acima do máximo"""
        validator = NumberValidator("temperature", max_value=2.0)
        result = validator.validate(3.0)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "max_value"
    
    def test_string_to_number_conversion(self):
        """Testa conversão de string para número"""
        validator = NumberValidator("temperature")
        result = validator.validate("1.5")
        
        assert result.valid is True
        assert result.data == 1.5

class TestIntegerValidator:
    """Testes para IntegerValidator"""
    
    def test_valid_integer(self):
        """Testa inteiro válido"""
        validator = IntegerValidator("max_tokens", min_value=1, max_value=4000)
        result = validator.validate(1000)
        
        assert result.valid is True
        assert result.data == 1000
    
    def test_float_conversion(self):
        """Testa conversão de float para inteiro"""
        validator = IntegerValidator("max_tokens")
        result = validator.validate(1000.0)
        
        assert result.valid is True
        assert result.data == 1000
    
    def test_invalid_float(self):
        """Testa float que não pode ser convertido para inteiro"""
        validator = IntegerValidator("max_tokens")
        result = validator.validate(1000.5)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "type_error"

class TestBooleanValidator:
    """Testes para BooleanValidator"""
    
    def test_valid_boolean(self):
        """Testa booleano válido"""
        validator = BooleanValidator("stream")
        result = validator.validate(True)
        
        assert result.valid is True
        assert result.data is True
    
    def test_string_true(self):
        """Testa string 'true'"""
        validator = BooleanValidator("stream")
        result = validator.validate("true")
        
        assert result.valid is True
        assert result.data is True
    
    def test_string_false(self):
        """Testa string 'false'"""
        validator = BooleanValidator("stream")
        result = validator.validate("false")
        
        assert result.valid is True
        assert result.data is False
    
    def test_invalid_string(self):
        """Testa string inválida"""
        validator = BooleanValidator("stream")
        result = validator.validate("maybe")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "type_error"

class TestArrayValidator:
    """Testes para ArrayValidator"""
    
    def test_valid_array(self):
        """Testa array válido"""
        validator = ArrayValidator("tags", StringValidator(), min_items=0, max_items=10)
        result = validator.validate(["tech", "ai", "blog"])
        
        assert result.valid is True
        assert result.data == ["tech", "ai", "blog"]
    
    def test_array_too_short(self):
        """Testa array muito curto"""
        validator = ArrayValidator("tags", min_items=2)
        result = validator.validate(["tech"])
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "min_items"
    
    def test_array_too_long(self):
        """Testa array muito longo"""
        validator = ArrayValidator("tags", max_items=2)
        result = validator.validate(["tech", "ai", "blog"])
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "max_items"
    
    def test_invalid_type(self):
        """Testa tipo inválido"""
        validator = ArrayValidator("tags")
        result = validator.validate("not an array")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "type_error"

class TestObjectValidator:
    """Testes para ObjectValidator"""
    
    def test_valid_object(self):
        """Testa objeto válido"""
        schema = {
            "title": StringValidator("title", min_length=1),
            "content": StringValidator("content", min_length=1)
        }
        validator = ObjectValidator("blog", schema, required_fields=["title", "content"])
        
        data = {
            "title": "Meu Blog",
            "content": "Conteúdo do blog"
        }
        result = validator.validate(data)
        
        assert result.valid is True
        assert result.data["title"] == "Meu Blog"
        assert result.data["content"] == "Conteúdo do blog"
    
    def test_missing_required_field(self):
        """Testa campo obrigatório ausente"""
        schema = {
            "title": StringValidator("title", min_length=1),
            "content": StringValidator("content", min_length=1)
        }
        validator = ObjectValidator("blog", schema, required_fields=["title", "content"])
        
        data = {
            "title": "Meu Blog"
            # content ausente
        }
        result = validator.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "required_field"
    
    def test_invalid_field_type(self):
        """Testa tipo inválido em campo"""
        schema = {
            "title": StringValidator("title", min_length=1),
            "max_tokens": IntegerValidator("max_tokens")
        }
        validator = ObjectValidator("blog", schema)
        
        data = {
            "title": "Meu Blog",
            "max_tokens": "not a number"
        }
        result = validator.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "type_error"

class TestEnumValidator:
    """Testes para EnumValidator"""
    
    def test_valid_enum_value(self):
        """Testa valor válido do enum"""
        validator = EnumValidator("status", ["draft", "published", "archived"])
        result = validator.validate("published")
        
        assert result.valid is True
        assert result.data == "published"
    
    def test_invalid_enum_value(self):
        """Testa valor inválido do enum"""
        validator = EnumValidator("status", ["draft", "published", "archived"])
        result = validator.validate("deleted")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "enum"

class TestEmailValidator:
    """Testes para EmailValidator"""
    
    def test_valid_email(self):
        """Testa email válido"""
        validator = EmailValidator("email")
        result = validator.validate("user@example.com")
        
        assert result.valid is True
        assert result.data == "user@example.com"
    
    def test_invalid_email(self):
        """Testa email inválido"""
        validator = EmailValidator("email")
        result = validator.validate("invalid-email")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "pattern"

class TestURLValidator:
    """Testes para URLValidator"""
    
    def test_valid_url(self):
        """Testa URL válida"""
        validator = URLValidator("url")
        result = validator.validate("https://example.com")
        
        assert result.valid is True
        assert result.data == "https://example.com"
    
    def test_invalid_url(self):
        """Testa URL inválida"""
        validator = URLValidator("url")
        result = validator.validate("not-a-url")
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "pattern"

class TestBlogSchema:
    """Testes para BlogSchema"""
    
    def test_valid_blog_create(self):
        """Testa criação de blog válida"""
        schema = BlogSchema.create()
        data = {
            "title": "Meu Blog",
            "content": "Conteúdo do blog",
            "tags": ["tech", "ai"]
        }
        result = schema.validate(data)
        
        assert result.valid is True
        assert result.data["title"] == "Meu Blog"
        assert result.data["content"] == "Conteúdo do blog"
        assert result.data["tags"] == ["tech", "ai"]
    
    def test_invalid_blog_create_missing_title(self):
        """Testa criação de blog sem título"""
        schema = BlogSchema.create()
        data = {
            "content": "Conteúdo do blog"
            # title ausente
        }
        result = schema.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "required_field"
    
    def test_valid_blog_update(self):
        """Testa atualização de blog válida"""
        schema = BlogSchema.update()
        data = {
            "title": "Título Atualizado",
            "status": "published"
        }
        result = schema.validate(data)
        
        assert result.valid is True
        assert result.data["title"] == "Título Atualizado"
        assert result.data["status"] == "published"

class TestGenerationRequestSchema:
    """Testes para GenerationRequestSchema"""
    
    def test_valid_generation_request(self):
        """Testa requisição de geração válida"""
        schema = GenerationRequestSchema.validate()
        data = {
            "prompt": "Escreva um artigo sobre IA",
            "max_tokens": 1000,
            "temperature": 0.7
        }
        result = schema.validate(data)
        
        assert result.valid is True
        assert result.data["prompt"] == "Escreva um artigo sobre IA"
        assert result.data["max_tokens"] == 1000
        assert result.data["temperature"] == 0.7
    
    def test_invalid_generation_request_missing_prompt(self):
        """Testa requisição de geração sem prompt"""
        schema = GenerationRequestSchema.validate()
        data = {
            "max_tokens": 1000
            # prompt ausente
        }
        result = schema.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "required_field"
    
    def test_invalid_temperature_range(self):
        """Testa temperatura fora do range válido"""
        schema = GenerationRequestSchema.validate()
        data = {
            "prompt": "Escreva um artigo",
            "temperature": 3.0  # Fora do range 0.0-2.0
        }
        result = schema.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "max_value"

class TestAuthRequestSchema:
    """Testes para AuthRequestSchema"""
    
    def test_valid_auth_request(self):
        """Testa requisição de autenticação válida"""
        schema = AuthRequestSchema.validate()
        data = {
            "email": "user@example.com",
            "password": "password123"
        }
        result = schema.validate(data)
        
        assert result.valid is True
        assert result.data["email"] == "user@example.com"
        assert result.data["password"] == "password123"
    
    def test_invalid_email(self):
        """Testa email inválido"""
        schema = AuthRequestSchema.validate()
        data = {
            "email": "invalid-email",
            "password": "password123"
        }
        result = schema.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "pattern"
    
    def test_short_password(self):
        """Testa senha muito curta"""
        schema = AuthRequestSchema.validate()
        data = {
            "email": "user@example.com",
            "password": "123"  # Menos de 6 caracteres
        }
        result = schema.validate(data)
        
        assert result.valid is False
        assert len(result.errors) == 1
        assert result.errors[0]["code"] == "min_length"

class TestUtilityFunctions:
    """Testes para funções utilitárias"""
    
    def test_format_validation_errors(self):
        """Testa formatação de erros de validação"""
        errors = [
            {
                "field": "title",
                "message": "Campo obrigatório",
                "code": "required",
                "value": None
            },
            {
                "field": "email",
                "message": "Email inválido",
                "code": "pattern",
                "value": "invalid"
            }
        ]
        
        formatted = format_validation_errors(errors)
        expected = "title: Campo obrigatório (code: required); email: Email inválido (code: pattern)"
        
        assert formatted == expected
    
    def test_format_validation_errors_empty(self):
        """Testa formatação de lista vazia de erros"""
        formatted = format_validation_errors([])
        assert formatted == "No validation errors"
    
    def test_validate_api_request(self):
        """Testa validação de requisição da API"""
        schema = BlogSchema.create()
        data = {
            "title": "Test Blog",
            "content": "Test content"
        }
        
        result = validate_api_request(data, schema)
        assert result.valid is True
        assert result.data["title"] == "Test Blog"
    
    def test_validate_api_response(self):
        """Testa validação de resposta da API"""
        schema = BlogSchema.create()
        data = {
            "title": "Test Blog",
            "content": "Test content"
        }
        
        result = validate_api_response(data, schema)
        assert result.valid is True
        assert result.data["title"] == "Test Blog" 