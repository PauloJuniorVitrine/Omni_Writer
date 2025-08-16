#!/usr/bin/env python3
"""
🧪 TESTES UNITÁRIOS - Auto Documentation
Tracing ID: AUTO_DOC_TEST_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Testes unitários para o sistema de auto-documentação de schemas.
Baseado no código real implementado em scripts/auto_documentation.py
"""

import pytest
import json
import sys
import os
from datetime import datetime
from unittest.mock import Mock, patch

# Adiciona scripts ao path para importação
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts'))

from auto_documentation import AutoDocumentationGenerator, FieldDocumentation, SchemaDocumentation

class TestAutoDocumentationGenerator:
    """Testes para a classe AutoDocumentationGenerator."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        self.generator = AutoDocumentationGenerator()
    
    def test_generator_initialization(self):
        """Testa inicialização correta do gerador."""
        assert self.generator.templates_path is not None
        assert len(self.generator.field_patterns) > 0
        assert len(self.generator.type_descriptions) > 0
        assert len(self.generator.validation_rules) > 0
    
    def test_generate_field_description_with_patterns(self):
        """Testa geração de descrições usando padrões."""
        # Testa padrões conhecidos
        test_cases = [
            ("user_id", "integer", "Identificador do usuário"),
            ("created_at", "datetime", "Data e hora de criação"),
            ("email", "string", "Endereço de email válido"),
            ("title", "string", "Título do conteúdo"),
            ("status", "string", "Status atual do recurso"),
        ]
        
        for field_name, field_type, expected_desc in test_cases:
            description = self.generator.generate_field_description(field_name, field_type)
            assert description == expected_desc
    
    def test_generate_field_description_fallback(self):
        """Testa geração de descrições quando não há padrão."""
        # Campo sem padrão específico
        description = self.generator.generate_field_description("custom_field", "string")
        
        assert description is not None
        assert len(description) > 0
        assert "custom_field" in description.lower()
    
    def test_generate_field_description_with_context(self):
        """Testa geração de descrições com contexto baseado no nome."""
        # Testa campos com palavras-chave no nome
        name_desc = self.generator.generate_field_description("user_name", "string")
        value_desc = self.generator.generate_field_description("config_value", "string")
        code_desc = self.generator.generate_field_description("error_code", "integer")
        
        assert "nome" in name_desc.lower()
        assert "valor" in value_desc.lower()
        assert "código" in code_desc.lower()
    
    def test_generate_validation_rules(self):
        """Testa geração de regras de validação."""
        # Testa regras básicas por tipo
        string_rules = self.generator.generate_validation_rules("test_field", "string")
        integer_rules = self.generator.generate_validation_rules("test_field", "integer")
        email_rules = self.generator.generate_validation_rules("user_email", "string")
        
        assert len(string_rules) > 0
        assert len(integer_rules) > 0
        assert len(email_rules) > 0
        
        # Verifica se regras específicas são adicionadas
        required_rules = self.generator.generate_validation_rules("required_field", "string")
        assert any("obrigatório" in rule.lower() for rule in required_rules)
    
    def test_generate_examples(self):
        """Testa geração de exemplos."""
        # Testa exemplos para diferentes tipos
        string_examples = self.generator.generate_examples("test_field", "string")
        integer_examples = self.generator.generate_examples("test_field", "integer")
        boolean_examples = self.generator.generate_examples("test_field", "boolean")
        email_examples = self.generator.generate_examples("user_email", "string")
        
        assert len(string_examples) > 0
        assert len(integer_examples) > 0
        assert len(boolean_examples) > 0
        assert len(email_examples) > 0
        
        # Verifica se exemplos são apropriados
        assert all(isinstance(ex, str) for ex in string_examples)
        assert all(isinstance(ex, str) for ex in integer_examples)
        assert all(ex in ["true", "false"] for ex in boolean_examples)
        assert all("@" in ex for ex in email_examples)
    
    def test_analyze_schema_basic(self):
        """Testa análise básica de schema."""
        schema_data = {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "email": {"type": "string"},
                "title": {"type": "string"}
            },
            "required": ["user_id", "email"]
        }
        
        schema_doc = self.generator.analyze_schema(schema_data, "test_schema")
        
        assert schema_doc.schema_name == "test_schema"
        assert schema_doc.schema_type == "model"
        assert len(schema_doc.fields) == 3
        
        # Verifica campos obrigatórios
        user_id_field = next(f for f in schema_doc.fields if f.field_name == "user_id")
        email_field = next(f for f in schema_doc.fields if f.field_name == "email")
        title_field = next(f for f in schema_doc.fields if f.field_name == "title")
        
        assert user_id_field.is_required
        assert email_field.is_required
        assert not title_field.is_required
    
    def test_analyze_schema_with_existing_descriptions(self):
        """Testa análise de schema com descrições existentes."""
        schema_data = {
            "type": "object",
            "description": "Schema de teste existente",
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Descrição existente do user_id"
                },
                "email": {
                    "type": "string",
                    "description": "Descrição existente do email"
                }
            }
        }
        
        schema_doc = self.generator.analyze_schema(schema_data, "test_schema")
        
        assert schema_doc.description == "Schema de teste existente"
        
        # Verifica se descrições existentes são preservadas
        user_id_field = next(f for f in schema_doc.fields if f.field_name == "user_id")
        email_field = next(f for f in schema_doc.fields if f.field_name == "email")
        
        assert user_id_field.description == "Descrição existente do user_id"
        assert email_field.description == "Descrição existente do email"
        assert not user_id_field.generated
        assert not email_field.generated
    
    def test_analyze_schema_request_response_types(self):
        """Testa detecção de tipos de schema (request/response)."""
        # Testa schema de request
        request_schema = {
            "type": "object",
            "properties": {"data": {"type": "string"}}
        }
        request_doc = self.generator.analyze_schema(request_schema, "create_user_request")
        assert request_doc.schema_type == "request"
        
        # Testa schema de response
        response_schema = {
            "type": "object",
            "properties": {"result": {"type": "string"}}
        }
        response_doc = self.generator.analyze_schema(response_schema, "user_response")
        assert response_doc.schema_type == "response"
        
        # Testa schema genérico
        model_schema = {
            "type": "object",
            "properties": {"field": {"type": "string"}}
        }
        model_doc = self.generator.analyze_schema(model_schema, "user_model")
        assert model_doc.schema_type == "model"
    
    def test_validate_schema_documentation_valid(self):
        """Testa validação de schema bem documentado."""
        # Cria schema com boa documentação
        schema_data = {
            "type": "object",
            "description": "Schema bem documentado para teste",
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Identificador único do usuário no sistema"
                },
                "email": {
                    "type": "string",
                    "description": "Endereço de email válido do usuário",
                    "examples": ["usuario@exemplo.com"]
                }
            },
            "required": ["user_id", "email"]
        }
        
        schema_doc = self.generator.analyze_schema(schema_data, "valid_schema")
        is_valid, issues = self.generator.validate_schema_documentation(schema_doc)
        
        assert is_valid
        assert len(issues) == 0
    
    def test_validate_schema_documentation_invalid(self):
        """Testa validação de schema mal documentado."""
        # Cria schema com problemas
        schema_data = {
            "type": "object",
            "properties": {
                "field1": {
                    "type": "string",
                    "description": ""  # Descrição vazia
                },
                "field2": {
                    "type": "string",
                    "description": "A"  # Descrição muito curta
                },
                "field3": {
                    "type": "object",
                    "description": "Campo complexo"
                    # Sem exemplos
                }
            },
            "required": ["field1", "field2"]
        }
        
        schema_doc = self.generator.analyze_schema(schema_data, "invalid_schema")
        is_valid, issues = self.generator.validate_schema_documentation(schema_doc)
        
        assert not is_valid
        assert len(issues) > 0
        
        # Verifica tipos específicos de problemas
        issue_types = [issue.field_name for issue in issues]
        assert "field1" in issue_types  # Descrição vazia
        assert "field2" in issue_types  # Descrição muito curta
        assert "field3" in issue_types  # Campo complexo sem exemplos
    
    def test_update_schema_with_documentation(self):
        """Testa atualização de schema com documentação gerada."""
        original_schema = {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "email": {"type": "string"}
            }
        }
        
        schema_doc = self.generator.analyze_schema(original_schema, "test_schema")
        updated_schema = self.generator.update_schema_with_documentation(original_schema, schema_doc)
        
        # Verifica se documentação foi adicionada
        assert "description" in updated_schema
        assert updated_schema["properties"]["user_id"]["description"] is not None
        assert updated_schema["properties"]["email"]["description"] is not None
        
        # Verifica se exemplos foram adicionados
        assert "examples" in updated_schema["properties"]["email"]
    
    def test_update_schema_preserves_existing(self):
        """Testa se atualização preserva dados existentes."""
        original_schema = {
            "type": "object",
            "description": "Descrição original",
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Descrição original",
                    "examples": ["123"]
                }
            }
        }
        
        schema_doc = self.generator.analyze_schema(original_schema, "test_schema")
        updated_schema = self.generator.update_schema_with_documentation(original_schema, schema_doc)
        
        # Verifica se dados originais foram preservados
        assert updated_schema["description"] == "Descrição original"
        assert updated_schema["properties"]["user_id"]["description"] == "Descrição original"
        assert updated_schema["properties"]["user_id"]["examples"] == ["123"]
    
    def test_generate_documentation_report(self):
        """Testa geração de relatório de documentação."""
        # Mock de arquivos de schema
        with patch('pathlib.Path.glob') as mock_glob:
            mock_glob.return_value = []
            
            report = self.generator.generate_documentation_report()
            
            assert "generated_at" in report
            assert "summary" in report
            assert "schemas" in report
            assert "recommendations" in report
            
            summary = report["summary"]
            assert summary["total_schemas"] == 0
            assert summary["total_fields"] == 0
            assert summary["coverage_percentage"] == 0
    
    def test_generate_recommendations(self):
        """Testa geração de recomendações."""
        # Cria schemas com problemas
        schemas = []
        
        # Schema sem problemas
        valid_schema = SchemaDocumentation(
            schema_name="valid",
            schema_type="model",
            fields=[],
            description="Schema válido",
            generated_at=datetime.now()
        )
        schemas.append(valid_schema)
        
        # Schema com problemas
        invalid_schema = SchemaDocumentation(
            schema_name="invalid",
            schema_type="model",
            fields=[
                FieldDocumentation(
                    field_name="field1",
                    field_type="string",
                    description="",
                    is_required=True
                ),
                FieldDocumentation(
                    field_name="field2",
                    field_type="object",
                    description="Campo complexo",
                    is_required=False
                )
            ],
            description="Schema com problemas",
            generated_at=datetime.now()
        )
        schemas.append(invalid_schema)
        
        recommendations = self.generator._generate_recommendations(schemas)
        
        assert len(recommendations) > 0
        assert any("descrições" in rec.lower() for rec in recommendations)
        assert any("exemplos" in rec.lower() for rec in recommendations)

class TestFieldDocumentation:
    """Testes específicos para FieldDocumentation."""
    
    def test_field_documentation_creation(self):
        """Testa criação de FieldDocumentation."""
        field_doc = FieldDocumentation(
            field_name="test_field",
            field_type="string",
            description="Campo de teste",
            is_required=True,
            default_value="default",
            validation_rules=["Regra 1", "Regra 2"],
            examples=["exemplo1", "exemplo2"],
            generated=True
        )
        
        assert field_doc.field_name == "test_field"
        assert field_doc.field_type == "string"
        assert field_doc.description == "Campo de teste"
        assert field_doc.is_required
        assert field_doc.default_value == "default"
        assert field_doc.validation_rules == ["Regra 1", "Regra 2"]
        assert field_doc.examples == ["exemplo1", "exemplo2"]
        assert field_doc.generated
    
    def test_field_documentation_default_initialization(self):
        """Testa inicialização com valores padrão."""
        field_doc = FieldDocumentation(
            field_name="test_field",
            field_type="string",
            description="Teste",
            is_required=False
        )
        
        assert field_doc.validation_rules == []
        assert field_doc.examples == []
        assert not field_doc.generated

class TestSchemaDocumentation:
    """Testes específicos para SchemaDocumentation."""
    
    def test_schema_documentation_creation(self):
        """Testa criação de SchemaDocumentation."""
        schema_doc = SchemaDocumentation(
            schema_name="test_schema",
            schema_type="request",
            fields=[],
            description="Schema de teste",
            generated_at=datetime.now(),
            validation_status="valid",
            issues=["Problema 1", "Problema 2"]
        )
        
        assert schema_doc.schema_name == "test_schema"
        assert schema_doc.schema_type == "request"
        assert schema_doc.description == "Schema de teste"
        assert schema_doc.validation_status == "valid"
        assert schema_doc.issues == ["Problema 1", "Problema 2"]
    
    def test_schema_documentation_default_initialization(self):
        """Testa inicialização com valores padrão."""
        schema_doc = SchemaDocumentation(
            schema_name="test_schema",
            schema_type="model",
            fields=[],
            description="Teste",
            generated_at=datetime.now()
        )
        
        assert schema_doc.validation_status == "pending"
        assert schema_doc.issues == []

# Testes de integração
class TestAutoDocumentationIntegration:
    """Testes de integração do sistema de auto-documentação."""
    
    def setup_method(self):
        """Configuração para testes de integração."""
        self.generator = AutoDocumentationGenerator()
    
    def test_full_workflow_simulation(self):
        """Simula workflow completo de auto-documentação."""
        # Schema original sem documentação
        original_schema = {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer"},
                "email": {"type": "string"},
                "created_at": {"type": "datetime"},
                "status": {"type": "string"},
                "metadata": {"type": "object"}
            },
            "required": ["user_id", "email"]
        }
        
        # 1. Analisa schema
        schema_doc = self.generator.analyze_schema(original_schema, "user_schema")
        
        # 2. Valida documentação
        is_valid, issues = self.generator.validate_schema_documentation(schema_doc)
        
        # 3. Atualiza schema com documentação
        updated_schema = self.generator.update_schema_with_documentation(original_schema, schema_doc)
        
        # Verifica resultados
        assert len(schema_doc.fields) == 5
        assert not is_valid  # Deve ter problemas (campos sem descrição)
        assert len(issues) > 0
        
        # Verifica se documentação foi adicionada
        assert updated_schema["properties"]["user_id"]["description"] is not None
        assert updated_schema["properties"]["email"]["description"] is not None
        
        # Verifica se exemplos foram adicionados para campo complexo
        assert "examples" in updated_schema["properties"]["metadata"]
    
    def test_documentation_quality_improvement(self):
        """Testa melhoria na qualidade da documentação."""
        # Schema com documentação ruim
        bad_schema = {
            "type": "object",
            "properties": {
                "field1": {"type": "string", "description": ""},
                "field2": {"type": "string", "description": "A"},
                "field3": {"type": "object", "description": "Campo complexo"}
            }
        }
        
        # Analisa e valida
        schema_doc = self.generator.analyze_schema(bad_schema, "bad_schema")
        is_valid_before, issues_before = self.generator.validate_schema_documentation(schema_doc)
        
        # Atualiza com documentação gerada
        updated_schema = self.generator.update_schema_with_documentation(bad_schema, schema_doc)
        
        # Re-analisa e valida
        updated_schema_doc = self.generator.analyze_schema(updated_schema, "updated_schema")
        is_valid_after, issues_after = self.generator.validate_schema_documentation(updated_schema_doc)
        
        # Verifica melhoria
        assert len(issues_after) < len(issues_before)
        assert is_valid_after or len(issues_after) == 0

if __name__ == "__main__":
    # Executa testes básicos
    print("🧪 Executando testes do Auto Documentation...")
    
    # Teste básico de funcionalidade
    generator = AutoDocumentationGenerator()
    
    # Testa geração de descrições
    test_fields = [
        ("user_id", "integer"),
        ("email", "string"),
        ("created_at", "datetime"),
        ("title", "string"),
    ]
    
    print("📝 Testando geração de descrições:")
    for field_name, field_type in test_fields:
        description = generator.generate_field_description(field_name, field_type)
        print(f"  {field_name} ({field_type}): {description}")
    
    # Testa análise de schema
    test_schema = {
        "type": "object",
        "properties": {
            "user_id": {"type": "integer"},
            "email": {"type": "string"},
            "title": {"type": "string"}
        },
        "required": ["user_id", "email"]
    }
    
    schema_doc = generator.analyze_schema(test_schema, "test_schema")
    print(f"\n📊 Schema processado: {len(schema_doc.fields)} campos")
    
    # Valida documentação
    is_valid, issues = generator.validate_schema_documentation(schema_doc)
    print(f"✅ Validação: {'Válido' if is_valid else 'Inválido'}")
    if issues:
        print(f"⚠️ Problemas: {len(issues)} encontrados")
    
    print("✅ AutoDocumentationGenerator testado com sucesso!") 