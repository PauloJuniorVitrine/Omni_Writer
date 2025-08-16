"""
Teste Unitário - Sistema de Documentação Automatizada
=====================================================

Testa funcionalidades do sistema de documentação automatizada:
- Geração de OpenAPI spec
- Versionamento de schemas
- Validação de compatibilidade
- Detecção de breaking changes

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

# Adiciona o diretório scripts ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from automated_documentation import (
    AutomatedDocumentation, 
    ApiEndpoint, 
    SchemaDefinition, 
    BreakingChange
)

class TestAutomatedDocumentation:
    """Testes para o sistema de documentação automatizada"""
    
    @pytest.fixture
    def temp_project(self):
        """Cria projeto temporário para testes"""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Cria estrutura de diretórios
            (project_path / "app").mkdir()
            (project_path / "docs").mkdir()
            
            # Cria arquivo de rotas de exemplo
            routes_content = '''
from flask import Blueprint, request, jsonify

blog_routes = Blueprint('blog', __name__)

@blog_routes.route('/blogs', methods=['GET'])
def get_blogs():
    """
    Lista todos os blogs
    200: Lista de blogs retornada com sucesso
    400: Parâmetros inválidos
    """
    return jsonify({"blogs": []})

@blog_routes.route('/blogs/<int:blog_id>', methods=['GET'])
def get_blog(blog_id):
    """
    Obtém um blog específico
    200: Blog encontrado
    404: Blog não encontrado
    """
    return jsonify({"blog": {"id": blog_id}})

@blog_routes.route('/blogs', methods=['POST'])
def create_blog():
    """
    Cria um novo blog
    201: Blog criado com sucesso
    400: Dados inválidos
    """
    data = request.get_json()
    return jsonify({"blog": data}), 201
'''
            
            with open(project_path / "app" / "blog_routes.py", 'w') as f:
                f.write(routes_content)
            
            # Cria schema JSON de exemplo
            schema_content = {
                "title": "Blog",
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                    "author": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"}
                },
                "required": ["title", "content", "author"]
            }
            
            with open(project_path / "blog_schema.json", 'w') as f:
                json.dump(schema_content, f)
            
            yield project_path
    
    @pytest.fixture
    def doc_generator(self, temp_project):
        """Cria instância do gerador de documentação"""
        return AutomatedDocumentation(str(temp_project))
    
    def test_scan_flask_routes(self, doc_generator):
        """Testa escaneamento de rotas Flask"""
        endpoints = doc_generator.scan_flask_routes()
        
        assert len(endpoints) == 3
        
        # Verifica endpoint GET /blogs
        get_blogs = next(ep for ep in endpoints if ep.path == '/blogs' and ep.method == 'GET')
        assert get_blogs.summary == 'Get Blogs'
        assert 'Lista todos os blogs' in get_blogs.description
        assert get_blogs.tags == ['Blog']
        
        # Verifica endpoint GET /blogs/<int:blog_id>
        get_blog = next(ep for ep in endpoints if ep.path == '/blogs/<int:blog_id>' and ep.method == 'GET')
        assert get_blog.summary == 'Get Blog'
        assert len(get_blog.parameters) == 1
        assert get_blog.parameters[0]['name'] == 'blog_id'
        assert get_blog.parameters[0]['schema']['type'] == 'integer'
        
        # Verifica endpoint POST /blogs
        create_blog = next(ep for ep in endpoints if ep.path == '/blogs' and ep.method == 'POST')
        assert create_blog.summary == 'Create Blog'
        assert create_blog.request_body is not None
    
    def test_scan_json_schemas(self, doc_generator):
        """Testa escaneamento de schemas JSON"""
        schemas = doc_generator.scan_json_schemas()
        
        assert len(schemas) == 1
        
        blog_schema = schemas[0]
        assert blog_schema.name == 'Blog'
        assert blog_schema.type == 'object'
        assert 'title' in blog_schema.properties
        assert 'title' in blog_schema.required
        assert 'content' in blog_schema.required
        assert 'author' in blog_schema.required
    
    def test_generate_openapi_spec(self, doc_generator):
        """Testa geração de especificação OpenAPI"""
        # Adiciona endpoints e schemas de exemplo
        doc_generator.endpoints = [
            ApiEndpoint(
                path="/test",
                method="GET",
                summary="Test endpoint",
                description="Test description",
                parameters=[],
                request_body=None,
                responses={"200": {"description": "Success"}},
                tags=["Test"]
            )
        ]
        
        doc_generator.schemas = [
            SchemaDefinition(
                name="TestSchema",
                type="object",
                properties={"test": {"type": "string"}},
                required=["test"],
                description="Test schema"
            )
        ]
        
        spec = doc_generator.generate_openapi_spec()
        
        assert spec["openapi"] == "3.0.3"
        assert spec["info"]["title"] == "Omni Writer API"
        assert "/test" in spec["paths"]
        assert spec["paths"]["/test"]["get"]["summary"] == "Test endpoint"
        assert "TestSchema" in spec["components"]["schemas"]
    
    def test_generate_versioned_schemas(self, doc_generator):
        """Testa geração de schemas versionados"""
        doc_generator.schemas = [
            SchemaDefinition(
                name="TestSchema",
                type="object",
                properties={"test": {"type": "string"}},
                required=["test"],
                description="Test schema",
                version="1.0"
            )
        ]
        
        versioned = doc_generator.generate_versioned_schemas()
        
        assert versioned["version"] == "1.0.0"
        assert "TestSchema" in versioned["schemas"]
        assert versioned["schemas"]["TestSchema"]["version"] == "1.0"
        assert versioned["schemas"]["TestSchema"]["compatibility"]["backward_compatible"] is True
    
    def test_validate_schema_compatibility(self, doc_generator):
        """Testa validação de compatibilidade de schemas"""
        old_schemas = {
            "schemas": {
                "TestSchema": {
                    "definition": {
                        "properties": {"old": {"type": "string"}, "common": {"type": "string"}},
                        "required": ["common"]
                    }
                }
            }
        }
        
        new_schemas = {
            "schemas": {
                "TestSchema": {
                    "definition": {
                        "properties": {"new": {"type": "string"}, "common": {"type": "string"}},
                        "required": ["common", "new"]
                    }
                }
            }
        }
        
        issues = doc_generator.validate_schema_compatibility(old_schemas, new_schemas)
        
        assert len(issues) == 2
        assert "Propriedades removidas" in issues[0]
        assert "Novas propriedades obrigatórias" in issues[1]
    
    def test_detect_breaking_changes(self, doc_generator):
        """Testa detecção de breaking changes"""
        old_endpoints = [
            ApiEndpoint(
                path="/test",
                method="GET",
                summary="Old endpoint",
                description="Old description",
                parameters=[{"name": "param1", "in": "query", "required": False, "schema": {"type": "string"}}],
                request_body=None,
                responses={},
                tags=["Test"]
            )
        ]
        
        new_endpoints = [
            ApiEndpoint(
                path="/test",
                method="GET",
                summary="New endpoint",
                description="New description",
                parameters=[{"name": "param2", "in": "query", "required": True, "schema": {"type": "string"}}],
                request_body=None,
                responses={},
                tags=["Test"]
            )
        ]
        
        breaking_changes = doc_generator.detect_breaking_changes(old_endpoints, new_endpoints)
        
        assert len(breaking_changes) == 2
        assert any("Parâmetros removidos" in change.description for change in breaking_changes)
        assert any("Novos parâmetros obrigatórios" in change.description for change in breaking_changes)
    
    def test_save_documentation(self, doc_generator):
        """Testa salvamento de documentação"""
        # Adiciona dados de exemplo
        doc_generator.endpoints = [
            ApiEndpoint(
                path="/test",
                method="GET",
                summary="Test",
                description="Test",
                parameters=[],
                request_body=None,
                responses={},
                tags=["Test"]
            )
        ]
        
        doc_generator.schemas = [
            SchemaDefinition(
                name="Test",
                type="object",
                properties={},
                required=[],
                description="Test"
            )
        ]
        
        # Testa salvamento
        doc_generator.save_documentation()
        
        # Verifica se arquivos foram criados
        assert (doc_generator.api_dir / "openapi.yaml").exists()
        assert (doc_generator.api_dir / "openapi.json").exists()
        assert (doc_generator.schemas_dir / "versioned_schemas.json").exists()
        assert (doc_generator.changelog_file).exists()
        assert (doc_generator.docs_dir / "compatibility_report.json").exists()
    
    def test_extract_parameters(self, doc_generator):
        """Testa extração de parâmetros de função"""
        import ast
        
        # Cria AST de função de exemplo
        func_code = '''
def test_function(user_id: int, name: str, active: bool = True):
    pass
'''
        
        func_ast = ast.parse(func_code).body[0]
        
        parameters = doc_generator._extract_parameters(func_ast)
        
        assert len(parameters) == 3
        assert parameters[0]["name"] == "user_id"
        assert parameters[0]["schema"]["type"] == "integer"
        assert parameters[1]["name"] == "name"
        assert parameters[1]["schema"]["type"] == "string"
        assert parameters[2]["name"] == "active"
        assert parameters[2]["schema"]["type"] == "boolean"
    
    def test_infer_parameter_type(self, doc_generator):
        """Testa inferência de tipo de parâmetro"""
        import ast
        
        # Testa inferência por anotação
        arg_with_annotation = ast.arg(arg="test_id", annotation=ast.Name(id="int"))
        assert doc_generator._infer_parameter_type(arg_with_annotation) == "integer"
        
        # Testa inferência por nome
        arg_by_name = ast.arg(arg="user_name")
        assert doc_generator._infer_parameter_type(arg_by_name) == "string"
        
        arg_count = ast.arg(arg="item_count")
        assert doc_generator._infer_parameter_type(arg_count) == "integer"
        
        arg_active = ast.arg(arg="is_active")
        assert doc_generator._infer_parameter_type(arg_active) == "boolean"
    
    def test_determine_tags(self, doc_generator):
        """Testa determinação de tags"""
        # Testa arquivo de blog
        blog_path = Path("app/blog_routes.py")
        assert doc_generator._determine_tags(blog_path) == ["Blog"]
        
        # Testa arquivo de auth
        auth_path = Path("app/auth_routes.py")
        assert doc_generator._determine_tags(auth_path) == ["Authentication"]
        
        # Testa arquivo genérico
        generic_path = Path("app/generic_routes.py")
        assert doc_generator._determine_tags(generic_path) == ["General"]
    
    def test_parse_json_schema(self, doc_generator):
        """Testa parse de schema JSON"""
        schema_data = {
            "title": "TestSchema",
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name"],
            "description": "Test schema description"
        }
        
        file_path = Path("test_schema.json")
        schema = doc_generator._parse_json_schema(schema_data, file_path)
        
        assert schema.name == "TestSchema"
        assert schema.type == "object"
        assert "name" in schema.properties
        assert "name" in schema.required
        assert schema.description == "Test schema description"
    
    def test_extract_string_literal(self, doc_generator):
        """Testa extração de literal de string"""
        import ast
        
        # Testa ast.Str (Python < 3.8)
        str_node = ast.Str(s="test")
        assert doc_generator._extract_string_literal(str_node) == "test"
        
        # Testa ast.Constant (Python >= 3.8)
        const_node = ast.Constant(value="test")
        assert doc_generator._extract_string_literal(const_node) == "test"
        
        # Testa nó inválido
        invalid_node = ast.Name(id="test")
        assert doc_generator._extract_string_literal(invalid_node) == ""

class TestApiEndpoint:
    """Testes para a classe ApiEndpoint"""
    
    def test_api_endpoint_creation(self):
        """Testa criação de ApiEndpoint"""
        endpoint = ApiEndpoint(
            path="/test",
            method="GET",
            summary="Test",
            description="Test description",
            parameters=[],
            request_body=None,
            responses={},
            tags=["Test"],
            deprecated=False,
            version="1.0"
        )
        
        assert endpoint.path == "/test"
        assert endpoint.method == "GET"
        assert endpoint.summary == "Test"
        assert endpoint.description == "Test description"
        assert endpoint.tags == ["Test"]
        assert endpoint.deprecated is False
        assert endpoint.version == "1.0"

class TestSchemaDefinition:
    """Testes para a classe SchemaDefinition"""
    
    def test_schema_definition_creation(self):
        """Testa criação de SchemaDefinition"""
        schema = SchemaDefinition(
            name="TestSchema",
            type="object",
            properties={"test": {"type": "string"}},
            required=["test"],
            description="Test schema",
            version="1.0"
        )
        
        assert schema.name == "TestSchema"
        assert schema.type == "object"
        assert "test" in schema.properties
        assert "test" in schema.required
        assert schema.description == "Test schema"
        assert schema.version == "1.0"

class TestBreakingChange:
    """Testes para a classe BreakingChange"""
    
    def test_breaking_change_creation(self):
        """Testa criação de BreakingChange"""
        change = BreakingChange(
            version="1.1.0",
            date="2025-01-27",
            type="removed",
            endpoint="GET /test",
            description="Parameter removed",
            migration_guide="Remove the parameter"
        )
        
        assert change.version == "1.1.0"
        assert change.date == "2025-01-27"
        assert change.type == "removed"
        assert change.endpoint == "GET /test"
        assert change.description == "Parameter removed"
        assert change.migration_guide == "Remove the parameter"

if __name__ == "__main__":
    pytest.main([__file__]) 