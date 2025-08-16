#!/usr/bin/env python3
"""
Testes unitários para o sistema de documentação automatizada de contratos.
Cobre geração de OpenAPI, JSON Schema e validação de compatibilidade.
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from shared.contract_documentation import (
    ContractDocumentationGenerator, 
    EndpointInfo, 
    SchemaInfo
)

class TestContractDocumentationGenerator:
    """Testes para ContractDocumentationGenerator."""
    
    @pytest.fixture
    def generator(self):
        """Instância do gerador para testes."""
        return ContractDocumentationGenerator(version="1.0.0")
    
    @pytest.fixture
    def mock_app(self):
        """Mock da aplicação Flask."""
        app = Mock()
        
        # Mock de view functions
        def mock_generate():
            """Rota de geração de artigos."""
            pass
        
        def mock_status(trace_id):
            """Consulta status de geração."""
            pass
        
        def mock_download():
            """Download de arquivo."""
            pass
        
        app.view_functions = {
            'routes.generate': mock_generate,
            'routes.status': mock_status,
            'routes.download': mock_download
        }
        
        # Mock de URL rules
        rule1 = Mock()
        rule1.endpoint = 'routes.generate'
        rule1.rule = '/generate'
        rule1.methods = {'POST'}
        rule1.arguments = []
        
        rule2 = Mock()
        rule2.endpoint = 'routes.status'
        rule2.rule = '/status/<trace_id>'
        rule2.methods = {'GET'}
        rule2.arguments = ['trace_id']
        
        rule3 = Mock()
        rule3.endpoint = 'routes.download'
        rule3.rule = '/download'
        rule3.methods = {'GET'}
        rule3.arguments = []
        
        app.url_map.iter_rules.return_value = [rule1, rule2, rule3]
        
        return app
    
    def test_init(self, generator):
        """Testa inicialização do gerador."""
        assert generator.version == "1.0.0"
        assert len(generator.endpoints) == 0
        assert len(generator.schemas) > 0
        assert "openapi" in generator.openapi_config
    
    def test_register_app(self, generator, mock_app):
        """Testa registro de aplicação."""
        generator.register_app(mock_app)
        
        assert generator.app == mock_app
        assert len(generator.endpoints) > 0
    
    def test_extract_url_parameters(self, generator):
        """Testa extração de parâmetros da URL."""
        rule = Mock()
        rule.arguments = ['trace_id', 'user_id']
        
        parameters = generator._extract_url_parameters(rule)
        
        assert len(parameters) == 2
        assert parameters[0]['name'] == 'trace_id'
        assert parameters[0]['in'] == 'path'
        assert parameters[0]['required'] is True
        assert parameters[1]['name'] == 'user_id'
    
    def test_determine_tags(self, generator):
        """Testa determinação de tags."""
        # Teste geração
        tags = generator._determine_tags('/generate')
        assert 'generation' in tags
        
        # Teste download
        tags = generator._determine_tags('/download')
        assert 'download' in tags
        
        # Teste status
        tags = generator._determine_tags('/status/123')
        assert 'status' in tags
        
        # Teste export
        tags = generator._determine_tags('/export_prompts')
        assert 'export' in tags
        
        # Teste feedback
        tags = generator._determine_tags('/feedback')
        assert 'feedback' in tags
        
        # Teste autenticação
        tags = generator._determine_tags('/token/rotate')
        assert 'authentication' in tags
        
        # Teste geral
        tags = generator._determine_tags('/')
        assert 'general' in tags
    
    def test_determine_security(self, generator):
        """Testa determinação de segurança."""
        # Mock de função sem decorators
        func = Mock()
        func._decorators = []
        
        security = generator._determine_security(func)
        assert len(security) == 0
        
        # Mock de função com decorator de autenticação
        func._decorators = ['require_bearer_token']
        security = generator._determine_security(func)
        assert 'bearerAuth' in security
    
    def test_analyze_responses(self, generator):
        """Testa análise de respostas."""
        func = Mock()
        
        responses = generator._analyze_responses(func)
        
        assert len(responses) == 4
        assert any(r['code'] == '200' for r in responses)
        assert any(r['code'] == '400' for r in responses)
        assert any(r['code'] == '401' for r in responses)
        assert any(r['code'] == '500' for r in responses)
    
    def test_extract_schemas(self, generator):
        """Testa extração de schemas."""
        generator._extract_schemas()
        
        assert 'GenerateRequest' in generator.schemas
        assert 'GenerateResponse' in generator.schemas
        assert 'StatusResponse' in generator.schemas
        assert 'FeedbackRequest' in generator.schemas
        assert 'ErrorResponse' in generator.schemas
        
        # Verifica estrutura do schema
        generate_request = generator.schemas['GenerateRequest']
        assert generate_request['type'] == 'object'
        assert 'properties' in generate_request
        assert 'required' in generate_request
        assert 'api_key' in generate_request['required']
    
    def test_generate_openapi_spec(self, generator):
        """Testa geração de especificação OpenAPI."""
        spec = generator.generate_openapi_spec()
        
        assert spec['openapi'] == '3.0.3'
        assert spec['info']['title'] == 'Omni Writer API'
        assert spec['info']['version'] == '1.0.0'
        assert 'paths' in spec
        assert 'components' in spec
        assert 'schemas' in spec['components']
    
    def test_save_openapi_spec(self, generator):
        """Testa salvamento de especificação OpenAPI."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Muda para diretório temporário
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Cria diretório docs
                os.makedirs('docs', exist_ok=True)
                
                # Salva especificação
                filepath = generator.save_openapi_spec('test_openapi.json')
                
                # Verifica se arquivo foi criado
                assert os.path.exists(filepath)
                
                # Verifica conteúdo
                with open(filepath, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                
                assert spec['openapi'] == '3.0.3'
                assert spec['info']['title'] == 'Omni Writer API'
                
            finally:
                os.chdir(original_cwd)
    
    def test_generate_json_schema(self, generator):
        """Testa geração de JSON Schema."""
        schema = generator.generate_json_schema('GenerateRequest')
        
        assert schema['$schema'] == 'http://json-schema.org/draft-07/schema#'
        assert schema['$id'] == 'https://api.omniwriter.com/schemas/GenerateRequest.json'
        assert schema['type'] == 'object'
        assert 'properties' in schema
        assert 'required' in schema
    
    def test_generate_json_schema_invalid(self, generator):
        """Testa geração de JSON Schema com nome inválido."""
        with pytest.raises(ValueError, match="Schema 'InvalidSchema' não encontrado"):
            generator.generate_json_schema('InvalidSchema')
    
    def test_save_json_schema(self, generator):
        """Testa salvamento de JSON Schema."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Muda para diretório temporário
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Cria diretório docs/schemas
                os.makedirs('docs/schemas', exist_ok=True)
                
                # Salva schema
                filepath = generator.save_json_schema('GenerateRequest', 'test_schema.json')
                
                # Verifica se arquivo foi criado
                assert os.path.exists(filepath)
                
                # Verifica conteúdo
                with open(filepath, 'r', encoding='utf-8') as f:
                    schema = json.load(f)
                
                assert schema['$schema'] == 'http://json-schema.org/draft-07/schema#'
                assert schema['type'] == 'object'
                
            finally:
                os.chdir(original_cwd)
    
    def test_validate_contract_compatibility(self, generator):
        """Testa validação de compatibilidade de contratos."""
        # Cria especificações de teste
        old_spec = {
            "paths": {
                "/generate": {
                    "post": {
                        "parameters": [
                            {"name": "api_key", "required": True},
                            {"name": "model_type", "required": True}
                        ]
                    }
                }
            }
        }
        
        new_spec = {
            "paths": {
                "/generate": {
                    "post": {
                        "parameters": [
                            {"name": "api_key", "required": True},
                            {"name": "model_type", "required": False}  # Mudança breaking
                        ]
                    }
                },
                "/new_endpoint": {  # Novo endpoint
                    "get": {}
                }
            }
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Salva especificações temporárias
            old_file = os.path.join(temp_dir, 'old.json')
            new_file = os.path.join(temp_dir, 'new.json')
            
            with open(old_file, 'w') as f:
                json.dump(old_spec, f)
            
            with open(new_file, 'w') as f:
                json.dump(new_spec, f)
            
            # Valida compatibilidade
            report = generator.validate_contract_compatibility(old_file, new_file)
            
            assert report['compatible'] is False
            assert len(report['breaking_changes']) > 0
            assert len(report['new_features']) > 0
    
    def test_validate_contract_compatibility_error(self, generator):
        """Testa validação de compatibilidade com erro."""
        report = generator.validate_contract_compatibility('invalid_file.json', 'another_invalid.json')
        
        assert report['compatible'] is False
        assert 'error' in report
    
    def test_generate_changelog(self, generator):
        """Testa geração de changelog."""
        changelog = generator.generate_changelog('1.0.0', '1.1.0')
        
        assert 'Changelog - v1.1.0' in changelog
        assert 'Data:' in changelog
        assert 'Novos Endpoints' in changelog
        assert 'Schemas Atualizados' in changelog
        assert 'Compatibilidade' in changelog
        assert 'Instruções de Migração' in changelog
    
    def test_save_changelog(self, generator):
        """Testa salvamento de changelog."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Muda para diretório temporário
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                # Cria diretório docs
                os.makedirs('docs', exist_ok=True)
                
                # Salva changelog
                filepath = generator.save_changelog('1.0.0', '1.1.0', 'test_changelog.md')
                
                # Verifica se arquivo foi criado
                assert os.path.exists(filepath)
                
                # Verifica conteúdo
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                assert 'Changelog - v1.1.0' in content
                assert 'Versão anterior: v1.0.0' in content
                assert 'Nova versão: v1.1.0' in content
                
            finally:
                os.chdir(original_cwd)
    
    def test_endpoint_info_dataclass(self):
        """Testa dataclass EndpointInfo."""
        endpoint = EndpointInfo(
            path="/test",
            method="GET",
            function_name="test_function",
            docstring="Test endpoint",
            parameters=[],
            responses=[],
            tags=["test"],
            security=["bearerAuth"]
        )
        
        assert endpoint.path == "/test"
        assert endpoint.method == "GET"
        assert endpoint.function_name == "test_function"
        assert endpoint.docstring == "Test endpoint"
        assert endpoint.tags == ["test"]
        assert endpoint.security == ["bearerAuth"]
        assert endpoint.deprecated is False
    
    def test_schema_info_dataclass(self):
        """Testa dataclass SchemaInfo."""
        schema = SchemaInfo(
            name="TestSchema",
            type="object",
            properties={"test": {"type": "string"}},
            required=["test"],
            description="Test schema",
            example={"test": "example"}
        )
        
        assert schema.name == "TestSchema"
        assert schema.type == "object"
        assert schema.properties == {"test": {"type": "string"}}
        assert schema.required == ["test"]
        assert schema.description == "Test schema"
        assert schema.example == {"test": "example"}
    
    def test_openapi_config_structure(self, generator):
        """Testa estrutura da configuração OpenAPI."""
        config = generator.openapi_config
        
        assert config['openapi'] == '3.0.3'
        assert 'info' in config
        assert 'servers' in config
        assert 'tags' in config
        assert 'components' in config
        
        # Verifica info
        info = config['info']
        assert info['title'] == 'Omni Writer API'
        assert info['version'] == '1.0.0'
        assert 'contact' in info
        assert 'license' in info
        
        # Verifica servers
        servers = config['servers']
        assert len(servers) == 2
        assert any(s['description'] == 'Development server' for s in servers)
        assert any(s['description'] == 'Production server' for s in servers)
        
        # Verifica tags
        tags = config['tags']
        assert len(tags) == 6
        tag_names = [t['name'] for t in tags]
        assert 'generation' in tag_names
        assert 'download' in tag_names
        assert 'status' in tag_names
        assert 'export' in tag_names
        assert 'feedback' in tag_names
        assert 'authentication' in tag_names
        
        # Verifica security schemes
        security_schemes = config['components']['securitySchemes']
        assert 'bearerAuth' in security_schemes
        assert 'apiKey' in security_schemes 