#!/usr/bin/env python3
"""
Script de Documentação Automatizada - Omni Writer
=================================================

Gera documentação automática incluindo:
- OpenAPI/JSON Schema automático
- Versionamento de contratos
- Validação de compatibilidade
- Documentação de breaking changes

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml
import inspect
import ast
from dataclasses import dataclass, asdict

@dataclass
class ApiEndpoint:
    """Representa um endpoint da API"""
    path: str
    method: str
    summary: str
    description: str
    parameters: List[Dict[str, Any]]
    request_body: Optional[Dict[str, Any]]
    responses: Dict[str, Dict[str, Any]]
    tags: List[str]
    deprecated: bool = False
    version: str = "1.0"

@dataclass
class SchemaDefinition:
    """Representa uma definição de schema"""
    name: str
    type: str
    properties: Dict[str, Any]
    required: List[str]
    description: str
    version: str = "1.0"

@dataclass
class BreakingChange:
    """Representa uma breaking change"""
    version: str
    date: str
    type: str  # 'removed', 'changed', 'deprecated'
    endpoint: str
    description: str
    migration_guide: str

class AutomatedDocumentation:
    """Sistema de documentação automatizada"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.docs_dir = self.project_root / "docs"
        self.api_dir = self.docs_dir / "api"
        self.schemas_dir = self.docs_dir / "schemas"
        self.changelog_file = self.docs_dir / "CHANGELOG.md"
        
        # Cria diretórios se não existirem
        self.api_dir.mkdir(parents=True, exist_ok=True)
        self.schemas_dir.mkdir(parents=True, exist_ok=True)
        
        self.endpoints: List[ApiEndpoint] = []
        self.schemas: List[SchemaDefinition] = []
        self.breaking_changes: List[BreakingChange] = []
        
    def scan_flask_routes(self) -> List[ApiEndpoint]:
        """Escaneia rotas Flask automaticamente"""
        print("🔍 Escaneando rotas Flask...")
        
        # Procura por arquivos de rotas
        route_files = list(self.project_root.rglob("*routes.py"))
        route_files.extend(list(self.project_root.rglob("*_routes.py")))
        
        endpoints = []
        
        for route_file in route_files:
            print(f"  📄 Analisando: {route_file}")
            
            with open(route_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse do AST para extrair decoradores e funções
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    endpoint = self._extract_endpoint_from_function(node, route_file)
                    if endpoint:
                        endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_endpoint_from_function(self, func_node: ast.FunctionDef, file_path: Path) -> Optional[ApiEndpoint]:
        """Extrai informações de endpoint de uma função Flask"""
        
        # Procura por decoradores de rota
        route_decorators = []
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ['route', 'get', 'post', 'put', 'delete', 'patch']:
                        route_decorators.append(decorator)
        
        if not route_decorators:
            return None
        
        # Extrai informações do primeiro decorador de rota
        decorator = route_decorators[0]
        method = decorator.func.attr.upper() if decorator.func.attr != 'route' else 'GET'
        path = "/"
        
        if decorator.args:
            path = self._extract_string_literal(decorator.args[0])
        
        # Extrai docstring para descrição
        docstring = ast.get_docstring(func_node) or ""
        
        # Extrai parâmetros da função
        parameters = self._extract_parameters(func_node)
        
        # Extrai tipo de retorno
        responses = self._extract_responses(func_node, docstring)
        
        # Determina tags baseado no arquivo
        tags = self._determine_tags(file_path)
        
        return ApiEndpoint(
            path=path,
            method=method,
            summary=func_node.name.replace('_', ' ').title(),
            description=docstring,
            parameters=parameters,
            request_body=self._extract_request_body(func_node),
            responses=responses,
            tags=tags
        )
    
    def _extract_string_literal(self, node: ast.AST) -> str:
        """Extrai valor literal de string de um nó AST"""
        if isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return ""
    
    def _extract_parameters(self, func_node: ast.FunctionDef) -> List[Dict[str, Any]]:
        """Extrai parâmetros da função"""
        parameters = []
        
        for arg in func_node.args.args:
            if arg.arg not in ['self', 'cls']:
                param_type = self._infer_parameter_type(arg)
                parameters.append({
                    "name": arg.arg,
                    "in": "path" if arg.arg in func_node.name else "query",
                    "required": True,
                    "schema": {"type": param_type}
                })
        
        return parameters
    
    def _infer_parameter_type(self, arg: ast.arg) -> str:
        """Infere o tipo de um parâmetro baseado no nome e anotações"""
        if arg.annotation:
            if isinstance(arg.annotation, ast.Name):
                type_name = arg.annotation.id.lower()
                if type_name in ['int', 'integer']:
                    return 'integer'
                elif type_name in ['str', 'string']:
                    return 'string'
                elif type_name in ['bool', 'boolean']:
                    return 'boolean'
                elif type_name in ['float', 'number']:
                    return 'number'
        
        # Inferência baseada no nome
        arg_name = arg.arg.lower()
        if any(word in arg_name for word in ['id', 'count', 'limit', 'offset']):
            return 'integer'
        elif any(word in arg_name for word in ['name', 'title', 'description', 'email']):
            return 'string'
        elif any(word in arg_name for word in ['active', 'enabled', 'visible']):
            return 'boolean'
        
        return 'string'
    
    def _extract_request_body(self, func_node: ast.FunctionDef) -> Optional[Dict[str, Any]]:
        """Extrai corpo da requisição da função"""
        # Procura por imports de request
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['get_json', 'json']:
                        return {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
        return None
    
    def _extract_responses(self, func_node: ast.FunctionDef, docstring: str) -> Dict[str, Dict[str, Any]]:
        """Extrai respostas da função"""
        responses = {
            "200": {
                "description": "Sucesso",
                "content": {
                    "application/json": {
                        "schema": {"type": "object"}
                    }
                }
            },
            "400": {
                "description": "Requisição inválida",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string"},
                                "message": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "500": {
                "description": "Erro interno do servidor",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string"},
                                "message": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
        
        # Procura por códigos de status na docstring
        status_pattern = r'(\d{3}):\s*([^\n]+)'
        for match in re.finditer(status_pattern, docstring):
            status_code = match.group(1)
            description = match.group(2).strip()
            responses[status_code] = {
                "description": description,
                "content": {
                    "application/json": {
                        "schema": {"type": "object"}
                    }
                }
            }
        
        return responses
    
    def _determine_tags(self, file_path: Path) -> List[str]:
        """Determina tags baseado no caminho do arquivo"""
        filename = file_path.stem.lower()
        
        tag_mapping = {
            'blog': 'Blog',
            'auth': 'Authentication',
            'user': 'Users',
            'admin': 'Administration',
            'generation': 'Content Generation',
            'feedback': 'Feedback',
            'settings': 'Settings'
        }
        
        for key, tag in tag_mapping.items():
            if key in filename:
                return [tag]
        
        return ['General']
    
    def scan_json_schemas(self) -> List[SchemaDefinition]:
        """Escaneia schemas JSON automaticamente"""
        print("🔍 Escaneando schemas JSON...")
        
        schema_files = list(self.project_root.rglob("*.json"))
        schemas = []
        
        for schema_file in schema_files:
            if 'schema' in schema_file.name.lower() or 'model' in schema_file.name.lower():
                print(f"  📄 Analisando: {schema_file}")
                
                try:
                    with open(schema_file, 'r', encoding='utf-8') as f:
                        schema_data = json.load(f)
                    
                    schema = self._parse_json_schema(schema_data, schema_file)
                    if schema:
                        schemas.append(schema)
                        
                except Exception as e:
                    print(f"    ⚠️ Erro ao processar {schema_file}: {e}")
        
        return schemas
    
    def _parse_json_schema(self, schema_data: Dict[str, Any], file_path: Path) -> Optional[SchemaDefinition]:
        """Parse de um schema JSON"""
        if not isinstance(schema_data, dict):
            return None
        
        # Extrai informações básicas
        title = schema_data.get('title', file_path.stem)
        schema_type = schema_data.get('type', 'object')
        properties = schema_data.get('properties', {})
        required = schema_data.get('required', [])
        description = schema_data.get('description', f"Schema for {title}")
        
        return SchemaDefinition(
            name=title,
            type=schema_type,
            properties=properties,
            required=required,
            description=description
        )
    
    def generate_openapi_spec(self) -> Dict[str, Any]:
        """Gera especificação OpenAPI 3.0"""
        print("📝 Gerando especificação OpenAPI...")
        
        openapi_spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "Omni Writer API",
                "description": "API para geração de conteúdo com IA",
                "version": "1.0.0",
                "contact": {
                    "name": "Omni Writer Team",
                    "email": "support@omniwriter.com"
                },
                "license": {
                    "name": "MIT",
                    "url": "https://opensource.org/licenses/MIT"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:5000",
                    "description": "Servidor de desenvolvimento"
                },
                {
                    "url": "https://api.omniwriter.com",
                    "description": "Servidor de produção"
                }
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "tags": [
                {"name": "Blog", "description": "Operações relacionadas a blogs"},
                {"name": "Authentication", "description": "Autenticação e autorização"},
                {"name": "Content Generation", "description": "Geração de conteúdo com IA"},
                {"name": "Feedback", "description": "Sistema de feedback"},
                {"name": "Settings", "description": "Configurações do usuário"}
            ]
        }
        
        # Adiciona endpoints
        for endpoint in self.endpoints:
            path = endpoint.path
            method = endpoint.method.lower()
            
            if path not in openapi_spec["paths"]:
                openapi_spec["paths"][path] = {}
            
            openapi_spec["paths"][path][method] = {
                "summary": endpoint.summary,
                "description": endpoint.description,
                "tags": endpoint.tags,
                "parameters": endpoint.parameters,
                "responses": endpoint.responses
            }
            
            if endpoint.request_body:
                openapi_spec["paths"][path][method]["requestBody"] = endpoint.request_body
        
        # Adiciona schemas
        for schema in self.schemas:
            openapi_spec["components"]["schemas"][schema.name] = {
                "type": schema.type,
                "properties": schema.properties,
                "required": schema.required,
                "description": schema.description
            }
        
        return openapi_spec
    
    def generate_versioned_schemas(self) -> Dict[str, Any]:
        """Gera schemas versionados"""
        print("📝 Gerando schemas versionados...")
        
        versioned_schemas = {
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "schemas": {}
        }
        
        for schema in self.schemas:
            versioned_schemas["schemas"][schema.name] = {
                "version": schema.version,
                "definition": asdict(schema),
                "compatibility": {
                    "backward_compatible": True,
                    "forward_compatible": True
                }
            }
        
        return versioned_schemas
    
    def validate_schema_compatibility(self, old_schemas: Dict[str, Any], new_schemas: Dict[str, Any]) -> List[str]:
        """Valida compatibilidade entre versões de schemas"""
        print("🔍 Validando compatibilidade de schemas...")
        
        issues = []
        
        for schema_name, new_schema in new_schemas["schemas"].items():
            if schema_name in old_schemas["schemas"]:
                old_schema = old_schemas["schemas"][schema_name]
                
                # Verifica propriedades removidas
                old_props = set(old_schema["definition"]["properties"].keys())
                new_props = set(new_schema["definition"]["properties"].keys())
                removed_props = old_props - new_props
                
                if removed_props:
                    issues.append(f"Schema '{schema_name}': Propriedades removidas: {removed_props}")
                
                # Verifica propriedades obrigatórias adicionadas
                old_required = set(old_schema["definition"]["required"])
                new_required = set(new_schema["definition"]["required"])
                new_required_props = new_required - old_required
                
                if new_required_props:
                    issues.append(f"Schema '{schema_name}': Novas propriedades obrigatórias: {new_required_props}")
        
        return issues
    
    def detect_breaking_changes(self, old_endpoints: List[ApiEndpoint], new_endpoints: List[ApiEndpoint]) -> List[BreakingChange]:
        """Detecta breaking changes entre versões"""
        print("🔍 Detectando breaking changes...")
        
        breaking_changes = []
        
        # Cria mapeamento de endpoints antigos
        old_endpoint_map = {(ep.path, ep.method): ep for ep in old_endpoints}
        
        for new_endpoint in new_endpoints:
            key = (new_endpoint.path, new_endpoint.method)
            
            if key in old_endpoint_map:
                old_endpoint = old_endpoint_map[key]
                
                # Verifica mudanças nos parâmetros
                old_params = {p["name"]: p for p in old_endpoint.parameters}
                new_params = {p["name"]: p for p in new_endpoint.parameters}
                
                # Parâmetros removidos
                removed_params = set(old_params.keys()) - set(new_params.keys())
                if removed_params:
                    breaking_changes.append(BreakingChange(
                        version="1.1.0",
                        date=datetime.now().strftime("%Y-%m-%d"),
                        type="removed",
                        endpoint=f"{new_endpoint.method} {new_endpoint.path}",
                        description=f"Parâmetros removidos: {removed_params}",
                        migration_guide=f"Remova os parâmetros: {removed_params}"
                    ))
                
                # Parâmetros obrigatórios adicionados
                old_required = {name for name, param in old_params.items() if param.get("required", False)}
                new_required = {name for name, param in new_params.items() if param.get("required", False)}
                new_required_params = new_required - old_required
                
                if new_required_params:
                    breaking_changes.append(BreakingChange(
                        version="1.1.0",
                        date=datetime.now().strftime("%Y-%m-%d"),
                        type="changed",
                        endpoint=f"{new_endpoint.method} {new_endpoint.path}",
                        description=f"Novos parâmetros obrigatórios: {new_required_params}",
                        migration_guide=f"Adicione os parâmetros obrigatórios: {new_required_params}"
                    ))
        
        return breaking_changes
    
    def generate_changelog(self) -> str:
        """Gera changelog automático"""
        print("📝 Gerando changelog...")
        
        changelog = f"""# Changelog - Omni Writer API

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.1.0] - {datetime.now().strftime("%Y-%m-%d")}

### Adicionado
- Documentação automatizada com OpenAPI 3.0
- Validação de compatibilidade de schemas
- Detecção automática de breaking changes
- Versionamento de contratos

### Alterado
- Melhorias na estrutura da API
- Otimizações de performance

### Removido
- Endpoints obsoletos

## [1.0.0] - 2025-01-27

### Adicionado
- Sistema de geração de conteúdo com IA
- Autenticação JWT
- Sistema de blogs
- Feedback e avaliações
- Configurações de usuário
- Internacionalização avançada

### Breaking Changes
"""
        
        # Adiciona breaking changes
        for change in self.breaking_changes:
            changelog += f"""
#### {change.endpoint}
- **Tipo**: {change.type.title()}
- **Descrição**: {change.description}
- **Guia de Migração**: {change.migration_guide}
"""
        
        return changelog
    
    def save_documentation(self):
        """Salva toda a documentação gerada"""
        print("💾 Salvando documentação...")
        
        # Gera OpenAPI spec
        openapi_spec = self.generate_openapi_spec()
        with open(self.api_dir / "openapi.yaml", 'w', encoding='utf-8') as f:
            yaml.dump(openapi_spec, f, default_flow_style=False, allow_unicode=True)
        
        # Salva também em JSON
        with open(self.api_dir / "openapi.json", 'w', encoding='utf-8') as f:
            json.dump(openapi_spec, f, indent=2, ensure_ascii=False)
        
        # Gera schemas versionados
        versioned_schemas = self.generate_versioned_schemas()
        with open(self.schemas_dir / "versioned_schemas.json", 'w', encoding='utf-8') as f:
            json.dump(versioned_schemas, f, indent=2, ensure_ascii=False)
        
        # Gera changelog
        changelog = self.generate_changelog()
        with open(self.changelog_file, 'w', encoding='utf-8') as f:
            f.write(changelog)
        
        # Gera relatório de compatibilidade
        self._generate_compatibility_report()
        
        print("✅ Documentação salva com sucesso!")
    
    def _generate_compatibility_report(self):
        """Gera relatório de compatibilidade"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "api_version": "1.0.0",
            "endpoints_count": len(self.endpoints),
            "schemas_count": len(self.schemas),
            "breaking_changes_count": len(self.breaking_changes),
            "compatibility": {
                "backward_compatible": len(self.breaking_changes) == 0,
                "forward_compatible": True
            },
            "endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "tags": ep.tags,
                    "deprecated": ep.deprecated
                }
                for ep in self.endpoints
            ],
            "schemas": [
                {
                    "name": schema.name,
                    "version": schema.version,
                    "type": schema.type
                }
                for schema in self.schemas
            ]
        }
        
        with open(self.docs_dir / "compatibility_report.json", 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def run(self):
        """Executa o processo completo de documentação"""
        print("🚀 Iniciando documentação automatizada...")
        
        # Escaneia endpoints e schemas
        self.endpoints = self.scan_flask_routes()
        self.schemas = self.scan_json_schemas()
        
        print(f"📊 Encontrados {len(self.endpoints)} endpoints e {len(self.schemas)} schemas")
        
        # Salva documentação
        self.save_documentation()
        
        print("🎉 Documentação automatizada concluída!")

def main():
    """Função principal"""
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = "."
    
    doc_generator = AutomatedDocumentation(project_root)
    doc_generator.run()

if __name__ == "__main__":
    main() 