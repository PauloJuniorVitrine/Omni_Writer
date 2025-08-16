#!/usr/bin/env python3
"""
Script para geração automática de contratos OpenAPI
Tracing ID: CONTRACT_GEN_20250127_001
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
import yaml
from datetime import datetime

# Adicionar o diretório raiz ao path
sys.path.append(str(Path(__file__).parent.parent))

from app.routes import app
from shared.schemas import blog_schema, categoria_schema, prompt_schema

class ContractGenerator:
    """Gerador automático de contratos OpenAPI"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.output_dir = self.base_path / "docs" / "generated"
        self.output_dir.mkdir(exist_ok=True)
        
    def generate_openapi_spec(self) -> Dict[str, Any]:
        """Gera especificação OpenAPI a partir das rotas Flask"""
        
        openapi_spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "Omni Writer API",
                "version": "1.0.0",
                "description": "API para geração de conteúdo com IA",
                "contact": {
                    "name": "Omni Writer Team"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:5000",
                    "description": "Development server"
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
            "security": [
                {
                    "bearerAuth": []
                }
            ]
        }
        
        # Extrair rotas do Flask app
        for rule in app.url_map.iter_rules():
            if rule.rule.startswith('/api/'):
                self._add_route_to_spec(openapi_spec, rule)
        
        # Adicionar schemas
        self._add_schemas_to_spec(openapi_spec)
        
        return openapi_spec
    
    def _add_route_to_spec(self, spec: Dict[str, Any], rule) -> None:
        """Adiciona rota ao spec OpenAPI"""
        
        path = rule.rule
        methods = list(rule.methods - {'HEAD', 'OPTIONS'})
        
        if path not in spec["paths"]:
            spec["paths"][path] = {}
        
        for method in methods:
            method_lower = method.lower()
            
            # Determinar operação baseada no método e path
            operation = self._determine_operation(method_lower, path)
            
            spec["paths"][path][method_lower] = {
                "summary": operation["summary"],
                "description": operation["description"],
                "tags": operation["tags"],
                "responses": operation["responses"]
            }
            
            # Adicionar parâmetros se necessário
            if "<" in path:
                spec["paths"][path][method_lower]["parameters"] = [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "string"
                        },
                        "description": "ID do recurso"
                    }
                ]
            
            # Adicionar request body para POST/PUT
            if method_lower in ["post", "put", "patch"]:
                spec["paths"][path][method_lower]["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": self._get_request_schema(path, method_lower)
                        }
                    }
                }
    
    def _determine_operation(self, method: str, path: str) -> Dict[str, Any]:
        """Determina operação baseada no método e path"""
        
        operations = {
            "/api/blogs": {
                "get": {
                    "summary": "Listar blogs",
                    "description": "Retorna lista de todos os blogs",
                    "tags": ["Blogs"],
                    "responses": {
                        "200": {
                            "description": "Lista de blogs",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/Blog"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Criar blog",
                    "description": "Cria um novo blog",
                    "tags": ["Blogs"],
                    "responses": {
                        "201": {
                            "description": "Blog criado",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Blog"}
                                }
                            }
                        }
                    }
                }
            },
            "/generate": {
                "post": {
                    "summary": "Gerar conteúdo",
                    "description": "Gera conteúdo usando IA",
                    "tags": ["Geração"],
                    "responses": {
                        "200": {
                            "description": "Conteúdo gerado",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "content": {"type": "string"},
                                            "trace_id": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Encontrar operação correspondente
        for base_path, methods in operations.items():
            if path.startswith(base_path):
                if method in methods:
                    return methods[method]
        
        # Operação padrão
        return {
            "summary": f"{method.upper()} {path}",
            "description": f"Operação {method.upper()} em {path}",
            "tags": ["API"],
            "responses": {
                "200": {
                    "description": "Sucesso"
                }
            }
        }
    
    def _get_request_schema(self, path: str, method: str) -> Dict[str, Any]:
        """Obtém schema para request body"""
        
        schemas = {
            "/api/blogs": {
                "post": {"$ref": "#/components/schemas/BlogCreate"}
            },
            "/generate": {
                "post": {"$ref": "#/components/schemas/GenerationRequest"}
            }
        }
        
        for base_path, methods in schemas.items():
            if path.startswith(base_path) and method in methods:
                return methods[method]
        
        return {"type": "object"}
    
    def _add_schemas_to_spec(self, spec: Dict[str, Any]) -> None:
        """Adiciona schemas ao spec OpenAPI"""
        
        spec["components"]["schemas"] = {
            "Blog": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"}
                },
                "required": ["title", "content"]
            },
            "BlogCreate": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["title", "content"]
            },
            "GenerationRequest": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "max_tokens": {"type": "integer"},
                    "temperature": {"type": "number"}
                },
                "required": ["prompt"]
            },
            "Error": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "trace_id": {"type": "string"}
                }
            }
        }
    
    def save_spec(self, spec: Dict[str, Any]) -> None:
        """Salva especificação OpenAPI"""
        
        # Salvar como YAML
        yaml_path = self.output_dir / "openapi_generated.yaml"
        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(spec, f, default_flow_style=False, sort_keys=False)
        
        # Salvar como JSON
        json_path = self.output_dir / "openapi_generated.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Contratos gerados em:")
        print(f"   📄 {yaml_path}")
        print(f"   📄 {json_path}")

def main():
    """Função principal"""
    print("🔗 Gerando contratos OpenAPI automaticamente...")
    
    generator = ContractGenerator()
    spec = generator.generate_openapi_spec()
    generator.save_spec(spec)
    
    print("✅ Geração de contratos concluída!")

if __name__ == "__main__":
    main() 