#!/usr/bin/env python3
"""
Sistema de Documentação Automatizada de Contratos para Omni Writer.
Gera OpenAPI/JSON Schema automaticamente a partir das rotas e modelos.
"""

import os
import json
import inspect
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass, asdict
import logging

# Configuração de logging
doc_logger = logging.getLogger('contract_documentation')
doc_logger.setLevel(logging.INFO)

@dataclass
class EndpointInfo:
    """Informações de um endpoint."""
    path: str
    method: str
    function_name: str
    docstring: str
    parameters: List[Dict]
    responses: List[Dict]
    tags: List[str]
    security: List[str]
    deprecated: bool = False

@dataclass
class SchemaInfo:
    """Informações de um schema."""
    name: str
    type: str
    properties: Dict
    required: List[str]
    description: str
    example: Optional[Dict] = None

class ContractDocumentationGenerator:
    """
    Gerador de documentação automatizada de contratos.
    
    Funcionalidades:
    - Geração automática de OpenAPI 3.0
    - Extração de schemas de modelos
    - Versionamento de contratos
    - Validação de compatibilidade
    - Documentação de breaking changes
    """
    
    def __init__(self, app=None, version: str = "1.0.0"):
        self.app = app
        self.version = version
        self.endpoints = []
        self.schemas = {}
        self.base_path = "/"
        
        # Configurações OpenAPI
        self.openapi_config = {
            "openapi": "3.0.3",
            "info": {
                "title": "Omni Writer API",
                "description": "API para geração automatizada de artigos",
                "version": version,
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
                    "description": "Development server"
                },
                {
                    "url": "https://api.omniwriter.com",
                    "description": "Production server"
                }
            ],
            "tags": [
                {
                    "name": "generation",
                    "description": "Geração de artigos"
                },
                {
                    "name": "download",
                    "description": "Download de arquivos"
                },
                {
                    "name": "status",
                    "description": "Status de operações"
                },
                {
                    "name": "export",
                    "description": "Exportação de dados"
                },
                {
                    "name": "feedback",
                    "description": "Sistema de feedback"
                },
                {
                    "name": "authentication",
                    "description": "Autenticação e tokens"
                }
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    }
                }
            }
        }
    
    def register_app(self, app):
        """Registra aplicação Flask para extração automática."""
        self.app = app
        self._extract_endpoints()
        self._extract_schemas()
    
    def _extract_endpoints(self):
        """Extrai informações dos endpoints da aplicação."""
        if not self.app:
            return
        
        for rule in self.app.url_map.iter_rules():
            endpoint_info = self._analyze_endpoint(rule)
            if endpoint_info:
                self.endpoints.append(endpoint_info)
    
    def _analyze_endpoint(self, rule) -> Optional[EndpointInfo]:
        """Analisa um endpoint específico."""
        try:
            # Obtém função do endpoint
            view_func = self.app.view_functions.get(rule.endpoint)
            if not view_func:
                return None
            
            # Extrai informações básicas
            path = str(rule)
            methods = list(rule.methods - {'HEAD', 'OPTIONS'})
            
            # Analisa docstring
            docstring = inspect.getdoc(view_func) or ""
            
            # Extrai parâmetros da URL
            parameters = self._extract_url_parameters(rule)
            
            # Determina tags baseado no path
            tags = self._determine_tags(path)
            
            # Determina segurança baseado em decorators
            security = self._determine_security(view_func)
            
            # Analisa respostas baseado no código
            responses = self._analyze_responses(view_func)
            
            return EndpointInfo(
                path=path,
                method=methods[0] if methods else "GET",
                function_name=view_func.__name__,
                docstring=docstring,
                parameters=parameters,
                responses=responses,
                tags=tags,
                security=security
            )
            
        except Exception as e:
            doc_logger.error(f"Erro ao analisar endpoint {rule}: {e}")
            return None
    
    def _extract_url_parameters(self, rule) -> List[Dict]:
        """Extrai parâmetros da URL."""
        parameters = []
        
        # Parâmetros de path
        for param in rule.arguments:
            parameters.append({
                "name": param,
                "in": "path",
                "required": True,
                "schema": {
                    "type": "string"
                },
                "description": f"Parâmetro {param} da URL"
            })
        
        return parameters
    
    def _determine_tags(self, path: str) -> List[str]:
        """Determina tags baseado no path."""
        if "/generate" in path:
            return ["generation"]
        elif "/download" in path:
            return ["download"]
        elif "/status" in path or "/events" in path:
            return ["status"]
        elif "/export" in path:
            return ["export"]
        elif "/feedback" in path:
            return ["feedback"]
        elif "/token" in path or "/api/protegido" in path:
            return ["authentication"]
        else:
            return ["general"]
    
    def _determine_security(self, view_func) -> List[str]:
        """Determina esquemas de segurança baseado em decorators."""
        security = []
        
        # Verifica se tem decorator de autenticação
        if hasattr(view_func, '_decorators'):
            for decorator in view_func._decorators:
                if 'require_bearer_token' in str(decorator):
                    security.append("bearerAuth")
                elif 'limiter' in str(decorator):
                    security.append("apiKey")
        
        return security
    
    def _analyze_responses(self, view_func) -> List[Dict]:
        """Analisa possíveis respostas da função."""
        responses = [
            {
                "code": "200",
                "description": "Sucesso",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object"
                        }
                    }
                }
            },
            {
                "code": "400",
                "description": "Dados inválidos",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            },
            {
                "code": "401",
                "description": "Não autorizado",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            },
            {
                "code": "500",
                "description": "Erro interno do servidor",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            }
        ]
        
        return responses
    
    def _extract_schemas(self):
        """Extrai schemas de modelos da aplicação."""
        # Schemas básicos baseados nas rotas
        self.schemas = {
            "GenerateRequest": {
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Chave de API para autenticação",
                        "minLength": 8,
                        "maxLength": 100
                    },
                    "model_type": {
                        "type": "string",
                        "description": "Tipo do modelo a ser usado",
                        "enum": ["openai", "deepseek"]
                    },
                    "instancias_json": {
                        "type": "string",
                        "description": "JSON com instâncias de geração"
                    }
                },
                "required": ["api_key", "model_type", "instancias_json"]
            },
            "GenerateResponse": {
                "type": "object",
                "properties": {
                    "download_link": {
                        "type": "string",
                        "description": "Link para download do arquivo gerado"
                    },
                    "trace_id": {
                        "type": "string",
                        "description": "ID de rastreamento da operação"
                    },
                    "status": {
                        "type": "string",
                        "description": "Status da geração",
                        "enum": ["processing", "completed", "failed"]
                    }
                }
            },
            "StatusResponse": {
                "type": "object",
                "properties": {
                    "trace_id": {
                        "type": "string",
                        "description": "ID de rastreamento"
                    },
                    "status": {
                        "type": "string",
                        "description": "Status atual",
                        "enum": ["processing", "completed", "failed"]
                    },
                    "progress": {
                        "type": "integer",
                        "description": "Progresso em porcentagem",
                        "minimum": 0,
                        "maximum": 100
                    },
                    "message": {
                        "type": "string",
                        "description": "Mensagem de status"
                    },
                    "created_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "Data de criação"
                    }
                }
            },
            "FeedbackRequest": {
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "ID do usuário"
                    },
                    "artigo_id": {
                        "type": "string",
                        "description": "ID do artigo"
                    },
                    "tipo": {
                        "type": "string",
                        "description": "Tipo de feedback",
                        "enum": ["positive", "negative", "suggestion"]
                    },
                    "comentario": {
                        "type": "string",
                        "description": "Comentário do feedback"
                    }
                },
                "required": ["user_id", "artigo_id", "tipo", "comentario"]
            },
            "ErrorResponse": {
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "description": "Mensagem de erro"
                    },
                    "code": {
                        "type": "string",
                        "description": "Código de erro"
                    },
                    "details": {
                        "type": "object",
                        "description": "Detalhes adicionais do erro"
                    }
                },
                "required": ["error"]
            }
        }
    
    def generate_openapi_spec(self) -> Dict:
        """
        Gera especificação OpenAPI completa.
        
        Returns:
            Dicionário com especificação OpenAPI 3.0
        """
        spec = self.openapi_config.copy()
        
        # Adiciona paths
        spec["paths"] = {}
        for endpoint in self.endpoints:
            path = endpoint.path
            method = endpoint.method.lower()
            
            if path not in spec["paths"]:
                spec["paths"][path] = {}
            
            spec["paths"][path][method] = {
                "summary": endpoint.docstring.split('\n')[0] if endpoint.docstring else endpoint.function_name,
                "description": endpoint.docstring,
                "tags": endpoint.tags,
                "parameters": endpoint.parameters,
                "responses": {
                    resp["code"]: {
                        "description": resp["description"],
                        "content": resp["content"]
                    }
                    for resp in endpoint.responses
                }
            }
            
            # Adiciona segurança se necessário
            if endpoint.security:
                spec["paths"][path][method]["security"] = [
                    {scheme: []} for scheme in endpoint.security
                ]
        
        # Adiciona schemas
        spec["components"]["schemas"] = self.schemas
        
        return spec
    
    def save_openapi_spec(self, filename: str = None) -> str:
        """
        Salva especificação OpenAPI em arquivo.
        
        Args:
            filename: Nome do arquivo (opcional)
        
        Returns:
            Caminho do arquivo salvo
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"openapi_spec_v{self.version}_{timestamp}.json"
        
        # Cria diretório se não existir
        os.makedirs('docs', exist_ok=True)
        filepath = os.path.join('docs', filename)
        
        spec = self.generate_openapi_spec()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)
        
        doc_logger.info(f"Especificação OpenAPI salva em: {filepath}")
        return filepath
    
    def generate_json_schema(self, schema_name: str) -> Dict:
        """
        Gera JSON Schema para um modelo específico.
        
        Args:
            schema_name: Nome do schema
        
        Returns:
            JSON Schema do modelo
        """
        if schema_name not in self.schemas:
            raise ValueError(f"Schema '{schema_name}' não encontrado")
        
        schema = self.schemas[schema_name].copy()
        schema["$schema"] = "http://json-schema.org/draft-07/schema#"
        schema["$id"] = f"https://api.omniwriter.com/schemas/{schema_name}.json"
        
        return schema
    
    def save_json_schema(self, schema_name: str, filename: str = None) -> str:
        """
        Salva JSON Schema em arquivo.
        
        Args:
            schema_name: Nome do schema
            filename: Nome do arquivo (opcional)
        
        Returns:
            Caminho do arquivo salvo
        """
        if not filename:
            filename = f"{schema_name}_schema.json"
        
        os.makedirs('docs/schemas', exist_ok=True)
        filepath = os.path.join('docs/schemas', filename)
        
        schema = self.generate_json_schema(schema_name)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(schema, f, indent=2, ensure_ascii=False)
        
        doc_logger.info(f"JSON Schema salvo em: {filepath}")
        return filepath
    
    def validate_contract_compatibility(self, old_spec_path: str, new_spec_path: str) -> Dict:
        """
        Valida compatibilidade entre versões de contratos.
        
        Args:
            old_spec_path: Caminho da especificação antiga
            new_spec_path: Caminho da especificação nova
        
        Returns:
            Relatório de compatibilidade
        """
        try:
            with open(old_spec_path, 'r', encoding='utf-8') as f:
                old_spec = json.load(f)
            
            with open(new_spec_path, 'r', encoding='utf-8') as f:
                new_spec = json.load(f)
            
            report = {
                "compatible": True,
                "breaking_changes": [],
                "new_features": [],
                "deprecated_features": [],
                "warnings": []
            }
            
            # Compara endpoints
            old_paths = old_spec.get("paths", {})
            new_paths = new_spec.get("paths", {})
            
            # Verifica endpoints removidos
            for path in old_paths:
                if path not in new_paths:
                    report["breaking_changes"].append(f"Endpoint removido: {path}")
                    report["compatible"] = False
            
            # Verifica novos endpoints
            for path in new_paths:
                if path not in old_paths:
                    report["new_features"].append(f"Novo endpoint: {path}")
            
            # Verifica mudanças em endpoints existentes
            for path in old_paths:
                if path in new_paths:
                    old_methods = old_paths[path]
                    new_methods = new_paths[path]
                    
                    for method in old_methods:
                        if method in new_methods:
                            # Compara parâmetros
                            old_params = old_methods[method].get("parameters", [])
                            new_params = new_methods[method].get("parameters", [])
                            
                            # Verifica parâmetros obrigatórios removidos
                            old_required = {p["name"] for p in old_params if p.get("required", False)}
                            new_required = {p["name"] for p in new_params if p.get("required", False)}
                            
                            removed_required = old_required - new_required
                            if removed_required:
                                report["breaking_changes"].append(
                                    f"Parâmetros obrigatórios removidos em {path} {method}: {removed_required}"
                                )
                                report["compatible"] = False
            
            return report
            
        except Exception as e:
            return {
                "compatible": False,
                "error": str(e),
                "breaking_changes": [],
                "new_features": [],
                "deprecated_features": [],
                "warnings": []
            }
    
    def generate_changelog(self, old_version: str, new_version: str) -> str:
        """
        Gera changelog entre versões.
        
        Args:
            old_version: Versão anterior
            new_version: Nova versão
        
        Returns:
            Changelog formatado
        """
        changelog = f"""# Changelog - v{new_version}

## Data: {datetime.now().strftime('%Y-%m-%d')}

### Novos Endpoints
"""
        
        # Adiciona novos endpoints
        for endpoint in self.endpoints:
            changelog += f"- `{endpoint.method} {endpoint.path}` - {endpoint.docstring.split('.')[0]}\n"
        
        changelog += """
### Schemas Atualizados
"""
        
        # Adiciona schemas
        for schema_name in self.schemas:
            changelog += f"- `{schema_name}` - Schema atualizado\n"
        
        changelog += f"""
### Compatibilidade
- **Versão anterior**: v{old_version}
- **Nova versão**: v{new_version}
- **Breaking changes**: Nenhuma detectada

### Instruções de Migração
1. Atualize a versão da API no seu cliente
2. Teste os novos endpoints
3. Verifique compatibilidade com schemas existentes

---
*Gerado automaticamente pelo sistema de documentação*
"""
        
        return changelog
    
    def save_changelog(self, old_version: str, new_version: str, filename: str = None) -> str:
        """
        Salva changelog em arquivo.
        
        Args:
            old_version: Versão anterior
            new_version: Nova versão
            filename: Nome do arquivo (opcional)
        
        Returns:
            Caminho do arquivo salvo
        """
        if not filename:
            filename = f"CHANGELOG_v{old_version}_to_v{new_version}.md"
        
        os.makedirs('docs', exist_ok=True)
        filepath = os.path.join('docs', filename)
        
        changelog = self.generate_changelog(old_version, new_version)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(changelog)
        
        doc_logger.info(f"Changelog salvo em: {filepath}")
        return filepath

# Instância global
contract_doc_generator = ContractDocumentationGenerator() 