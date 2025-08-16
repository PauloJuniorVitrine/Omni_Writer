#!/usr/bin/env python3
"""
Script de Sincronização OpenAPI - Omni Writer
Sincroniza documentação OpenAPI com código atual

Tracing ID: OPENAPI_SYNC_20250127_001
"""

import os
import sys
import json
import yaml
import inspect
import ast
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configuração
CONFIG = {
    'openapi_file': 'docs/openapi.yaml',
    'app_dir': 'app',
    'shared_dir': 'shared',
    'ui_dir': 'ui',
    'output_dir': 'docs',
    'backup_dir': 'docs/backups',
    'tracing_id': 'OPENAPI_SYNC_20250127_001'
}

class OpenAPISynchronizer:
    """Sincronizador de documentação OpenAPI"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.endpoints = {}
        self.schemas = {}
        self.errors = []
        
    def log(self, message: str, level: str = 'INFO'):
        """Log estruturado"""
        timestamp = datetime.utcnow().isoformat()
        print(f"[{timestamp}] [{level}] [{self.config['tracing_id']}] {message}")
        
    def backup_current_docs(self) -> bool:
        """Cria backup da documentação atual"""
        try:
            openapi_path = Path(self.config['openapi_file'])
            if not openapi_path.exists():
                self.log("Documentação OpenAPI não encontrada, criando nova", 'WARN')
                return True
                
            backup_dir = Path(self.config['backup_dir'])
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = backup_dir / f"openapi_backup_{timestamp}.yaml"
            
            with open(openapi_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            with open(backup_file, 'w', encoding='utf-8') as f:
                f.write(content)
                
            self.log(f"Backup criado: {backup_file}")
            return True
            
        except Exception as e:
            self.log(f"Erro ao criar backup: {e}", 'ERROR')
            return False
    
    def extract_endpoints_from_code(self) -> Dict[str, Any]:
        """Extrai endpoints do código Python"""
        endpoints = {}
        
        try:
            # Analisa app/main.py
            main_file = Path(self.config['app_dir']) / 'main.py'
            if main_file.exists():
                with open(main_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Procura por decoradores @app.route
                        for decorator in node.decorator_list:
                            if (isinstance(decorator, ast.Call) and 
                                isinstance(decorator.func, ast.Attribute) and
                                decorator.func.attr == 'route'):
                                
                                # Extrai path e métodos
                                path = decorator.args[0].s if decorator.args else '/'
                                methods = ['GET']  # Default
                                
                                for keyword in decorator.keywords:
                                    if keyword.arg == 'methods':
                                        methods = [m.s for m in keyword.value.elts]
                                
                                # Adiciona endpoint
                                for method in methods:
                                    key = f"{method} {path}"
                                    endpoints[key] = {
                                        'path': path,
                                        'method': method,
                                        'function': node.name,
                                        'docstring': ast.get_docstring(node) or '',
                                        'line': node.lineno
                                    }
                                    
            self.log(f"Extraídos {len(endpoints)} endpoints do código")
            return endpoints
            
        except Exception as e:
            self.log(f"Erro ao extrair endpoints: {e}", 'ERROR')
            return {}
    
    def extract_schemas_from_code(self) -> Dict[str, Any]:
        """Extrai schemas do código Python"""
        schemas = {}
        
        try:
            # Analisa shared/types.py
            types_file = Path(self.config['shared_dir']) / 'types.py'
            if types_file.exists():
                with open(types_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        # Procura por dataclasses
                        if any('dataclass' in d.id for d in node.decorator_list 
                               if isinstance(d, ast.Name)):
                            
                            schema = {
                                'type': 'object',
                                'properties': {},
                                'required': []
                            }
                            
                            for field in node.body:
                                if isinstance(field, ast.AnnAssign):
                                    field_name = field.target.id
                                    field_type = self._extract_type_annotation(field.annotation)
                                    
                                    schema['properties'][field_name] = field_type
                                    
                                    # Se não tem default, é obrigatório
                                    if not field.value:
                                        schema['required'].append(field_name)
                            
                            schemas[node.name] = schema
                            
            self.log(f"Extraídos {len(schemas)} schemas do código")
            return schemas
            
        except Exception as e:
            self.log(f"Erro ao extrair schemas: {e}", 'ERROR')
            return {}
    
    def _extract_type_annotation(self, annotation) -> Dict[str, Any]:
        """Extrai tipo de anotação Python para OpenAPI"""
        if annotation is None:
            return {'type': 'string'}
            
        if isinstance(annotation, ast.Name):
            type_name = annotation.id
            if type_name == 'str':
                return {'type': 'string'}
            elif type_name == 'int':
                return {'type': 'integer'}
            elif type_name == 'bool':
                return {'type': 'boolean'}
            elif type_name == 'float':
                return {'type': 'number'}
            else:
                return {'type': 'string'}
                
        elif isinstance(annotation, ast.Subscript):
            if isinstance(annotation.value, ast.Name) and annotation.value.id == 'Optional':
                # Optional[T] -> nullable T
                inner_type = self._extract_type_annotation(annotation.slice)
                inner_type['nullable'] = True
                return inner_type
            elif isinstance(annotation.value, ast.Name) and annotation.value.id == 'List':
                # List[T] -> array of T
                inner_type = self._extract_type_annotation(annotation.slice)
                return {
                    'type': 'array',
                    'items': inner_type
                }
                
        return {'type': 'string'}
    
    def validate_openapi_spec(self, spec: Dict[str, Any]) -> bool:
        """Valida especificação OpenAPI"""
        try:
            # Validações básicas
            required_fields = ['openapi', 'info', 'paths']
            for field in required_fields:
                if field not in spec:
                    self.log(f"Campo obrigatório ausente: {field}", 'ERROR')
                    return False
            
            # Valida versão OpenAPI
            if not spec['openapi'].startswith('3.'):
                self.log("Versão OpenAPI deve ser 3.x", 'ERROR')
                return False
                
            # Valida paths
            if not spec['paths']:
                self.log("Nenhum path definido", 'WARN')
                
            self.log("Especificação OpenAPI válida")
            return True
            
        except Exception as e:
            self.log(f"Erro na validação: {e}", 'ERROR')
            return False
    
    def generate_openapi_spec(self, endpoints: Dict[str, Any], schemas: Dict[str, Any]) -> Dict[str, Any]:
        """Gera especificação OpenAPI completa"""
        
        # Base da especificação
        spec = {
            'openapi': '3.1.0',
            'info': {
                'title': 'Omni Writer API',
                'description': 'API para geração de artigos com IA',
                'version': '2.0.0',
                'contact': {
                    'name': 'Omni Writer Team',
                    'email': 'support@omniwriter.com'
                },
                'license': {
                    'name': 'MIT',
                    'url': 'https://opensource.org/licenses/MIT'
                }
            },
            'servers': [
                {
                    'url': 'http://localhost:5000',
                    'description': 'Development server'
                },
                {
                    'url': 'https://api.omniwriter.com',
                    'description': 'Production server'
                }
            ],
            'paths': {},
            'components': {
                'securitySchemes': {
                    'BearerAuth': {
                        'type': 'http',
                        'scheme': 'bearer',
                        'bearerFormat': 'JWT',
                        'description': 'Token JWT para autenticação'
                    }
                },
                'schemas': schemas
            },
            'tags': [
                {'name': 'System', 'description': 'Endpoints do sistema'},
                {'name': 'Blogs', 'description': 'Gerenciamento de blogs'},
                {'name': 'Prompts', 'description': 'Gerenciamento de prompts'},
                {'name': 'Generation', 'description': 'Geração de artigos'},
                {'name': 'Download', 'description': 'Download de arquivos'},
                {'name': 'Webhook', 'description': 'Webhooks e notificações'}
            ]
        }
        
        # Adiciona endpoints
        for key, endpoint in endpoints.items():
            path = endpoint['path']
            method = endpoint['method'].lower()
            
            if path not in spec['paths']:
                spec['paths'][path] = {}
                
            # Determina tag baseado no path
            tag = self._determine_tag(path)
            
            spec['paths'][path][method] = {
                'summary': self._generate_summary(endpoint),
                'description': endpoint['docstring'] or f"{method.upper()} {path}",
                'tags': [tag],
                'responses': self._generate_responses(endpoint)
            }
            
            # Adiciona autenticação se necessário
            if not path.startswith('/api/health') and not path.startswith('/api/versions'):
                spec['paths'][path][method]['security'] = [{'BearerAuth': []}]
        
        return spec
    
    def _determine_tag(self, path: str) -> str:
        """Determina tag baseado no path"""
        if '/health' in path or '/versions' in path:
            return 'System'
        elif '/blogs' in path:
            return 'Blogs'
        elif '/prompts' in path:
            return 'Prompts'
        elif '/generate' in path or '/status' in path or '/events' in path:
            return 'Generation'
        elif '/download' in path:
            return 'Download'
        elif '/webhook' in path:
            return 'Webhook'
        else:
            return 'System'
    
    def _generate_summary(self, endpoint: Dict[str, Any]) -> str:
        """Gera resumo do endpoint"""
        method = endpoint['method']
        path = endpoint['path']
        
        if method == 'GET':
            if '/blogs' in path:
                return 'Listar blogs'
            elif '/prompts' in path:
                return 'Listar prompts'
            elif '/status' in path:
                return 'Status da geração'
            elif '/events' in path:
                return 'Eventos da geração'
            elif '/download' in path:
                return 'Download do artigo'
            else:
                return f'GET {path}'
        elif method == 'POST':
            if '/blogs' in path:
                return 'Criar blog'
            elif '/prompts' in path:
                return 'Criar prompt'
            elif '/generate' in path:
                return 'Gerar artigo'
            elif '/webhook' in path:
                return 'Webhook de notificação'
            else:
                return f'POST {path}'
        else:
            return f'{method} {path}'
    
    def _generate_responses(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Gera respostas padrão para endpoint"""
        responses = {
            '200': {
                'description': 'Sucesso',
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            },
            '400': {
                'description': 'Dados inválidos',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            },
            '401': {
                'description': 'Não autorizado',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            },
            '500': {
                'description': 'Erro interno',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            }
        }
        
        # Adiciona 404 para endpoints com parâmetros
        if '{' in endpoint['path']:
            responses['404'] = {
                'description': 'Recurso não encontrado',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/ErrorResponse'}
                    }
                }
            }
        
        return responses
    
    def save_openapi_spec(self, spec: Dict[str, Any]) -> bool:
        """Salva especificação OpenAPI"""
        try:
            output_file = Path(self.config['openapi_file'])
            output_file.parent.mkdir(exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(spec, f, default_flow_style=False, 
                         sort_keys=False, allow_unicode=True, indent=2)
                
            self.log(f"Especificação OpenAPI salva: {output_file}")
            return True
            
        except Exception as e:
            self.log(f"Erro ao salvar especificação: {e}", 'ERROR')
            return False
    
    def create_sync_report(self, endpoints: Dict[str, Any], schemas: Dict[str, Any]) -> bool:
        """Cria relatório de sincronização"""
        try:
            report = {
                'tracing_id': self.config['tracing_id'],
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'endpoints_extracted': len(endpoints),
                    'schemas_extracted': len(schemas),
                    'errors': len(self.errors)
                },
                'endpoints': list(endpoints.keys()),
                'schemas': list(schemas.keys()),
                'errors': self.errors
            }
            
            report_file = Path(self.config['output_dir']) / f"openapi_sync_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            self.log(f"Relatório de sincronização criado: {report_file}")
            return True
            
        except Exception as e:
            self.log(f"Erro ao criar relatório: {e}", 'ERROR')
            return False
    
    def sync(self) -> bool:
        """Executa sincronização completa"""
        self.log("Iniciando sincronização OpenAPI")
        
        # Backup da documentação atual
        if not self.backup_current_docs():
            return False
        
        # Extrai endpoints do código
        endpoints = self.extract_endpoints_from_code()
        if not endpoints:
            self.log("Nenhum endpoint extraído", 'WARN')
        
        # Extrai schemas do código
        schemas = self.extract_schemas_from_code()
        if not schemas:
            self.log("Nenhum schema extraído", 'WARN')
        
        # Gera especificação OpenAPI
        spec = self.generate_openapi_spec(endpoints, schemas)
        
        # Valida especificação
        if not self.validate_openapi_spec(spec):
            return False
        
        # Salva especificação
        if not self.save_openapi_spec(spec):
            return False
        
        # Cria relatório
        self.create_sync_report(endpoints, schemas)
        
        self.log("Sincronização OpenAPI concluída com sucesso")
        return True

def main():
    """Função principal"""
    print("🔄 Sincronização OpenAPI - Omni Writer")
    print("=" * 50)
    
    # Verifica dependências
    try:
        import yaml
    except ImportError:
        print("❌ PyYAML não encontrado. Instale com: pip install PyYAML")
        sys.exit(1)
    
    # Executa sincronização
    synchronizer = OpenAPISynchronizer(CONFIG)
    success = synchronizer.sync()
    
    if success:
        print("✅ Sincronização concluída com sucesso")
        sys.exit(0)
    else:
        print("❌ Sincronização falhou")
        sys.exit(1)

if __name__ == '__main__':
    main() 