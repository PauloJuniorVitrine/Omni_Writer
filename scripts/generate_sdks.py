#!/usr/bin/env python3
"""
Geração Automática de SDKs - Omni Writer
Tracing ID: SDK_GENERATION_20250127_001

Este script gera SDKs automaticamente para:
- TypeScript/JavaScript
- Python
- Baseado na especificação OpenAPI
"""

import json
import yaml
import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging
import tempfile

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SDKGenerationResult:
    """Resultado da geração de SDK"""
    language: str
    status: str
    output_path: str
    files_generated: List[str]
    errors: List[str]
    warnings: List[str]

class SDKGenerator:
    """Gerador de SDKs baseado em OpenAPI"""
    
    def __init__(self, openapi_path: str, output_dir: str = "generated_sdks"):
        self.openapi_path = Path(openapi_path)
        self.output_dir = Path(output_dir)
        self.openapi_spec = None
        self.generation_results: List[SDKGenerationResult] = []
        
    def load_openapi_spec(self) -> bool:
        """Carrega especificação OpenAPI"""
        try:
            if self.openapi_path.suffix == '.yaml' or self.openapi_path.suffix == '.yml':
                with open(self.openapi_path, 'r', encoding='utf-8') as f:
                    self.openapi_spec = yaml.safe_load(f)
            else:
                with open(self.openapi_path, 'r', encoding='utf-8') as f:
                    self.openapi_spec = json.load(f)
            
            logger.info(f"OpenAPI spec carregada: {self.openapi_path}")
            return True
        except Exception as e:
            logger.error(f"Erro ao carregar OpenAPI spec: {e}")
            return False
    
    def generate_typescript_sdk(self) -> SDKGenerationResult:
        """Gera SDK TypeScript usando OpenAPI Generator"""
        result = SDKGenerationResult(
            language="typescript",
            status="PENDING",
            output_path="",
            files_generated=[],
            errors=[],
            warnings=[]
        )
        
        try:
            # Cria diretório de saída
            ts_output = self.output_dir / "typescript"
            ts_output.mkdir(parents=True, exist_ok=True)
            
            # Configuração do OpenAPI Generator
            config = {
                "supportsES6": True,
                "npmName": "@omni-writer/api-client",
                "npmVersion": "1.0.0",
                "npmRepository": "https://github.com/omni-writer/api-client",
                "withInterfaces": True,
                "usePromise": True,
                "useRxJS": False,
                "legacyDiscriminatorBehavior": False,
                "disallowAdditionalPropertiesIfNotPresent": False,
                "useTypeScript": True
            }
            
            # Salva configuração temporária
            config_path = ts_output / "openapi-generator-config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Comando OpenAPI Generator
            cmd = [
                "npx", "@openapitools/openapi-generator-cli", "generate",
                "-i", str(self.openapi_path),
                "-g", "typescript-axios",
                "-o", str(ts_output),
                "-c", str(config_path)
            ]
            
            # Executa geração
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.output_dir
            )
            
            if process.returncode == 0:
                result.status = "SUCCESS"
                result.output_path = str(ts_output)
                
                # Lista arquivos gerados
                for file_path in ts_output.rglob("*"):
                    if file_path.is_file():
                        result.files_generated.append(str(file_path.relative_to(ts_output)))
                
                logger.info(f"SDK TypeScript gerado: {len(result.files_generated)} arquivos")
            else:
                result.status = "FAILED"
                result.errors.append(f"Erro na execução: {process.stderr}")
                logger.error(f"Erro ao gerar SDK TypeScript: {process.stderr}")
            
        except Exception as e:
            result.status = "FAILED"
            result.errors.append(str(e))
            logger.error(f"Exceção ao gerar SDK TypeScript: {e}")
        
        return result
    
    def generate_python_sdk(self) -> SDKGenerationResult:
        """Gera SDK Python usando OpenAPI Generator"""
        result = SDKGenerationResult(
            language="python",
            status="PENDING",
            output_path="",
            files_generated=[],
            errors=[],
            warnings=[]
        )
        
        try:
            # Cria diretório de saída
            py_output = self.output_dir / "python"
            py_output.mkdir(parents=True, exist_ok=True)
            
            # Configuração do OpenAPI Generator
            config = {
                "packageName": "omni_writer_api_client",
                "packageVersion": "1.0.0",
                "packageUrl": "https://github.com/omni-writer/api-client-python",
                "packageDescription": "Python SDK for Omni Writer API",
                "packageAuthor": "Omni Writer Team",
                "packageAuthorEmail": "team@omni-writer.com",
                "useNose": False,
                "usePytest": True,
                "pythonAttrNoneIfUnset": True,
                "hideGenerationTimestamp": True
            }
            
            # Salva configuração temporária
            config_path = py_output / "openapi-generator-config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Comando OpenAPI Generator
            cmd = [
                "npx", "@openapitools/openapi-generator-cli", "generate",
                "-i", str(self.openapi_path),
                "-g", "python",
                "-o", str(py_output),
                "-c", str(config_path)
            ]
            
            # Executa geração
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.output_dir
            )
            
            if process.returncode == 0:
                result.status = "SUCCESS"
                result.output_path = str(py_output)
                
                # Lista arquivos gerados
                for file_path in py_output.rglob("*"):
                    if file_path.is_file():
                        result.files_generated.append(str(file_path.relative_to(py_output)))
                
                logger.info(f"SDK Python gerado: {len(result.files_generated)} arquivos")
            else:
                result.status = "FAILED"
                result.errors.append(f"Erro na execução: {process.stderr}")
                logger.error(f"Erro ao gerar SDK Python: {process.stderr}")
            
        except Exception as e:
            result.status = "FAILED"
            result.errors.append(str(e))
            logger.error(f"Exceção ao gerar SDK Python: {e}")
        
        return result
    
    def generate_javascript_sdk(self) -> SDKGenerationResult:
        """Gera SDK JavaScript usando OpenAPI Generator"""
        result = SDKGenerationResult(
            language="javascript",
            status="PENDING",
            output_path="",
            files_generated=[],
            errors=[],
            warnings=[]
        )
        
        try:
            # Cria diretório de saída
            js_output = self.output_dir / "javascript"
            js_output.mkdir(parents=True, exist_ok=True)
            
            # Configuração do OpenAPI Generator
            config = {
                "supportsES6": True,
                "npmName": "@omni-writer/api-client-js",
                "npmVersion": "1.0.0",
                "npmRepository": "https://github.com/omni-writer/api-client-js",
                "usePromise": True,
                "useRxJS": False,
                "legacyDiscriminatorBehavior": False,
                "disallowAdditionalPropertiesIfNotPresent": False
            }
            
            # Salva configuração temporária
            config_path = js_output / "openapi-generator-config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Comando OpenAPI Generator
            cmd = [
                "npx", "@openapitools/openapi-generator-cli", "generate",
                "-i", str(self.openapi_path),
                "-g", "javascript",
                "-o", str(js_output),
                "-c", str(config_path)
            ]
            
            # Executa geração
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.output_dir
            )
            
            if process.returncode == 0:
                result.status = "SUCCESS"
                result.output_path = str(js_output)
                
                # Lista arquivos gerados
                for file_path in js_output.rglob("*"):
                    if file_path.is_file():
                        result.files_generated.append(str(file_path.relative_to(js_output)))
                
                logger.info(f"SDK JavaScript gerado: {len(result.files_generated)} arquivos")
            else:
                result.status = "FAILED"
                result.errors.append(f"Erro na execução: {process.stderr}")
                logger.error(f"Erro ao gerar SDK JavaScript: {process.stderr}")
            
        except Exception as e:
            result.status = "FAILED"
            result.errors.append(str(e))
            logger.error(f"Exceção ao gerar SDK JavaScript: {e}")
        
        return result
    
    def create_custom_typescript_sdk(self) -> SDKGenerationResult:
        """Cria SDK TypeScript customizado baseado na especificação"""
        result = SDKGenerationResult(
            language="typescript-custom",
            status="PENDING",
            output_path="",
            files_generated=[],
            errors=[],
            warnings=[]
        )
        
        try:
            # Cria diretório de saída
            ts_custom_output = self.output_dir / "typescript-custom"
            ts_custom_output.mkdir(parents=True, exist_ok=True)
            
            # Gera tipos TypeScript
            types_content = self._generate_typescript_types()
            types_file = ts_custom_output / "types.ts"
            with open(types_file, 'w', encoding='utf-8') as f:
                f.write(types_content)
            
            # Gera cliente API
            client_content = self._generate_typescript_client()
            client_file = ts_custom_output / "api-client.ts"
            with open(client_file, 'w', encoding='utf-8') as f:
                f.write(client_content)
            
            # Gera package.json
            package_content = self._generate_package_json("typescript-custom")
            package_file = ts_custom_output / "package.json"
            with open(package_file, 'w', encoding='utf-8') as f:
                f.write(package_content)
            
            # Gera README
            readme_content = self._generate_readme("TypeScript Custom")
            readme_file = ts_custom_output / "README.md"
            with open(readme_file, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            
            result.status = "SUCCESS"
            result.output_path = str(ts_custom_output)
            result.files_generated = [
                "types.ts",
                "api-client.ts", 
                "package.json",
                "README.md"
            ]
            
            logger.info(f"SDK TypeScript Custom gerado: {len(result.files_generated)} arquivos")
            
        except Exception as e:
            result.status = "FAILED"
            result.errors.append(str(e))
            logger.error(f"Exceção ao gerar SDK TypeScript Custom: {e}")
        
        return result
    
    def _generate_typescript_types(self) -> str:
        """Gera tipos TypeScript baseados na especificação OpenAPI"""
        types = []
        types.append("// Generated TypeScript types for Omni Writer API")
        types.append("// Tracing ID: SDK_GENERATION_20250127_001")
        types.append("")
        
        # Gera tipos para schemas
        schemas = self.openapi_spec.get('components', {}).get('schemas', {})
        for schema_name, schema in schemas.items():
            types.append(f"export interface {schema_name} {{")
            
            if 'properties' in schema:
                for prop_name, prop_schema in schema['properties'].items():
                    prop_type = self._get_typescript_type(prop_schema)
                    required = prop_name in schema.get('required', [])
                    optional = "" if required else "?"
                    types.append(f"  {prop_name}{optional}: {prop_type};")
            
            types.append("}")
            types.append("")
        
        # Gera tipos para responses
        types.append("// API Response Types")
        types.append("export interface ApiResponse<T> {")
        types.append("  data: T;")
        types.append("  message?: string;")
        types.append("  status: number;")
        types.append("}")
        types.append("")
        
        return "\n".join(types)
    
    def _generate_typescript_client(self) -> str:
        """Gera cliente TypeScript baseado na especificação OpenAPI"""
        client = []
        client.append("// Generated TypeScript API Client for Omni Writer")
        client.append("// Tracing ID: SDK_GENERATION_20250127_001")
        client.append("")
        client.append("import axios, { AxiosInstance, AxiosResponse } from 'axios';")
        client.append("import { ApiResponse } from './types';")
        client.append("")
        
        # Classe principal
        client.append("export class OmniWriterApiClient {")
        client.append("  private client: AxiosInstance;")
        client.append("")
        client.append("  constructor(baseURL: string = 'http://localhost:5000', apiKey?: string) {")
        client.append("    this.client = axios.create({")
        client.append("      baseURL,")
        client.append("      headers: {")
        client.append("        'Content-Type': 'application/json',")
        client.append("        ...(apiKey && { 'Authorization': `Bearer ${apiKey}` })")
        client.append("      }")
        client.append("    });")
        client.append("  }")
        client.append("")
        
        # Gera métodos para cada endpoint
        paths = self.openapi_spec.get('paths', {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE']:
                    method_name = self._generate_method_name(path, method, operation)
                    client.append(f"  async {method_name}(params?: any): Promise<ApiResponse<any>> {{")
                    client.append(f"    const response: AxiosResponse = await this.client.{method.lower()}('{path}', params);")
                    client.append("    return response.data;")
                    client.append("  }")
                    client.append("")
        
        client.append("}")
        client.append("")
        
        return "\n".join(client)
    
    def _generate_method_name(self, path: str, method: str, operation: Dict) -> str:
        """Gera nome do método baseado no endpoint"""
        operation_id = operation.get('operationId', '')
        if operation_id:
            return operation_id
        
        # Fallback: gera nome baseado no path e método
        path_parts = path.strip('/').split('/')
        method_name = f"{method.lower()}_{path_parts[-1]}"
        return method_name.replace('-', '_').replace('{', '').replace('}', '')
    
    def _get_typescript_type(self, schema: Dict) -> str:
        """Converte schema OpenAPI para tipo TypeScript"""
        if 'type' not in schema:
            return 'any'
        
        schema_type = schema['type']
        
        if schema_type == 'string':
            if 'enum' in schema:
                enum_values = " | ".join([f"'{v}'" for v in schema['enum']])
                return enum_values
            return 'string'
        elif schema_type == 'number' or schema_type == 'integer':
            return 'number'
        elif schema_type == 'boolean':
            return 'boolean'
        elif schema_type == 'array':
            items_type = self._get_typescript_type(schema.get('items', {}))
            return f"{items_type}[]"
        elif schema_type == 'object':
            return 'Record<string, any>'
        else:
            return 'any'
    
    def _generate_package_json(self, sdk_type: str) -> str:
        """Gera package.json para o SDK"""
        package = {
            "name": f"@omni-writer/api-client-{sdk_type}",
            "version": "1.0.0",
            "description": f"Omni Writer API Client - {sdk_type}",
            "main": "index.js",
            "types": "types.ts",
            "scripts": {
                "build": "tsc",
                "test": "jest"
            },
            "dependencies": {
                "axios": "^1.6.0"
            },
            "devDependencies": {
                "typescript": "^5.0.0",
                "@types/node": "^20.0.0"
            },
            "repository": {
                "type": "git",
                "url": "https://github.com/omni-writer/api-client"
            },
            "keywords": ["api", "client", "omni-writer"],
            "author": "Omni Writer Team",
            "license": "MIT"
        }
        
        return json.dumps(package, indent=2)
    
    def _generate_readme(self, sdk_name: str) -> str:
        """Gera README para o SDK"""
        readme = f"""# Omni Writer API Client - {sdk_name}

SDK gerado automaticamente para integração com a API Omni Writer.

## Instalação

```bash
npm install @omni-writer/api-client-{sdk_name.lower().replace(' ', '-')}
```

## Uso

```typescript
import {{ OmniWriterApiClient }} from '@omni-writer/api-client-{sdk_name.lower().replace(' ', '-')}';

const client = new OmniWriterApiClient('http://localhost:5000', 'your-api-key');

// Exemplo de uso
const response = await client.get_blogs();
console.log(response.data);
```

## Documentação

Para mais informações, consulte a documentação da API em: `/docs/openapi.yaml`

## Tracing ID

SDK_GENERATION_20250127_001
"""
        return readme
    
    def generate_all_sdks(self) -> List[SDKGenerationResult]:
        """Gera todos os SDKs"""
        logger.info("Iniciando geração de SDKs...")
        
        # Gera SDKs usando OpenAPI Generator
        results = []
        
        # TypeScript
        ts_result = self.generate_typescript_sdk()
        results.append(ts_result)
        
        # Python
        py_result = self.generate_python_sdk()
        results.append(py_result)
        
        # JavaScript
        js_result = self.generate_javascript_sdk()
        results.append(js_result)
        
        # TypeScript Custom
        ts_custom_result = self.create_custom_typescript_sdk()
        results.append(ts_custom_result)
        
        self.generation_results = results
        return results
    
    def generate_report(self) -> Dict[str, Any]:
        """Gera relatório de geração de SDKs"""
        total_sdks = len(self.generation_results)
        successful = len([r for r in self.generation_results if r.status == "SUCCESS"])
        failed = len([r for r in self.generation_results if r.status == "FAILED"])
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": "SDK_GENERATION_20250127_001",
            "summary": {
                "total_sdks": total_sdks,
                "successful": successful,
                "failed": failed,
                "success_rate": (successful / total_sdks * 100) if total_sdks > 0 else 0
            },
            "results": [
                {
                    "language": r.language,
                    "status": r.status,
                    "output_path": r.output_path,
                    "files_generated": r.files_generated,
                    "errors": r.errors,
                    "warnings": r.warnings
                }
                for r in self.generation_results
            ]
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], output_path: str = "sdk_generation_report.json"):
        """Salva relatório em arquivo"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"Relatório salvo: {output_path}")
        except Exception as e:
            logger.error(f"Erro ao salvar relatório: {e}")

def main():
    """Função principal"""
    # Configuração
    openapi_path = "docs/openapi.yaml"
    output_dir = "generated_sdks"
    
    # Geração
    generator = SDKGenerator(openapi_path, output_dir)
    
    if not generator.load_openapi_spec():
        sys.exit(1)
    
    logger.info("Iniciando geração de SDKs...")
    results = generator.generate_all_sdks()
    
    # Gera relatório
    report = generator.generate_report()
    generator.save_report(report)
    
    # Exibe resumo
    summary = report["summary"]
    logger.info(f"Geração de SDKs concluída:")
    logger.info(f"  - Total: {summary['total_sdks']}")
    logger.info(f"  - Sucessos: {summary['successful']}")
    logger.info(f"  - Falhas: {summary['failed']}")
    logger.info(f"  - Taxa de sucesso: {summary['success_rate']:.1f}%")
    
    # Exibe resultados detalhados
    for result in results:
        logger.info(f"  {result.language}: {result.status}")
        if result.status == "SUCCESS":
            logger.info(f"    - Arquivos: {len(result.files_generated)}")
            logger.info(f"    - Output: {result.output_path}")
        elif result.status == "FAILED":
            for error in result.errors:
                logger.error(f"    - Erro: {error}")
    
    # Exit code baseado no resultado
    if summary['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 