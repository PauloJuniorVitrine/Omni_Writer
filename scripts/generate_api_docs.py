#!/usr/bin/env python3
"""
Script para Geração Automatizada de Documentação da API.
Gera OpenAPI, JSON Schema e changelog automaticamente.
"""

import os
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

# Adiciona o diretório raiz ao path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.contract_documentation import ContractDocumentationGenerator
from app.app_factory import create_app

def generate_api_documentation(version: str = None, output_dir: str = "docs"):
    """
    Gera documentação completa da API.
    
    Args:
        version: Versão da API (opcional)
        output_dir: Diretório de saída
    
    Returns:
        Dicionário com informações dos arquivos gerados
    """
    print("🚀 Iniciando geração de documentação da API...")
    
    # Cria aplicação Flask
    app = create_app()
    
    # Determina versão
    if not version:
        version = os.getenv('API_VERSION', '1.0.0')
    
    # Cria gerador de documentação
    generator = ContractDocumentationGenerator(version=version)
    generator.register_app(app)
    
    # Cria diretório de saída
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/schemas", exist_ok=True)
    
    generated_files = {
        'version': version,
        'timestamp': datetime.now().isoformat(),
        'files': []
    }
    
    try:
        # 1. Gera especificação OpenAPI
        print("📋 Gerando especificação OpenAPI...")
        openapi_file = generator.save_openapi_spec(f"openapi_v{version}.json")
        generated_files['files'].append({
            'type': 'openapi',
            'path': openapi_file,
            'description': 'Especificação OpenAPI 3.0'
        })
        print(f"✅ OpenAPI salvo em: {openapi_file}")
        
        # 2. Gera JSON Schemas
        print("📊 Gerando JSON Schemas...")
        for schema_name in generator.schemas:
            schema_file = generator.save_json_schema(schema_name, f"{schema_name}_schema.json")
            generated_files['files'].append({
                'type': 'json_schema',
                'path': schema_file,
                'schema_name': schema_name,
                'description': f'JSON Schema para {schema_name}'
            })
            print(f"✅ Schema {schema_name} salvo em: {schema_file}")
        
        # 3. Gera changelog se versão anterior existir
        changelog_file = f"{output_dir}/CHANGELOG_v{version}.md"
        if os.path.exists(changelog_file):
            print("📝 Gerando changelog...")
            # Aqui você poderia implementar lógica para detectar versão anterior
            old_version = "1.0.0"  # Exemplo
            changelog_path = generator.save_changelog(old_version, version, f"CHANGELOG_v{old_version}_to_v{version}.md")
            generated_files['files'].append({
                'type': 'changelog',
                'path': changelog_path,
                'description': f'Changelog de v{old_version} para v{version}'
            })
            print(f"✅ Changelog salvo em: {changelog_path}")
        
        # 4. Gera índice de documentação
        print("📚 Gerando índice de documentação...")
        index_file = generate_documentation_index(generated_files, output_dir)
        generated_files['files'].append({
            'type': 'index',
            'path': index_file,
            'description': 'Índice da documentação'
        })
        print(f"✅ Índice salvo em: {index_file}")
        
        # 5. Salva metadados da geração
        metadata_file = f"{output_dir}/generation_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(generated_files, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Metadados salvos em: {metadata_file}")
        
        return generated_files
        
    except Exception as e:
        print(f"❌ Erro na geração de documentação: {e}")
        raise

def generate_documentation_index(generated_files: dict, output_dir: str) -> str:
    """
    Gera índice da documentação.
    
    Args:
        generated_files: Informações dos arquivos gerados
        output_dir: Diretório de saída
    
    Returns:
        Caminho do arquivo de índice
    """
    index_content = f"""# 📚 Documentação da API Omni Writer

## Versão: {generated_files['version']}
## Gerado em: {generated_files['timestamp']}

## 📋 Especificação OpenAPI

A especificação completa da API está disponível em formato OpenAPI 3.0:

- [Especificação OpenAPI](openapi_v{generated_files['version']}.json)
- [Visualização Swagger UI](https://editor.swagger.io/?url=./openapi_v{generated_files['version']}.json)

## 📊 Schemas JSON

Os seguintes schemas JSON estão disponíveis:

"""
    
    # Adiciona schemas
    schemas = [f for f in generated_files['files'] if f['type'] == 'json_schema']
    for schema in schemas:
        schema_name = schema['schema_name']
        filename = os.path.basename(schema['path'])
        index_content += f"- [{schema_name}](schemas/{filename})\n"
    
    index_content += """
## 🔗 Endpoints Principais

### Geração de Artigos
- `POST /generate` - Gera artigos baseado em prompts
- `GET /status/<trace_id>` - Consulta status de geração
- `GET /events/<trace_id>` - Stream de eventos SSE

### Download e Exportação
- `GET /download` - Download de arquivo ZIP
- `GET /download_multi` - Download de múltiplos arquivos
- `GET /export_prompts` - Exporta prompts
- `GET /export_artigos_csv` - Exporta artigos em CSV

### Autenticação e Tokens
- `POST /token/rotate` - Rotaciona token de API
- `POST /api/protegido` - Endpoint protegido

### Feedback
- `POST /feedback` - Envia feedback sobre artigos

## 🔐 Autenticação

A API suporta dois métodos de autenticação:

1. **Bearer Token**: `Authorization: Bearer <token>`
2. **API Key**: `X-API-Key: <key>`

## 📝 Exemplos de Uso

### Geração de Artigo

```bash
curl -X POST http://localhost:5000/generate \\
  -H "Authorization: Bearer your-token" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "api_key=your-api-key" \\
  -d "model_type=openai" \\
  -d "instancias_json={\\"tema\\":\\"Inteligência Artificial\\"}"
```

### Consulta de Status

```bash
curl -X GET http://localhost:5000/status/trace-123 \\
  -H "Authorization: Bearer your-token"
```

## 🚨 Códigos de Resposta

- `200` - Sucesso
- `400` - Dados inválidos
- `401` - Não autorizado
- `500` - Erro interno do servidor

## 📈 Rate Limiting

- Geração: 10 requests/minuto
- Feedback: 20 requests/minuto
- Geral: 100 requests/minuto

## 🔄 Versionamento

Esta documentação corresponde à versão `{generated_files['version']}` da API.

Para informações sobre mudanças entre versões, consulte o [CHANGELOG](CHANGELOG_v{generated_files['version']}.md).

---

*Documentação gerada automaticamente em {generated_files['timestamp']}*
"""
    
    index_file = f"{output_dir}/README.md"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(index_content)
    
    return index_file

def validate_generated_docs(generated_files: dict) -> dict:
    """
    Valida documentação gerada.
    
    Args:
        generated_files: Informações dos arquivos gerados
    
    Returns:
        Relatório de validação
    """
    validation_report = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'files_checked': 0
    }
    
    for file_info in generated_files['files']:
        file_path = file_info['path']
        validation_report['files_checked'] += 1
        
        # Verifica se arquivo existe
        if not os.path.exists(file_path):
            validation_report['errors'].append(f"Arquivo não encontrado: {file_path}")
            validation_report['valid'] = False
            continue
        
        # Verifica tamanho do arquivo
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            validation_report['warnings'].append(f"Arquivo vazio: {file_path}")
        
        # Validações específicas por tipo
        if file_info['type'] == 'openapi':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    spec = json.load(f)
                
                # Valida estrutura OpenAPI
                required_fields = ['openapi', 'info', 'paths']
                for field in required_fields:
                    if field not in spec:
                        validation_report['errors'].append(f"Campo obrigatório ausente em OpenAPI: {field}")
                        validation_report['valid'] = False
                
                # Verifica se tem endpoints
                if 'paths' in spec and len(spec['paths']) == 0:
                    validation_report['warnings'].append("Especificação OpenAPI sem endpoints")
                
            except json.JSONDecodeError as e:
                validation_report['errors'].append(f"JSON inválido em {file_path}: {e}")
                validation_report['valid'] = False
        
        elif file_info['type'] == 'json_schema':
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    schema = json.load(f)
                
                # Valida estrutura JSON Schema
                if '$schema' not in schema:
                    validation_report['warnings'].append(f"JSON Schema sem $schema: {file_path}")
                
                if 'type' not in schema:
                    validation_report['errors'].append(f"JSON Schema sem tipo: {file_path}")
                    validation_report['valid'] = False
                
            except json.JSONDecodeError as e:
                validation_report['errors'].append(f"JSON inválido em {file_path}: {e}")
                validation_report['valid'] = False
    
    return validation_report

def main():
    """Função principal do script."""
    parser = argparse.ArgumentParser(description='Gerador de Documentação da API')
    parser.add_argument('--version', help='Versão da API')
    parser.add_argument('--output-dir', default='docs', help='Diretório de saída')
    parser.add_argument('--validate', action='store_true', help='Validar documentação gerada')
    parser.add_argument('--verbose', action='store_true', help='Modo verboso')
    
    args = parser.parse_args()
    
    try:
        # Gera documentação
        generated_files = generate_api_documentation(
            version=args.version,
            output_dir=args.output_dir
        )
        
        # Valida se solicitado
        if args.validate:
            print("\n🔍 Validando documentação gerada...")
            validation_report = validate_generated_docs(generated_files)
            
            if validation_report['valid']:
                print("✅ Documentação válida!")
            else:
                print("❌ Documentação com erros:")
                for error in validation_report['errors']:
                    print(f"  - {error}")
            
            if validation_report['warnings']:
                print("⚠️  Avisos:")
                for warning in validation_report['warnings']:
                    print(f"  - {warning}")
            
            print(f"📊 Arquivos verificados: {validation_report['files_checked']}")
        
        # Resumo final
        print(f"\n🎉 Documentação gerada com sucesso!")
        print(f"📁 Diretório: {args.output_dir}")
        print(f"📄 Arquivos gerados: {len(generated_files['files'])}")
        print(f"🔗 Especificação OpenAPI: {args.output_dir}/openapi_v{generated_files['version']}.json")
        print(f"📚 Índice: {args.output_dir}/README.md")
        
    except Exception as e:
        print(f"❌ Erro: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 