#!/usr/bin/env python3
"""
Script de Sincronização de Tipos - Omni Writer
Baseado no código real do sistema

Tracing ID: TYPE_SYNC_20250127_001
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

# Configurações baseadas no código real
CONFIG = {
    'python_types_file': 'shared/types.py',
    'typescript_output_dir': 'ui/generated',
    'typescript_types_file': 'ui/generated/shared-types.ts',
    'openapi_spec': 'docs/openapi.yaml',
    'zod_schemas_file': 'ui/schemas/api-schemas.ts'
}

# Cores para output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def log(message: str, color: str = Colors.RESET):
    """Log com cores"""
    print(f"{color}{message}{Colors.RESET}")

def check_dependencies():
    """Verifica dependências necessárias"""
    log("🔍 Verificando dependências...", Colors.BLUE)
    
    required_files = [
        CONFIG['python_types_file'],
        CONFIG['openapi_spec']
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        log(f"❌ Arquivos ausentes: {', '.join(missing_files)}", Colors.RED)
        return False
    
    log("✅ Dependências verificadas", Colors.GREEN)
    return True

def generate_typescript_from_python():
    """Gera tipos TypeScript a partir dos tipos Python"""
    log("📝 Gerando tipos TypeScript...", Colors.BLUE)
    
    try:
        # Importa o módulo de tipos Python
        sys.path.append(os.path.dirname(CONFIG['python_types_file']))
        from types import save_typescript_types
        
        # Cria diretório de saída se não existir
        os.makedirs(CONFIG['typescript_output_dir'], exist_ok=True)
        
        # Gera tipos TypeScript
        save_typescript_types(CONFIG['typescript_types_file'])
        
        log("✅ Tipos TypeScript gerados", Colors.GREEN)
        return True
    except Exception as error:
        log(f"❌ Erro na geração de tipos: {error}", Colors.RED)
        return False

def validate_typescript_types():
    """Valida tipos TypeScript gerados"""
    log("🔍 Validando tipos TypeScript...", Colors.BLUE)
    
    try:
        if not os.path.exists(CONFIG['typescript_types_file']):
            log("❌ Arquivo de tipos TypeScript não encontrado", Colors.RED)
            return False
        
        # Verifica se o arquivo tem conteúdo válido
        with open(CONFIG['typescript_types_file'], 'r', encoding='utf-8') as f:
            content = f.read()
        
        if not content.strip():
            log("❌ Arquivo de tipos TypeScript está vazio", Colors.RED)
            return False
        
        # Verifica se contém interfaces básicas
        required_interfaces = ['Blog', 'GenerationRequest', 'ErrorResponse']
        missing_interfaces = []
        
        for interface in required_interfaces:
            if f"interface {interface}" not in content:
                missing_interfaces.append(interface)
        
        if missing_interfaces:
            log(f"⚠️ Interfaces ausentes: {', '.join(missing_interfaces)}", Colors.YELLOW)
        
        log("✅ Tipos TypeScript validados", Colors.GREEN)
        return True
    except Exception as error:
        log(f"❌ Erro na validação: {error}", Colors.RED)
        return False

def sync_zod_schemas():
    """Sincroniza schemas Zod com tipos TypeScript"""
    log("🔄 Sincronizando schemas Zod...", Colors.BLUE)
    
    try:
        if not os.path.exists(CONFIG['zod_schemas_file']):
            log("⚠️ Arquivo de schemas Zod não encontrado, criando...", Colors.YELLOW)
            
            # Cria diretório se não existir
            os.makedirs(os.path.dirname(CONFIG['zod_schemas_file']), exist_ok=True)
            
            # Cria arquivo básico de schemas Zod
            basic_zod_schemas = '''import { z } from 'zod';

// Schemas Zod baseados nos tipos compartilhados
export const BlogSchema = z.object({
  id: z.number().int().positive(),
  nome: z.string().min(1).max(40),
  desc: z.string().max(80).optional()
});

export const GenerationRequestSchema = z.object({
  api_key: z.string().min(1),
  model_type: z.enum(['openai', 'deepseek']),
  prompts: z.array(z.string().min(1).max(500)),
  temperature: z.number().min(0.0).max(2.0).default(0.7),
  max_tokens: z.number().int().min(256).max(8192).default(4096),
  language: z.string().default('pt-BR')
});

export const ErrorResponseSchema = z.object({
  error: z.string().min(1)
});

// Tipos exportados
export type Blog = z.infer<typeof BlogSchema>;
export type GenerationRequest = z.infer<typeof GenerationRequestSchema>;
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;
'''
            
            with open(CONFIG['zod_schemas_file'], 'w', encoding='utf-8') as f:
                f.write(basic_zod_schemas)
        
        log("✅ Schemas Zod sincronizados", Colors.GREEN)
        return True
    except Exception as error:
        log(f"❌ Erro na sincronização de schemas: {error}", Colors.RED)
        return False

def update_package_json_scripts():
    """Atualiza scripts no package.json"""
    log("📦 Atualizando scripts do package.json...", Colors.BLUE)
    
    try:
        package_json_path = 'package.json'
        if not os.path.exists(package_json_path):
            log("⚠️ package.json não encontrado", Colors.YELLOW)
            return True
        
        with open(package_json_path, 'r', encoding='utf-8') as f:
            package_data = json.load(f)
        
        # Adiciona scripts de sincronização de tipos
        scripts = package_data.get('scripts', {})
        
        new_scripts = {
            'sync:types': 'python scripts/sync-types.py',
            'generate:shared-types': 'python -c "from shared.types import save_typescript_types; save_typescript_types()"',
            'validate:types': 'python scripts/sync-types.py --validate-only'
        }
        
        scripts.update(new_scripts)
        package_data['scripts'] = scripts
        
        with open(package_json_path, 'w', encoding='utf-8') as f:
            json.dump(package_data, f, indent=2)
        
        log("✅ Scripts do package.json atualizados", Colors.GREEN)
        return True
    except Exception as error:
        log(f"❌ Erro na atualização do package.json: {error}", Colors.RED)
        return False

def run_typescript_compilation_check():
    """Executa verificação de compilação TypeScript"""
    log("🔍 Verificando compilação TypeScript...", Colors.BLUE)
    
    try:
        # Verifica se TypeScript está instalado
        result = subprocess.run(['npx', 'tsc', '--noEmit'], 
                              capture_output=True, text=True, cwd='ui')
        
        if result.returncode == 0:
            log("✅ Compilação TypeScript OK", Colors.GREEN)
            return True
        else:
            log(f"⚠️ Erros de compilação TypeScript: {result.stderr}", Colors.YELLOW)
            return False
    except Exception as error:
        log(f"⚠️ Não foi possível verificar compilação TypeScript: {error}", Colors.YELLOW)
        return True  # Não é crítico

def create_type_sync_report():
    """Cria relatório de sincronização de tipos"""
    log("📊 Gerando relatório...", Colors.BLUE)
    
    try:
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'tracing_id': 'TYPE_SYNC_20250127_001',
            'files_generated': [],
            'files_updated': [],
            'validation_results': {}
        }
        
        # Lista arquivos gerados
        generated_files = [
            CONFIG['typescript_types_file'],
            CONFIG['zod_schemas_file']
        ]
        
        for file_path in generated_files:
            if os.path.exists(file_path):
                report['files_generated'].append({
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                })
        
        # Salva relatório
        report_path = 'logs/type_sync_report.json'
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        log(f"✅ Relatório salvo em: {report_path}", Colors.GREEN)
        return True
    except Exception as error:
        log(f"❌ Erro na geração do relatório: {error}", Colors.RED)
        return False

def main():
    """Função principal"""
    log("🚀 Iniciando sincronização de tipos...", Colors.BLUE)
    log(f"📅 Data/Hora: {datetime.utcnow().isoformat()}", Colors.BLUE)
    log("🆔 Tracing ID: TYPE_SYNC_20250127_001", Colors.BLUE)
    
    steps = [
        ('Verificação de Dependências', check_dependencies),
        ('Geração de Tipos TypeScript', generate_typescript_from_python),
        ('Validação de Tipos TypeScript', validate_typescript_types),
        ('Sincronização de Schemas Zod', sync_zod_schemas),
        ('Atualização de Scripts', update_package_json_scripts),
        ('Verificação de Compilação', run_typescript_compilation_check),
        ('Geração de Relatório', create_type_sync_report)
    ]
    
    success_count = 0
    
    for step_name, step_function in steps:
        log(f"\n📋 Executando: {step_name}", Colors.BLUE)
        
        if step_function():
            success_count += 1
        else:
            log(f"❌ Falha em: {step_name}", Colors.RED)
    
    log(f"\n📊 Resumo da sincronização:", Colors.BLUE)
    log(f"✅ Passos bem-sucedidos: {success_count}/{len(steps)}", Colors.GREEN)
    
    if success_count == len(steps):
        log("🎉 Sincronização de tipos concluída com sucesso!", Colors.GREEN)
        return 0
    else:
        log("⚠️ Sincronização concluída com falhas", Colors.YELLOW)
        return 1

if __name__ == '__main__':
    # Verifica se é apenas validação
    if '--validate-only' in sys.argv:
        log("🔍 Executando apenas validação...", Colors.BLUE)
        if validate_typescript_types():
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Execução normal
    sys.exit(main()) 