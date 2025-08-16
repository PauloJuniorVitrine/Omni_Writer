#!/usr/bin/env python3
"""
Script de geração automática de SDK usando OpenAPI Generator.

Tracing ID: COMM_IMPL_20250128_001
Data/Hora: 2025-01-28T11:15:00Z
Prompt: Fullstack Communication Audit
Ruleset: Enterprise+ Standards
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OpenAPIGenerator:
    """
    Gerador automático de SDK baseado em OpenAPI.
    
    Responsável por:
    - Gerar SDK TypeScript automaticamente
    - Validar contratos
    - Integrar com CI/CD
    - Manter sincronização backend/frontend
    """
    
    def __init__(self, config_path: str = "scripts/openapi_config.json"):
        self.config_path = config_path
        self.project_root = Path(__file__).parent.parent
        self.openapi_spec = self.project_root / "docs" / "openapi.yaml"
        self.output_dir = self.project_root / "ui" / "generated"
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Carrega configuração do gerador."""
        default_config = {
            "generator": "typescript-fetch",
            "output_dir": str(self.output_dir),
            "additional_properties": {
                "supportsES6": "true",
                "withInterfaces": "true",
                "typescriptThreePlus": "true"
            },
            "template_dir": None,
            "git_user_id": "omni-writer",
            "git_repo_id": "omni-writer-sdk",
            "release_note": "Auto-generated SDK"
        }
        
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        
        return default_config
    
    def validate_openapi_spec(self) -> bool:
        """
        Valida especificação OpenAPI.
        
        Returns:
            bool: True se válida, False caso contrário
        """
        try:
            import yaml
            from jsonschema import validate, ValidationError
            
            # Carrega especificação
            with open(self.openapi_spec, 'r') as f:
                spec = yaml.safe_load(f)
            
            # Validação básica de estrutura
            required_fields = ['openapi', 'info', 'paths']
            for field in required_fields:
                if field not in spec:
                    logger.error(f"Campo obrigatório '{field}' não encontrado na especificação OpenAPI")
                    return False
            
            # Validação de versão
            if not spec['openapi'].startswith('3.'):
                logger.error("Especificação deve ser OpenAPI 3.x")
                return False
            
            logger.info("✅ Especificação OpenAPI válida")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na validação da especificação OpenAPI: {e}")
            return False
    
    def install_openapi_generator(self) -> bool:
        """
        Instala OpenAPI Generator se não estiver disponível.
        
        Returns:
            bool: True se instalado com sucesso
        """
        try:
            # Verifica se já está instalado
            result = subprocess.run(
                ['openapi-generator-cli', 'version'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"✅ OpenAPI Generator já instalado: {result.stdout.strip()}")
                return True
            
            # Instala via npm
            logger.info("📦 Instalando OpenAPI Generator...")
            result = subprocess.run(
                ['npm', 'install', '-g', '@openapitools/openapi-generator-cli'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info("✅ OpenAPI Generator instalado com sucesso")
                return True
            else:
                logger.error(f"❌ Erro na instalação: {result.stderr}")
                return False
                
        except FileNotFoundError:
            logger.error("❌ npm não encontrado. Instale Node.js primeiro.")
            return False
    
    def generate_sdk(self) -> bool:
        """
        Gera SDK TypeScript automaticamente.
        
        Returns:
            bool: True se gerado com sucesso
        """
        try:
            # Cria diretório de saída
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Comando de geração
            cmd = [
                'openapi-generator-cli', 'generate',
                '-i', str(self.openapi_spec),
                '-g', self.config['generator'],
                '-o', self.config['output_dir'],
                '--additional-properties', json.dumps(self.config['additional_properties'])
            ]
            
            logger.info(f"🚀 Gerando SDK com comando: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_root
            )
            
            if result.returncode == 0:
                logger.info("✅ SDK gerado com sucesso")
                self._create_index_file()
                self._update_package_json()
                return True
            else:
                logger.error(f"❌ Erro na geração do SDK: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Erro inesperado na geração: {e}")
            return False
    
    def _create_index_file(self):
        """Cria arquivo index.ts para exportar todas as APIs."""
        index_content = """/**
 * SDK gerado automaticamente pelo OpenAPI Generator
 * 
 * Tracing ID: COMM_IMPL_20250128_001
 * Data/Hora: {datetime}
 * 
 * ⚠️ NÃO EDITE MANUALMENTE - Este arquivo é gerado automaticamente
 */

export * from './apis';
export * from './models';
export * from './runtime';

// Configuração padrão
export const DEFAULT_CONFIG = {{
    basePath: process.env.REACT_APP_API_BASE_URL || '/',
    headers: {{
        'Content-Type': 'application/json',
    }},
}};
""".format(datetime=datetime.now().isoformat())
        
        index_file = self.output_dir / "index.ts"
        with open(index_file, 'w') as f:
            f.write(index_content)
        
        logger.info("✅ Arquivo index.ts criado")
    
    def _update_package_json(self):
        """Atualiza package.json com dependências do SDK."""
        package_json_path = self.project_root / "ui" / "package.json"
        
        if not package_json_path.exists():
            logger.warning("⚠️ package.json não encontrado")
            return
        
        try:
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
            
            # Adiciona dependências necessárias
            dependencies = package_data.get('dependencies', {})
            required_deps = {
                'node-fetch': '^3.3.0',
                'form-data': '^4.0.0'
            }
            
            updated = False
            for dep, version in required_deps.items():
                if dep not in dependencies:
                    dependencies[dep] = version
                    updated = True
            
            if updated:
                package_data['dependencies'] = dependencies
                with open(package_json_path, 'w') as f:
                    json.dump(package_data, f, indent=2)
                logger.info("✅ package.json atualizado com dependências do SDK")
            
        except Exception as e:
            logger.error(f"❌ Erro ao atualizar package.json: {e}")
    
    def validate_contracts(self) -> Dict[str, bool]:
        """
        Valida contratos entre backend e frontend.
        
        Returns:
            Dict[str, bool]: Resultado da validação por endpoint
        """
        validation_results = {}
        
        try:
            # Carrega especificação
            import yaml
            with open(self.openapi_spec, 'r') as f:
                spec = yaml.safe_load(f)
            
            # Valida endpoints implementados
            implemented_endpoints = self._get_implemented_endpoints()
            
            for path, methods in spec['paths'].items():
                for method, operation in methods.items():
                    endpoint_key = f"{method.upper()} {path}"
                    
                    # Verifica se endpoint está implementado
                    is_implemented = endpoint_key in implemented_endpoints
                    validation_results[endpoint_key] = is_implemented
                    
                    if not is_implemented:
                        logger.warning(f"⚠️ Endpoint {endpoint_key} documentado mas não implementado")
            
            logger.info(f"✅ Validação de contratos concluída: {sum(validation_results.values())}/{len(validation_results)} endpoints sincronizados")
            return validation_results
            
        except Exception as e:
            logger.error(f"❌ Erro na validação de contratos: {e}")
            return {}
    
    def _get_implemented_endpoints(self) -> List[str]:
        """Obtém lista de endpoints implementados no backend."""
        implemented = []
        
        try:
            # Analisa app/routes.py
            routes_file = self.project_root / "app" / "routes.py"
            if routes_file.exists():
                with open(routes_file, 'r') as f:
                    content = f.read()
                
                # Extrai rotas usando regex simples
                import re
                route_pattern = r'@routes_bp\.route\([\'"]([^\'"]+)[\'"],\s*methods=\[[^\]]*[\'"]([^\'"]+)[\'"]'
                matches = re.findall(route_pattern, content)
                
                for path, method in matches:
                    implemented.append(f"{method.upper()} {path}")
            
            logger.info(f"📋 {len(implemented)} endpoints implementados encontrados")
            return implemented
            
        except Exception as e:
            logger.error(f"❌ Erro ao analisar endpoints implementados: {e}")
            return []
    
    def run_full_pipeline(self) -> bool:
        """
        Executa pipeline completo de geração.
        
        Returns:
            bool: True se pipeline executado com sucesso
        """
        logger.info("🚀 Iniciando pipeline completo de geração de SDK")
        
        steps = [
            ("Validação da especificação OpenAPI", self.validate_openapi_spec),
            ("Instalação do OpenAPI Generator", self.install_openapi_generator),
            ("Geração do SDK", self.generate_sdk),
            ("Validação de contratos", lambda: self.validate_contracts())
        ]
        
        for step_name, step_func in steps:
            logger.info(f"📋 Executando: {step_name}")
            result = step_func()
            
            if isinstance(result, bool) and not result:
                logger.error(f"❌ Falha no passo: {step_name}")
                return False
        
        logger.info("✅ Pipeline completo executado com sucesso")
        return True

def main():
    """Função principal do script."""
    generator = OpenAPIGenerator()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "validate":
            success = generator.validate_openapi_spec()
            sys.exit(0 if success else 1)
        
        elif command == "generate":
            success = generator.run_full_pipeline()
            sys.exit(0 if success else 1)
        
        elif command == "contracts":
            results = generator.validate_contracts()
            print(json.dumps(results, indent=2))
            sys.exit(0)
        
        else:
            print("Comandos disponíveis: validate, generate, contracts")
            sys.exit(1)
    else:
        # Executa pipeline completo por padrão
        success = generator.run_full_pipeline()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 