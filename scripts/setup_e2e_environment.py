#!/usr/bin/env python3
"""
Script de Setup Automático - Ambiente E2E
- Configura ambiente completo para testes E2E
- Instala dependências e configura variáveis
- Valida configuração e gera relatório

📐 CoCoT: Baseado em boas práticas de setup de ambiente de testes
🌲 ToT: Múltiplas estratégias de configuração implementadas
♻️ ReAct: Simulado para diferentes cenários de setup

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T11:25:00Z
**Tracing ID:** SETUP_E2E_ENVIRONMENT_md1ppfhs
**Origem:** Necessidade de automatização do setup do ambiente E2E
"""

import os
import sys
import subprocess
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class SetupStep:
    """Representa um passo do setup"""
    name: str
    description: str
    command: str
    success_criteria: str
    required: bool = True

@dataclass
class SetupResult:
    """Resultado de um passo do setup"""
    step: SetupStep
    success: bool
    output: str
    error: str = ""
    duration: float = 0.0

class E2ESetupManager:
    """Gerenciador de setup do ambiente E2E"""
    
    def __init__(self, environment: str = 'dev'):
        self.environment = environment
        self.results: List[SetupResult] = []
        self.start_time = datetime.now()
        
        # Configurações por ambiente
        self.configs = {
            'dev': {
                'base_url': 'http://localhost:5000',
                'api_key': 'dev-fake-key',
                'timeout': 30000,
                'workers': 1
            },
            'staging': {
                'base_url': 'https://staging.omni-writer.com',
                'api_key': os.getenv('STAGING_API_KEY', 'staging-fake-key'),
                'timeout': 60000,
                'workers': 2
            },
            'prod': {
                'base_url': 'https://omni-writer.com',
                'api_key': os.getenv('PROD_API_KEY', 'prod-fake-key'),
                'timeout': 90000,
                'workers': 3
            }
        }
        
        self.config = self.configs.get(environment, self.configs['dev'])
    
    def get_setup_steps(self) -> List[SetupStep]:
        """Retorna lista de passos do setup"""
        return [
            SetupStep(
                name="Verificar Python",
                description="Verificar se Python 3.11+ está instalado",
                command="python --version",
                success_criteria="Python 3.11"
            ),
            SetupStep(
                name="Verificar Node.js",
                description="Verificar se Node.js 18+ está instalado",
                command="node --version",
                success_criteria="v18"
            ),
            SetupStep(
                name="Verificar npm",
                description="Verificar se npm está disponível",
                command="npm --version",
                success_criteria=""
            ),
            SetupStep(
                name="Instalar dependências Python",
                description="Instalar dependências Python do projeto",
                command="pip install -r requirements.txt",
                success_criteria="Successfully installed"
            ),
            SetupStep(
                name="Instalar dependências Node.js",
                description="Instalar dependências Node.js do projeto",
                command="npm ci",
                success_criteria="added"
            ),
            SetupStep(
                name="Instalar Playwright",
                description="Instalar Playwright e browsers",
                command="npx playwright install --with-deps",
                success_criteria="Installing"
            ),
            SetupStep(
                name="Criar diretórios necessários",
                description="Criar estrutura de diretórios para testes",
                command="mkdir -p test-results tests/e2e/snapshots logs/e2e",
                success_criteria=""
            ),
            SetupStep(
                name="Configurar variáveis de ambiente",
                description="Configurar variáveis de ambiente para E2E",
                command="echo 'E2E_ENV={self.environment}' >> .env",
                success_criteria=""
            ),
            SetupStep(
                name="Validar configuração",
                description="Validar se configuração está correta",
                command="python scripts/validate_e2e_config.py",
                success_criteria="Configuration valid"
            ),
            SetupStep(
                name="Teste de conectividade",
                description="Testar conectividade com aplicação",
                command=f"curl -f {self.config['base_url']}/health",
                success_criteria="200",
                required=False
            )
        ]
    
    def execute_step(self, step: SetupStep) -> SetupResult:
        """Executa um passo específico do setup"""
        print(f"🔧 Executando: {step.name}")
        print(f"   📝 {step.description}")
        
        start_time = datetime.now()
        success = False
        output = ""
        error = ""
        
        try:
            # Executar comando
            result = subprocess.run(
                step.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            output = result.stdout
            error = result.stderr
            
            # Verificar sucesso
            if result.returncode == 0:
                if step.success_criteria:
                    success = step.success_criteria in output or step.success_criteria in error
                else:
                    success = True
            else:
                success = False
                
        except subprocess.TimeoutExpired:
            error = "Timeout: comando demorou mais de 5 minutos"
            success = False
        except Exception as e:
            error = str(e)
            success = False
        
        duration = (datetime.now() - start_time).total_seconds()
        
        result = SetupResult(
            step=step,
            success=success,
            output=output,
            error=error,
            duration=duration
        )
        
        # Exibir resultado
        if success:
            print(f"   ✅ Sucesso ({duration:.1f}s)")
        else:
            print(f"   ❌ Falha ({duration:.1f}s)")
            if error:
                print(f"      Erro: {error}")
        
        return result
    
    def run_setup(self) -> bool:
        """Executa setup completo"""
        print(f"🚀 Iniciando setup do ambiente E2E - {self.environment.upper()}")
        print(f"⏰ Início: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        steps = self.get_setup_steps()
        all_success = True
        
        for step in steps:
            result = self.execute_step(step)
            self.results.append(result)
            
            if not result.success and step.required:
                all_success = False
                print(f"❌ Setup falhou no passo obrigatório: {step.name}")
                break
            
            print()
        
        # Resumo final
        self._print_summary()
        
        return all_success
    
    def _print_summary(self) -> None:
        """Exibe resumo do setup"""
        total_duration = (datetime.now() - self.start_time).total_seconds()
        successful_steps = len([r for r in self.results if r.success])
        total_steps = len(self.results)
        
        print("=" * 60)
        print(f"📊 RESUMO DO SETUP")
        print(f"   Ambiente: {self.environment.upper()}")
        print(f"   Passos executados: {successful_steps}/{total_steps}")
        print(f"   Tempo total: {total_duration:.1f}s")
        print(f"   Status: {'✅ SUCESSO' if successful_steps == total_steps else '❌ FALHA'}")
        
        if successful_steps < total_steps:
            print(f"\n❌ Passos com falha:")
            for result in self.results:
                if not result.success:
                    print(f"   • {result.step.name}: {result.error}")
    
    def generate_report(self, output_path: str) -> None:
        """Gera relatório detalhado do setup"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'environment': self.environment,
            'config': self.config,
            'summary': {
                'total_steps': len(self.results),
                'successful_steps': len([r for r in self.results if r.success]),
                'failed_steps': len([r for r in self.results if not r.success]),
                'total_duration': (datetime.now() - self.start_time).total_seconds(),
                'success_rate': (len([r for r in self.results if r.success]) / len(self.results) * 100) if self.results else 0
            },
            'steps': [
                {
                    'name': result.step.name,
                    'description': result.step.description,
                    'success': result.success,
                    'duration': result.duration,
                    'output': result.output,
                    'error': result.error,
                    'required': result.step.required
                }
                for result in self.results
            ],
            'recommendations': self._generate_recommendations()
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Relatório salvo em: {output_path}")
    
    def _generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas nos resultados"""
        recommendations = []
        
        failed_steps = [r for r in self.results if not r.success]
        
        if failed_steps:
            recommendations.append(f"Corrigir {len(failed_steps)} passos com falha")
            
            for result in failed_steps:
                if "Python" in result.step.name and not result.success:
                    recommendations.append("Instalar Python 3.11+ se não estiver disponível")
                elif "Node.js" in result.step.name and not result.success:
                    recommendations.append("Instalar Node.js 18+ se não estiver disponível")
                elif "npm" in result.step.name and not result.success:
                    recommendations.append("Verificar se npm está instalado corretamente")
                elif "Playwright" in result.step.name and not result.success:
                    recommendations.append("Verificar permissões de instalação do Playwright")
        
        # Verificar configurações específicas
        if self.environment == 'staging' and not os.getenv('STAGING_API_KEY'):
            recommendations.append("Configurar STAGING_API_KEY para ambiente staging")
        
        if self.environment == 'prod' and not os.getenv('PROD_API_KEY'):
            recommendations.append("Configurar PROD_API_KEY para ambiente produção")
        
        return recommendations

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Setup Automático do Ambiente E2E')
    parser.add_argument('--environment', '-e', default='dev', 
                       choices=['dev', 'staging', 'prod'],
                       help='Ambiente para configurar')
    parser.add_argument('--report', '-r', default='test-results/setup-report.json',
                       help='Arquivo de relatório de saída')
    parser.add_argument('--skip-validation', action='store_true',
                       help='Pular validação de configuração')
    
    args = parser.parse_args()
    
    setup_manager = E2ESetupManager(args.environment)
    
    # Executar setup
    success = setup_manager.run_setup()
    
    # Gerar relatório
    setup_manager.generate_report(args.report)
    
    # Retornar código de saída
    exit_code = 0 if success else 1
    exit(exit_code)

if __name__ == '__main__':
    main() 