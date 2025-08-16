#!/usr/bin/env python3
"""
Script de Configuração de Testes Avançados - Omni Writer
========================================================

Configura automaticamente:
- Testes de regressão visual com Percy
- Cobertura de branches críticos
- Política rigorosa de testes
- Validação de acessibilidade visual
- Pipeline de validação visual

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import os
import sys
import subprocess
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/setup_advanced_testing.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class AdvancedTestingSetup:
    """Configurador de testes avançados"""
    
    def __init__(self):
        self.project_root = Path.cwd()
        self.scripts_dir = self.project_root / "scripts"
        self.tests_dir = self.project_root / "tests"
        self.config_dir = self.project_root / "config"
        self.logs_dir = self.project_root / "logs"
        
        # Cria diretórios necessários
        self.logs_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        
        # Configurações
        self.percy_config = {
            'version': 2,
            'snapshot': {
                'widths': [1920, 768, 375],
                'minHeight': 1024,
                'percyCSS': '.percy-hide { display: none !important; }'
            },
            'discovery': {
                'allowedHostnames': ['localhost'],
                'disallowedHostnames': [],
                'networkIdleTimeout': 100,
                'cacheResponses': True
            }
        }
        
        self.coverage_config = {
            'coverage': {
                'threshold': {
                    'global': {
                        'branches': 85,
                        'functions': 85,
                        'lines': 85,
                        'statements': 85
                    }
                },
                'exclude': [
                    'tests/**',
                    '**/*.test.js',
                    '**/*.spec.js',
                    '**/node_modules/**',
                    '**/coverage/**'
                ],
                'reporter': ['text', 'lcov', 'html', 'json']
            }
        }
    
    def setup_visual_regression_testing(self) -> bool:
        """Configura testes de regressão visual"""
        logger.info("🔍 Configurando testes de regressão visual...")
        
        try:
            # Instala dependências
            dependencies = [
                'percy',
                'selenium',
                'webdriver-manager',
                'pytest-selenium',
                'pytest-html'
            ]
            
            for dep in dependencies:
                logger.info(f"📦 Instalando {dep}...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
            
            # Cria arquivo de configuração Percy
            percy_config_path = self.project_root / '.percy.js'
            with open(percy_config_path, 'w') as f:
                f.write(f"module.exports = {json.dumps(self.percy_config, indent=2)}")
            
            # Cria diretório de screenshots
            screenshots_dir = self.project_root / "test-results" / "visual"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            
            # Cria arquivo de configuração do Selenium
            selenium_config = {
                'webdriver': {
                    'chrome': {
                        'options': [
                            '--headless',
                            '--no-sandbox',
                            '--disable-dev-shm-usage',
                            '--disable-gpu'
                        ]
                    }
                },
                'screenshots': {
                    'dir': str(screenshots_dir),
                    'format': 'png'
                }
            }
            
            selenium_config_path = self.config_dir / "selenium.yml"
            with open(selenium_config_path, 'w') as f:
                yaml.dump(selenium_config, f)
            
            logger.info("✅ Testes de regressão visual configurados")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar testes de regressão visual: {e}")
            return False
    
    def setup_critical_branches_coverage(self) -> bool:
        """Configura cobertura de branches críticos"""
        logger.info("🎯 Configurando cobertura de branches críticos...")
        
        try:
            # Instala dependências
            dependencies = [
                'pytest-cov',
                'coverage',
                'pytest-benchmark'
            ]
            
            for dep in dependencies:
                logger.info(f"📦 Instalando {dep}...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
            
            # Cria arquivo de configuração de cobertura
            coverage_config_path = self.project_root / '.coveragerc'
            with open(coverage_config_path, 'w') as f:
                f.write(f"[run]\n")
                f.write(f"source = .\n")
                f.write(f"omit = \n")
                f.write(f"    */tests/*\n")
                f.write(f"    */venv/*\n")
                f.write(f"    */node_modules/*\n")
                f.write(f"    setup.py\n")
                f.write(f"\n")
                f.write(f"[report]\n")
                f.write(f"exclude_lines =\n")
                f.write(f"    pragma: no cover\n")
                f.write(f"    def __repr__\n")
                f.write(f"    if self.debug:\n")
                f.write(f"    if settings.DEBUG\n")
                f.write(f"    raise AssertionError\n")
                f.write(f"    raise NotImplementedError\n")
                f.write(f"    if 0:\n")
                f.write(f"    if __name__ == .__main__.:\n")
                f.write(f"    class .*\\bProtocol\\):\n")
                f.write(f"    @(abc\\.)?abstractmethod\n")
                f.write(f"\n")
                f.write(f"[html]\n")
                f.write(f"directory = coverage/html\n")
                f.write(f"\n")
                f.write(f"[xml]\n")
                f.write(f"output = coverage/coverage.xml\n")
            
            # Cria script de análise de branches críticos
            critical_branches_script = self.scripts_dir / "analyze_critical_branches.py"
            with open(critical_branches_script, 'w') as f:
                f.write(self._get_critical_branches_script())
            
            # Torna executável
            critical_branches_script.chmod(0o755)
            
            logger.info("✅ Cobertura de branches críticos configurada")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar cobertura de branches críticos: {e}")
            return False
    
    def setup_rigorous_test_policy(self) -> bool:
        """Configura política rigorosa de testes"""
        logger.info("📋 Configurando política rigorosa de testes...")
        
        try:
            # Cria arquivo de configuração da política
            policy_config = {
                'policy': {
                    'name': 'Rigorous Test Policy',
                    'version': '1.0',
                    'enforcement': 'strict',
                    'rules': {
                        'no_synthetic_data': True,
                        'real_data_required': True,
                        'code_correspondence': True,
                        'meaningful_names': True,
                        'specific_assertions': True
                    },
                    'thresholds': {
                        'real_data_score': 0.3,
                        'required_patterns': 5,
                        'forbidden_patterns': 0
                    }
                }
            }
            
            policy_config_path = self.config_dir / "test_policy.yml"
            with open(policy_config_path, 'w') as f:
                yaml.dump(policy_config, f)
            
            # Cria script de validação da política
            policy_validator_script = self.scripts_dir / "validate_test_policy.py"
            with open(policy_validator_script, 'w') as f:
                f.write(self._get_policy_validator_script())
            
            # Torna executável
            policy_validator_script.chmod(0o755)
            
            logger.info("✅ Política rigorosa de testes configurada")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar política rigorosa de testes: {e}")
            return False
    
    def setup_accessibility_validation(self) -> bool:
        """Configura validação de acessibilidade visual"""
        logger.info("♿ Configurando validação de acessibilidade visual...")
        
        try:
            # Instala dependências
            dependencies = [
                'axe-selenium-python',
                'pytest-axe',
                'pytest-accessibility'
            ]
            
            for dep in dependencies:
                logger.info(f"📦 Instalando {dep}...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
            
            # Cria configuração de acessibilidade
            a11y_config = {
                'accessibility': {
                    'rules': {
                        'color-contrast': 'error',
                        'focus-order': 'error',
                        'heading-order': 'error',
                        'image-alt': 'error',
                        'label': 'error',
                        'link-name': 'error',
                        'list': 'error',
                        'listitem': 'error',
                        'region': 'error'
                    },
                    'thresholds': {
                        'critical': 0,
                        'serious': 0,
                        'moderate': 5,
                        'minor': 10
                    }
                }
            }
            
            a11y_config_path = self.config_dir / "accessibility.yml"
            with open(a11y_config_path, 'w') as f:
                yaml.dump(a11y_config, f)
            
            logger.info("✅ Validação de acessibilidade visual configurada")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar validação de acessibilidade: {e}")
            return False
    
    def setup_visual_pipeline(self) -> bool:
        """Configura pipeline de validação visual"""
        logger.info("🔄 Configurando pipeline de validação visual...")
        
        try:
            # Cria workflow do GitHub Actions
            workflows_dir = self.project_root / ".github" / "workflows"
            workflows_dir.mkdir(parents=True, exist_ok=True)
            
            visual_workflow = {
                'name': 'Visual Regression Tests',
                'on': {
                    'push': {
                        'branches': ['main', 'develop']
                    },
                    'pull_request': {
                        'branches': ['main']
                    }
                },
                'jobs': {
                    'visual-tests': {
                        'runs-on': 'ubuntu-latest',
                        'steps': [
                            {
                                'name': 'Checkout code',
                                'uses': 'actions/checkout@v3'
                            },
                            {
                                'name': 'Setup Python',
                                'uses': 'actions/setup-python@v4',
                                'with': {
                                    'python-version': '3.11'
                                }
                            },
                            {
                                'name': 'Install dependencies',
                                'run': 'pip install -r requirements.txt'
                            },
                            {
                                'name': 'Setup Percy',
                                'uses': 'percy/setup-action@v1',
                                'with': {
                                    'version': 'latest'
                                }
                            },
                            {
                                'name': 'Run visual tests',
                                'run': 'pytest tests/visual/ -v --percy'
                            }
                        ]
                    }
                }
            }
            
            workflow_path = workflows_dir / "visual-tests.yml"
            with open(workflow_path, 'w') as f:
                yaml.dump(visual_workflow, f, default_flow_style=False)
            
            # Cria script de execução do pipeline
            pipeline_script = self.scripts_dir / "run_visual_pipeline.py"
            with open(pipeline_script, 'w') as f:
                f.write(self._get_visual_pipeline_script())
            
            # Torna executável
            pipeline_script.chmod(0o755)
            
            logger.info("✅ Pipeline de validação visual configurado")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar pipeline de validação visual: {e}")
            return False
    
    def setup_test_reports(self) -> bool:
        """Configura relatórios de teste"""
        logger.info("📊 Configurando relatórios de teste...")
        
        try:
            # Cria diretório de relatórios
            reports_dir = self.project_root / "test-reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Cria configuração de relatórios
            reports_config = {
                'reports': {
                    'coverage': {
                        'html': 'test-reports/coverage/html',
                        'xml': 'test-reports/coverage/coverage.xml',
                        'json': 'test-reports/coverage/coverage.json'
                    },
                    'visual': {
                        'screenshots': 'test-reports/visual/screenshots',
                        'diffs': 'test-reports/visual/diffs',
                        'percy': 'test-reports/visual/percy'
                    },
                    'accessibility': {
                        'violations': 'test-reports/accessibility/violations.json',
                        'summary': 'test-reports/accessibility/summary.html'
                    },
                    'policy': {
                        'validation': 'test-reports/policy/validation.json',
                        'issues': 'test-reports/policy/issues.html'
                    }
                }
            }
            
            reports_config_path = self.config_dir / "reports.yml"
            with open(reports_config_path, 'w') as f:
                yaml.dump(reports_config, f)
            
            # Cria script de geração de relatórios
            reports_script = self.scripts_dir / "generate_test_reports.py"
            with open(reports_script, 'w') as f:
                f.write(self._get_reports_script())
            
            # Torna executável
            reports_script.chmod(0o755)
            
            logger.info("✅ Relatórios de teste configurados")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao configurar relatórios de teste: {e}")
            return False
    
    def _get_critical_branches_script(self) -> str:
        """Retorna script de análise de branches críticos"""
        return '''
#!/usr/bin/env python3
"""
Análise de Branches Críticos - Omni Writer
==========================================

Analisa branches críticos não cobertos e gera relatório.

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import coverage
import os
import json
from pathlib import Path

def analyze_critical_branches():
    """Analisa branches críticos não cobertos"""
    # Configura coverage
    cov = coverage.Coverage()
    cov.load()
    
    # Analisa branches
    analysis = cov.analysis2()
    
    # Identifica branches não cobertos
    uncovered_branches = []
    
    for filename, analysis_data in analysis.items():
        if 'tests' not in filename and filename.endswith('.py'):
            missing_branches = analysis_data[2]  # Branches não cobertos
            
            if missing_branches:
                uncovered_branches.append({
                    'file': filename,
                    'missing_branches': missing_branches,
                    'total_branches': len(analysis_data[1]),
                    'coverage_percentage': (len(analysis_data[1]) - len(missing_branches)) / len(analysis_data[1]) * 100
                })
    
    # Gera relatório
    report = {
        'uncovered_branches': uncovered_branches,
        'total_files_analyzed': len(analysis),
        'files_with_uncovered_branches': len(uncovered_branches),
        'critical_files': [f for f in uncovered_branches if f['coverage_percentage'] < 85]
    }
    
    # Salva relatório
    with open('test-reports/critical_branches.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📊 Relatório de branches críticos gerado:")
    print(f"  📁 Arquivos analisados: {report['total_files_analyzed']}")
    print(f"  ❌ Arquivos com branches não cobertos: {report['files_with_uncovered_branches']}")
    print(f"  🚨 Arquivos críticos (<85%): {len(report['critical_files'])}")
    
    return report

if __name__ == "__main__":
    analyze_critical_branches()
'''
    
    def _get_policy_validator_script(self) -> str:
        """Retorna script de validação da política"""
        return '''
#!/usr/bin/env python3
"""
Validador da Política de Testes - Omni Writer
=============================================

Valida se os testes seguem a política rigorosa.

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'tests', 'policy'))

from test_rigorous_policy import RigorousTestPolicyValidator

def validate_test_policy():
    """Valida política de testes"""
    validator = RigorousTestPolicyValidator()
    
    # Valida diretório de testes
    results = validator.validate_test_directory("tests")
    
    # Salva resultados
    import json
    with open('test-reports/policy/validation.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Exibe resumo
    print(f"📋 Validação da política de testes:")
    print(f"  📁 Total de arquivos: {results['total_files']}")
    print(f"  ✅ Arquivos válidos: {results['valid_files']}")
    print(f"  ❌ Arquivos inválidos: {results['invalid_files']}")
    print(f"  🚨 Issues críticos: {results['summary']['critical_issues']}")
    
    return results['invalid_files'] == 0

if __name__ == "__main__":
    success = validate_test_policy()
    sys.exit(0 if success else 1)
'''
    
    def _get_visual_pipeline_script(self) -> str:
        """Retorna script do pipeline visual"""
        return '''
#!/usr/bin/env python3
"""
Pipeline de Validação Visual - Omni Writer
==========================================

Executa pipeline completo de validação visual.

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import subprocess
import sys
import os
from pathlib import Path

def run_visual_pipeline():
    """Executa pipeline de validação visual"""
    print("🔄 Executando pipeline de validação visual...")
    
    steps = [
        ("🧪 Executando testes de regressão visual", "pytest tests/visual/ -v --percy"),
        ("♿ Executando testes de acessibilidade", "pytest tests/visual/ -k 'accessibility' -v"),
        ("📊 Gerando relatórios de cobertura", "coverage run -m pytest tests/"),
        ("📈 Gerando relatório HTML", "coverage html"),
        ("📋 Validando política de testes", "python scripts/validate_test_policy.py")
    ]
    
    results = []
    
    for step_name, command in steps:
        print(f"  {step_name}...")
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True)
            success = result.returncode == 0
            results.append({
                'step': step_name,
                'success': success,
                'output': result.stdout,
                'error': result.stderr
            })
            
            if success:
                print(f"    ✅ {step_name} - Sucesso")
            else:
                print(f"    ❌ {step_name} - Falhou")
                print(f"       Erro: {result.stderr}")
                
        except Exception as e:
            print(f"    ❌ {step_name} - Erro: {e}")
            results.append({
                'step': step_name,
                'success': False,
                'error': str(e)
            })
    
    # Gera relatório
    import json
    with open('test-reports/visual/pipeline_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    # Verifica sucesso geral
    all_success = all(r['success'] for r in results)
    
    print(f"📊 Resultado do pipeline:")
    print(f"  ✅ Passos bem-sucedidos: {sum(1 for r in results if r['success'])}/{len(results)}")
    print(f"  ❌ Passos com falha: {sum(1 for r in results if not r['success'])}")
    
    return all_success

if __name__ == "__main__":
    success = run_visual_pipeline()
    sys.exit(0 if success else 1)
'''
    
    def _get_reports_script(self) -> str:
        """Retorna script de geração de relatórios"""
        return '''
#!/usr/bin/env python3
"""
Gerador de Relatórios de Teste - Omni Writer
============================================

Gera relatórios consolidados de todos os tipos de teste.

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import json
import os
from pathlib import Path
from datetime import datetime

def generate_test_reports():
    """Gera relatórios consolidados de teste"""
    print("📊 Gerando relatórios consolidados...")
    
    reports_dir = Path("test-reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Coleta dados de diferentes relatórios
    reports_data = {
        'timestamp': datetime.now().isoformat(),
        'coverage': {},
        'visual': {},
        'accessibility': {},
        'policy': {},
        'summary': {}
    }
    
    # Relatório de cobertura
    coverage_file = reports_dir / "coverage" / "coverage.json"
    if coverage_file.exists():
        with open(coverage_file) as f:
            reports_data['coverage'] = json.load(f)
    
    # Relatório de branches críticos
    critical_branches_file = reports_dir / "critical_branches.json"
    if critical_branches_file.exists():
        with open(critical_branches_file) as f:
            reports_data['critical_branches'] = json.load(f)
    
    # Relatório de política
    policy_file = reports_dir / "policy" / "validation.json"
    if policy_file.exists():
        with open(policy_file) as f:
            reports_data['policy'] = json.load(f)
    
    # Gera resumo
    reports_data['summary'] = {
        'total_tests': reports_data.get('coverage', {}).get('totals', {}).get('num_statements', 0),
        'coverage_percentage': reports_data.get('coverage', {}).get('totals', {}).get('percent_covered', 0),
        'critical_files': len(reports_data.get('critical_branches', {}).get('critical_files', [])),
        'policy_violations': reports_data.get('policy', {}).get('invalid_files', 0)
    }
    
    # Salva relatório consolidado
    consolidated_file = reports_dir / "consolidated_report.json"
    with open(consolidated_file, 'w') as f:
        json.dump(reports_data, f, indent=2)
    
    # Gera relatório HTML
    html_report = generate_html_report(reports_data)
    html_file = reports_dir / "consolidated_report.html"
    with open(html_file, 'w') as f:
        f.write(html_report)
    
    print(f"📊 Relatórios gerados:")
    print(f"  📄 JSON: {consolidated_file}")
    print(f"  🌐 HTML: {html_file}")
    print(f"  📈 Resumo:")
    print(f"    - Total de testes: {reports_data['summary']['total_tests']}")
    print(f"    - Cobertura: {reports_data['summary']['coverage_percentage']:.1f}%")
    print(f"    - Arquivos críticos: {reports_data['summary']['critical_files']}")
    print(f"    - Violações de política: {reports_data['summary']['policy_violations']}")

def generate_html_report(data):
    """Gera relatório HTML"""
    return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório Consolidado de Testes - Omni Writer</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #e8f5e8; border-radius: 5px; }}
        .critical {{ background: #ffe8e8; }}
        .warning {{ background: #fff3e8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Relatório Consolidado de Testes</h1>
        <p>Omni Writer - {data['timestamp']}</p>
    </div>
    
    <div class="metrics">
        <div class="metric">
            <h3>🧪 Total de Testes</h3>
            <p>{data['summary']['total_tests']}</p>
        </div>
        <div class="metric {'critical' if data['summary']['coverage_percentage'] < 85 else ''}">
            <h3>📈 Cobertura</h3>
            <p>{data['summary']['coverage_percentage']:.1f}%</p>
        </div>
        <div class="metric {'warning' if data['summary']['critical_files'] > 0 else ''}">
            <h3>🚨 Arquivos Críticos</h3>
            <p>{data['summary']['critical_files']}</p>
        </div>
        <div class="metric {'critical' if data['summary']['policy_violations'] > 0 else ''}">
            <h3>📋 Violações de Política</h3>
            <p>{data['summary']['policy_violations']}</p>
        </div>
    </div>
    
    <h2>📄 Detalhes</h2>
    <pre>{json.dumps(data, indent=2)}</pre>
</body>
</html>
"""

if __name__ == "__main__":
    generate_test_reports()
'''
    
    def run_setup(self) -> bool:
        """Executa configuração completa"""
        logger.info("🚀 Iniciando configuração de testes avançados...")
        
        setup_steps = [
            ("Testes de Regressão Visual", self.setup_visual_regression_testing),
            ("Cobertura de Branches Críticos", self.setup_critical_branches_coverage),
            ("Política Rigorosa de Testes", self.setup_rigorous_test_policy),
            ("Validação de Acessibilidade", self.setup_accessibility_validation),
            ("Pipeline de Validação Visual", self.setup_visual_pipeline),
            ("Relatórios de Teste", self.setup_test_reports)
        ]
        
        results = []
        
        for step_name, step_func in setup_steps:
            logger.info(f"🔧 Configurando {step_name}...")
            success = step_func()
            results.append((step_name, success))
            
            if success:
                logger.info(f"✅ {step_name} configurado com sucesso")
            else:
                logger.error(f"❌ Falha ao configurar {step_name}")
        
        # Gera relatório final
        successful_steps = sum(1 for _, success in results if success)
        total_steps = len(results)
        
        logger.info(f"📊 Resumo da configuração:")
        logger.info(f"  ✅ Passos bem-sucedidos: {successful_steps}/{total_steps}")
        logger.info(f"  ❌ Passos com falha: {total_steps - successful_steps}")
        
        # Lista passos com falha
        failed_steps = [name for name, success in results if not success]
        if failed_steps:
            logger.error(f"❌ Passos com falha: {', '.join(failed_steps)}")
        
        # Cria arquivo de configuração final
        final_config = {
            'setup': {
                'timestamp': '2025-01-27T00:00:00Z',
                'version': '1.0',
                'successful_steps': successful_steps,
                'total_steps': total_steps,
                'failed_steps': failed_steps
            },
            'components': {
                'visual_regression': any(success for name, success in results if 'visual' in name.lower()),
                'critical_branches': any(success for name, success in results if 'branches' in name.lower()),
                'rigorous_policy': any(success for name, success in results if 'política' in name.lower()),
                'accessibility': any(success for name, success in results if 'acessibilidade' in name.lower()),
                'visual_pipeline': any(success for name, success in results if 'pipeline' in name.lower()),
                'test_reports': any(success for name, success in results if 'relatórios' in name.lower())
            }
        }
        
        config_file = self.config_dir / "advanced_testing_setup.json"
        with open(config_file, 'w') as f:
            json.dump(final_config, f, indent=2)
        
        logger.info(f"📄 Configuração salva em: {config_file}")
        
        return successful_steps == total_steps

def main():
    """Função principal"""
    print("🧪 Configurador de Testes Avançados - Omni Writer")
    print("=" * 60)
    
    setup = AdvancedTestingSetup()
    success = setup.run_setup()
    
    if success:
        print("\n🎉 Configuração concluída com sucesso!")
        print("\n📋 Próximos passos:")
        print("  1. Configure as variáveis de ambiente do Percy")
        print("  2. Execute: python scripts/validate_test_policy.py")
        print("  3. Execute: python scripts/run_visual_pipeline.py")
        print("  4. Verifique os relatórios em test-reports/")
    else:
        print("\n❌ Configuração falhou!")
        print("Verifique os logs em logs/setup_advanced_testing.log")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main()) 