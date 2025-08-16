#!/usr/bin/env python3
"""
Script de Configuração Percy e Baseline - Omni Writer
=====================================================

Configura Percy para regressão visual automatizada e cria baseline de imagens.

Prompt: Configuração Percy e Baseline - Item 10
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-28T10:15:00Z
Tracing ID: ENTERPRISE_20250128_010

Autor: Análise Técnica Omni Writer
Data: 2025-01-28
Versão: 1.0
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [percy_setup] %(message)s',
    handlers=[
        logging.FileHandler('logs/exec_trace/percy_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PercyBaselineSetup:
    """
    Configuração do Percy e criação de baseline.
    
    Funcionalidades:
    - Instalação e configuração do Percy
    - Criação de baseline de imagens
    - Configuração de alertas
    - Validação do ambiente
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.visual_dir = self.project_root / 'tests' / 'visual'
        self.baseline_dir = self.visual_dir / 'baselines'
        self.screenshots_dir = self.visual_dir / 'screenshots'
        self.config_dir = self.visual_dir / 'config'
        
    def setup_percy_environment(self) -> bool:
        """
        Configura ambiente completo do Percy.
        
        Returns:
            True se configuração bem-sucedida
        """
        try:
            logger.info("=== INICIANDO CONFIGURAÇÃO PERCY ===")
            
            # Passo 1: Instalar dependências
            if not self._install_dependencies():
                return False
            
            # Passo 2: Configurar Percy
            if not self._setup_percy_config():
                return False
            
            # Passo 3: Criar baseline
            if not self._create_baseline_images():
                return False
            
            # Passo 4: Configurar alertas
            if not self._setup_alerts():
                return False
            
            # Passo 5: Validar ambiente
            if not self._validate_environment():
                return False
            
            logger.info("=== CONFIGURAÇÃO PERCY CONCLUÍDA ===")
            return True
            
        except Exception as e:
            logger.error(f"Erro na configuração Percy: {e}")
            return False
    
    def _install_dependencies(self) -> bool:
        """Instala dependências necessárias."""
        try:
            logger.info("Instalando dependências Percy...")
            
            dependencies = [
                'percy',
                'selenium',
                'webdriver-manager',
                'opencv-python',
                'pillow',
                'requests'
            ]
            
            for dep in dependencies:
                logger.info(f"📦 Instalando {dep}...")
                try:
                    subprocess.run([
                        sys.executable, '-m', 'pip', 'install', dep
                    ], check=True, capture_output=True)
                    logger.info(f"✓ {dep} instalado")
                except subprocess.CalledProcessError as e:
                    logger.error(f"✗ Erro ao instalar {dep}: {e}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao instalar dependências: {e}")
            return False
    
    def _setup_percy_config(self) -> bool:
        """Configura Percy."""
        try:
            logger.info("Configurando Percy...")
            
            # Cria arquivo de configuração Percy
            percy_config = {
                'version': 2,
                'snapshot': {
                    'widths': [375, 768, 1920],
                    'minHeight': 1024,
                    'percyCSS': """
                        /* Esconde elementos dinâmicos */
                        .loading, .spinner { display: none !important; }
                        .timestamp, .dynamic-content { display: none !important; }
                        /* Fixa posições para screenshots consistentes */
                        * { animation: none !important; }
                        /* Mascara elementos sensíveis */
                        .user-specific, .session-data { 
                            background: #f0f0f0 !important; 
                            color: transparent !important; 
                        }
                    """
                },
                'discovery': {
                    'allowedHostnames': ['localhost', '127.0.0.1'],
                    'disallowedHostnames': [],
                    'networkIdleTimeout': 100
                },
                'agent': {
                    'assetDiscovery': {
                        'allowedHostnames': ['localhost', '127.0.0.1'],
                        'disallowedHostnames': [],
                        'networkIdleTimeout': 100
                    }
                }
            }
            
            config_file = self.config_dir / 'percy.json'
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(percy_config, f, indent=2)
            
            logger.info(f"✓ Configuração Percy salva: {config_file}")
            
            # Cria arquivo .percy.js na raiz do projeto
            percy_js_content = f"""
module.exports = {{
    version: 2,
    snapshot: {{
        widths: [375, 768, 1920],
        minHeight: 1024,
        percyCSS: `
            .loading, .spinner {{ display: none !important; }}
            .timestamp, .dynamic-content {{ display: none !important; }}
            * {{ animation: none !important; }}
            .user-specific, .session-data {{ 
                background: #f0f0f0 !important; 
                color: transparent !important; 
            }}
        `
    }},
    discovery: {{
        allowedHostnames: ['localhost', '127.0.0.1'],
        disallowedHostnames: [],
        networkIdleTimeout: 100
    }}
}};
"""
            
            percy_js_file = self.project_root / '.percy.js'
            with open(percy_js_file, 'w', encoding='utf-8') as f:
                f.write(percy_js_content)
            
            logger.info(f"✓ Arquivo .percy.js criado: {percy_js_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao configurar Percy: {e}")
            return False
    
    def _create_baseline_images(self) -> bool:
        """Cria baseline de imagens de referência."""
        try:
            logger.info("Criando baseline de imagens...")
            
            # Importa módulos necessários
            sys.path.insert(0, str(self.project_root))
            
            from tests.visual.visual_comparison import visual_comparison_engine
            from tests.visual.test_visual_regression import VisualRegressionTester
            
            # Configurações de teste
            test_configs = [
                {'name': 'Homepage', 'url': '/', 'selector': '.main-content'},
                {'name': 'Generation Form', 'url': '/generate', 'selector': '.generation-form'},
                {'name': 'Blog List', 'url': '/blogs', 'selector': '.blog-list'},
                {'name': 'Article Detail', 'url': '/article/1', 'selector': '.article-content'}
            ]
            
            viewports = ['desktop', 'tablet', 'mobile']
            
            # Cria instância do testador
            tester = VisualRegressionTester()
            
            baseline_created = 0
            
            for test_config in test_configs:
                for viewport in viewports:
                    try:
                        logger.info(f"Criando baseline: {test_config['name']} - {viewport}")
                        
                        # Configura driver
                        tester.setup_driver(viewport)
                        
                        # Navega para página
                        tester.driver.get(f"{tester.base_url}{test_config['url']}")
                        
                        # Aguarda elemento
                        tester.wait.until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, test_config['selector']))
                        )
                        
                        # Tira screenshot
                        screenshot_path = f"{self.screenshots_dir}/{test_config['name']}_{viewport}.png"
                        tester.driver.save_screenshot(screenshot_path)
                        
                        # Cria baseline
                        if visual_comparison_engine.create_baseline(
                            test_config['name'], 
                            viewport, 
                            screenshot_path
                        ):
                            baseline_created += 1
                            logger.info(f"✓ Baseline criado: {test_config['name']} - {viewport}")
                        else:
                            logger.error(f"✗ Falha ao criar baseline: {test_config['name']} - {viewport}")
                        
                        # Finaliza driver
                        tester.teardown_driver()
                        
                    except Exception as e:
                        logger.error(f"Erro ao criar baseline {test_config['name']} - {viewport}: {e}")
                        if tester.driver:
                            tester.teardown_driver()
            
            logger.info(f"✓ Baseline criado: {baseline_created} imagens")
            return baseline_created > 0
            
        except Exception as e:
            logger.error(f"Erro ao criar baseline: {e}")
            return False
    
    def _setup_alerts(self) -> bool:
        """Configura sistema de alertas."""
        try:
            logger.info("Configurando alertas visuais...")
            
            # Cria arquivo de configuração de alertas
            alerts_config = {
                'enabled': True,
                'slack_webhook': os.getenv('SLACK_WEBHOOK_URL', ''),
                'email_recipients': os.getenv('VISUAL_ALERT_EMAILS', '').split(','),
                'notification_levels': ['error', 'warning', 'info'],
                'auto_approve_minor': False,
                'require_human_review': True,
                'threshold': 0.1
            }
            
            alerts_file = self.config_dir / 'alerts.json'
            with open(alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alerts_config, f, indent=2)
            
            logger.info(f"✓ Configuração de alertas salva: {alerts_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao configurar alertas: {e}")
            return False
    
    def _validate_environment(self) -> bool:
        """Valida ambiente configurado."""
        try:
            logger.info("Validando ambiente Percy...")
            
            # Verifica dependências
            try:
                import percy
                logger.info("✓ Percy disponível")
            except ImportError:
                logger.error("✗ Percy não disponível")
                return False
            
            try:
                import cv2
                logger.info("✓ OpenCV disponível")
            except ImportError:
                logger.error("✗ OpenCV não disponível")
                return False
            
            # Verifica arquivos de configuração
            config_files = [
                self.config_dir / 'percy.json',
                self.config_dir / 'alerts.json',
                self.project_root / '.percy.js'
            ]
            
            for config_file in config_files:
                if not config_file.exists():
                    logger.error(f"✗ Arquivo de configuração não encontrado: {config_file}")
                    return False
                logger.info(f"✓ Configuração encontrada: {config_file}")
            
            # Verifica diretórios
            directories = [
                self.baseline_dir,
                self.screenshots_dir,
                self.config_dir
            ]
            
            for directory in directories:
                if not directory.exists():
                    logger.error(f"✗ Diretório não encontrado: {directory}")
                    return False
                logger.info(f"✓ Diretório encontrado: {directory}")
            
            # Verifica baseline
            baseline_files = list(self.baseline_dir.glob('*.png'))
            if not baseline_files:
                logger.warning("⚠️ Nenhum arquivo de baseline encontrado")
            else:
                logger.info(f"✓ {len(baseline_files)} arquivos de baseline encontrados")
            
            logger.info("✓ Ambiente Percy validado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação: {e}")
            return False
    
    def run_visual_tests(self) -> bool:
        """
        Executa testes visuais com Percy.
        
        Returns:
            True se testes passaram
        """
        try:
            logger.info("Executando testes visuais com Percy...")
            
            # Executa testes visuais
            result = subprocess.run([
                sys.executable, '-m', 'pytest',
                str(self.visual_dir / 'test_visual_regression.py'),
                '--percy',
                '-v',
                '--tb=short'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("✓ Testes visuais passaram")
                return True
            else:
                logger.error(f"✗ Testes visuais falharam: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao executar testes: {e}")
            return False
    
    def generate_baseline_report(self) -> str:
        """
        Gera relatório do baseline.
        
        Returns:
            Caminho do relatório gerado
        """
        try:
            logger.info("Gerando relatório do baseline...")
            
            baseline_files = list(self.baseline_dir.glob('*.png'))
            metadata_files = list(self.baseline_dir.glob('*_metadata.json'))
            
            report_content = f"""
# Relatório de Baseline Visual - Omni Writer

## Resumo
- **Data de geração**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total de imagens baseline**: {len(baseline_files)}
- **Total de metadados**: {len(metadata_files)}

## Imagens Baseline
"""
            
            for baseline_file in sorted(baseline_files):
                report_content += f"- `{baseline_file.name}`\n"
            
            report_content += f"""
## Metadados
"""
            
            for metadata_file in sorted(metadata_files):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    report_content += f"- `{metadata_file.name}`: {metadata.get('test_name', 'N/A')} - {metadata.get('viewport', 'N/A')}\n"
                except Exception as e:
                    report_content += f"- `{metadata_file.name}`: Erro ao ler metadados\n"
            
            report_content += f"""
## Configuração
- **Threshold**: {visual_config.baseline_config.threshold}
- **Alertas habilitados**: {visual_config.alert_config.enabled}
- **Slack webhook**: {'Configurado' if visual_config.alert_config.slack_webhook else 'Não configurado'}
- **Emails**: {len(visual_config.alert_config.email_recipients)} destinatários

## Próximos Passos
1. Execute os testes visuais: `python -m pytest tests/visual/ --percy`
2. Monitore os alertas para mudanças visuais
3. Atualize o baseline quando necessário: `python scripts/setup_percy_baseline.py --update-baseline`
"""
            
            report_path = self.visual_dir / 'BASELINE_REPORT.md'
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            logger.info(f"✓ Relatório gerado: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            raise


def main():
    """Função principal."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Configuração Percy e Baseline')
    parser.add_argument('--setup', action='store_true', help='Configurar ambiente completo')
    parser.add_argument('--create-baseline', action='store_true', help='Criar baseline de imagens')
    parser.add_argument('--run-tests', action='store_true', help='Executar testes visuais')
    parser.add_argument('--generate-report', action='store_true', help='Gerar relatório')
    parser.add_argument('--all', action='store_true', help='Executar todas as operações')
    
    args = parser.parse_args()
    
    setup = PercyBaselineSetup()
    
    if args.all or args.setup:
        if not setup.setup_percy_environment():
            sys.exit(1)
    
    if args.all or args.create_baseline:
        if not setup._create_baseline_images():
            sys.exit(1)
    
    if args.all or args.run_tests:
        if not setup.run_visual_tests():
            sys.exit(1)
    
    if args.all or args.generate_report:
        setup.generate_baseline_report()
    
    if not any([args.setup, args.create_baseline, args.run_tests, args.generate_report, args.all]):
        # Executa configuração completa por padrão
        if not setup.setup_percy_environment():
            sys.exit(1)
        setup.generate_baseline_report()


if __name__ == "__main__":
    main() 