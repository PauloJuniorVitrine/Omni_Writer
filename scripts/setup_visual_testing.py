#!/usr/bin/env python3
"""
Script de Configuração para Testes Visuais - Omni Writer
========================================================

Configura ambiente para testes de regressão visual com Percy.

Prompt: Script de configuração para testes visuais
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import os
import sys
import subprocess
import json
import logging
from pathlib import Path

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [visual_setup] %(message)s',
    handlers=[
        logging.FileHandler('logs/exec_trace/visual_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VisualTestingSetup:
    """
    Configuração para testes visuais.
    
    Funcionalidades:
    - Instalação de dependências
    - Configuração do Percy
    - Configuração do Selenium
    - Criação de diretórios
    - Validação do ambiente
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.requirements_file = self.project_root / 'requirements.txt'
        self.visual_dir = self.project_root / 'tests' / 'visual'
        self.screenshots_dir = self.visual_dir / 'screenshots'
        self.baselines_dir = self.visual_dir / 'baselines'
        
    def setup_environment(self) -> bool:
        """
        Configura ambiente completo para testes visuais.
        
        Returns:
            True se configuração bem-sucedida
        """
        try:
            logger.info("=== INICIANDO CONFIGURAÇÃO DE TESTES VISUAIS ===")
            
            # Passo 1: Criar diretórios
            if not self._create_directories():
                return False
            
            # Passo 2: Instalar dependências
            if not self._install_dependencies():
                return False
            
            # Passo 3: Configurar Percy
            if not self._setup_percy():
                return False
            
            # Passo 4: Configurar Selenium
            if not self._setup_selenium():
                return False
            
            # Passo 5: Validar ambiente
            if not self._validate_environment():
                return False
            
            logger.info("=== CONFIGURAÇÃO CONCLUÍDA COM SUCESSO ===")
            return True
            
        except Exception as e:
            logger.error(f"Erro na configuração: {e}")
            return False
    
    def _create_directories(self) -> bool:
        """Cria diretórios necessários."""
        try:
            logger.info("Criando diretórios...")
            
            directories = [
                self.visual_dir,
                self.screenshots_dir,
                self.baselines_dir,
                self.visual_dir / 'reports',
                self.visual_dir / 'config'
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                logger.info(f"✓ Diretório criado: {directory}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao criar diretórios: {e}")
            return False
    
    def _install_dependencies(self) -> bool:
        """Instala dependências para testes visuais."""
        try:
            logger.info("Instalando dependências...")
            
            # Dependências para testes visuais
            visual_deps = [
                'selenium>=4.0.0',
                'pillow>=9.0.0',
                'scikit-image>=0.19.0',
                'numpy>=1.21.0',
                'webdriver-manager>=3.8.0',
                'percy>=2.0.0'
            ]
            
            # Adiciona ao requirements.txt se não existir
            if self.requirements_file.exists():
                with open(self.requirements_file, 'r', encoding='utf-8') as f:
                    current_content = f.read()
                
                # Verifica quais dependências já existem
                missing_deps = []
                for dep in visual_deps:
                    if dep.split('>=')[0] not in current_content:
                        missing_deps.append(dep)
                
                if missing_deps:
                    with open(self.requirements_file, 'a', encoding='utf-8') as f:
                        f.write('\n# Testes visuais\n')
                        for dep in missing_deps:
                            f.write(f'{dep}\n')
                    
                    logger.info(f"Dependências adicionadas ao requirements.txt: {missing_deps}")
                else:
                    logger.info("Todas as dependências já estão no requirements.txt")
            
            # Instala dependências
            logger.info("Executando pip install...")
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', str(self.requirements_file)
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Erro na instalação: {result.stderr}")
                return False
            
            logger.info("✓ Dependências instaladas")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao instalar dependências: {e}")
            return False
    
    def _setup_percy(self) -> bool:
        """Configura Percy para testes visuais."""
        try:
            logger.info("Configurando Percy...")
            
            # Verifica se Percy está disponível
            try:
                import percy
                logger.info("✓ Percy disponível")
            except ImportError:
                logger.warning("Percy não disponível. Instalando...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', 'percy'], check=True)
            
            # Cria arquivo de configuração do Percy
            percy_config = {
                'version': 2,
                'snapshot': {
                    'widths': [375, 768, 1920],
                    'minHeight': 1024,
                    'percyCSS': """
                        /* Esconde elementos dinâmicos */
                        .loading, .spinner { display: none !important; }
                        /* Fixa posições para screenshots consistentes */
                        * { animation: none !important; }
                    """
                },
                'discovery': {
                    'allowedHostnames': ['localhost', '127.0.0.1'],
                    'disallowedHostnames': [],
                    'networkIdleTimeout': 100
                }
            }
            
            config_file = self.visual_dir / 'config' / 'percy.json'
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(percy_config, f, indent=2)
            
            logger.info(f"✓ Configuração Percy salva: {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao configurar Percy: {e}")
            return False
    
    def _setup_selenium(self) -> bool:
        """Configura Selenium WebDriver."""
        try:
            logger.info("Configurando Selenium...")
            
            # Verifica se Chrome está disponível
            try:
                from selenium import webdriver
                from webdriver_manager.chrome import ChromeDriverManager
                
                # Testa instalação do ChromeDriver
                driver_path = ChromeDriverManager().install()
                logger.info(f"✓ ChromeDriver instalado: {driver_path}")
                
            except Exception as e:
                logger.error(f"Erro ao configurar ChromeDriver: {e}")
                logger.info("Instale o Chrome manualmente se necessário")
                return False
            
            # Cria arquivo de configuração do Selenium
            selenium_config = {
                'browser': 'chrome',
                'headless': True,
                'window_size': {
                    'width': 1920,
                    'height': 1080
                },
                'timeouts': {
                    'implicit': 10,
                    'page_load': 30,
                    'script': 30
                },
                'chrome_options': [
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-extensions',
                    '--disable-plugins'
                ]
            }
            
            config_file = self.visual_dir / 'config' / 'selenium.json'
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(selenium_config, f, indent=2)
            
            logger.info(f"✓ Configuração Selenium salva: {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao configurar Selenium: {e}")
            return False
    
    def _validate_environment(self) -> bool:
        """Valida ambiente configurado."""
        try:
            logger.info("Validando ambiente...")
            
            # Verifica dependências
            required_modules = [
                'selenium',
                'PIL',
                'skimage',
                'numpy',
                'webdriver_manager'
            ]
            
            missing_modules = []
            for module in required_modules:
                try:
                    __import__(module)
                    logger.info(f"✓ {module} disponível")
                except ImportError:
                    missing_modules.append(module)
                    logger.error(f"✗ {module} não disponível")
            
            if missing_modules:
                logger.error(f"Módulos faltando: {missing_modules}")
                return False
            
            # Verifica diretórios
            required_dirs = [
                self.visual_dir,
                self.screenshots_dir,
                self.baselines_dir
            ]
            
            for directory in required_dirs:
                if not directory.exists():
                    logger.error(f"Diretório não encontrado: {directory}")
                    return False
                logger.info(f"✓ Diretório existe: {directory}")
            
            # Verifica arquivos de configuração
            config_files = [
                self.visual_dir / 'config' / 'percy.json',
                self.visual_dir / 'config' / 'selenium.json'
            ]
            
            for config_file in config_files:
                if not config_file.exists():
                    logger.error(f"Arquivo de configuração não encontrado: {config_file}")
                    return False
                logger.info(f"✓ Configuração existe: {config_file}")
            
            logger.info("✓ Ambiente validado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação: {e}")
            return False
    
    def create_baseline_screenshots(self, base_url: str = 'http://localhost:5000') -> bool:
        """
        Cria screenshots baseline para comparação.
        
        Args:
            base_url: URL base da aplicação
            
        Returns:
            True se screenshots criados com sucesso
        """
        try:
            logger.info("Criando screenshots baseline...")
            
            # Importa módulo de teste visual
            sys.path.insert(0, str(self.project_root))
            from tests.visual.test_visual_regression import VisualRegressionTest
            
            visual_test = VisualRegressionTest()
            driver = visual_test.setup_driver(headless=True)
            
            try:
                # Páginas para capturar
                pages = [
                    ('/', 'homepage'),
                    ('/generate', 'generation_form'),
                    ('/feedback', 'feedback_page'),
                    ('/status', 'status_page')
                ]
                
                breakpoints = ['desktop', 'tablet', 'mobile']
                
                for url, name in pages:
                    logger.info(f"Capturando {name}...")
                    visual_test.navigate_to_page(url, wait_for_element='body')
                    
                    for breakpoint in breakpoints:
                        screenshot_path = visual_test.take_screenshot(f"{name}_baseline", breakpoint)
                        
                        # Move para diretório de baselines
                        baseline_path = self.baselines_dir / f"{name}_{breakpoint}.png"
                        if screenshot_path and os.path.exists(screenshot_path):
                            import shutil
                            shutil.move(screenshot_path, baseline_path)
                            logger.info(f"✓ Baseline criado: {baseline_path}")
                
                logger.info("✓ Screenshots baseline criados")
                return True
                
            finally:
                visual_test.teardown_driver()
                
        except Exception as e:
            logger.error(f"Erro ao criar baselines: {e}")
            return False
    
    def run_visual_tests(self) -> bool:
        """
        Executa testes visuais.
        
        Returns:
            True se testes passaram
        """
        try:
            logger.info("Executando testes visuais...")
            
            # Executa pytest para testes visuais
            result = subprocess.run([
                sys.executable, '-m', 'pytest',
                str(self.visual_dir / 'test_visual_regression.py'),
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

def main():
    """Função principal do script."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Configuração para testes visuais')
    parser.add_argument('--baseline', action='store_true', help='Criar screenshots baseline')
    parser.add_argument('--test', action='store_true', help='Executar testes visuais')
    parser.add_argument('--url', default='http://localhost:5000', help='URL base da aplicação')
    
    args = parser.parse_args()
    
    try:
        setup = VisualTestingSetup()
        
        if args.baseline:
            # Cria screenshots baseline
            success = setup.create_baseline_screenshots(args.url)
            sys.exit(0 if success else 1)
        elif args.test:
            # Executa testes
            success = setup.run_visual_tests()
            sys.exit(0 if success else 1)
        else:
            # Configuração completa
            success = setup.setup_environment()
            sys.exit(0 if success else 1)
            
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 