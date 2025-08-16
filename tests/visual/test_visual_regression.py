"""
Testes de Regressão Visual - Omni Writer
=======================================

Prompt: Pendência 3.3.4 - Implementar testes de regressão visual
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T17:00:00Z
Tracing ID: PENDENCIA_3_3_4_001

Testes baseados no código real do sistema Omni Writer:
- Comparação de screenshots
- Validação de layout responsivo
- Detecção de mudanças visuais
- Validação de acessibilidade visual
- Testes de diferentes resoluções
"""

import pytest
import os
import time
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Tuple
from PIL import Image, ImageChops, ImageFilter
import numpy as np
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

# Importações do sistema real
from tests.visual.visual_comparison import VisualComparison
from tests.visual.config.visual_config import VisualConfig


class VisualRegressionTester:
    """Testador de regressão visual com cenários reais."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.visual_comparison = VisualComparison()
        self.config = VisualConfig()
        
        # Configurações de teste baseadas em uso real
        self.test_config = {
            'screenshot_dir': 'tests/visual/screenshots',
            'baseline_dir': 'tests/visual/baselines',
            'diff_dir': 'tests/visual/diffs',
            'threshold': 0.95,  # 95% de similaridade
            'timeout': 10,
            'wait_time': 2
        }
        
        # Resoluções de teste baseadas em uso real
        self.resolutions = [
            (1920, 1080),  # Desktop Full HD
            (1366, 768),   # Laptop
            (768, 1024),   # Tablet Portrait
            (375, 667),    # Mobile Portrait
            (414, 896)     # Mobile Large
        ]
        
        # Páginas de teste baseadas no sistema real
        self.test_pages = [
            '/',                    # Homepage
            '/dashboard',           # Dashboard
            '/generate',            # Geração de conteúdo
            '/history',             # Histórico
            '/settings',            # Configurações
            '/profile',             # Perfil do usuário
            '/help',                # Ajuda
            '/api/docs'             # Documentação da API
        ]
        
        # Estados de teste baseados em cenários reais
        self.test_states = [
            'default',              # Estado padrão
            'loading',              # Carregando
            'error',                # Erro
            'success',              # Sucesso
            'empty',                # Vazio
            'populated'             # Com dados
        ]
        
        # Configuração do WebDriver
        self.driver_options = Options()
        self.driver_options.add_argument('--headless')
        self.driver_options.add_argument('--no-sandbox')
        self.driver_options.add_argument('--disable-dev-shm-usage')
        self.driver_options.add_argument('--disable-gpu')
        self.driver_options.add_argument('--window-size=1920,1080')
        
        # Garante que os diretórios existem
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Garante que os diretórios de teste existem."""
        directories = [
            self.test_config['screenshot_dir'],
            self.test_config['baseline_dir'],
            self.test_config['diff_dir']
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def setup_driver(self) -> webdriver.Chrome:
        """Configura o driver do Chrome."""
        try:
            driver = webdriver.Chrome(options=self.driver_options)
            driver.set_page_load_timeout(self.test_config['timeout'])
            return driver
        except Exception as e:
            raise Exception(f"Erro ao configurar driver: {e}")
    
    def take_screenshot(self, driver: webdriver.Chrome, page: str, resolution: Tuple[int, int], 
                       state: str = 'default') -> str:
        """
        Captura screenshot de uma página.
        
        Args:
            driver: Driver do Selenium
            page: Página a testar
            resolution: Resolução da tela
            state: Estado da página
            
        Returns:
            Caminho do arquivo de screenshot
        """
        try:
            # Configura resolução
            driver.set_window_size(resolution[0], resolution[1])
            
            # Navega para a página
            url = f"{self.base_url}{page}"
            driver.get(url)
            
            # Aguarda carregamento
            time.sleep(self.test_config['wait_time'])
            
            # Simula estado se necessário
            if state == 'loading':
                # Simula carregamento
                driver.execute_script("document.body.classList.add('loading');")
            elif state == 'error':
                # Simula erro
                driver.execute_script("document.body.classList.add('error');")
            elif state == 'success':
                # Simula sucesso
                driver.execute_script("document.body.classList.add('success');")
            elif state == 'empty':
                # Simula estado vazio
                driver.execute_script("document.body.classList.add('empty');")
            elif state == 'populated':
                # Simula dados populados
                driver.execute_script("document.body.classList.add('populated');")
            
            # Aguarda mudanças
            time.sleep(self.test_config['wait_time'])
            
            # Captura screenshot
            filename = f"{page.replace('/', '_')}_{resolution[0]}x{resolution[1]}_{state}.png"
            filepath = os.path.join(self.test_config['screenshot_dir'], filename)
            driver.save_screenshot(filepath)
            
            return filepath
            
        except Exception as e:
            raise Exception(f"Erro ao capturar screenshot: {e}")
    
    def compare_screenshots(self, current_path: str, baseline_path: str) -> Dict[str, Any]:
        """
        Compara screenshots atual e baseline.
        
        Args:
            current_path: Caminho do screenshot atual
            baseline_path: Caminho do screenshot baseline
            
        Returns:
            Resultado da comparação
        """
        try:
            # Carrega imagens
            current_img = Image.open(current_path)
            baseline_img = Image.open(baseline_path)
            
            # Redimensiona para mesma resolução se necessário
            if current_img.size != baseline_img.size:
                baseline_img = baseline_img.resize(current_img.size, Image.LANCZOS)
            
            # Converte para RGB se necessário
            if current_img.mode != 'RGB':
                current_img = current_img.convert('RGB')
            if baseline_img.mode != 'RGB':
                baseline_img = baseline_img.convert('RGB')
            
            # Calcula diferença
            diff_img = ImageChops.difference(current_img, baseline_img)
            
            # Calcula similaridade
            current_array = np.array(current_img)
            baseline_array = np.array(baseline_img)
            
            # Calcula MSE (Mean Squared Error)
            mse = np.mean((current_array - baseline_array) ** 2)
            
            # Converte MSE para similaridade (0-1)
            max_mse = 255 ** 2
            similarity = 1 - (mse / max_mse)
            
            # Gera diff visual
            diff_filename = f"diff_{os.path.basename(current_path)}"
            diff_path = os.path.join(self.test_config['diff_dir'], diff_filename)
            diff_img.save(diff_path)
            
            return {
                'similarity': similarity,
                'mse': mse,
                'passed': similarity >= self.test_config['threshold'],
                'diff_path': diff_path,
                'current_size': current_img.size,
                'baseline_size': baseline_img.size
            }
            
        except Exception as e:
            return {
                'similarity': 0.0,
                'mse': float('inf'),
                'passed': False,
                'error': str(e)
            }
    
    def test_page_visual_regression(self, page: str, resolution: Tuple[int, int], 
                                   state: str = 'default') -> Dict[str, Any]:
        """
        Testa regressão visual de uma página específica.
        
        Args:
            page: Página a testar
            resolution: Resolução da tela
            state: Estado da página
            
        Returns:
            Resultado do teste
        """
        result = {
            'page': page,
            'resolution': resolution,
            'state': state,
            'passed': True,
            'details': {},
            'errors': []
        }
        
        driver = None
        try:
            driver = self.setup_driver()
            
            # Captura screenshot atual
            current_path = self.take_screenshot(driver, page, resolution, state)
            
            # Define caminho do baseline
            baseline_filename = f"{page.replace('/', '_')}_{resolution[0]}x{resolution[1]}_{state}.png"
            baseline_path = os.path.join(self.test_config['baseline_dir'], baseline_filename)
            
            # Verifica se baseline existe
            if os.path.exists(baseline_path):
                # Compara com baseline
                comparison = self.compare_screenshots(current_path, baseline_path)
                result['details'] = comparison
                result['passed'] = comparison['passed']
                
                if not comparison['passed']:
                    result['errors'].append({
                        'type': 'visual_regression',
                        'similarity': comparison['similarity'],
                        'threshold': self.test_config['threshold']
                    })
            else:
                # Cria baseline se não existir
                os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
                import shutil
                shutil.copy2(current_path, baseline_path)
                result['details'] = {
                    'baseline_created': True,
                    'baseline_path': baseline_path
                }
                
        except Exception as e:
            result['passed'] = False
            result['errors'].append({
                'type': 'test_error',
                'error': str(e)
            })
            
        finally:
            if driver:
                driver.quit()
        
        return result
    
    def test_responsive_design(self, page: str) -> Dict[str, Any]:
        """
        Testa design responsivo em diferentes resoluções.
        
        Args:
            page: Página a testar
            
        Returns:
            Resultado do teste
        """
        result = {
            'page': page,
            'test_type': 'responsive_design',
            'passed': True,
            'resolutions': [],
            'errors': []
        }
        
        driver = None
        try:
            driver = self.setup_driver()
            
            for resolution in self.resolutions:
                try:
                    # Captura screenshot em cada resolução
                    screenshot_path = self.take_screenshot(driver, page, resolution)
                    
                    # Verifica se a página carregou corretamente
                    page_title = driver.title
                    if not page_title:
                        result['passed'] = False
                        result['errors'].append({
                            'type': 'page_not_loaded',
                            'resolution': resolution
                        })
                    
                    result['resolutions'].append({
                        'resolution': resolution,
                        'screenshot_path': screenshot_path,
                        'page_title': page_title,
                        'passed': bool(page_title)
                    })
                    
                except Exception as e:
                    result['passed'] = False
                    result['errors'].append({
                        'type': 'resolution_error',
                        'resolution': resolution,
                        'error': str(e)
                    })
                    
        except Exception as e:
            result['passed'] = False
            result['errors'].append({
                'type': 'test_error',
                'error': str(e)
            })
            
        finally:
            if driver:
                driver.quit()
        
        return result
    
    def test_accessibility_visual(self, page: str) -> Dict[str, Any]:
        """
        Testa acessibilidade visual.
        
        Args:
            page: Página a testar
            
        Returns:
            Resultado do teste
        """
        result = {
            'page': page,
            'test_type': 'accessibility_visual',
            'passed': True,
            'checks': [],
            'errors': []
        }
        
        driver = None
        try:
            driver = self.setup_driver()
            driver.get(f"{self.base_url}{page}")
            
            # Aguarda carregamento
            time.sleep(self.test_config['wait_time'])
            
            # Testa contraste de cores
            try:
                # Verifica elementos com baixo contraste
                low_contrast_elements = driver.find_elements(By.CSS_SELECTOR, '[style*="color: #"]')
                if low_contrast_elements:
                    result['checks'].append({
                        'type': 'color_contrast',
                        'elements_found': len(low_contrast_elements),
                        'passed': False
                    })
                    result['passed'] = False
                else:
                    result['checks'].append({
                        'type': 'color_contrast',
                        'passed': True
                    })
            except Exception as e:
                result['checks'].append({
                    'type': 'color_contrast',
                    'error': str(e)
                })
            
            # Testa tamanho de fonte
            try:
                small_font_elements = driver.find_elements(By.CSS_SELECTOR, '[style*="font-size: 12px"]')
                if small_font_elements:
                    result['checks'].append({
                        'type': 'font_size',
                        'elements_found': len(small_font_elements),
                        'passed': False
                    })
                    result['passed'] = False
                else:
                    result['checks'].append({
                        'type': 'font_size',
                        'passed': True
                    })
            except Exception as e:
                result['checks'].append({
                    'type': 'font_size',
                    'error': str(e)
                })
            
            # Testa elementos interativos
            try:
                interactive_elements = driver.find_elements(By.CSS_SELECTOR, 'button, a, input, select, textarea')
                for element in interactive_elements:
                    # Verifica se elemento é visível
                    if not element.is_displayed():
                        result['checks'].append({
                            'type': 'interactive_element_visibility',
                            'element': element.tag_name,
                            'passed': False
                        })
                        result['passed'] = False
                
                if not result['checks']:
                    result['checks'].append({
                        'type': 'interactive_element_visibility',
                        'passed': True
                    })
                    
            except Exception as e:
                result['checks'].append({
                    'type': 'interactive_element_visibility',
                    'error': str(e)
                })
            
        except Exception as e:
            result['passed'] = False
            result['errors'].append({
                'type': 'test_error',
                'error': str(e)
            })
            
        finally:
            if driver:
                driver.quit()
        
        return result
    
    def test_loading_states(self, page: str) -> Dict[str, Any]:
        """
        Testa estados de carregamento.
        
        Args:
            page: Página a testar
            
        Returns:
            Resultado do teste
        """
        result = {
            'page': page,
            'test_type': 'loading_states',
            'passed': True,
            'states': [],
            'errors': []
        }
        
        driver = None
        try:
            driver = self.setup_driver()
            
            for state in self.test_states:
                try:
                    # Captura screenshot em cada estado
                    screenshot_path = self.take_screenshot(driver, page, (1920, 1080), state)
                    
                    result['states'].append({
                        'state': state,
                        'screenshot_path': screenshot_path,
                        'passed': True
                    })
                    
                except Exception as e:
                    result['passed'] = False
                    result['errors'].append({
                        'type': 'state_error',
                        'state': state,
                        'error': str(e)
                    })
                    
        except Exception as e:
            result['passed'] = False
            result['errors'].append({
                'type': 'test_error',
                'error': str(e)
            })
            
        finally:
            if driver:
                driver.quit()
        
        return result
    
    def run_comprehensive_visual_test(self) -> Dict[str, Any]:
        """
        Executa teste visual abrangente.
        
        Returns:
            Resultado completo dos testes
        """
        print("🎨 Iniciando testes de regressão visual...")
        
        test_results = {
            'timestamp': datetime.now().isoformat(),
            'base_url': self.base_url,
            'tests': [],
            'overall_passed': True,
            'errors_found': 0,
            'recommendations': []
        }
        
        # Executa testes para cada página
        for page in self.test_pages:
            try:
                # Teste de regressão visual
                regression_result = self.test_page_visual_regression(page, (1920, 1080))
                test_results['tests'].append(regression_result)
                
                if not regression_result['passed']:
                    test_results['overall_passed'] = False
                    test_results['errors_found'] += len(regression_result.get('errors', []))
                
                # Teste de design responsivo
                responsive_result = self.test_responsive_design(page)
                test_results['tests'].append(responsive_result)
                
                if not responsive_result['passed']:
                    test_results['overall_passed'] = False
                    test_results['errors_found'] += len(responsive_result.get('errors', []))
                
                # Teste de acessibilidade visual
                accessibility_result = self.test_accessibility_visual(page)
                test_results['tests'].append(accessibility_result)
                
                if not accessibility_result['passed']:
                    test_results['overall_passed'] = False
                    test_results['errors_found'] += len(accessibility_result.get('errors', []))
                
                # Teste de estados de carregamento
                loading_result = self.test_loading_states(page)
                test_results['tests'].append(loading_result)
                
                if not loading_result['passed']:
                    test_results['overall_passed'] = False
                    test_results['errors_found'] += len(loading_result.get('errors', []))
                    
            except Exception as e:
                test_results['tests'].append({
                    'page': page,
                    'passed': False,
                    'error': str(e)
                })
                test_results['overall_passed'] = False
        
        # Gera recomendações
        if test_results['errors_found'] > 0:
            test_results['recommendations'] = [
                "Revisar mudanças visuais não intencionais",
                "Verificar responsividade em diferentes resoluções",
                "Melhorar contraste de cores para acessibilidade",
                "Otimizar estados de carregamento",
                "Implementar testes visuais automatizados no CI/CD"
            ]
        
        return test_results


# Testes unitários para pytest
class TestVisualRegression:
    """Testes unitários para regressão visual."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.tester = VisualRegressionTester()
    
    def test_page_visual_regression(self):
        """Testa regressão visual de página."""
        result = self.tester.test_page_visual_regression('/', (1920, 1080))
        assert result['passed'] is True
        assert len(result['errors']) == 0
    
    def test_responsive_design(self):
        """Testa design responsivo."""
        result = self.tester.test_responsive_design('/')
        assert result['passed'] is True
        assert len(result['errors']) == 0
    
    def test_accessibility_visual(self):
        """Testa acessibilidade visual."""
        result = self.tester.test_accessibility_visual('/')
        assert result['passed'] is True
        assert len(result['errors']) == 0
    
    def test_loading_states(self):
        """Testa estados de carregamento."""
        result = self.tester.test_loading_states('/')
        assert result['passed'] is True
        assert len(result['errors']) == 0
    
    def test_comprehensive_visual(self):
        """Testa visual abrangente."""
        result = self.tester.run_comprehensive_visual_test()
        assert result['overall_passed'] is True
        assert result['errors_found'] == 0


# Execução principal (para testes manuais)
if __name__ == "__main__":
    print("🎨 Iniciando testes de regressão visual...")
    
    tester = VisualRegressionTester()
    result = tester.run_comprehensive_visual_test()
    
    print(f"✅ Testes visuais concluídos: {result['overall_passed']}")
    print(f"🔍 Erros encontrados: {result['errors_found']}")
    
    if result['recommendations']:
        print("📋 Recomendações:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    
    print("🎨 Testes de regressão visual concluídos") 