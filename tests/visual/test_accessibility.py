"""
Testes específicos de acessibilidade para Omni Writer.

Prompt: Testes de Regressão Visual - IMP-011
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:35:00Z
Tracing ID: ENTERPRISE_20250127_011
"""

import pytest
import time
import os
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from axe_selenium_python import Axe
import logging

from tests.visual.config.visual_config import (
    visual_config,
    ViewportType,
    AccessibilityLevel
)

logger = logging.getLogger(__name__)


class AccessibilityTester:
    """Testador de acessibilidade com axe-core"""
    
    def __init__(self, base_url=None):
        self.base_url = base_url or visual_config.base_url
        self.driver = None
        self.wait = None
        self.axe = None
        self.results_dir = visual_config.results_dir
        
        # Cria diretório de resultados
        os.makedirs(f"{self.results_dir}/accessibility", exist_ok=True)
    
    def setup_driver(self, viewport_type: ViewportType = ViewportType.DESKTOP):
        """Configura driver do Selenium"""
        viewport_config = visual_config.get_viewport_config(viewport_type)
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument(f'--window-size={viewport_config.width},{viewport_config.height}')
        
        # Configurações para acessibilidade
        chrome_options.add_argument('--force-device-scale-factor=1')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.wait = WebDriverWait(self.driver, 10)
        
        # Inicializa axe-core
        self.axe = Axe(self.driver)
        
        logger.info(f"Driver configurado para viewport: {viewport_type.value}")
    
    def teardown_driver(self):
        """Finaliza driver"""
        if self.driver:
            self.driver.quit()
    
    def run_accessibility_scan(self, level: AccessibilityLevel = AccessibilityLevel.WCAG_AA):
        """Executa scan de acessibilidade"""
        accessibility_config = visual_config.get_accessibility_config(level)
        
        # Executa análise com axe-core
        results = self.axe.analyze()
        
        # Filtra resultados baseado na configuração
        filtered_violations = []
        for violation in results['violations']:
            if violation['id'] in accessibility_config.rules:
                filtered_violations.append(violation)
        
        # Remove violações ignoradas
        for violation in filtered_violations[:]:
            if violation['id'] in accessibility_config.ignore_rules:
                filtered_violations.remove(violation)
        
        return {
            'violations': filtered_violations,
            'passes': results['passes'],
            'incomplete': results['incomplete'],
            'inapplicable': results['inapplicable'],
            'timestamp': results['timestamp'],
            'url': results['url'],
            'testEngine': results['testEngine'],
            'testRunner': results['testRunner'],
            'testEnvironment': results['testEnvironment']
        }
    
    def save_accessibility_results(self, results: dict, test_name: str, viewport: str):
        """Salva resultados de acessibilidade"""
        filename = f"{self.results_dir}/accessibility/{test_name}_{viewport}_{int(time.time())}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Resultados salvos em: {filename}")
        return filename
    
    def test_homepage_accessibility(self, level: AccessibilityLevel = AccessibilityLevel.WCAG_AA):
        """Testa acessibilidade da página inicial"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/")
            
            # Aguarda carregamento da página
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
            
            # Executa scan de acessibilidade
            results = self.run_accessibility_scan(level)
            
            # Salva resultados
            self.save_accessibility_results(results, "homepage", "desktop")
            
            # Valida resultados
            assert len(results['violations']) == 0, f"Violations encontradas: {len(results['violations'])}"
            
            logger.info("✅ Acessibilidade da homepage validada")
            
        finally:
            self.teardown_driver()
    
    def test_generation_form_accessibility(self, level: AccessibilityLevel = AccessibilityLevel.WCAG_AA):
        """Testa acessibilidade do formulário de geração"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/generate")
            
            # Aguarda carregamento do formulário
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".generation-form")))
            
            # Executa scan de acessibilidade
            results = self.run_accessibility_scan(level)
            
            # Salva resultados
            self.save_accessibility_results(results, "generation_form", "desktop")
            
            # Valida resultados
            assert len(results['violations']) == 0, f"Violations encontradas: {len(results['violations'])}"
            
            logger.info("✅ Acessibilidade do formulário de geração validada")
            
        finally:
            self.teardown_driver()
    
    def test_blog_list_accessibility(self, level: AccessibilityLevel = AccessibilityLevel.WCAG_AA):
        """Testa acessibilidade da lista de blogs"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/blogs")
            
            # Aguarda carregamento da lista
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".blog-list")))
            
            # Executa scan de acessibilidade
            results = self.run_accessibility_scan(level)
            
            # Salva resultados
            self.save_accessibility_results(results, "blog_list", "desktop")
            
            # Valida resultados
            assert len(results['violations']) == 0, f"Violations encontradas: {len(results['violations'])}"
            
            logger.info("✅ Acessibilidade da lista de blogs validada")
            
        finally:
            self.teardown_driver()
    
    def test_article_detail_accessibility(self, level: AccessibilityLevel = AccessibilityLevel.WCAG_AA):
        """Testa acessibilidade da página de detalhes do artigo"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/article/1")
            
            # Aguarda carregamento do artigo
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".article-content")))
            
            # Executa scan de acessibilidade
            results = self.run_accessibility_scan(level)
            
            # Salva resultados
            self.save_accessibility_results(results, "article_detail", "desktop")
            
            # Valida resultados
            assert len(results['violations']) == 0, f"Violations encontradas: {len(results['violations'])}"
            
            logger.info("✅ Acessibilidade da página de artigo validada")
            
        finally:
            self.teardown_driver()
    
    def test_keyboard_navigation(self):
        """Testa navegação por teclado"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/")
            
            # Aguarda carregamento da página
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
            
            # Testa navegação por Tab
            body = self.driver.find_element(By.TAG_NAME, "body")
            body.send_keys(webdriver.Keys.TAB)
            
            # Verifica se há elemento em foco
            focused_element = self.driver.switch_to.active_element
            assert focused_element is not None, "Nenhum elemento em foco após Tab"
            
            # Testa navegação por Shift+Tab
            body.send_keys(webdriver.Keys.SHIFT + webdriver.Keys.TAB)
            
            # Testa Enter em botões
            buttons = self.driver.find_elements(By.TAG_NAME, "button")
            if buttons:
                buttons[0].send_keys(webdriver.Keys.ENTER)
            
            logger.info("✅ Navegação por teclado validada")
            
        finally:
            self.teardown_driver()
    
    def test_screen_reader_compatibility(self):
        """Testa compatibilidade com leitores de tela"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/")
            
            # Aguarda carregamento da página
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
            
            # Verifica elementos com aria-label
            aria_elements = self.driver.find_elements(By.CSS_SELECTOR, "[aria-label]")
            assert len(aria_elements) > 0, "Nenhum elemento com aria-label encontrado"
            
            # Verifica elementos com role
            role_elements = self.driver.find_elements(By.CSS_SELECTOR, "[role]")
            assert len(role_elements) > 0, "Nenhum elemento com role encontrado"
            
            # Verifica imagens com alt
            images = self.driver.find_elements(By.TAG_NAME, "img")
            for img in images:
                alt = img.get_attribute("alt")
                assert alt is not None, f"Imagem sem alt: {img.get_attribute('src')}"
            
            logger.info("✅ Compatibilidade com leitores de tela validada")
            
        finally:
            self.teardown_driver()
    
    def test_color_contrast(self):
        """Testa contraste de cores"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/")
            
            # Aguarda carregamento da página
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
            
            # Executa scan específico para contraste
            results = self.run_accessibility_scan(AccessibilityLevel.WCAG_AA)
            
            # Verifica violações de contraste
            contrast_violations = [
                v for v in results['violations'] 
                if 'color-contrast' in v['id']
            ]
            
            assert len(contrast_violations) == 0, f"Violations de contraste: {len(contrast_violations)}"
            
            logger.info("✅ Contraste de cores validado")
            
        finally:
            self.teardown_driver()
    
    def test_focus_visibility(self):
        """Testa visibilidade do foco"""
        try:
            self.setup_driver(ViewportType.DESKTOP)
            self.driver.get(f"{self.base_url}/")
            
            # Aguarda carregamento da página
            self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
            
            # Testa foco em elementos interativos
            interactive_elements = self.driver.find_elements(
                By.CSS_SELECTOR, 
                "button, a, input, select, textarea, [tabindex]"
            )
            
            for element in interactive_elements[:3]:  # Testa apenas os primeiros 3
                element.click()
                
                # Verifica se o elemento tem foco visível
                focused_element = self.driver.switch_to.active_element
                assert focused_element == element, f"Elemento não recebeu foco: {element.tag_name}"
                
                # Verifica se há estilo de foco
                focus_style = element.value_of_css_property('outline')
                assert focus_style != 'none', f"Elemento sem foco visível: {element.tag_name}"
            
            logger.info("✅ Visibilidade do foco validada")
            
        finally:
            self.teardown_driver()
    
    def test_responsive_accessibility(self):
        """Testa acessibilidade em diferentes viewports"""
        viewports = [ViewportType.TABLET, ViewportType.MOBILE]
        
        for viewport in viewports:
            try:
                self.setup_driver(viewport)
                self.driver.get(f"{self.base_url}/")
                
                # Aguarda carregamento da página
                self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
                
                # Executa scan de acessibilidade
                results = self.run_accessibility_scan(AccessibilityLevel.WCAG_AA)
                
                # Salva resultados
                self.save_accessibility_results(results, "responsive", viewport.value)
                
                # Valida resultados
                assert len(results['violations']) == 0, f"Violations em {viewport.value}: {len(results['violations'])}"
                
                logger.info(f"✅ Acessibilidade em {viewport.value} validada")
                
            finally:
                self.teardown_driver()


class TestAccessibility:
    """Classe de testes de acessibilidade"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup para cada teste"""
        self.tester = AccessibilityTester()
        yield
        self.tester.teardown_driver()
    
    def test_homepage_wcag_aa(self):
        """Testa acessibilidade da homepage com WCAG AA"""
        self.tester.test_homepage_accessibility(AccessibilityLevel.WCAG_AA)
    
    def test_homepage_wcag_aaa(self):
        """Testa acessibilidade da homepage com WCAG AAA"""
        self.tester.test_homepage_accessibility(AccessibilityLevel.WCAG_AAA)
    
    def test_generation_form_wcag_aa(self):
        """Testa acessibilidade do formulário com WCAG AA"""
        self.tester.test_generation_form_accessibility(AccessibilityLevel.WCAG_AA)
    
    def test_blog_list_wcag_aa(self):
        """Testa acessibilidade da lista de blogs com WCAG AA"""
        self.tester.test_blog_list_accessibility(AccessibilityLevel.WCAG_AA)
    
    def test_article_detail_wcag_aa(self):
        """Testa acessibilidade da página de artigo com WCAG AA"""
        self.tester.test_article_detail_accessibility(AccessibilityLevel.WCAG_AA)
    
    def test_keyboard_navigation(self):
        """Testa navegação por teclado"""
        self.tester.test_keyboard_navigation()
    
    def test_screen_reader_compatibility(self):
        """Testa compatibilidade com leitores de tela"""
        self.tester.test_screen_reader_compatibility()
    
    def test_color_contrast(self):
        """Testa contraste de cores"""
        self.tester.test_color_contrast()
    
    def test_focus_visibility(self):
        """Testa visibilidade do foco"""
        self.tester.test_focus_visibility()
    
    def test_responsive_accessibility_tablet(self):
        """Testa acessibilidade em tablet"""
        self.tester.setup_driver(ViewportType.TABLET)
        self.tester.driver.get(f"{self.tester.base_url}/")
        self.tester.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
        results = self.tester.run_accessibility_scan(AccessibilityLevel.WCAG_AA)
        assert len(results['violations']) == 0
    
    def test_responsive_accessibility_mobile(self):
        """Testa acessibilidade em mobile"""
        self.tester.setup_driver(ViewportType.MOBILE)
        self.tester.driver.get(f"{self.tester.base_url}/")
        self.tester.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".main-content")))
        results = self.tester.run_accessibility_scan(AccessibilityLevel.WCAG_AA)
        assert len(results['violations']) == 0


if __name__ == "__main__":
    # Executa testes de acessibilidade
    tester = AccessibilityTester()
    
    # Testa todas as páginas principais
    test_methods = [
        tester.test_homepage_accessibility,
        tester.test_generation_form_accessibility,
        tester.test_blog_list_accessibility,
        tester.test_article_detail_accessibility,
        tester.test_keyboard_navigation,
        tester.test_screen_reader_compatibility,
        tester.test_color_contrast,
        tester.test_focus_visibility,
        tester.test_responsive_accessibility
    ]
    
    for test_method in test_methods:
        try:
            test_method()
            print(f"✅ {test_method.__name__} executado com sucesso")
        except Exception as e:
            print(f"❌ {test_method.__name__} falhou: {e}")
    
    print("🎉 Testes de acessibilidade concluídos!") 