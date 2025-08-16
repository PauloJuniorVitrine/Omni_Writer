"""
Testes para configuração de testes visuais.

Prompt: Testes de Regressão Visual - IMP-011
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:45:00Z
Tracing ID: ENTERPRISE_20250127_011
"""

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock

from tests.visual.config.visual_config import (
    VisualTestingConfiguration,
    ViewportType,
    AccessibilityLevel,
    ViewportConfig,
    AccessibilityConfig,
    VisualTestConfig,
    visual_config
)


class TestVisualTestingConfiguration:
    """Testes para configuração de testes visuais"""
    
    def test_viewport_configs_are_valid(self):
        """Testa se as configurações de viewport são válidas"""
        config = VisualTestingConfiguration()
        
        # Verifica se todos os viewports têm configurações válidas
        for viewport_type, viewport_config in config.viewports.items():
            assert isinstance(viewport_config, ViewportConfig)
            assert viewport_config.width > 0
            assert viewport_config.height > 0
            assert viewport_config.device_scale_factor > 0
    
    def test_accessibility_configs_are_valid(self):
        """Testa se as configurações de acessibilidade são válidas"""
        config = VisualTestingConfiguration()
        
        # Verifica se todos os níveis têm configurações válidas
        for level, accessibility_config in config.accessibility_configs.items():
            assert isinstance(accessibility_config, AccessibilityConfig)
            assert accessibility_config.level == level
            assert len(accessibility_config.rules) > 0
            assert accessibility_config.threshold >= 0
    
    def test_visual_tests_are_valid(self):
        """Testa se as configurações de testes visuais são válidas"""
        config = VisualTestingConfiguration()
        
        # Verifica se todos os testes têm configurações válidas
        for test in config.visual_tests:
            assert isinstance(test, VisualTestConfig)
            assert test.name
            assert test.url
            assert test.selector
            assert test.wait_time >= 0
            assert len(test.viewports) > 0
    
    def test_get_viewport_config(self):
        """Testa obtenção de configuração de viewport"""
        config = VisualTestingConfiguration()
        
        # Testa viewport existente
        desktop_config = config.get_viewport_config(ViewportType.DESKTOP)
        assert isinstance(desktop_config, ViewportConfig)
        assert desktop_config.width == 1920
        assert desktop_config.height == 1080
        
        # Testa viewport inexistente
        invalid_config = config.get_viewport_config("invalid")
        assert invalid_config is None
    
    def test_get_accessibility_config(self):
        """Testa obtenção de configuração de acessibilidade"""
        config = VisualTestingConfiguration()
        
        # Testa nível existente
        wcag_aa_config = config.get_accessibility_config(AccessibilityLevel.WCAG_AA)
        assert isinstance(wcag_aa_config, AccessibilityConfig)
        assert wcag_aa_config.level == AccessibilityLevel.WCAG_AA
        assert len(wcag_aa_config.rules) > 0
        
        # Testa nível inexistente
        invalid_config = config.get_accessibility_config("invalid")
        assert invalid_config is None
    
    def test_get_visual_test(self):
        """Testa obtenção de configuração de teste visual"""
        config = VisualTestingConfiguration()
        
        # Testa teste existente
        homepage_test = config.get_visual_test("Homepage")
        assert isinstance(homepage_test, VisualTestConfig)
        assert homepage_test.name == "Homepage"
        assert homepage_test.url == "/"
        
        # Testa teste inexistente
        invalid_test = config.get_visual_test("Invalid Test")
        assert invalid_test is None
    
    def test_get_all_visual_tests(self):
        """Testa obtenção de todos os testes visuais"""
        config = VisualTestingConfiguration()
        
        all_tests = config.get_all_visual_tests()
        assert isinstance(all_tests, list)
        assert len(all_tests) > 0
        
        for test in all_tests:
            assert isinstance(test, VisualTestConfig)
    
    def test_get_tests_by_viewport(self):
        """Testa filtragem de testes por viewport"""
        config = VisualTestingConfiguration()
        
        # Testa filtragem por desktop
        desktop_tests = config.get_tests_by_viewport(ViewportType.DESKTOP)
        assert isinstance(desktop_tests, list)
        
        for test in desktop_tests:
            assert ViewportType.DESKTOP in test.viewports
        
        # Testa filtragem por mobile
        mobile_tests = config.get_tests_by_viewport(ViewportType.MOBILE)
        assert isinstance(mobile_tests, list)
        
        for test in mobile_tests:
            assert ViewportType.MOBILE in test.viewports
    
    def test_get_accessibility_tests(self):
        """Testa filtragem de testes com acessibilidade"""
        config = VisualTestingConfiguration()
        
        accessibility_tests = config.get_accessibility_tests()
        assert isinstance(accessibility_tests, list)
        
        for test in accessibility_tests:
            assert test.accessibility is True
    
    def test_get_screenshot_tests(self):
        """Testa filtragem de testes com screenshot"""
        config = VisualTestingConfiguration()
        
        screenshot_tests = config.get_screenshot_tests()
        assert isinstance(screenshot_tests, list)
        
        for test in screenshot_tests:
            assert test.screenshot is True
    
    def test_get_responsive_tests(self):
        """Testa filtragem de testes responsivos"""
        config = VisualTestingConfiguration()
        
        responsive_tests = config.get_responsive_tests()
        assert isinstance(responsive_tests, list)
        
        for test in responsive_tests:
            assert test.responsive is True
    
    def test_create_directories(self):
        """Testa criação de diretórios"""
        config = VisualTestingConfiguration()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Modifica configuração para usar diretório temporário
            original_screenshots_dir = config.screenshots_dir
            original_results_dir = config.results_dir
            
            config.screenshots_dir = os.path.join(temp_dir, "screenshots")
            config.results_dir = os.path.join(temp_dir, "results")
            
            # Cria diretórios
            config.create_directories()
            
            # Verifica se diretórios foram criados
            assert os.path.exists(config.screenshots_dir)
            assert os.path.exists(config.results_dir)
            assert os.path.exists(f"{config.results_dir}/screenshots")
            assert os.path.exists(f"{config.results_dir}/accessibility")
            assert os.path.exists(f"{config.results_dir}/reports")
            assert os.path.exists(f"{config.results_dir}/comparisons")
            
            # Restaura configuração original
            config.screenshots_dir = original_screenshots_dir
            config.results_dir = original_results_dir
    
    def test_validate_configuration_success(self):
        """Testa validação de configuração válida"""
        config = VisualTestingConfiguration()
        
        # Configura base URL válida
        config.base_url = "http://localhost:5000"
        
        # Valida configuração
        validation = config.validate_configuration()
        
        assert validation['valid'] is True
        assert len(validation['issues']) == 0
        # Pode ter warnings sobre Percy token não configurado
    
    def test_validate_configuration_failure(self):
        """Testa validação de configuração inválida"""
        config = VisualTestingConfiguration()
        
        # Remove base URL para causar erro
        config.base_url = ""
        
        # Adiciona viewport inválido
        config.viewports[ViewportType.DESKTOP] = ViewportConfig(0, 0)
        
        # Valida configuração
        validation = config.validate_configuration()
        
        assert validation['valid'] is False
        assert len(validation['issues']) > 0
        assert "Base URL não configurada" in validation['issues']
        assert "Viewport desktop tem dimensões inválidas" in validation['issues']
    
    def test_validate_configuration_warnings(self):
        """Testa avisos na validação de configuração"""
        config = VisualTestingConfiguration()
        
        # Configura base URL válida
        config.base_url = "http://localhost:5000"
        
        # Remove token do Percy para causar warning
        config.percy_token = ""
        
        # Valida configuração
        validation = config.validate_configuration()
        
        assert validation['valid'] is True
        assert len(validation['warnings']) > 0
        assert "Token do Percy não configurado" in validation['warnings'][0]
    
    def test_selenium_config_is_valid(self):
        """Testa se a configuração do Selenium é válida"""
        config = VisualTestingConfiguration()
        
        selenium_config = config.selenium_config
        
        # Verifica se todas as chaves necessárias estão presentes
        required_keys = [
            'headless', 'no_sandbox', 'disable_dev_shm_usage', 
            'disable_gpu', 'window_size', 'implicit_wait', 
            'page_load_timeout', 'script_timeout'
        ]
        
        for key in required_keys:
            assert key in selenium_config
        
        # Verifica se os valores são válidos
        assert isinstance(selenium_config['headless'], bool)
        assert isinstance(selenium_config['no_sandbox'], bool)
        assert isinstance(selenium_config['disable_dev_shm_usage'], bool)
        assert isinstance(selenium_config['disable_gpu'], bool)
        assert isinstance(selenium_config['window_size'], str)
        assert isinstance(selenium_config['implicit_wait'], int)
        assert isinstance(selenium_config['page_load_timeout'], int)
        assert isinstance(selenium_config['script_timeout'], int)
        
        # Verifica se os timeouts são positivos
        assert selenium_config['implicit_wait'] > 0
        assert selenium_config['page_load_timeout'] > 0
        assert selenium_config['script_timeout'] > 0
    
    def test_percy_config_is_valid(self):
        """Testa se a configuração do Percy é válida"""
        config = VisualTestingConfiguration()
        
        percy_config = config.percy_config
        
        # Verifica se todas as chaves necessárias estão presentes
        required_keys = [
            'project_token', 'build_id', 'parallel_nonce', 
            'parallel_total_shards', 'commit', 'branch', 
            'pull_request', 'environment'
        ]
        
        for key in required_keys:
            assert key in percy_config
        
        # Verifica se os valores são do tipo correto
        assert isinstance(percy_config['project_token'], str)
        assert isinstance(percy_config['build_id'], str)
        assert isinstance(percy_config['parallel_nonce'], str)
        assert isinstance(percy_config['parallel_total_shards'], int)
        assert isinstance(percy_config['commit'], str)
        assert isinstance(percy_config['branch'], str)
        assert isinstance(percy_config['pull_request'], str)
        assert isinstance(percy_config['environment'], str)
    
    def test_comparison_config_is_valid(self):
        """Testa se a configuração de comparação é válida"""
        config = VisualTestingConfiguration()
        
        comparison_config = config.comparison_config
        
        # Verifica se todas as chaves necessárias estão presentes
        required_keys = ['threshold', 'ignore_areas', 'mask_selectors']
        
        for key in required_keys:
            assert key in comparison_config
        
        # Verifica se os valores são válidos
        assert isinstance(comparison_config['threshold'], float)
        assert isinstance(comparison_config['ignore_areas'], list)
        assert isinstance(comparison_config['mask_selectors'], list)
        
        # Verifica se o threshold está no intervalo válido
        assert 0 <= comparison_config['threshold'] <= 1
    
    def test_reporting_config_is_valid(self):
        """Testa se a configuração de relatórios é válida"""
        config = VisualTestingConfiguration()
        
        reporting_config = config.reporting_config
        
        # Verifica se todas as chaves necessárias estão presentes
        required_keys = [
            'generate_html', 'generate_json', 'generate_junit',
            'include_screenshots', 'include_accessibility_results',
            'include_performance_metrics'
        ]
        
        for key in required_keys:
            assert key in reporting_config
        
        # Verifica se os valores são booleanos
        for key in required_keys:
            assert isinstance(reporting_config[key], bool)
    
    def test_environment_variables_loading(self):
        """Testa carregamento de variáveis de ambiente"""
        with patch.dict(os.environ, {
            'TEST_BASE_URL': 'http://test.example.com',
            'PERCY_TOKEN': 'test_token',
            'PERCY_BUILD_ID': 'test_build',
            'PERCY_BRANCH': 'test_branch'
        }):
            config = VisualTestingConfiguration()
            
            assert config.base_url == 'http://test.example.com'
            assert config.percy_token == 'test_token'
            assert config.percy_config['build_id'] == 'test_build'
            assert config.percy_config['branch'] == 'test_branch'
    
    def test_default_values(self):
        """Testa valores padrão quando variáveis de ambiente não estão definidas"""
        with patch.dict(os.environ, {}, clear=True):
            config = VisualTestingConfiguration()
            
            assert config.base_url == 'http://localhost:5000'
            assert config.percy_token == ''
            assert config.percy_config['branch'] == 'main'
            assert config.percy_config['environment'] == 'test'


class TestVisualConfigIntegration:
    """Testes de integração para configuração visual"""
    
    def test_global_config_instance(self):
        """Testa se a instância global da configuração é válida"""
        # Verifica se a instância global existe
        assert visual_config is not None
        assert isinstance(visual_config, VisualTestingConfiguration)
        
        # Verifica se a configuração é válida
        validation = visual_config.validate_configuration()
        assert validation['valid'] is True
    
    def test_config_consistency(self):
        """Testa consistência da configuração"""
        config = visual_config
        
        # Verifica se todos os testes referenciam viewports válidos
        for test in config.visual_tests:
            for viewport in test.viewports:
                assert viewport in config.viewports
        
        # Verifica se todos os testes têm URLs válidas
        for test in config.visual_tests:
            assert test.url.startswith('/') or test.url.startswith('http')
        
        # Verifica se todos os seletores são válidos
        for test in config.visual_tests:
            assert test.selector.startswith('.') or test.selector.startswith('#') or test.selector.startswith('[')
    
    def test_config_completeness(self):
        """Testa completude da configuração"""
        config = visual_config
        
        # Verifica se há testes para todas as páginas principais
        test_names = [test.name for test in config.visual_tests]
        
        expected_tests = [
            "Homepage", "Generation Form", "Blog List", "Article Detail",
            "Dark Mode", "Language Selector", "Loading States", "Error States"
        ]
        
        for expected_test in expected_tests:
            assert expected_test in test_names
        
        # Verifica se há configurações para todos os viewports principais
        viewport_types = list(config.viewports.keys())
        
        expected_viewports = [
            ViewportType.DESKTOP, ViewportType.LARGE_DESKTOP,
            ViewportType.TABLET, ViewportType.MOBILE
        ]
        
        for expected_viewport in expected_viewports:
            assert expected_viewport in viewport_types
        
        # Verifica se há configurações para todos os níveis de acessibilidade
        accessibility_levels = list(config.accessibility_configs.keys())
        
        expected_levels = [
            AccessibilityLevel.WCAG_A, AccessibilityLevel.WCAG_AA, AccessibilityLevel.WCAG_AAA
        ]
        
        for expected_level in expected_levels:
            assert expected_level in accessibility_levels 