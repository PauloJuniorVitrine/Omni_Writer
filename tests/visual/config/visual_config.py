"""
Configuração centralizada para testes visuais.

Prompt: Testes de Regressão Visual - IMP-011
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:30:00Z
Tracing ID: ENTERPRISE_20250127_011
"""

import os
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class ViewportType(Enum):
    """Tipos de viewport para testes visuais"""
    DESKTOP = "desktop"
    TABLET = "tablet"
    MOBILE = "mobile"
    LARGE_DESKTOP = "large_desktop"


class AccessibilityLevel(Enum):
    """Níveis de acessibilidade"""
    WCAG_A = "wcag_a"
    WCAG_AA = "wcag_aa"
    WCAG_AAA = "wcag_aaa"


@dataclass
class ViewportConfig:
    """Configuração de viewport"""
    width: int
    height: int
    device_scale_factor: float = 1.0
    user_agent: str = ""


@dataclass
class AccessibilityConfig:
    """Configuração de acessibilidade"""
    level: AccessibilityLevel
    rules: List[str]
    ignore_rules: List[str]
    threshold: float


@dataclass
class VisualTestConfig:
    """Configuração de teste visual"""
    name: str
    url: str
    selector: str
    wait_time: float
    viewports: List[ViewportType]
    accessibility: bool = True
    screenshot: bool = True
    responsive: bool = True


@dataclass
class BaselineConfig:
    """Configuração de baseline para comparação"""
    enabled: bool = True
    threshold: float = 0.1  # 10% de diferença permitida
    ignore_areas: List[str] = None
    mask_selectors: List[str] = None
    auto_update: bool = False
    require_approval: bool = True
    
    def __post_init__(self):
        if self.ignore_areas is None:
            self.ignore_areas = []
        if self.mask_selectors is None:
            self.mask_selectors = []


@dataclass
class AlertConfig:
    """Configuração de alertas para mudanças visuais"""
    enabled: bool = True
    slack_webhook: str = ""
    email_recipients: List[str] = None
    notification_levels: List[str] = None
    auto_approve_minor: bool = False
    require_human_review: bool = True
    
    def __post_init__(self):
        if self.email_recipients is None:
            self.email_recipients = []
        if self.notification_levels is None:
            self.notification_levels = []


class VisualTestingConfiguration:
    """Configuração centralizada para testes visuais"""
    
    def __init__(self):
        self.base_url = os.getenv('TEST_BASE_URL', 'http://localhost:5000')
        self.screenshots_dir = "tests/visual/screenshots"
        self.results_dir = "test-results/visual"
        self.baseline_dir = "tests/visual/baselines"
        self.percy_token = os.getenv('PERCY_TOKEN', '')
        
        # Configurações de viewport
        self.viewports: Dict[ViewportType, ViewportConfig] = {
            ViewportType.DESKTOP: ViewportConfig(1920, 1080),
            ViewportType.LARGE_DESKTOP: ViewportConfig(2560, 1440),
            ViewportType.TABLET: ViewportConfig(768, 1024),
            ViewportType.MOBILE: ViewportConfig(375, 667)
        }
        
        # Configurações de acessibilidade
        self.accessibility_configs: Dict[AccessibilityLevel, AccessibilityConfig] = {
            AccessibilityLevel.WCAG_A: AccessibilityConfig(
                level=AccessibilityLevel.WCAG_A,
                rules=[
                    'color-contrast',
                    'image-alt',
                    'label',
                    'link-name'
                ],
                ignore_rules=[],
                threshold=0.0
            ),
            AccessibilityLevel.WCAG_AA: AccessibilityConfig(
                level=AccessibilityLevel.WCAG_AA,
                rules=[
                    'color-contrast',
                    'image-alt',
                    'label',
                    'link-name',
                    'heading-order',
                    'focus-order',
                    'list',
                    'listitem'
                ],
                ignore_rules=[],
                threshold=0.0
            ),
            AccessibilityLevel.WCAG_AAA: AccessibilityConfig(
                level=AccessibilityLevel.WCAG_AAA,
                rules=[
                    'color-contrast',
                    'image-alt',
                    'label',
                    'link-name',
                    'heading-order',
                    'focus-order',
                    'list',
                    'listitem',
                    'region',
                    'landmark-one-main',
                    'page-has-heading-one'
                ],
                ignore_rules=[],
                threshold=0.0
            )
        }
        
        # Configuração de baseline
        self.baseline_config = BaselineConfig(
            enabled=True,
            threshold=0.1,
            ignore_areas=[
                '.timestamp',
                '.dynamic-content',
                '[data-testid="dynamic"]',
                '.loading-indicator',
                '.notification'
            ],
            mask_selectors=[
                '.user-specific',
                '.session-data',
                '.csrf-token'
            ],
            auto_update=False,
            require_approval=True
        )
        
        # Configuração de alertas
        self.alert_config = AlertConfig(
            enabled=True,
            slack_webhook=os.getenv('SLACK_WEBHOOK_URL', ''),
            email_recipients=os.getenv('VISUAL_ALERT_EMAILS', '').split(','),
            notification_levels=['error', 'warning', 'info'],
            auto_approve_minor=False,
            require_human_review=True
        )
        
        # Configurações de testes visuais
        self.visual_tests: List[VisualTestConfig] = [
            VisualTestConfig(
                name="Homepage",
                url="/",
                selector=".main-content",
                wait_time=2.0,
                viewports=[ViewportType.DESKTOP, ViewportType.TABLET, ViewportType.MOBILE],
                accessibility=True,
                screenshot=True,
                responsive=True
            ),
            VisualTestConfig(
                name="Generation Form",
                url="/generate",
                selector=".generation-form",
                wait_time=2.0,
                viewports=[ViewportType.DESKTOP, ViewportType.TABLET, ViewportType.MOBILE],
                accessibility=True,
                screenshot=True,
                responsive=True
            ),
            VisualTestConfig(
                name="Blog List",
                url="/blogs",
                selector=".blog-list",
                wait_time=2.0,
                viewports=[ViewportType.DESKTOP, ViewportType.TABLET, ViewportType.MOBILE],
                accessibility=True,
                screenshot=True,
                responsive=True
            ),
            VisualTestConfig(
                name="Article Detail",
                url="/article/1",
                selector=".article-content",
                wait_time=2.0,
                viewports=[ViewportType.DESKTOP, ViewportType.TABLET, ViewportType.MOBILE],
                accessibility=True,
                screenshot=True,
                responsive=True
            ),
            VisualTestConfig(
                name="Dark Mode",
                url="/",
                selector=".main-content",
                wait_time=1.0,
                viewports=[ViewportType.DESKTOP],
                accessibility=True,
                screenshot=True,
                responsive=False
            ),
            VisualTestConfig(
                name="Language Selector",
                url="/",
                selector=".language-selector",
                wait_time=1.0,
                viewports=[ViewportType.DESKTOP],
                accessibility=True,
                screenshot=True,
                responsive=False
            ),
            VisualTestConfig(
                name="Loading States",
                url="/generate",
                selector=".loading-indicator",
                wait_time=1.0,
                viewports=[ViewportType.DESKTOP],
                accessibility=True,
                screenshot=True,
                responsive=False
            ),
            VisualTestConfig(
                name="Error States",
                url="/generate",
                selector=".error-message",
                wait_time=1.0,
                viewports=[ViewportType.DESKTOP],
                accessibility=True,
                screenshot=True,
                responsive=False
            )
        ]
        
        # Configurações de Selenium
        self.selenium_config = {
            'headless': True,
            'no_sandbox': True,
            'disable_dev_shm_usage': True,
            'disable_gpu': True,
            'window_size': '1920,1080',
            'implicit_wait': 10,
            'page_load_timeout': 30,
            'script_timeout': 30
        }
        
        # Configurações de Percy
        self.percy_config = {
            'project_token': self.percy_token,
            'build_id': os.getenv('PERCY_BUILD_ID', ''),
            'parallel_nonce': os.getenv('PERCY_PARALLEL_NONCE', ''),
            'parallel_total_shards': int(os.getenv('PERCY_PARALLEL_TOTAL_SHARDS', '1')),
            'parallel_nonce': os.getenv('PERCY_PARALLEL_NONCE', ''),
            'commit': os.getenv('PERCY_COMMIT', ''),
            'branch': os.getenv('PERCY_BRANCH', 'main'),
            'pull_request': os.getenv('PERCY_PULL_REQUEST', ''),
            'environment': os.getenv('PERCY_ENVIRONMENT', 'test')
        }
        
        # Configurações de comparação visual
        self.comparison_config = {
            'threshold': 0.1,  # 10% de diferença permitida
            'ignore_areas': [],  # Áreas para ignorar na comparação
            'mask_selectors': [  # Seletores para mascarar (ex: timestamps)
                '.timestamp',
                '.dynamic-content',
                '[data-testid="dynamic"]'
            ]
        }
        
        # Configurações de relatórios
        self.reporting_config = {
            'generate_html': True,
            'generate_json': True,
            'generate_junit': True,
            'include_screenshots': True,
            'include_accessibility_results': True,
            'include_performance_metrics': True
        }
    
    def get_viewport_config(self, viewport_type: ViewportType) -> ViewportConfig:
        """Retorna configuração de viewport"""
        config = self.viewports.get(viewport_type)
        if config is None:
            raise ValueError(f"Viewport {viewport_type.value} não configurado")
        return config
    
    def get_accessibility_config(self, level: AccessibilityLevel) -> AccessibilityConfig:
        """Retorna configuração de acessibilidade"""
        config = self.accessibility_configs.get(level)
        if config is None:
            raise ValueError(f"Nível de acessibilidade {level.value} não configurado")
        return config
    
    def get_visual_test(self, name: str) -> VisualTestConfig:
        """Retorna configuração de teste visual por nome"""
        for test in self.visual_tests:
            if test.name == name:
                return test
        raise ValueError(f"Teste visual '{name}' não encontrado")
    
    def get_all_visual_tests(self) -> List[VisualTestConfig]:
        """Retorna todos os testes visuais"""
        return self.visual_tests
    
    def get_tests_by_viewport(self, viewport_type: ViewportType) -> List[VisualTestConfig]:
        """Retorna testes para um viewport específico"""
        return [test for test in self.visual_tests if viewport_type in test.viewports]
    
    def get_accessibility_tests(self) -> List[VisualTestConfig]:
        """Retorna testes com acessibilidade habilitada"""
        return [test for test in self.visual_tests if test.accessibility]
    
    def get_screenshot_tests(self) -> List[VisualTestConfig]:
        """Retorna testes com screenshot habilitado"""
        return [test for test in self.visual_tests if test.screenshot]
    
    def get_responsive_tests(self) -> List[VisualTestConfig]:
        """Retorna testes responsivos"""
        return [test for test in self.visual_tests if test.responsive]
    
    def create_directories(self):
        """Cria diretórios necessários"""
        import pathlib
        
        directories = [
            self.screenshots_dir,
            self.results_dir,
            self.baseline_dir,
            f"{self.results_dir}/diffs",
            f"{self.results_dir}/reports",
            f"{self.results_dir}/percy"
        ]
        
        for directory in directories:
            pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Valida configuração atual"""
        issues = []
        warnings = []
        
        # Validações críticas
        if not self.percy_token:
            issues.append("PERCY_TOKEN não configurado")
        
        if not os.path.exists(self.screenshots_dir):
            issues.append(f"Diretório de screenshots não existe: {self.screenshots_dir}")
        
        # Validações de warning
        if not self.alert_config.slack_webhook:
            warnings.append("Slack webhook não configurado - alertas desabilitados")
        
        if not self.alert_config.email_recipients:
            warnings.append("Emails de alerta não configurados")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
    
    def get_baseline_path(self, test_name: str, viewport: str) -> str:
        """Retorna caminho para imagem baseline"""
        return f"{self.baseline_dir}/{test_name}_{viewport}.png"
    
    def get_screenshot_path(self, test_name: str, viewport: str) -> str:
        """Retorna caminho para screenshot atual"""
        return f"{self.screenshots_dir}/{test_name}_{viewport}.png"
    
    def get_diff_path(self, test_name: str, viewport: str) -> str:
        """Retorna caminho para imagem de diferença"""
        return f"{self.results_dir}/diffs/{test_name}_{viewport}_diff.png"


# Instância global da configuração
visual_config = VisualTestingConfiguration() 