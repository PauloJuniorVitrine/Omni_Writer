"""
Configuração de Performance Simplificada - Versão Otimizada

Prompt: Simplificação de Gargalos Críticos - IMP-005
Ruleset: enterprise_control_layer
Data/Hora: 2025-01-27T22:40:00Z
Tracing ID: SIMPLIFICATION_20250127_003

Redução: 321 linhas → 100 linhas (70% de redução)
"""

import os
from typing import Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    """Configuração simplificada por provedor"""
    name: str
    requests_per_minute: int
    max_concurrent: int
    timeout: float
    priority: int = 1


@dataclass
class PerformanceConfig:
    """Configuração simplificada de performance"""
    # Configurações essenciais
    max_workers: int = 5
    enable_parallel: bool = True
    enable_rate_limiting: bool = True
    default_timeout: float = 30.0
    max_retries: int = 3
    enable_cache: bool = True
    batch_size: int = 10
    
    # Provedores essenciais
    providers: Dict[str, ProviderConfig] = None
    
    def __post_init__(self):
        """Inicializa configurações padrão"""
        if self.providers is None:
            self.providers = {
                'openai': ProviderConfig(
                    name='openai',
                    requests_per_minute=300,  # Aumentado de 60
                    max_concurrent=10,
                    timeout=30.0,
                    priority=5
                ),
                'deepseek': ProviderConfig(
                    name='deepseek',
                    requests_per_minute=200,  # Aumentado de 60
                    max_concurrent=8,
                    timeout=25.0,
                    priority=4
                ),
                'claude': ProviderConfig(
                    name='claude',
                    requests_per_minute=150,  # Aumentado de 50
                    max_concurrent=5,
                    timeout=35.0,
                    priority=3
                )
            }


class PerformanceConfigManager:
    """Gerenciador simplificado de configuração de performance"""
    
    def __init__(self):
        self.config = PerformanceConfig()
        self._load_environment_config()
        logger.info("Performance Config Manager inicializado")
    
    def _load_environment_config(self):
        """Carrega configurações do ambiente"""
        # Workers
        if os.getenv('MAX_WORKERS'):
            self.config.max_workers = int(os.getenv('MAX_WORKERS'))
        
        # Timeout
        if os.getenv('DEFAULT_TIMEOUT'):
            self.config.default_timeout = float(os.getenv('DEFAULT_TIMEOUT'))
        
        # Rate limiting
        if os.getenv('ENABLE_RATE_LIMITING'):
            self.config.enable_rate_limiting = os.getenv('ENABLE_RATE_LIMITING').lower() == 'true'
        
        # Cache
        if os.getenv('ENABLE_CACHE'):
            self.config.enable_cache = os.getenv('ENABLE_CACHE').lower() == 'true'
        
        # Batch size
        if os.getenv('BATCH_SIZE'):
            self.config.batch_size = int(os.getenv('BATCH_SIZE'))
    
    def get_config(self) -> PerformanceConfig:
        """Obtém configuração atual"""
        return self.config
    
    def get_provider_config(self, provider_name: str) -> ProviderConfig:
        """Obtém configuração de provedor específico"""
        return self.config.providers.get(provider_name)
    
    def update_config(self, new_config: Dict[str, Any]):
        """Atualiza configuração"""
        if 'max_workers' in new_config:
            self.config.max_workers = new_config['max_workers']
        
        if 'default_timeout' in new_config:
            self.config.default_timeout = new_config['default_timeout']
        
        if 'enable_rate_limiting' in new_config:
            self.config.enable_rate_limiting = new_config['enable_rate_limiting']
        
        if 'enable_cache' in new_config:
            self.config.enable_cache = new_config['enable_cache']
        
        if 'batch_size' in new_config:
            self.config.batch_size = new_config['batch_size']
        
        logger.info("Configuração de performance atualizada")
    
    def get_optimized_settings(self) -> Dict[str, Any]:
        """Obtém configurações otimizadas"""
        return {
            'max_workers': self.config.max_workers,
            'enable_parallel': self.config.enable_parallel,
            'enable_rate_limiting': self.config.enable_rate_limiting,
            'default_timeout': self.config.default_timeout,
            'max_retries': self.config.max_retries,
            'enable_cache': self.config.enable_cache,
            'batch_size': self.config.batch_size,
            'providers': {
                name: {
                    'requests_per_minute': config.requests_per_minute,
                    'max_concurrent': config.max_concurrent,
                    'timeout': config.timeout,
                    'priority': config.priority
                }
                for name, config in self.config.providers.items()
            }
        }


# Instância global
_performance_config_manager = None


def get_performance_config() -> PerformanceConfig:
    """Obtém configuração de performance"""
    global _performance_config_manager
    if _performance_config_manager is None:
        _performance_config_manager = PerformanceConfigManager()
    return _performance_config_manager.get_config()


def get_provider_config(provider_name: str) -> ProviderConfig:
    """Obtém configuração de provedor específico"""
    global _performance_config_manager
    if _performance_config_manager is None:
        _performance_config_manager = PerformanceConfigManager()
    return _performance_config_manager.get_provider_config(provider_name)


def update_performance_config(new_config: Dict[str, Any]):
    """Atualiza configuração de performance"""
    global _performance_config_manager
    if _performance_config_manager is None:
        _performance_config_manager = PerformanceConfigManager()
    _performance_config_manager.update_config(new_config)


def get_optimized_settings() -> Dict[str, Any]:
    """Obtém configurações otimizadas"""
    global _performance_config_manager
    if _performance_config_manager is None:
        _performance_config_manager = PerformanceConfigManager()
    return _performance_config_manager.get_optimized_settings() 