"""
Performance Config Simplificada - Versão 2.0

Prompt: Simplificação de Complexidade - Seção 2.3
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T23:40:00Z
Tracing ID: SIMPLIFICATION_20250127_003

Redução de 321 linhas para ~100 linhas mantendo apenas configurações essenciais.
"""

import os
from typing import Dict, Any
from dataclasses import dataclass, field

from shared.logging_config import get_structured_logger

logger = get_structured_logger("app.performance_config_simplified")


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
        self.config = self._load_config()
        logger.info("PerformanceConfigManager simplificado inicializado")
    
    def _load_config(self) -> PerformanceConfig:
        """Carrega configuração simplificada"""
        config = PerformanceConfig()
        
        # Carrega configurações essenciais de ambiente
        config.max_workers = int(os.getenv('PERFORMANCE_MAX_WORKERS', config.max_workers))
        config.enable_parallel = os.getenv('PERFORMANCE_ENABLE_PARALLEL', 'true').lower() == 'true'
        config.enable_rate_limiting = os.getenv('PERFORMANCE_ENABLE_RATE_LIMITING', 'true').lower() == 'true'
        config.default_timeout = float(os.getenv('PERFORMANCE_DEFAULT_TIMEOUT', config.default_timeout))
        config.max_retries = int(os.getenv('PERFORMANCE_MAX_RETRIES', config.max_retries))
        config.enable_cache = os.getenv('PERFORMANCE_ENABLE_CACHE', 'true').lower() == 'true'
        config.batch_size = int(os.getenv('PERFORMANCE_BATCH_SIZE', config.batch_size))
        
        # Carrega configurações de provedores essenciais
        self._load_provider_configs(config)
        
        logger.info(f"Configuração carregada | workers={config.max_workers} | parallel={config.enable_parallel}")
        return config
    
    def _load_provider_configs(self, config: PerformanceConfig):
        """Carrega configurações de provedores essenciais"""
        for provider_name in config.providers:
            provider = config.providers[provider_name]
            
            # Rate limits
            provider.requests_per_minute = int(os.getenv(
                f'PERFORMANCE_{provider_name.upper()}_RPM', 
                provider.requests_per_minute
            ))
            provider.max_concurrent = int(os.getenv(
                f'PERFORMANCE_{provider_name.upper()}_MAX_CONCURRENT', 
                provider.max_concurrent
            ))
            
            # Timeout
            provider.timeout = float(os.getenv(
                f'PERFORMANCE_{provider_name.upper()}_TIMEOUT', 
                provider.timeout
            ))
            
            # Prioridade
            provider.priority = int(os.getenv(
                f'PERFORMANCE_{provider_name.upper()}_PRIORITY', 
                provider.priority
            ))
    
    def get_config(self) -> PerformanceConfig:
        """Retorna configuração atual"""
        return self.config
    
    def get_provider_config(self, provider_name: str) -> ProviderConfig:
        """Retorna configuração de um provedor específico"""
        return self.config.providers.get(provider_name)
    
    def update_config(self, new_config: Dict[str, Any]):
        """Atualiza configuração essencial"""
        if 'max_workers' in new_config:
            self.config.max_workers = new_config['max_workers']
        if 'enable_parallel' in new_config:
            self.config.enable_parallel = new_config['enable_parallel']
        if 'enable_rate_limiting' in new_config:
            self.config.enable_rate_limiting = new_config['enable_rate_limiting']
        if 'default_timeout' in new_config:
            self.config.default_timeout = new_config['default_timeout']
        if 'max_retries' in new_config:
            self.config.max_retries = new_config['max_retries']
        if 'enable_cache' in new_config:
            self.config.enable_cache = new_config['enable_cache']
        if 'batch_size' in new_config:
            self.config.batch_size = new_config['batch_size']
        
        logger.info("Configuração atualizada")
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas da configuração"""
        return {
            'max_workers': self.config.max_workers,
            'enable_parallel': self.config.enable_parallel,
            'enable_rate_limiting': self.config.enable_rate_limiting,
            'default_timeout': self.config.default_timeout,
            'max_retries': self.config.max_retries,
            'enable_cache': self.config.enable_cache,
            'batch_size': self.config.batch_size,
            'providers': list(self.config.providers.keys())
        }


# Instância global
_performance_config_manager = PerformanceConfigManager()


def get_performance_config() -> PerformanceConfig:
    """Obtém configuração de performance"""
    return _performance_config_manager.get_config()


def get_provider_config(provider_name: str) -> ProviderConfig:
    """Obtém configuração de provedor específico"""
    return _performance_config_manager.get_provider_config(provider_name)


def update_performance_config(new_config: Dict[str, Any]):
    """Atualiza configuração de performance"""
    _performance_config_manager.update_config(new_config)


def get_performance_stats() -> Dict[str, Any]:
    """Obtém estatísticas da configuração"""
    return _performance_config_manager.get_stats() 