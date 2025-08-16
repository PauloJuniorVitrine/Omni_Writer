"""
Configuração centralizada para otimização de performance.

Prompt: Otimização de Performance - IMP-006
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:05:00Z
Tracing ID: ENTERPRISE_20250127_006
"""

import os
from typing import Dict, Any
from dataclasses import dataclass, field
from shared.logging_config import get_structured_logger

logger = get_structured_logger("app.performance_config")


@dataclass
class ProviderConfig:
    """Configuração específica por provedor de IA"""
    name: str
    requests_per_minute: int
    requests_per_hour: int
    max_concurrent: int
    retry_delay: float
    backoff_multiplier: float
    timeout: float
    priority: int = 1  # 1=baixa, 5=alta


@dataclass
class PerformanceConfig:
    """Configuração geral de performance"""
    # Configurações de paralelismo
    max_workers: int = 5
    max_concurrent_per_provider: int = 3
    enable_parallel: bool = True
    fallback_to_sequential: bool = True
    
    # Configurações de rate limiting
    enable_rate_limiting: bool = True
    rate_limit_window: int = 60  # segundos
    
    # Configurações de timeout
    default_timeout: float = 30.0
    max_retries: int = 3
    
    # Configurações de monitoramento
    enable_performance_monitoring: bool = True
    metrics_collection_interval: int = 60  # segundos
    
    # Configurações de cache
    enable_cache: bool = True
    cache_ttl: int = 3600  # segundos
    
    # Configurações de otimização
    batch_size: int = 10
    enable_batching: bool = True
    
    # Configurações de provedores
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    
    def __post_init__(self):
        """Inicializa configurações padrão de provedores"""
        if not self.providers:
            self.providers = {
                'openai': ProviderConfig(
                    name='openai',
                    requests_per_minute=60,
                    requests_per_hour=3500,
                    max_concurrent=10,
                    retry_delay=1.0,
                    backoff_multiplier=2.0,
                    timeout=30.0,
                    priority=5
                ),
                'deepseek': ProviderConfig(
                    name='deepseek',
                    requests_per_minute=60,
                    requests_per_hour=2000,
                    max_concurrent=8,
                    retry_delay=1.5,
                    backoff_multiplier=1.5,
                    timeout=25.0,
                    priority=4
                ),
                'gemini': ProviderConfig(
                    name='gemini',
                    requests_per_minute=60,
                    requests_per_hour=1500,
                    max_concurrent=5,
                    retry_delay=2.0,
                    backoff_multiplier=1.5,
                    timeout=20.0,
                    priority=3
                ),
                'claude': ProviderConfig(
                    name='claude',
                    requests_per_minute=50,
                    requests_per_hour=1000,
                    max_concurrent=3,
                    retry_delay=3.0,
                    backoff_multiplier=2.0,
                    timeout=35.0,
                    priority=2
                )
            }


class PerformanceConfigManager:
    """
    Gerenciador de configuração de performance.
    """
    
    def __init__(self):
        self.config = self._load_config()
        logger.info("PerformanceConfigManager inicializado")
        
    def _load_config(self) -> PerformanceConfig:
        """
        Carrega configuração de performance.
        """
        config = PerformanceConfig()
        
        # Carrega configurações de ambiente
        config.max_workers = int(os.getenv('PERFORMANCE_MAX_WORKERS', config.max_workers))
        config.max_concurrent_per_provider = int(os.getenv('PERFORMANCE_MAX_CONCURRENT', config.max_concurrent_per_provider))
        config.enable_parallel = os.getenv('PERFORMANCE_ENABLE_PARALLEL', 'true').lower() == 'true'
        config.fallback_to_sequential = os.getenv('PERFORMANCE_FALLBACK_SEQUENTIAL', 'true').lower() == 'true'
        
        config.enable_rate_limiting = os.getenv('PERFORMANCE_ENABLE_RATE_LIMITING', 'true').lower() == 'true'
        config.rate_limit_window = int(os.getenv('PERFORMANCE_RATE_LIMIT_WINDOW', config.rate_limit_window))
        
        config.default_timeout = float(os.getenv('PERFORMANCE_DEFAULT_TIMEOUT', config.default_timeout))
        config.max_retries = int(os.getenv('PERFORMANCE_MAX_RETRIES', config.max_retries))
        
        config.enable_performance_monitoring = os.getenv('PERFORMANCE_ENABLE_MONITORING', 'true').lower() == 'true'
        config.metrics_collection_interval = int(os.getenv('PERFORMANCE_METRICS_INTERVAL', config.metrics_collection_interval))
        
        config.enable_cache = os.getenv('PERFORMANCE_ENABLE_CACHE', 'true').lower() == 'true'
        config.cache_ttl = int(os.getenv('PERFORMANCE_CACHE_TTL', config.cache_ttl))
        
        config.batch_size = int(os.getenv('PERFORMANCE_BATCH_SIZE', config.batch_size))
        config.enable_batching = os.getenv('PERFORMANCE_ENABLE_BATCHING', 'true').lower() == 'true'
        
        # Carrega configurações específicas de provedores
        self._load_provider_configs(config)
        
        logger.info(f"Configuração carregada | workers={config.max_workers} | parallel={config.enable_parallel}")
        
        return config
        
    def _load_provider_configs(self, config: PerformanceConfig):
        """
        Carrega configurações específicas de provedores.
        """
        for provider_name in config.providers:
            provider = config.providers[provider_name]
            
            # Rate limits
            provider.requests_per_minute = int(os.getenv(f'PERFORMANCE_{provider_name.upper()}_RPM', provider.requests_per_minute))
            provider.requests_per_hour = int(os.getenv(f'PERFORMANCE_{provider_name.upper()}_RPH', provider.requests_per_hour))
            provider.max_concurrent = int(os.getenv(f'PERFORMANCE_{provider_name.upper()}_MAX_CONCURRENT', provider.max_concurrent))
            
            # Timeouts e retries
            provider.retry_delay = float(os.getenv(f'PERFORMANCE_{provider_name.upper()}_RETRY_DELAY', provider.retry_delay))
            provider.backoff_multiplier = float(os.getenv(f'PERFORMANCE_{provider_name.upper()}_BACKOFF', provider.backoff_multiplier))
            provider.timeout = float(os.getenv(f'PERFORMANCE_{provider_name.upper()}_TIMEOUT', provider.timeout))
            
            # Prioridade
            provider.priority = int(os.getenv(f'PERFORMANCE_{provider_name.upper()}_PRIORITY', provider.priority))
            
    def get_config(self) -> PerformanceConfig:
        """
        Retorna configuração atual.
        """
        return self.config
        
    def get_provider_config(self, provider_name: str) -> ProviderConfig:
        """
        Retorna configuração de um provedor específico.
        """
        return self.config.providers.get(provider_name)
        
    def update_config(self, new_config: Dict[str, Any]):
        """
        Atualiza configuração.
        """
        for key, value in new_config.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                
        logger.info(f"Configuração atualizada | changes={list(new_config.keys())}")
        
    def get_optimized_settings(self, provider_name: str = None) -> Dict[str, Any]:
        """
        Retorna configurações otimizadas para uso.
        """
        settings = {
            'max_workers': self.config.max_workers,
            'max_concurrent_per_provider': self.config.max_concurrent_per_provider,
            'enable_parallel': self.config.enable_parallel,
            'fallback_to_sequential': self.config.fallback_to_sequential,
            'enable_rate_limiting': self.config.enable_rate_limiting,
            'default_timeout': self.config.default_timeout,
            'max_retries': self.config.max_retries,
            'batch_size': self.config.batch_size,
            'enable_batching': self.config.enable_batching
        }
        
        if provider_name and provider_name in self.config.providers:
            provider = self.config.providers[provider_name]
            settings.update({
                'provider_timeout': provider.timeout,
                'provider_retry_delay': provider.retry_delay,
                'provider_max_concurrent': provider.max_concurrent,
                'provider_requests_per_minute': provider.requests_per_minute
            })
            
        return settings
        
    def validate_config(self) -> Dict[str, Any]:
        """
        Valida configuração atual.
        """
        issues = []
        warnings = []
        
        # Validações críticas
        if self.config.max_workers <= 0:
            issues.append("max_workers deve ser maior que 0")
            
        if self.config.max_concurrent_per_provider <= 0:
            issues.append("max_concurrent_per_provider deve ser maior que 0")
            
        if self.config.default_timeout <= 0:
            issues.append("default_timeout deve ser maior que 0")
            
        # Validações de provedores
        for provider_name, provider in self.config.providers.items():
            if provider.requests_per_minute <= 0:
                issues.append(f"{provider_name}: requests_per_minute deve ser maior que 0")
                
            if provider.max_concurrent <= 0:
                issues.append(f"{provider_name}: max_concurrent deve ser maior que 0")
                
            if provider.timeout <= 0:
                issues.append(f"{provider_name}: timeout deve ser maior que 0")
                
        # Avisos
        if self.config.max_workers > 20:
            warnings.append("max_workers muito alto pode causar sobrecarga")
            
        if self.config.batch_size > 50:
            warnings.append("batch_size muito alto pode causar timeouts")
            
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
        
    def get_performance_recommendations(self) -> Dict[str, Any]:
        """
        Retorna recomendações de performance baseadas na configuração.
        """
        recommendations = []
        
        # Recomendações baseadas em workers
        if self.config.max_workers < 3:
            recommendations.append("Considere aumentar max_workers para melhor paralelismo")
        elif self.config.max_workers > 10:
            recommendations.append("Considere reduzir max_workers para evitar sobrecarga")
            
        # Recomendações baseadas em batch size
        if self.config.batch_size < 5:
            recommendations.append("Considere aumentar batch_size para melhor throughput")
        elif self.config.batch_size > 20:
            recommendations.append("Considere reduzir batch_size para evitar timeouts")
            
        # Recomendações baseadas em timeouts
        if self.config.default_timeout < 15:
            recommendations.append("Considere aumentar default_timeout para provedores lentos")
            
        # Recomendações de cache
        if not self.config.enable_cache:
            recommendations.append("Habilite cache para melhorar performance")
            
        # Recomendações de monitoramento
        if not self.config.enable_performance_monitoring:
            recommendations.append("Habilite monitoramento para otimização contínua")
            
        return {
            'recommendations': recommendations,
            'priority': 'high' if len(recommendations) > 3 else 'medium'
        }


# Instância global do gerenciador de configuração
performance_config_manager = PerformanceConfigManager()


def get_performance_config() -> PerformanceConfig:
    """
    Função de conveniência para obter configuração de performance.
    """
    return performance_config_manager.get_config()


def get_provider_config(provider_name: str) -> ProviderConfig:
    """
    Função de conveniência para obter configuração de provedor.
    """
    return performance_config_manager.get_provider_config(provider_name)


def update_performance_config(new_config: Dict[str, Any]):
    """
    Função de conveniência para atualizar configuração.
    """
    performance_config_manager.update_config(new_config) 