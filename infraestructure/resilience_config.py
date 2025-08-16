"""
Configuração centralizada para resiliência e circuit breaker.

Prompt: Circuit Breaker - IMP-012
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:00:00Z
Tracing ID: ENTERPRISE_20250127_012
"""

import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import timedelta


class CircuitBreakerState(Enum):
    """Estados do circuit breaker"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class FailureType(Enum):
    """Tipos de falha"""
    TEMPORARY = "temporary"
    PERMANENT = "permanent"
    UNKNOWN = "unknown"


@dataclass
class CircuitBreakerConfig:
    """Configuração de circuit breaker"""
    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # segundos
    expected_exception: type = Exception
    monitor_interval: float = 10.0
    enable_metrics: bool = True
    enable_logging: bool = True


@dataclass
class RetryConfig:
    """Configuração de retry"""
    name: str
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    backoff_multiplier: float = 2.0
    jitter_factor: float = 0.1
    timeout: float = 30.0
    enable_exponential_backoff: bool = True
    enable_jitter: bool = True


@dataclass
class FallbackConfig:
    """Configuração de fallback"""
    name: str
    primary_provider: str
    fallback_providers: List[str] = field(default_factory=list)
    enable_automatic_fallback: bool = True
    fallback_timeout: float = 30.0
    max_fallback_attempts: int = 2


@dataclass
class ResilienceConfig:
    """Configuração de resiliência para um componente"""
    name: str
    circuit_breaker: CircuitBreakerConfig
    retry: RetryConfig
    fallback: Optional[FallbackConfig] = None
    enable_monitoring: bool = True
    enable_alerting: bool = True
    alert_threshold: float = 0.8  # 80% de falhas


class ResilienceConfiguration:
    """Configuração centralizada para resiliência"""
    
    def __init__(self):
        self.base_config = self._get_base_config()
        self.component_configs = self._get_component_configs()
        self.global_settings = self._get_global_settings()
    
    def _get_base_config(self) -> Dict[str, Any]:
        """Retorna configuração base"""
        return {
            'enable_resilience': os.getenv('ENABLE_RESILIENCE', 'true').lower() == 'true',
            'default_failure_threshold': int(os.getenv('DEFAULT_FAILURE_THRESHOLD', '5')),
            'default_recovery_timeout': float(os.getenv('DEFAULT_RECOVERY_TIMEOUT', '60.0')),
            'default_max_retries': int(os.getenv('DEFAULT_MAX_RETRIES', '3')),
            'default_timeout': float(os.getenv('DEFAULT_TIMEOUT', '30.0')),
            'enable_metrics': os.getenv('ENABLE_RESILIENCE_METRICS', 'true').lower() == 'true',
            'enable_logging': os.getenv('ENABLE_RESILIENCE_LOGGING', 'true').lower() == 'true',
            'monitoring_interval': float(os.getenv('RESILIENCE_MONITORING_INTERVAL', '10.0')),
            'alert_threshold': float(os.getenv('RESILIENCE_ALERT_THRESHOLD', '0.8'))
        }
    
    def _get_component_configs(self) -> Dict[str, ResilienceConfig]:
        """Retorna configurações por componente"""
        configs = {}
        
        # Configuração para APIs externas
        configs['external_api'] = ResilienceConfig(
            name='external_api',
            circuit_breaker=CircuitBreakerConfig(
                name='external_api_cb',
                failure_threshold=3,
                recovery_timeout=120.0,
                monitor_interval=15.0
            ),
            retry=RetryConfig(
                name='external_api_retry',
                max_retries=3,
                base_delay=2.0,
                max_delay=60.0,
                timeout=30.0
            ),
            fallback=FallbackConfig(
                name='external_api_fallback',
                primary_provider='primary_api',
                fallback_providers=['backup_api', 'cache'],
                fallback_timeout=45.0
            )
        )
        
        # Configuração para provedores de IA
        configs['ai_providers'] = ResilienceConfig(
            name='ai_providers',
            circuit_breaker=CircuitBreakerConfig(
                name='ai_providers_cb',
                failure_threshold=5,
                recovery_timeout=180.0,
                monitor_interval=20.0
            ),
            retry=RetryConfig(
                name='ai_providers_retry',
                max_retries=3,
                base_delay=1.0,
                max_delay=90.0,
                timeout=60.0
            ),
            fallback=FallbackConfig(
                name='ai_providers_fallback',
                primary_provider='openai',
                fallback_providers=['deepseek', 'gemini', 'claude'],
                fallback_timeout=60.0
            )
        )
        
        # Configuração para banco de dados
        configs['database'] = ResilienceConfig(
            name='database',
            circuit_breaker=CircuitBreakerConfig(
                name='database_cb',
                failure_threshold=3,
                recovery_timeout=60.0,
                monitor_interval=10.0
            ),
            retry=RetryConfig(
                name='database_retry',
                max_retries=2,
                base_delay=1.0,
                max_delay=30.0,
                timeout=15.0
            ),
            fallback=FallbackConfig(
                name='database_fallback',
                primary_provider='postgresql',
                fallback_providers=['sqlite', 'cache'],
                fallback_timeout=30.0
            )
        )
        
        # Configuração para cache
        configs['cache'] = ResilienceConfig(
            name='cache',
            circuit_breaker=CircuitBreakerConfig(
                name='cache_cb',
                failure_threshold=2,
                recovery_timeout=30.0,
                monitor_interval=5.0
            ),
            retry=RetryConfig(
                name='cache_retry',
                max_retries=1,
                base_delay=0.5,
                max_delay=10.0,
                timeout=5.0
            ),
            fallback=FallbackConfig(
                name='cache_fallback',
                primary_provider='redis',
                fallback_providers=['memory', 'database'],
                fallback_timeout=10.0
            )
        )
        
        # Configuração para filas
        configs['queues'] = ResilienceConfig(
            name='queues',
            circuit_breaker=CircuitBreakerConfig(
                name='queues_cb',
                failure_threshold=3,
                recovery_timeout=90.0,
                monitor_interval=15.0
            ),
            retry=RetryConfig(
                name='queues_retry',
                max_retries=2,
                base_delay=2.0,
                max_delay=45.0,
                timeout=30.0
            ),
            fallback=FallbackConfig(
                name='queues_fallback',
                primary_provider='celery',
                fallback_providers=['synchronous', 'file_queue'],
                fallback_timeout=45.0
            )
        )
        
        # Configuração para storage
        configs['storage'] = ResilienceConfig(
            name='storage',
            circuit_breaker=CircuitBreakerConfig(
                name='storage_cb',
                failure_threshold=3,
                recovery_timeout=60.0,
                monitor_interval=10.0
            ),
            retry=RetryConfig(
                name='storage_retry',
                max_retries=2,
                base_delay=1.0,
                max_delay=30.0,
                timeout=20.0
            ),
            fallback=FallbackConfig(
                name='storage_fallback',
                primary_provider='distributed_storage',
                fallback_providers=['local_storage', 'memory'],
                fallback_timeout=30.0
            )
        )
        
        return configs
    
    def _get_global_settings(self) -> Dict[str, Any]:
        """Retorna configurações globais"""
        return {
            'monitoring': {
                'enabled': self.base_config['enable_metrics'],
                'interval': self.base_config['monitoring_interval'],
                'metrics_retention': int(os.getenv('RESILIENCE_METRICS_RETENTION', '86400')),  # 24h
                'alert_threshold': self.base_config['alert_threshold']
            },
            'logging': {
                'enabled': self.base_config['enable_logging'],
                'level': os.getenv('RESILIENCE_LOG_LEVEL', 'INFO'),
                'format': os.getenv('RESILIENCE_LOG_FORMAT', 'json'),
                'file': os.getenv('RESILIENCE_LOG_FILE', 'logs/resilience.log')
            },
            'alerting': {
                'enabled': os.getenv('ENABLE_RESILIENCE_ALERTS', 'true').lower() == 'true',
                'channels': os.getenv('RESILIENCE_ALERT_CHANNELS', 'log,metrics').split(','),
                'cooldown': float(os.getenv('RESILIENCE_ALERT_COOLDOWN', '300.0'))  # 5min
            },
            'performance': {
                'enable_circuit_breaker': True,
                'enable_retry': True,
                'enable_fallback': True,
                'enable_timeout': True,
                'enable_bulkhead': False,  # Futuro
                'enable_rate_limiting': True
            }
        }
    
    def get_component_config(self, component_name: str) -> Optional[ResilienceConfig]:
        """Retorna configuração de um componente"""
        return self.component_configs.get(component_name)
    
    def get_all_component_configs(self) -> Dict[str, ResilienceConfig]:
        """Retorna todas as configurações de componentes"""
        return self.component_configs
    
    def get_circuit_breaker_config(self, component_name: str) -> Optional[CircuitBreakerConfig]:
        """Retorna configuração de circuit breaker de um componente"""
        config = self.get_component_config(component_name)
        return config.circuit_breaker if config else None
    
    def get_retry_config(self, component_name: str) -> Optional[RetryConfig]:
        """Retorna configuração de retry de um componente"""
        config = self.get_component_config(component_name)
        return config.retry if config else None
    
    def get_fallback_config(self, component_name: str) -> Optional[FallbackConfig]:
        """Retorna configuração de fallback de um componente"""
        config = self.get_component_config(component_name)
        return config.fallback if config else None
    
    def is_resilience_enabled(self) -> bool:
        """Verifica se resiliência está habilitada"""
        return self.base_config['enable_resilience']
    
    def is_monitoring_enabled(self) -> bool:
        """Verifica se monitoramento está habilitado"""
        return self.global_settings['monitoring']['enabled']
    
    def is_logging_enabled(self) -> bool:
        """Verifica se logging está habilitado"""
        return self.global_settings['logging']['enabled']
    
    def is_alerting_enabled(self) -> bool:
        """Verifica se alertas estão habilitados"""
        return self.global_settings['alerting']['enabled']
    
    def get_monitoring_interval(self) -> float:
        """Retorna intervalo de monitoramento"""
        return self.global_settings['monitoring']['interval']
    
    def get_alert_threshold(self) -> float:
        """Retorna threshold de alerta"""
        return self.global_settings['monitoring']['alert_threshold']
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Valida configuração e retorna problemas encontrados"""
        issues = []
        warnings = []
        
        # Valida configurações base
        if self.base_config['default_failure_threshold'] <= 0:
            issues.append("DEFAULT_FAILURE_THRESHOLD deve ser maior que 0")
        
        if self.base_config['default_recovery_timeout'] <= 0:
            issues.append("DEFAULT_RECOVERY_TIMEOUT deve ser maior que 0")
        
        if self.base_config['default_max_retries'] < 0:
            issues.append("DEFAULT_MAX_RETRIES deve ser maior ou igual a 0")
        
        # Valida configurações de componentes
        for component_name, config in self.component_configs.items():
            if config.circuit_breaker.failure_threshold <= 0:
                issues.append(f"Circuit breaker {component_name} tem failure_threshold inválido")
            
            if config.circuit_breaker.recovery_timeout <= 0:
                issues.append(f"Circuit breaker {component_name} tem recovery_timeout inválido")
            
            if config.retry.max_retries < 0:
                issues.append(f"Retry {component_name} tem max_retries inválido")
            
            if config.retry.base_delay <= 0:
                issues.append(f"Retry {component_name} tem base_delay inválido")
            
            if config.retry.max_delay <= 0:
                issues.append(f"Retry {component_name} tem max_delay inválido")
            
            if config.retry.timeout <= 0:
                issues.append(f"Retry {component_name} tem timeout inválido")
            
            if config.fallback and config.fallback.fallback_timeout <= 0:
                issues.append(f"Fallback {component_name} tem fallback_timeout inválido")
        
        # Valida configurações globais
        if self.global_settings['monitoring']['interval'] <= 0:
            issues.append("RESILIENCE_MONITORING_INTERVAL deve ser maior que 0")
        
        if not (0 <= self.global_settings['monitoring']['alert_threshold'] <= 1):
            issues.append("RESILIENCE_ALERT_THRESHOLD deve estar entre 0 e 1")
        
        # Avisos
        if not self.is_resilience_enabled():
            warnings.append("Resiliência está desabilitada")
        
        if not self.is_monitoring_enabled():
            warnings.append("Monitoramento de resiliência está desabilitado")
        
        if not self.is_alerting_enabled():
            warnings.append("Alertas de resiliência estão desabilitados")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Retorna resumo da configuração"""
        return {
            'enabled': self.is_resilience_enabled(),
            'components': {
                name: {
                    'circuit_breaker': {
                        'failure_threshold': config.circuit_breaker.failure_threshold,
                        'recovery_timeout': config.circuit_breaker.recovery_timeout
                    },
                    'retry': {
                        'max_retries': config.retry.max_retries,
                        'timeout': config.retry.timeout
                    },
                    'fallback': {
                        'enabled': config.fallback is not None,
                        'providers': config.fallback.fallback_providers if config.fallback else []
                    }
                }
                for name, config in self.component_configs.items()
            },
            'monitoring': {
                'enabled': self.is_monitoring_enabled(),
                'interval': self.get_monitoring_interval(),
                'alert_threshold': self.get_alert_threshold()
            },
            'logging': {
                'enabled': self.is_logging_enabled(),
                'level': self.global_settings['logging']['level']
            },
            'alerting': {
                'enabled': self.is_alerting_enabled(),
                'channels': self.global_settings['alerting']['channels']
            }
        }


# Instância global da configuração
resilience_config = ResilienceConfiguration() 