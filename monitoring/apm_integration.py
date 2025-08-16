"""
APM Integration Module - IMP-100
Prompt: Observabilidade Total - Fase 1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: ENTERPRISE_20250127_100

Implementação de APM (Application Performance Monitoring) para
monitoramento em tempo real e detecção proativa de problemas.
"""

import time
import logging
from typing import Dict, Any, Optional, Callable
from functools import wraps
from dataclasses import dataclass
from datetime import datetime
import json

# APM Providers
try:
    import newrelic.agent
    NEW_RELIC_AVAILABLE = True
except ImportError:
    NEW_RELIC_AVAILABLE = False

try:
    import datadog
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False

logger = logging.getLogger("monitoring.apm")

@dataclass
class APMConfig:
    """Configuração do APM"""
    provider: str = "newrelic"  # newrelic, datadog, custom
    enabled: bool = True
    sampling_rate: float = 1.0
    custom_metrics: bool = True
    distributed_tracing: bool = True
    error_tracking: bool = True
    performance_monitoring: bool = True

class APMIntegration:
    """
    Integração com APM para monitoramento em tempo real.
    
    Funcionalidades:
    - Performance monitoring
    - Error tracking
    - Custom metrics
    - Distributed tracing
    - Real-time alerting
    """
    
    def __init__(self, config: APMConfig):
        self.config = config
        self.provider = None
        self.metrics_buffer = []
        self.error_buffer = []
        
        self._initialize_provider()
        logger.info(f"APM Integration inicializada com provider: {config.provider}")
    
    def _initialize_provider(self):
        """Inicializa o provider de APM"""
        if self.config.provider == "newrelic" and NEW_RELIC_AVAILABLE:
            self.provider = "newrelic"
            newrelic.agent.initialize()
            logger.info("New Relic APM inicializado")
            
        elif self.config.provider == "datadog" and DATADOG_AVAILABLE:
            self.provider = "datadog"
            datadog.initialize()
            logger.info("Datadog APM inicializado")
            
        else:
            self.provider = "custom"
            logger.info("Usando APM customizado")
    
    def track_performance(self, operation: str, duration_ms: float, metadata: Optional[Dict] = None):
        """Registra métrica de performance"""
        metric_data = {
            "operation": operation,
            "duration_ms": duration_ms,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        }
        
        self.metrics_buffer.append(metric_data)
        
        # Enviar para APM provider
        self._send_metric(metric_data)
        
        logger.debug(f"Performance tracked: {operation} - {duration_ms}ms")
    
    def track_error(self, error: Exception, context: Optional[Dict] = None):
        """Registra erro para tracking"""
        error_data = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.utcnow().isoformat(),
            "context": context or {}
        }
        
        self.error_buffer.append(error_data)
        
        # Enviar para APM provider
        self._send_error(error_data)
        
        logger.error(f"Error tracked: {error_data['error_type']} - {error_data['error_message']}")
    
    def custom_metric(self, name: str, value: float, tags: Optional[Dict] = None):
        """Registra métrica customizada"""
        metric_data = {
            "name": name,
            "value": value,
            "tags": tags or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self._send_custom_metric(metric_data)
        
        logger.debug(f"Custom metric: {name} = {value}")
    
    def _send_metric(self, metric_data: Dict):
        """Envia métrica para o provider"""
        if self.provider == "newrelic":
            newrelic.agent.record_custom_metric(
                f"Custom/{metric_data['operation']}", 
                metric_data['duration_ms']
            )
        elif self.provider == "datadog":
            datadog.statsd.timing(
                f"custom.{metric_data['operation']}", 
                metric_data['duration_ms']
            )
    
    def _send_error(self, error_data: Dict):
        """Envia erro para o provider"""
        if self.provider == "newrelic":
            newrelic.agent.notice_error(
                Exception(error_data['error_message']),
                attributes=error_data['context']
            )
        elif self.provider == "datadog":
            datadog.statsd.increment("errors", tags=[f"type:{error_data['error_type']}"])
    
    def _send_custom_metric(self, metric_data: Dict):
        """Envia métrica customizada para o provider"""
        if self.provider == "newrelic":
            newrelic.agent.record_custom_metric(
                f"Custom/{metric_data['name']}", 
                metric_data['value']
            )
        elif self.provider == "datadog":
            datadog.statsd.gauge(
                f"custom.{metric_data['name']}", 
                metric_data['value']
            )

def apm_track(operation: str):
    """Decorator para tracking automático de performance"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Track performance
                apm_instance.track_performance(
                    operation=operation,
                    duration_ms=duration_ms,
                    metadata={"function": func.__name__}
                )
                
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                # Track error
                apm_instance.track_error(
                    error=e,
                    context={
                        "operation": operation,
                        "function": func.__name__,
                        "duration_ms": duration_ms
                    }
                )
                
                raise
        
        return wrapper
    return decorator

# Instância global do APM
apm_instance: Optional[APMIntegration] = None

def initialize_apm(config: APMConfig):
    """Inicializa o APM globalmente"""
    global apm_instance
    apm_instance = APMIntegration(config)
    return apm_instance

def get_apm() -> APMIntegration:
    """Retorna instância do APM"""
    if apm_instance is None:
        raise RuntimeError("APM não foi inicializado. Chame initialize_apm() primeiro.")
    return apm_instance 