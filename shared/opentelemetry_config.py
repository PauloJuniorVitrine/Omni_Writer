"""
OpenTelemetry Configuration - Omni Writer
=========================================

Configuração completa do OpenTelemetry para observabilidade distribuída:
- Tracing distribuído
- Métricas padronizadas
- Logs estruturados interoperáveis

Prompt: Implementação de OpenTelemetry - ETAPA 8
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: OPENTELEMETRY_20250127_001
"""

import os
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

# OpenTelemetry imports
from opentelemetry import trace, metrics, context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    OTLPSpanExporter
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
    ConsoleMetricExporter,
    OTLPMetricExporter
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.semconv.trace import SpanAttributes

# Configuração de logging
logger = logging.getLogger(__name__)

class OpenTelemetryConfig:
    """
    Configuração centralizada do OpenTelemetry para o Omni Writer.
    
    Funcionalidades:
    - Tracing distribuído com Jaeger/OTLP
    - Métricas Prometheus/OTLP
    - Logs estruturados interoperáveis
    - Instrumentação automática de frameworks
    - Fallback para sistema existente
    """
    
    def __init__(self, service_name: str = "omni-writer", service_version: str = "1.0.0"):
        self.service_name = service_name
        self.service_version = service_version
        self.tracer_provider = None
        self.meter_provider = None
        self.tracer = None
        self.meter = None
        self._initialized = False
        
    def initialize(self, 
                   enable_tracing: bool = True,
                   enable_metrics: bool = True,
                   enable_logging: bool = True,
                   jaeger_endpoint: Optional[str] = None,
                   prometheus_endpoint: Optional[str] = None,
                   otlp_endpoint: Optional[str] = None) -> None:
        """
        Inicializa o OpenTelemetry com configurações específicas.
        
        Args:
            enable_tracing: Habilita tracing distribuído
            enable_metrics: Habilita métricas
            enable_logging: Habilita logs estruturados
            jaeger_endpoint: Endpoint do Jaeger (ex: http://localhost:14268/api/traces)
            prometheus_endpoint: Endpoint do Prometheus
            otlp_endpoint: Endpoint OTLP (ex: http://localhost:4317)
        """
        
        try:
            # Configurar resource com metadados do serviço
            resource = Resource.create({
                ResourceAttributes.SERVICE_NAME: self.service_name,
                ResourceAttributes.SERVICE_VERSION: self.service_version,
                ResourceAttributes.DEPLOYMENT_ENVIRONMENT: os.getenv("ENVIRONMENT", "development"),
                "service.instance.id": os.getenv("HOSTNAME", "unknown"),
                "service.namespace": "omni-writer",
                "service.owner": "omni-writer-team"
            })
            
            # Configurar tracing
            if enable_tracing:
                self._setup_tracing(resource, jaeger_endpoint, otlp_endpoint)
                
            # Configurar métricas
            if enable_metrics:
                self._setup_metrics(resource, prometheus_endpoint, otlp_endpoint)
                
            # Configurar logging
            if enable_logging:
                self._setup_logging()
                
            # Instrumentar frameworks
            self._instrument_frameworks()
            
            self._initialized = True
            logger.info(f"OpenTelemetry inicializado com sucesso para {self.service_name}")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar OpenTelemetry: {e}")
            # Fallback para sistema existente
            self._fallback_to_existing_system()
    
    def _setup_tracing(self, resource: Resource, jaeger_endpoint: Optional[str], otlp_endpoint: Optional[str]) -> None:
        """Configura o sistema de tracing."""
        
        # Criar TracerProvider
        self.tracer_provider = TracerProvider(resource=resource)
        
        # Configurar exportadores
        exporters = [ConsoleSpanExporter()]  # Sempre incluir console para debug
        
        if jaeger_endpoint:
            try:
                jaeger_exporter = OTLPSpanExporter(endpoint=jaeger_endpoint)
                exporters.append(jaeger_exporter)
                logger.info(f"Jaeger exporter configurado: {jaeger_endpoint}")
            except Exception as e:
                logger.warning(f"Falha ao configurar Jaeger: {e}")
                
        if otlp_endpoint:
            try:
                otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                exporters.append(otlp_exporter)
                logger.info(f"OTLP exporter configurado: {otlp_endpoint}")
            except Exception as e:
                logger.warning(f"Falha ao configurar OTLP: {e}")
        
        # Configurar processadores
        for exporter in exporters:
            self.tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
        
        # Configurar tracer global
        trace.set_tracer_provider(self.tracer_provider)
        self.tracer = trace.get_tracer(self.service_name, self.service_version)
        
    def _setup_metrics(self, resource: Resource, prometheus_endpoint: Optional[str], otlp_endpoint: Optional[str]) -> None:
        """Configura o sistema de métricas."""
        
        # Configurar exportadores de métricas
        exporters = [ConsoleMetricExporter()]  # Sempre incluir console para debug
        
        if otlp_endpoint:
            try:
                otlp_metric_exporter = OTLPMetricExporter(endpoint=otlp_endpoint)
                exporters.append(otlp_metric_exporter)
                logger.info(f"OTLP metrics exporter configurado: {otlp_endpoint}")
            except Exception as e:
                logger.warning(f"Falha ao configurar OTLP metrics: {e}")
        
        # Configurar readers
        readers = []
        for exporter in exporters:
            reader = PeriodicExportingMetricReader(exporter, export_interval_millis=5000)
            readers.append(reader)
        
        # Criar MeterProvider
        self.meter_provider = MeterProvider(resource=resource, metric_readers=readers)
        metrics.set_meter_provider(self.meter_provider)
        self.meter = metrics.get_meter(self.service_name, self.service_version)
        
    def _setup_logging(self) -> None:
        """Configura o sistema de logging estruturado."""
        
        try:
            LoggingInstrumentor().instrument(
                set_logging_format=True,
                log_level=logging.INFO
            )
            logger.info("Logging instrumentation configurado")
        except Exception as e:
            logger.warning(f"Falha ao configurar logging instrumentation: {e}")
    
    def _instrument_frameworks(self) -> None:
        """Instrumenta frameworks automaticamente."""
        
        try:
            # Instrumentar Flask (será aplicado quando app Flask for criado)
            FlaskInstrumentor().instrument()
            logger.info("Flask instrumentation configurado")
        except Exception as e:
            logger.warning(f"Falha ao configurar Flask instrumentation: {e}")
            
        try:
            # Instrumentar requests
            RequestsInstrumentor().instrument()
            logger.info("Requests instrumentation configurado")
        except Exception as e:
            logger.warning(f"Falha ao configurar Requests instrumentation: {e}")
            
        try:
            # Instrumentar SQLite3
            SQLite3Instrumentor().instrument()
            logger.info("SQLite3 instrumentation configurado")
        except Exception as e:
            logger.warning(f"Falha ao configurar SQLite3 instrumentation: {e}")
    
    def _fallback_to_existing_system(self) -> None:
        """Fallback para o sistema de tracing existente."""
        
        logger.info("Usando sistema de tracing existente como fallback")
        # Importar sistema existente
        try:
            from .tracing_system import TracingSystem
            self.existing_tracing = TracingSystem()
        except ImportError:
            logger.warning("Sistema de tracing existente não encontrado")
    
    def get_tracer(self):
        """Retorna o tracer configurado."""
        if self._initialized and self.tracer:
            return self.tracer
        elif hasattr(self, 'existing_tracing'):
            return self.existing_tracing
        else:
            # Tracer dummy para não quebrar
            return trace.get_tracer("dummy")
    
    def get_meter(self):
        """Retorna o meter configurado."""
        if self._initialized and self.meter:
            return self.meter
        else:
            # Meter dummy para não quebrar
            return metrics.get_meter("dummy")
    
    @contextmanager
    def span(self, name: str, attributes: Dict[str, Any] = None):
        """
        Context manager para criar spans automaticamente.
        
        Args:
            name: Nome do span
            attributes: Atributos do span
        """
        
        tracer = self.get_tracer()
        with tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            try:
                yield span
            except Exception as e:
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                span.record_exception(e)
                raise
    
    def record_metric(self, name: str, value: float, attributes: Dict[str, Any] = None):
        """
        Registra uma métrica.
        
        Args:
            name: Nome da métrica
            value: Valor da métrica
            attributes: Atributos da métrica
        """
        
        meter = self.get_meter()
        counter = meter.create_counter(name)
        counter.add(value, attributes=attributes or {})
    
    def cleanup(self):
        """Limpa recursos do OpenTelemetry."""
        
        if self.tracer_provider:
            self.tracer_provider.force_flush()
            self.tracer_provider.shutdown()
            
        if self.meter_provider:
            self.meter_provider.force_flush()
            self.meter_provider.shutdown()
            
        logger.info("OpenTelemetry cleanup concluído")

# Instância global
opentelemetry_config = OpenTelemetryConfig()

def initialize_opentelemetry(**kwargs):
    """Função de conveniência para inicializar OpenTelemetry."""
    return opentelemetry_config.initialize(**kwargs)

def get_tracer():
    """Função de conveniência para obter tracer."""
    return opentelemetry_config.get_tracer()

def get_meter():
    """Função de conveniência para obter meter."""
    return opentelemetry_config.get_meter()

def create_span(name: str, attributes: Dict[str, Any] = None):
    """Função de conveniência para criar span."""
    return opentelemetry_config.span(name, attributes)

def record_metric(name: str, value: float, attributes: Dict[str, Any] = None):
    """Função de conveniência para registrar métrica."""
    return opentelemetry_config.record_metric(name, value, attributes) 