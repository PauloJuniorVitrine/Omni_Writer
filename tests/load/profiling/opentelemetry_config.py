#!/usr/bin/env python3
"""
OpenTelemetry Configuration para Load Tests - Omni Writer
========================================================

Configuração de tracing distribuído com OpenTelemetry e Jaeger
para análise detalhada de performance durante testes de carga.

Autor: Equipe de Performance
Data: 2025-01-27
Versão: 1.0
"""

import os
import logging
import time
from typing import Dict, Any, Optional
from contextlib import contextmanager

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[OTEL][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

class OpenTelemetryProfiler:
    """Gerenciador de profiling com OpenTelemetry."""
    
    def __init__(self, service_name: str = "omni-writer-load-tests"):
        self.service_name = service_name
        self.tracer_provider = None
        self.tracer = None
        self.jaeger_exporter = None
        self._setup_tracing()
    
    def _setup_tracing(self):
        """Configura o sistema de tracing."""
        try:
            logger.info("Configurando OpenTelemetry tracing...")
            
            # Configurar resource com metadados do serviço
            resource = Resource.create({
                "service.name": self.service_name,
                "service.version": "1.0.0",
                "environment": "load-testing"
            })
            
            # Criar tracer provider
            self.tracer_provider = TracerProvider(resource=resource)
            
            # Configurar Jaeger exporter
            self.jaeger_exporter = JaegerExporter(
                agent_host_name=os.getenv("JAEGER_HOST", "localhost"),
                agent_port=int(os.getenv("JAEGER_PORT", "6831"))
            )
            
            # Adicionar span processor
            span_processor = BatchSpanProcessor(self.jaeger_exporter)
            self.tracer_provider.add_span_processor(span_processor)
            
            # Configurar tracer global
            trace.set_tracer_provider(self.tracer_provider)
            self.tracer = trace.get_tracer(__name__)
            
            # Instrumentar bibliotecas
            self._instrument_libraries()
            
            logger.info("OpenTelemetry tracing configurado com sucesso!")
            
        except Exception as e:
            logger.error(f"Erro na configuração do tracing: {e}")
            raise
    
    def _instrument_libraries(self):
        """Instrumenta bibliotecas para tracing automático."""
        try:
            # Instrumentar requests para chamadas HTTP
            RequestsInstrumentor().instrument()
            logger.info("Requests instrumentado")
            
            # Instrumentar Flask se disponível
            try:
                FlaskInstrumentor().instrument()
                logger.info("Flask instrumentado")
            except ImportError:
                logger.info("Flask não disponível, pulando instrumentação")
            
            # Instrumentar SQLite se disponível
            try:
                SQLite3Instrumentor().instrument()
                logger.info("SQLite3 instrumentado")
            except ImportError:
                logger.info("SQLite3 não disponível, pulando instrumentação")
                
        except Exception as e:
            logger.warning(f"Erro na instrumentação de bibliotecas: {e}")
    
    @contextmanager
    def trace_span(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Context manager para criar spans de tracing.
        
        Args:
            name: Nome do span
            attributes: Atributos adicionais do span
        """
        if not self.tracer:
            yield
            return
        
        attributes = attributes or {}
        with self.tracer.start_as_current_span(name, attributes=attributes) as span:
            try:
                yield span
            except Exception as e:
                span.record_exception(e)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
    
    def trace_function(self, name: str = None, attributes: Optional[Dict[str, Any]] = None):
        """
        Decorator para traçar funções.
        
        Args:
            name: Nome do span (opcional, usa nome da função se não fornecido)
            attributes: Atributos adicionais do span
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                span_name = name or f"{func.__module__}.{func.__name__}"
                
                with self.trace_span(span_name, attributes) as span:
                    # Adicionar argumentos como atributos
                    span.set_attribute("function.args", str(args))
                    span.set_attribute("function.kwargs", str(kwargs))
                    
                    start_time = time.time()
                    try:
                        result = func(*args, **kwargs)
                        span.set_attribute("function.success", True)
                        span.set_attribute("function.duration", time.time() - start_time)
                        return result
                    except Exception as e:
                        span.set_attribute("function.success", False)
                        span.set_attribute("function.error", str(e))
                        span.set_attribute("function.duration", time.time() - start_time)
                        raise
            
            return wrapper
        return decorator
    
    def trace_load_test(self, test_name: str, user_count: int, duration: int):
        """
        Cria span principal para teste de carga.
        
        Args:
            test_name: Nome do teste
            user_count: Número de usuários
            duration: Duração do teste em segundos
        """
        attributes = {
            "test.type": "load_test",
            "test.name": test_name,
            "test.user_count": user_count,
            "test.duration": duration,
            "test.timestamp": time.time()
        }
        
        return self.trace_span(f"load_test.{test_name}", attributes)
    
    def trace_api_call(self, endpoint: str, method: str, status_code: int, duration: float):
        """
        Traça chamada de API.
        
        Args:
            endpoint: Endpoint chamado
            method: Método HTTP
            status_code: Código de status da resposta
            duration: Duração da chamada
        """
        attributes = {
            "api.endpoint": endpoint,
            "api.method": method,
            "api.status_code": status_code,
            "api.duration": duration,
            "api.timestamp": time.time()
        }
        
        with self.trace_span(f"api.{method}.{endpoint}", attributes) as span:
            if status_code >= 400:
                span.set_status(trace.Status(trace.StatusCode.ERROR, f"HTTP {status_code}"))
            else:
                span.set_status(trace.Status(trace.StatusCode.OK))
    
    def trace_database_query(self, query: str, duration: float, success: bool):
        """
        Traça query de banco de dados.
        
        Args:
            query: Query executada
            duration: Duração da execução
            success: Se a query foi bem-sucedida
        """
        attributes = {
            "db.query": query[:100] + "..." if len(query) > 100 else query,
            "db.duration": duration,
            "db.success": success,
            "db.timestamp": time.time()
        }
        
        with self.trace_span("database.query", attributes) as span:
            if not success:
                span.set_status(trace.Status(trace.StatusCode.ERROR, "Query failed"))
            else:
                span.set_status(trace.Status(trace.StatusCode.OK))
    
    def trace_external_service(self, service: str, operation: str, duration: float, success: bool):
        """
        Traça chamada para serviço externo.
        
        Args:
            service: Nome do serviço externo
            operation: Operação realizada
            duration: Duração da chamada
            success: Se a chamada foi bem-sucedida
        """
        attributes = {
            "external.service": service,
            "external.operation": operation,
            "external.duration": duration,
            "external.success": success,
            "external.timestamp": time.time()
        }
        
        with self.trace_span(f"external.{service}.{operation}", attributes) as span:
            if not success:
                span.set_status(trace.Status(trace.StatusCode.ERROR, "External call failed"))
            else:
                span.set_status(trace.Status(trace.StatusCode.OK))
    
    def get_slow_spans(self, threshold_ms: int = 1000) -> list:
        """
        Identifica spans lentos.
        
        Args:
            threshold_ms: Threshold em milissegundos
            
        Returns:
            list: Lista de spans lentos
        """
        # Esta é uma implementação simplificada
        # Em produção, você consultaria o Jaeger API
        logger.info(f"Identificando spans com duração > {threshold_ms}ms")
        return []
    
    def get_error_spans(self) -> list:
        """
        Identifica spans com erro.
        
        Returns:
            list: Lista de spans com erro
        """
        logger.info("Identificando spans com erro")
        return []
    
    def shutdown(self):
        """Desliga o sistema de tracing."""
        try:
            if self.tracer_provider:
                self.tracer_provider.shutdown()
            logger.info("OpenTelemetry tracing desligado")
        except Exception as e:
            logger.error(f"Erro ao desligar tracing: {e}")

# Instância global para uso em load tests
profiler = OpenTelemetryProfiler()

def setup_profiling():
    """Configura profiling para load tests."""
    return profiler

def trace_load_test_execution(test_name: str, user_count: int, duration: int):
    """
    Decorator para traçar execução completa de load test.
    
    Args:
        test_name: Nome do teste
        user_count: Número de usuários
        duration: Duração do teste
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            with profiler.trace_load_test(test_name, user_count, duration):
                return func(*args, **kwargs)
        return wrapper
    return decorator

if __name__ == "__main__":
    # Exemplo de uso
    profiler = setup_profiling()
    
    # Exemplo de tracing de função
    @profiler.trace_function(attributes={"component": "load_test"})
    def example_function():
        time.sleep(0.1)
        return "success"
    
    # Exemplo de tracing de API
    profiler.trace_api_call("/generate", "POST", 200, 0.5)
    
    # Exemplo de tracing de banco
    profiler.trace_database_query("SELECT * FROM articles", 0.1, True)
    
    # Exemplo de tracing de serviço externo
    profiler.trace_external_service("openai", "completion", 2.5, True)
    
    print("Exemplos de tracing executados!") 