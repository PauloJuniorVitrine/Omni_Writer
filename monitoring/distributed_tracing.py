"""
Distributed Tracing Module - IMP-101
Prompt: Observabilidade Total - Fase 1
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:15:00Z
Tracing ID: ENTERPRISE_20250127_101

Implementação de Distributed Tracing para rastreamento completo
de requisições através de microserviços.
"""

import uuid
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import contextmanager
import json
import threading

logger = logging.getLogger("monitoring.tracing")

@dataclass
class TraceSpan:
    """Representa um span no trace distribuído"""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str] = None
    operation_name: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[Exception] = None

class DistributedTracer:
    """
    Sistema de Distributed Tracing para rastreamento completo.
    
    Funcionalidades:
    - Geração de trace IDs únicos
    - Criação e gerenciamento de spans
    - Propagação de contexto entre serviços
    - Integração com APM providers
    """
    
    def __init__(self):
        self.active_spans = {}
        self.trace_storage = []
        self._lock = threading.RLock()
        
        logger.info("Distributed Tracer inicializado")
    
    def generate_trace_id(self) -> str:
        """Gera ID único para o trace"""
        return str(uuid.uuid4())
    
    def generate_span_id(self) -> str:
        """Gera ID único para o span"""
        return str(uuid.uuid4())
    
    def start_span(self, operation_name: str, trace_id: Optional[str] = None, 
                   parent_span_id: Optional[str] = None, tags: Optional[Dict] = None) -> TraceSpan:
        """Inicia um novo span"""
        span_id = self.generate_span_id()
        if not trace_id:
            trace_id = self.generate_trace_id()
        
        span = TraceSpan(
            span_id=span_id,
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            tags=tags or {}
        )
        
        with self._lock:
            self.active_spans[span_id] = span
        
        logger.debug(f"Span iniciado: {operation_name} (ID: {span_id})")
        return span
    
    def end_span(self, span: TraceSpan, error: Optional[Exception] = None):
        """Finaliza um span"""
        span.end_time = datetime.utcnow()
        span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
        span.error = error
        
        with self._lock:
            if span.span_id in self.active_spans:
                del self.active_spans[span.span_id]
            
            self.trace_storage.append(span)
        
        logger.debug(f"Span finalizado: {span.operation_name} ({span.duration_ms:.2f}ms)")
    
    def add_tag(self, span: TraceSpan, key: str, value: Any):
        """Adiciona tag ao span"""
        span.tags[key] = value
    
    def add_log(self, span: TraceSpan, message: str, level: str = "info", 
                data: Optional[Dict] = None):
        """Adiciona log ao span"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        span.logs.append(log_entry)
    
    def get_trace(self, trace_id: str) -> List[TraceSpan]:
        """Recupera todos os spans de um trace"""
        with self._lock:
            return [span for span in self.trace_storage if span.trace_id == trace_id]
    
    def get_active_spans(self) -> Dict[str, TraceSpan]:
        """Retorna spans ativos"""
        with self._lock:
            return self.active_spans.copy()
    
    def inject_headers(self, span: TraceSpan) -> Dict[str, str]:
        """Injeta headers para propagação de contexto"""
        return {
            "X-Trace-ID": span.trace_id,
            "X-Span-ID": span.span_id,
            "X-Parent-Span-ID": span.parent_span_id or ""
        }
    
    def extract_headers(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extrai contexto de headers"""
        trace_context = {}
        
        if "X-Trace-ID" in headers:
            trace_context["trace_id"] = headers["X-Trace-ID"]
        if "X-Span-ID" in headers:
            trace_context["parent_span_id"] = headers["X-Span-ID"]
        
        return trace_context if trace_context else None

# Instância global do tracer
tracer_instance: Optional[DistributedTracer] = None

def initialize_tracer() -> DistributedTracer:
    """Inicializa o tracer globalmente"""
    global tracer_instance
    tracer_instance = DistributedTracer()
    return tracer_instance

def get_tracer() -> DistributedTracer:
    """Retorna instância do tracer"""
    if tracer_instance is None:
        raise RuntimeError("Tracer não foi inicializado. Chame initialize_tracer() primeiro.")
    return tracer_instance

@contextmanager
def trace_span(operation_name: str, trace_id: Optional[str] = None, 
               parent_span_id: Optional[str] = None, tags: Optional[Dict] = None):
    """Context manager para criação automática de spans"""
    tracer = get_tracer()
    span = tracer.start_span(operation_name, trace_id, parent_span_id, tags)
    
    try:
        yield span
    except Exception as e:
        tracer.end_span(span, error=e)
        raise
    else:
        tracer.end_span(span)

def trace_operation(operation_name: str):
    """Decorator para tracing automático de operações"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            
            with trace_span(operation_name) as span:
                try:
                    result = func(*args, **kwargs)
                    tracer.add_tag(span, "success", True)
                    return result
                except Exception as e:
                    tracer.add_tag(span, "success", False)
                    tracer.add_tag(span, "error", str(e))
                    raise
        
        return wrapper
    return decorator 