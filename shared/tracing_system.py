"""
Tracing System - Omni Writer
============================

Sistema de tracing distribuído básico com OpenTelemetry para
rastrear fluxo: request → geração → storage.

Prompt: Implementação de tracing distribuído básico
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:00:00Z
"""

import os
import uuid
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List
from contextlib import contextmanager
import json
import threading
from functools import wraps

# Configuração de logging estruturado
tracing_logger = logging.getLogger("tracing_system")
tracing_logger.setLevel(logging.INFO)
if not tracing_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/tracing_system.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [tracing_system] %(message)s'
    )
    handler.setFormatter(formatter)
    tracing_logger.addHandler(handler)

class TraceContext:
    """
    Contexto de tracing para rastrear operações distribuídas.
    """
    
    def __init__(self, trace_id: str = None, span_id: str = None, parent_span_id: str = None):
        self.trace_id = trace_id or str(uuid.uuid4())
        self.span_id = span_id or str(uuid.uuid4())
        self.parent_span_id = parent_span_id
        self.start_time = time.time()
        self.end_time = None
        self.attributes = {}
        self.events = []
        self.status = "started"
        self.error = None
    
    def add_attribute(self, key: str, value: Any):
        """Adiciona atributo ao span."""
        self.attributes[key] = value
    
    def add_event(self, name: str, attributes: Dict[str, Any] = None):
        """Adiciona evento ao span."""
        event = {
            'name': name,
            'timestamp': datetime.utcnow().isoformat(),
            'attributes': attributes or {}
        }
        self.events.append(event)
    
    def set_status(self, status: str, error: str = None):
        """Define status do span."""
        self.status = status
        if error:
            self.error = error
    
    def end(self):
        """Finaliza o span."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte span para dicionário."""
        return {
            'trace_id': self.trace_id,
            'span_id': self.span_id,
            'parent_span_id': self.parent_span_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': getattr(self, 'duration', None),
            'attributes': self.attributes,
            'events': self.events,
            'status': self.status,
            'error': self.error
        }

class TracingSystem:
    """
    Sistema de tracing distribuído básico.
    
    Funcionalidades:
    - Geração automática de trace_id e span_id
    - Rastreamento de fluxo: request → geração → storage
    - Correlação com logs estruturados
    - Exportação de traces para análise
    """
    
    def __init__(self):
        self.active_spans = {}
        self.completed_spans = []
        self.max_spans = 10000  # Limite de spans em memória
        self.trace_lock = threading.Lock()
        
        # Configurações
        self.enabled = os.getenv('TRACING_ENABLED', 'true').lower() == 'true'
        self.sample_rate = float(os.getenv('TRACING_SAMPLE_RATE', '1.0'))  # 100% por padrão
        self.max_duration = float(os.getenv('TRACING_MAX_DURATION', '300.0'))  # 5 min
        
        if self.enabled:
            tracing_logger.info("Sistema de tracing inicializado")
    
    def start_span(self, name: str, trace_id: str = None, parent_span_id: str = None, attributes: Dict[str, Any] = None) -> TraceContext:
        """
        Inicia um novo span.
        
        Args:
            name: Nome do span
            trace_id: ID do trace (opcional)
            parent_span_id: ID do span pai (opcional)
            attributes: Atributos do span (opcional)
            
        Returns:
            TraceContext: Contexto do span
        """
        if not self.enabled:
            return TraceContext()
        
        try:
            span = TraceContext(trace_id, parent_span_id=parent_span_id)
            
            # Adiciona atributos padrão
            span.add_attribute('span.name', name)
            span.add_attribute('span.start_time', datetime.utcnow().isoformat())
            
            if attributes:
                for key, value in attributes.items():
                    span.add_attribute(key, value)
            
            # Armazena span ativo
            with self.trace_lock:
                self.active_spans[span.span_id] = span
            
            tracing_logger.info(f"Span iniciado: {name} (trace_id: {span.trace_id}, span_id: {span.span_id})")
            
            return span
            
        except Exception as e:
            tracing_logger.error(f"Erro ao iniciar span: {e}")
            return TraceContext()
    
    def end_span(self, span: TraceContext, status: str = "completed", error: str = None):
        """
        Finaliza um span.
        
        Args:
            span: Contexto do span
            status: Status final
            error: Mensagem de erro (opcional)
        """
        if not self.enabled or not span:
            return
        
        try:
            span.set_status(status, error)
            span.end()
            
            # Move para spans completados
            with self.trace_lock:
                if span.span_id in self.active_spans:
                    del self.active_spans[span.span_id]
                
                self.completed_spans.append(span)
                
                # Limita número de spans em memória
                if len(self.completed_spans) > self.max_spans:
                    self.completed_spans.pop(0)
            
            tracing_logger.info(f"Span finalizado: {span.attributes.get('span.name', 'unknown')} (duration: {span.duration:.3f}s, status: {status})")
            
        except Exception as e:
            tracing_logger.error(f"Erro ao finalizar span: {e}")
    
    @contextmanager
    def span(self, name: str, trace_id: str = None, parent_span_id: str = None, attributes: Dict[str, Any] = None):
        """
        Context manager para spans.
        
        Args:
            name: Nome do span
            trace_id: ID do trace (opcional)
            parent_span_id: ID do span pai (opcional)
            attributes: Atributos do span (opcional)
            
        Yields:
            TraceContext: Contexto do span
        """
        span = self.start_span(name, trace_id, parent_span_id, attributes)
        try:
            yield span
            self.end_span(span, "completed")
        except Exception as e:
            self.end_span(span, "error", str(e))
            raise
    
    def add_event(self, span: TraceContext, name: str, attributes: Dict[str, Any] = None):
        """
        Adiciona evento a um span.
        
        Args:
            span: Contexto do span
            name: Nome do evento
            attributes: Atributos do evento (opcional)
        """
        if not self.enabled or not span:
            return
        
        try:
            span.add_event(name, attributes)
            tracing_logger.debug(f"Evento adicionado: {name} (span_id: {span.span_id})")
        except Exception as e:
            tracing_logger.error(f"Erro ao adicionar evento: {e}")
    
    def get_trace(self, trace_id: str) -> List[TraceContext]:
        """
        Obtém todos os spans de um trace.
        
        Args:
            trace_id: ID do trace
            
        Returns:
            List[TraceContext]: Lista de spans do trace
        """
        if not self.enabled:
            return []
        
        try:
            with self.trace_lock:
                spans = [span for span in self.completed_spans if span.trace_id == trace_id]
                spans.extend([span for span in self.active_spans.values() if span.trace_id == trace_id])
                
                # Ordena por tempo de início
                spans.sort(key=lambda x: x.start_time)
                
                return spans
        except Exception as e:
            tracing_logger.error(f"Erro ao obter trace: {e}")
            return []
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """
        Obtém resumo de um trace.
        
        Args:
            trace_id: ID do trace
            
        Returns:
            Dict[str, Any]: Resumo do trace
        """
        if not self.enabled:
            return {}
        
        try:
            spans = self.get_trace(trace_id)
            
            if not spans:
                return {}
            
            total_duration = sum(span.duration for span in spans if hasattr(span, 'duration'))
            error_spans = [span for span in spans if span.status == "error"]
            
            summary = {
                'trace_id': trace_id,
                'span_count': len(spans),
                'total_duration': total_duration,
                'error_count': len(error_spans),
                'start_time': min(span.start_time for span in spans),
                'end_time': max(span.end_time for span in spans if span.end_time),
                'spans': [span.to_dict() for span in spans]
            }
            
            return summary
            
        except Exception as e:
            tracing_logger.error(f"Erro ao obter resumo do trace: {e}")
            return {}
    
    def export_traces(self, output_file: str = None) -> str:
        """
        Exporta traces para arquivo JSON.
        
        Args:
            output_file: Arquivo de saída (opcional)
            
        Returns:
            str: Caminho do arquivo exportado
        """
        if not self.enabled:
            return ""
        
        try:
            if not output_file:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_file = f"logs/exec_trace/traces_{timestamp}.json"
            
            # Agrupa spans por trace_id
            traces = {}
            with self.trace_lock:
                all_spans = list(self.completed_spans) + list(self.active_spans.values())
            
            for span in all_spans:
                if span.trace_id not in traces:
                    traces[span.trace_id] = []
                traces[span.trace_id].append(span.to_dict())
            
            # Exporta para JSON
            export_data = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'total_traces': len(traces),
                'total_spans': sum(len(spans) for spans in traces.values()),
                'traces': traces
            }
            
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            tracing_logger.info(f"Traces exportados: {output_file}")
            return output_file
            
        except Exception as e:
            tracing_logger.error(f"Erro ao exportar traces: {e}")
            return ""
    
    def correlate_with_logs(self, trace_id: str) -> List[Dict[str, Any]]:
        """
        Correlaciona trace com logs estruturados.
        
        Args:
            trace_id: ID do trace
            
        Returns:
            List[Dict[str, Any]]: Logs correlacionados
        """
        if not self.enabled:
            return []
        
        try:
            correlated_logs = []
            
            # Lê logs estruturados
            log_file = "logs/exec_trace/requests.log"
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log_data = json.loads(line.strip())
                            if log_data.get('trace_id') == trace_id:
                                correlated_logs.append(log_data)
                        except json.JSONDecodeError:
                            continue
            
            return correlated_logs
            
        except Exception as e:
            tracing_logger.error(f"Erro ao correlacionar logs: {e}")
            return []

# Instância global do sistema de tracing
tracing_system = TracingSystem()

def trace_function(name: str = None, attributes: Dict[str, Any] = None):
    """
    Decorator para tracing de funções.
    
    Args:
        name: Nome do span (opcional, usa nome da função se não fornecido)
        attributes: Atributos do span (opcional)
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            span_name = name or f"{func.__module__}.{func.__name__}"
            
            # Extrai trace_id dos argumentos se disponível
            trace_id = None
            if 'trace_id' in kwargs:
                trace_id = kwargs['trace_id']
            elif args and hasattr(args[0], 'trace_id'):
                trace_id = args[0].trace_id
            
            with tracing_system.span(span_name, trace_id, attributes=attributes) as span:
                # Adiciona argumentos como atributos (sem dados sensíveis)
                safe_kwargs = {k: str(v)[:100] for k, v in kwargs.items() 
                             if k not in ['api_key', 'password', 'token']}
                span.add_attribute('function.args_count', len(args))
                span.add_attribute('function.kwargs', str(safe_kwargs))
                
                try:
                    result = func(*args, **kwargs)
                    span.add_attribute('function.result_type', type(result).__name__)
                    return result
                except Exception as e:
                    span.add_attribute('function.error', str(e))
                    raise
        
        return wrapper
    return decorator

def start_span(name: str, trace_id: str = None, parent_span_id: str = None, attributes: Dict[str, Any] = None) -> TraceContext:
    """Função de conveniência para iniciar span."""
    return tracing_system.start_span(name, trace_id, parent_span_id, attributes)

def end_span(span: TraceContext, status: str = "completed", error: str = None):
    """Função de conveniência para finalizar span."""
    tracing_system.end_span(span, status, error)

def add_event(span: TraceContext, name: str, attributes: Dict[str, Any] = None):
    """Função de conveniência para adicionar evento."""
    tracing_system.add_event(span, name, attributes)

def get_trace_summary(trace_id: str) -> Dict[str, Any]:
    """Função de conveniência para obter resumo do trace."""
    return tracing_system.get_trace_summary(trace_id)

def correlate_with_logs(trace_id: str) -> List[Dict[str, Any]]:
    """Função de conveniência para correlacionar com logs."""
    return tracing_system.correlate_with_logs(trace_id) 