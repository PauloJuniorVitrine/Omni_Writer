"""
Coletor de métricas de performance para Omni Writer.

Prompt: Monitoramento de Performance - IMP-008
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:45:00Z
Tracing ID: ENTERPRISE_20250127_008
"""

import time
import psutil
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import logging

from prometheus_client import Counter, Histogram, Gauge, Summary, generate_latest, CONTENT_TYPE_LATEST
from flask import Flask, Response

from shared.logging_config import get_structured_logger


@dataclass
class PerformanceMetric:
    """Estrutura para métricas de performance."""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str]
    metric_type: str = "gauge"


@dataclass
class SystemMetrics:
    """Métricas do sistema."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: Dict[str, float]
    timestamp: datetime


class MetricsCollector:
    """Coletor principal de métricas de performance."""
    
    def __init__(self):
        """Inicializa o coletor de métricas."""
        self.logger = get_structured_logger(__name__)
        self.metrics_lock = threading.Lock()
        self.metrics_history = deque(maxlen=1000)  # Últimas 1000 métricas
        
        # Métricas Prometheus
        self.request_counter = Counter(
            'omni_writer_requests_total',
            'Total de requisições',
            ['endpoint', 'method', 'status']
        )
        
        self.request_duration = Histogram(
            'omni_writer_request_duration_seconds',
            'Duração das requisições',
            ['endpoint', 'method']
        )
        
        self.generation_counter = Counter(
            'omni_writer_generations_total',
            'Total de gerações de artigos',
            ['model_type', 'status']
        )
        
        self.generation_duration = Histogram(
            'omni_writer_generation_duration_seconds',
            'Duração das gerações',
            ['model_type']
        )
        
        self.cache_hits = Counter(
            'omni_writer_cache_hits_total',
            'Total de hits no cache',
            ['cache_type']
        )
        
        self.cache_misses = Counter(
            'omni_writer_cache_misses_total',
            'Total de misses no cache',
            ['cache_type']
        )
        
        self.error_counter = Counter(
            'omni_writer_errors_total',
            'Total de erros',
            ['error_type', 'endpoint']
        )
        
        self.active_workers = Gauge(
            'omni_writer_active_workers',
            'Número de workers ativos'
        )
        
        self.queue_size = Gauge(
            'omni_writer_queue_size',
            'Tamanho das filas',
            ['queue_name']
        )
        
        self.system_metrics = Gauge(
            'omni_writer_system_metrics',
            'Métricas do sistema',
            ['metric_name']
        )
        
        # Inicia thread de coleta de métricas do sistema
        self.collection_thread = threading.Thread(target=self._collect_system_metrics, daemon=True)
        self.collection_thread.start()
        
        self.logger.info("Coletor de métricas inicializado", extra={
            'tracing_id': 'ENTERPRISE_20250127_008',
            'component': 'metrics_collector'
        })
    
    def record_request(self, endpoint: str, method: str, status: int, duration: float):
        """Registra métrica de requisição."""
        try:
            self.request_counter.labels(endpoint=endpoint, method=method, status=status).inc()
            self.request_duration.labels(endpoint=endpoint, method=method).observe(duration)
            
            metric = PerformanceMetric(
                name=f"request_{endpoint}_{method}",
                value=duration,
                timestamp=datetime.now(),
                labels={'endpoint': endpoint, 'method': method, 'status': str(status)},
                metric_type="histogram"
            )
            
            with self.metrics_lock:
                self.metrics_history.append(metric)
                
        except Exception as e:
            self.logger.error(f"Erro ao registrar métrica de requisição: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'endpoint': endpoint,
                'method': method,
                'status': status
            })
    
    def record_generation(self, model_type: str, status: str, duration: float):
        """Registra métrica de geração."""
        try:
            self.generation_counter.labels(model_type=model_type, status=status).inc()
            self.generation_duration.labels(model_type=model_type).observe(duration)
            
            metric = PerformanceMetric(
                name=f"generation_{model_type}",
                value=duration,
                timestamp=datetime.now(),
                labels={'model_type': model_type, 'status': status},
                metric_type="histogram"
            )
            
            with self.metrics_lock:
                self.metrics_history.append(metric)
                
        except Exception as e:
            self.logger.error(f"Erro ao registrar métrica de geração: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'model_type': model_type,
                'status': status
            })
    
    def record_cache_operation(self, cache_type: str, hit: bool):
        """Registra operação de cache."""
        try:
            if hit:
                self.cache_hits.labels(cache_type=cache_type).inc()
            else:
                self.cache_misses.labels(cache_type=cache_type).inc()
                
        except Exception as e:
            self.logger.error(f"Erro ao registrar operação de cache: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'cache_type': cache_type,
                'hit': hit
            })
    
    def record_error(self, error_type: str, endpoint: str):
        """Registra erro."""
        try:
            self.error_counter.labels(error_type=error_type, endpoint=endpoint).inc()
            
        except Exception as e:
            self.logger.error(f"Erro ao registrar erro: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'error_type': error_type,
                'endpoint': endpoint
            })
    
    def update_worker_count(self, count: int):
        """Atualiza contador de workers ativos."""
        try:
            self.active_workers.set(count)
            
        except Exception as e:
            self.logger.error(f"Erro ao atualizar contador de workers: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'worker_count': count
            })
    
    def update_queue_size(self, queue_name: str, size: int):
        """Atualiza tamanho da fila."""
        try:
            self.queue_size.labels(queue_name=queue_name).set(size)
            
        except Exception as e:
            self.logger.error(f"Erro ao atualizar tamanho da fila: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'queue_name': queue_name,
                'size': size
            })
    
    def _collect_system_metrics(self):
        """Coleta métricas do sistema em background."""
        while True:
            try:
                # CPU
                cpu_percent = psutil.cpu_percent(interval=1)
                self.system_metrics.labels(metric_name="cpu_usage_percent").set(cpu_percent)
                
                # Memória
                memory = psutil.virtual_memory()
                self.system_metrics.labels(metric_name="memory_usage_percent").set(memory.percent)
                self.system_metrics.labels(metric_name="memory_available_mb").set(memory.available / 1024 / 1024)
                
                # Disco
                disk = psutil.disk_usage('/')
                self.system_metrics.labels(metric_name="disk_usage_percent").set(disk.percent)
                self.system_metrics.labels(metric_name="disk_free_gb").set(disk.free / 1024 / 1024 / 1024)
                
                # Rede
                network = psutil.net_io_counters()
                self.system_metrics.labels(metric_name="network_bytes_sent").set(network.bytes_sent)
                self.system_metrics.labels(metric_name="network_bytes_recv").set(network.bytes_recv)
                
                # Processos
                process = psutil.Process()
                self.system_metrics.labels(metric_name="process_cpu_percent").set(process.cpu_percent())
                self.system_metrics.labels(metric_name="process_memory_mb").set(process.memory_info().rss / 1024 / 1024)
                
                # Health score baseado em métricas
                health_score = self._calculate_health_score(cpu_percent, memory.percent, disk.percent)
                self.system_metrics.labels(metric_name="health_score").set(health_score)
                
                # Aguarda próxima coleta
                time.sleep(15)  # Coleta a cada 15 segundos
                
            except Exception as e:
                self.logger.error(f"Erro na coleta de métricas do sistema: {e}", extra={
                    'tracing_id': 'ENTERPRISE_20250127_008',
                    'component': 'system_metrics'
                })
                time.sleep(30)  # Aguarda mais tempo em caso de erro
    
    def _calculate_health_score(self, cpu_percent: float, memory_percent: float, disk_percent: float) -> float:
        """Calcula score de saúde do sistema."""
        try:
            # CPU: 0-100%, peso 40%
            cpu_score = max(0, 100 - cpu_percent)
            
            # Memória: 0-100%, peso 35%
            memory_score = max(0, 100 - memory_percent)
            
            # Disco: 0-100%, peso 25%
            disk_score = max(0, 100 - disk_percent)
            
            # Score ponderado
            health_score = (cpu_score * 0.4) + (memory_score * 0.35) + (disk_score * 0.25)
            
            return round(health_score, 2)
            
        except Exception as e:
            self.logger.error(f"Erro ao calcular health score: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'health_score'
            })
            return 0.0
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Retorna resumo das métricas."""
        try:
            with self.metrics_lock:
                recent_metrics = list(self.metrics_history)[-100:]  # Últimas 100 métricas
            
            summary = {
                'total_metrics': len(self.metrics_history),
                'recent_metrics': len(recent_metrics),
                'collection_time': datetime.now().isoformat(),
                'system_health': {
                    'cpu_usage': psutil.cpu_percent(),
                    'memory_usage': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent,
                    'health_score': self._calculate_health_score(
                        psutil.cpu_percent(),
                        psutil.virtual_memory().percent,
                        psutil.disk_usage('/').percent
                    )
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar resumo de métricas: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'metrics_summary'
            })
            return {}
    
    def export_metrics(self) -> str:
        """Exporta métricas no formato Prometheus."""
        try:
            return generate_latest()
        except Exception as e:
            self.logger.error(f"Erro ao exportar métricas: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'metrics_export'
            })
            return ""


# Instância global do coletor
metrics_collector = MetricsCollector()


def create_metrics_app() -> Flask:
    """Cria aplicação Flask para exposição de métricas."""
    app = Flask(__name__)
    
    @app.route('/metrics')
    def metrics():
        """Endpoint para métricas Prometheus."""
        try:
            metrics_data = metrics_collector.export_metrics()
            return Response(metrics_data, mimetype=CONTENT_TYPE_LATEST)
        except Exception as e:
            app.logger.error(f"Erro ao gerar métricas: {e}")
            return Response("Error generating metrics", status=500)
    
    @app.route('/health')
    def health():
        """Endpoint de saúde."""
        try:
            summary = metrics_collector.get_metrics_summary()
            return Response(json.dumps(summary, indent=2), mimetype='application/json')
        except Exception as e:
            app.logger.error(f"Erro ao gerar health check: {e}")
            return Response("Error generating health check", status=500)
    
    return app 