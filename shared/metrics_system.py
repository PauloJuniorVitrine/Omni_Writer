"""
Metrics System - Omni Writer
============================

Sistema de métricas avançado com Prometheus ativo por padrão,
métricas customizadas, alertas e dashboards.

Prompt: Implementação de Prometheus/Grafana ativo por padrão
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T10:50:00Z
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from prometheus_client import (
    Counter, Histogram, Gauge, Summary, 
    generate_latest, CONTENT_TYPE_LATEST,
    CollectorRegistry, multiprocess
)
from prometheus_client.exposition import start_http_server
import threading
import json

# Configuração de logging estruturado
metrics_logger = logging.getLogger("metrics_system")
metrics_logger.setLevel(logging.INFO)
if not metrics_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/metrics_system.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [metrics_system] %(message)s'
    )
    handler.setFormatter(formatter)
    metrics_logger.addHandler(handler)

class MetricsSystem:
    """
    Sistema de métricas avançado com Prometheus ativo por padrão.
    
    Funcionalidades:
    - Métricas de geração (sucesso/falha)
    - Dashboard de latência e throughput
    - Alertas para erro >2% ou latência >5s
    - Métricas de uso de tokens e rate limiting
    - Métricas customizadas de negócio
    """
    
    def __init__(self):
        # Configuração do registry
        self.registry = CollectorRegistry()
        
        # Métricas de geração
        self.articles_generated = Counter(
            'omniwriter_articles_generated_total',
            'Total de artigos gerados',
            ['model', 'status', 'user_id'],
            registry=self.registry
        )
        
        self.generation_duration = Histogram(
            'omniwriter_generation_duration_seconds',
            'Duração da geração de artigos',
            ['model', 'status'],
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
            registry=self.registry
        )
        
        # Métricas de throughput
        self.requests_total = Counter(
            'omniwriter_requests_total',
            'Total de requisições HTTP',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'omniwriter_request_duration_seconds',
            'Duração das requisições HTTP',
            ['method', 'endpoint'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0],
            registry=self.registry
        )
        
        # Métricas de tokens e rate limiting
        self.token_usage = Counter(
            'omniwriter_token_usage_total',
            'Uso de tokens de API',
            ['model', 'user_id', 'status'],
            registry=self.registry
        )
        
        self.rate_limit_hits = Counter(
            'omniwriter_rate_limit_hits_total',
            'Hits de rate limiting',
            ['endpoint', 'ip_address'],
            registry=self.registry
        )
        
        # Métricas de sistema
        self.active_generations = Gauge(
            'omniwriter_active_generations',
            'Gerações ativas no momento',
            ['model'],
            registry=self.registry
        )
        
        self.queue_size = Gauge(
            'omniwriter_queue_size',
            'Tamanho da fila de geração',
            registry=self.registry
        )
        
        # Métricas de erro
        self.errors_total = Counter(
            'omniwriter_errors_total',
            'Total de erros',
            ['type', 'endpoint', 'user_id'],
            registry=self.registry
        )
        
        # Métricas de upload
        self.uploads_total = Counter(
            'omniwriter_uploads_total',
            'Total de uploads de arquivos',
            ['file_type', 'status', 'user_id'],
            registry=self.registry
        )
        
        self.upload_size = Histogram(
            'omniwriter_upload_size_bytes',
            'Tamanho dos uploads',
            ['file_type'],
            buckets=[1024, 10240, 102400, 1048576, 10485760],
            registry=self.registry
        )
        
        # Métricas de storage
        self.storage_operations = Counter(
            'omniwriter_storage_operations_total',
            'Operações de storage',
            ['operation', 'status'],
            registry=self.registry
        )
        
        self.storage_size = Gauge(
            'omniwriter_storage_size_bytes',
            'Tamanho do storage em bytes',
            registry=self.registry
        )
        
        # Alertas
        self.error_rate = Gauge(
            'omniwriter_error_rate',
            'Taxa de erro (0-1)',
            registry=self.registry
        )
        
        self.avg_latency = Gauge(
            'omniwriter_avg_latency_seconds',
            'Latência média em segundos',
            registry=self.registry
        )
        
        # Configurações
        self.metrics_port = int(os.getenv('METRICS_PORT', '9090'))
        self.metrics_enabled = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'
        self.alert_threshold_error = float(os.getenv('ALERT_THRESHOLD_ERROR', '0.02'))  # 2%
        self.alert_threshold_latency = float(os.getenv('ALERT_THRESHOLD_LATENCY', '5.0'))  # 5s
        
        # Histórico para cálculos
        self.request_history = []
        self.error_history = []
        self.max_history_size = 1000
        
        # Thread de monitoramento
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Inicialização
        if self.metrics_enabled:
            self._start_metrics_server()
            self._start_monitoring()
    
    def _start_metrics_server(self):
        """Inicia servidor de métricas Prometheus."""
        try:
            start_http_server(self.metrics_port, registry=self.registry)
            metrics_logger.info(f"Servidor de métricas iniciado na porta {self.metrics_port}")
        except Exception as e:
            metrics_logger.error(f"Erro ao iniciar servidor de métricas: {e}")
    
    def _start_monitoring(self):
        """Inicia thread de monitoramento de alertas."""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            metrics_logger.info("Thread de monitoramento iniciada")
    
    def _monitoring_loop(self):
        """Loop de monitoramento para alertas."""
        while self.monitoring_active:
            try:
                self._calculate_metrics()
                self._check_alerts()
                time.sleep(30)  # Verifica a cada 30 segundos
            except Exception as e:
                metrics_logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(60)  # Espera mais tempo em caso de erro
    
    def _calculate_metrics(self):
        """Calcula métricas derivadas."""
        try:
            # Calcula taxa de erro
            if len(self.error_history) > 0:
                recent_errors = [e for e in self.error_history if e > time.time() - 300]  # Últimos 5 min
                recent_requests = [r for r in self.request_history if r > time.time() - 300]
                
                if len(recent_requests) > 0:
                    error_rate = len(recent_errors) / len(recent_requests)
                    self.error_rate.set(error_rate)
            
            # Calcula latência média
            if len(self.request_history) > 0:
                recent_requests = [r for r in self.request_history if r > time.time() - 300]
                if len(recent_requests) > 0:
                    avg_latency = sum(recent_requests) / len(recent_requests)
                    self.avg_latency.set(avg_latency)
                    
        except Exception as e:
            metrics_logger.error(f"Erro ao calcular métricas: {e}")
    
    def _check_alerts(self):
        """Verifica e dispara alertas."""
        try:
            current_error_rate = self.error_rate._value.get()
            current_latency = self.avg_latency._value.get()
            
            if current_error_rate > self.alert_threshold_error:
                self._trigger_alert('error_rate', current_error_rate)
            
            if current_latency > self.alert_threshold_latency:
                self._trigger_alert('latency', current_latency)
                
        except Exception as e:
            metrics_logger.error(f"Erro ao verificar alertas: {e}")
    
    def _trigger_alert(self, alert_type: str, value: float):
        """Dispara alerta."""
        alert_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'alert_type': alert_type,
            'value': value,
            'threshold': self.alert_threshold_error if alert_type == 'error_rate' else self.alert_threshold_latency
        }
        
        metrics_logger.warning(f"ALERTA: {alert_type} = {value}")
        
        # Salva alerta em arquivo
        try:
            with open('logs/exec_trace/alerts.log', 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        except Exception as e:
            metrics_logger.error(f"Erro ao salvar alerta: {e}")
    
    def record_article_generation(self, model: str, status: str, user_id: str, duration: float):
        """Registra geração de artigo."""
        try:
            self.articles_generated.labels(model=model, status=status, user_id=user_id).inc()
            self.generation_duration.labels(model=model, status=status).observe(duration)
            
            # Atualiza gerações ativas
            if status == 'started':
                self.active_generations.labels(model=model).inc()
            elif status in ['completed', 'failed']:
                self.active_generations.labels(model=model).dec()
            
            metrics_logger.info(f"Geração registrada: {model}, {status}, {duration}s")
            
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar geração: {e}")
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Registra requisição HTTP."""
        try:
            self.requests_total.labels(method=method, endpoint=endpoint, status_code=str(status_code)).inc()
            self.request_duration.labels(method=method, endpoint=endpoint).observe(duration)
            
            # Adiciona ao histórico
            self.request_history.append(duration)
            if len(self.request_history) > self.max_history_size:
                self.request_history.pop(0)
            
            # Registra erro se aplicável
            if status_code >= 400:
                self.error_history.append(time.time())
                if len(self.error_history) > self.max_history_size:
                    self.error_history.pop(0)
            
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar requisição: {e}")
    
    def record_token_usage(self, model: str, user_id: str, status: str):
        """Registra uso de token."""
        try:
            self.token_usage.labels(model=model, user_id=user_id, status=status).inc()
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar uso de token: {e}")
    
    def record_rate_limit_hit(self, endpoint: str, ip_address: str):
        """Registra hit de rate limiting."""
        try:
            self.rate_limit_hits.labels(endpoint=endpoint, ip_address=ip_address).inc()
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar rate limit: {e}")
    
    def record_error(self, error_type: str, endpoint: str, user_id: str):
        """Registra erro."""
        try:
            self.errors_total.labels(type=error_type, endpoint=endpoint, user_id=user_id).inc()
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar erro: {e}")
    
    def record_upload(self, file_type: str, status: str, user_id: str, size: int):
        """Registra upload de arquivo."""
        try:
            self.uploads_total.labels(file_type=file_type, status=status, user_id=user_id).inc()
            self.upload_size.labels(file_type=file_type).observe(size)
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar upload: {e}")
    
    def record_storage_operation(self, operation: str, status: str):
        """Registra operação de storage."""
        try:
            self.storage_operations.labels(operation=operation, status=status).inc()
        except Exception as e:
            metrics_logger.error(f"Erro ao registrar operação de storage: {e}")
    
    def update_queue_size(self, size: int):
        """Atualiza tamanho da fila."""
        try:
            self.queue_size.set(size)
        except Exception as e:
            metrics_logger.error(f"Erro ao atualizar tamanho da fila: {e}")
    
    def update_storage_size(self, size: int):
        """Atualiza tamanho do storage."""
        try:
            self.storage_size.set(size)
        except Exception as e:
            metrics_logger.error(f"Erro ao atualizar tamanho do storage: {e}")
    
    def get_metrics(self) -> str:
        """Retorna métricas em formato Prometheus."""
        try:
            return generate_latest(self.registry)
        except Exception as e:
            metrics_logger.error(f"Erro ao gerar métricas: {e}")
            return ""
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Retorna resumo das métricas para dashboard."""
        try:
            return {
                'articles_generated': {
                    'total': self.articles_generated._value.get(),
                    'by_model': {},  # Seria calculado dinamicamente
                    'by_status': {}   # Seria calculado dinamicamente
                },
                'requests': {
                    'total': self.requests_total._value.get(),
                    'avg_duration': self.avg_latency._value.get(),
                    'error_rate': self.error_rate._value.get()
                },
                'tokens': {
                    'total_usage': self.token_usage._value.get()
                },
                'system': {
                    'active_generations': self.active_generations._value.get(),
                    'queue_size': self.queue_size._value.get(),
                    'storage_size': self.storage_size._value.get()
                },
                'alerts': {
                    'error_threshold': self.alert_threshold_error,
                    'latency_threshold': self.alert_threshold_latency
                }
            }
        except Exception as e:
            metrics_logger.error(f"Erro ao gerar resumo: {e}")
            return {}

# Instância global do sistema de métricas
metrics_system = MetricsSystem()

def record_article_generation(model: str, status: str, user_id: str, duration: float):
    """Função de conveniência para registrar geração de artigo."""
    metrics_system.record_article_generation(model, status, user_id, duration)

def record_request(method: str, endpoint: str, status_code: int, duration: float):
    """Função de conveniência para registrar requisição."""
    metrics_system.record_request(method, endpoint, status_code, duration)

def record_token_usage(model: str, user_id: str, status: str):
    """Função de conveniência para registrar uso de token."""
    metrics_system.record_token_usage(model, user_id, status)

def record_error(error_type: str, endpoint: str, user_id: str):
    """Função de conveniência para registrar erro."""
    metrics_system.record_error(error_type, endpoint, user_id)

def get_metrics_summary() -> Dict[str, Any]:
    """Função de conveniência para obter resumo de métricas."""
    return metrics_system.get_metrics_summary() 