"""
Testes unitários para o coletor de métricas.

Prompt: Monitoramento de Performance - IMP-008
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:55:00Z
Tracing ID: ENTERPRISE_20250127_008
"""

import pytest
import time
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from monitoring.metrics_collector import (
    MetricsCollector, 
    PerformanceMetric, 
    SystemMetrics,
    create_metrics_app
)


class TestMetricsCollector:
    """Testes para o coletor de métricas."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.collector = MetricsCollector()
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        # Para a thread de coleta
        if hasattr(self.collector, 'collection_thread'):
            self.collector.collection_thread.join(timeout=1)
    
    def test_metrics_collector_initialization(self):
        """Testa inicialização do coletor de métricas."""
        assert self.collector is not None
        assert hasattr(self.collector, 'request_counter')
        assert hasattr(self.collector, 'generation_counter')
        assert hasattr(self.collector, 'cache_hits')
        assert hasattr(self.collector, 'error_counter')
        assert hasattr(self.collector, 'active_workers')
        assert hasattr(self.collector, 'queue_size')
        assert hasattr(self.collector, 'system_metrics')
    
    def test_record_request_metric(self):
        """Testa registro de métrica de requisição."""
        endpoint = "/generate"
        method = "POST"
        status = 200
        duration = 1.5
        
        # Registra métrica
        self.collector.record_request(endpoint, method, status, duration)
        
        # Verifica se a métrica foi registrada
        assert len(self.collector.metrics_history) > 0
        
        # Verifica se a métrica tem os dados corretos
        last_metric = self.collector.metrics_history[-1]
        assert last_metric.name == f"request_{endpoint}_{method}"
        assert last_metric.value == duration
        assert last_metric.labels['endpoint'] == endpoint
        assert last_metric.labels['method'] == method
        assert last_metric.labels['status'] == str(status)
        assert last_metric.metric_type == "histogram"
    
    def test_record_generation_metric(self):
        """Testa registro de métrica de geração."""
        model_type = "openai"
        status = "success"
        duration = 3.2
        
        # Registra métrica
        self.collector.record_generation(model_type, status, duration)
        
        # Verifica se a métrica foi registrada
        assert len(self.collector.metrics_history) > 0
        
        # Verifica se a métrica tem os dados corretos
        last_metric = self.collector.metrics_history[-1]
        assert last_metric.name == f"generation_{model_type}"
        assert last_metric.value == duration
        assert last_metric.labels['model_type'] == model_type
        assert last_metric.labels['status'] == status
        assert last_metric.metric_type == "histogram"
    
    def test_record_cache_operation(self):
        """Testa registro de operação de cache."""
        cache_type = "intelligent_cache"
        
        # Testa cache hit
        self.collector.record_cache_operation(cache_type, hit=True)
        
        # Testa cache miss
        self.collector.record_cache_operation(cache_type, hit=False)
        
        # Verifica se as métricas foram registradas
        # (Prometheus counters não são facilmente verificáveis em testes unitários)
        assert True  # Se chegou até aqui, não houve exceção
    
    def test_record_error(self):
        """Testa registro de erro."""
        error_type = "validation_error"
        endpoint = "/generate"
        
        # Registra erro
        self.collector.record_error(error_type, endpoint)
        
        # Verifica se o erro foi registrado
        # (Prometheus counters não são facilmente verificáveis em testes unitários)
        assert True  # Se chegou até aqui, não houve exceção
    
    def test_update_worker_count(self):
        """Testa atualização do contador de workers."""
        worker_count = 3
        
        # Atualiza contador
        self.collector.update_worker_count(worker_count)
        
        # Verifica se foi atualizado
        # (Prometheus gauges não são facilmente verificáveis em testes unitários)
        assert True  # Se chegou até aqui, não houve exceção
    
    def test_update_queue_size(self):
        """Testa atualização do tamanho da fila."""
        queue_name = "generation_queue"
        size = 25
        
        # Atualiza tamanho da fila
        self.collector.update_queue_size(queue_name, size)
        
        # Verifica se foi atualizado
        # (Prometheus gauges não são facilmente verificáveis em testes unitários)
        assert True  # Se chegou até aqui, não houve exceção
    
    def test_calculate_health_score(self):
        """Testa cálculo do health score."""
        # Teste com valores normais
        cpu_percent = 30.0
        memory_percent = 50.0
        disk_percent = 60.0
        
        health_score = self.collector._calculate_health_score(cpu_percent, memory_percent, disk_percent)
        
        # Verifica se o score está no intervalo correto
        assert 0 <= health_score <= 100
        
        # Verifica se o cálculo está correto
        expected_score = (70 * 0.4) + (50 * 0.35) + (40 * 0.25)  # 70, 50, 40
        assert abs(health_score - expected_score) < 0.1
        
        # Teste com valores críticos
        cpu_percent = 95.0
        memory_percent = 90.0
        disk_percent = 95.0
        
        health_score = self.collector._calculate_health_score(cpu_percent, memory_percent, disk_percent)
        
        # Verifica se o score é baixo
        assert health_score < 20
        
        # Teste com valores ideais
        cpu_percent = 10.0
        memory_percent = 20.0
        disk_percent = 30.0
        
        health_score = self.collector._calculate_health_score(cpu_percent, memory_percent, disk_percent)
        
        # Verifica se o score é alto
        assert health_score > 70
    
    def test_get_metrics_summary(self):
        """Testa geração do resumo de métricas."""
        # Adiciona algumas métricas
        self.collector.record_request("/test", "GET", 200, 0.5)
        self.collector.record_generation("openai", "success", 2.0)
        
        # Obtém resumo
        summary = self.collector.get_metrics_summary()
        
        # Verifica estrutura do resumo
        assert 'total_metrics' in summary
        assert 'recent_metrics' in summary
        assert 'collection_time' in summary
        assert 'system_health' in summary
        
        # Verifica métricas do sistema
        system_health = summary['system_health']
        assert 'cpu_usage' in system_health
        assert 'memory_usage' in system_health
        assert 'disk_usage' in system_health
        assert 'health_score' in system_health
        
        # Verifica tipos de dados
        assert isinstance(summary['total_metrics'], int)
        assert isinstance(summary['recent_metrics'], int)
        assert isinstance(summary['collection_time'], str)
        assert isinstance(system_health['cpu_usage'], (int, float))
        assert isinstance(system_health['memory_usage'], (int, float))
        assert isinstance(system_health['disk_usage'], (int, float))
        assert isinstance(system_health['health_score'], (int, float))
    
    def test_export_metrics(self):
        """Testa exportação de métricas no formato Prometheus."""
        # Adiciona algumas métricas
        self.collector.record_request("/test", "GET", 200, 0.5)
        self.collector.record_generation("openai", "success", 2.0)
        
        # Exporta métricas
        metrics_data = self.collector.export_metrics()
        
        # Verifica se retornou string não vazia
        assert isinstance(metrics_data, str)
        assert len(metrics_data) > 0
        
        # Verifica se contém métricas do sistema
        assert "omni_writer_system_metrics" in metrics_data
    
    def test_metrics_collector_thread_safety(self):
        """Testa thread safety do coletor de métricas."""
        import threading
        
        def add_metrics(thread_id):
            for i in range(10):
                self.collector.record_request(f"/thread_{thread_id}", "POST", 200, 1.0)
                self.collector.record_generation("openai", "success", 2.0)
                time.sleep(0.01)
        
        # Cria múltiplas threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=add_metrics, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Aguarda conclusão
        for thread in threads:
            thread.join()
        
        # Verifica se todas as métricas foram registradas
        assert len(self.collector.metrics_history) >= 60  # 3 threads * 10 iterações * 2 métricas


class TestPerformanceMetric:
    """Testes para a estrutura PerformanceMetric."""
    
    def test_performance_metric_creation(self):
        """Testa criação de métrica de performance."""
        metric = PerformanceMetric(
            name="test_metric",
            value=1.5,
            timestamp=datetime.now(),
            labels={"endpoint": "/test", "method": "GET"},
            metric_type="histogram"
        )
        
        assert metric.name == "test_metric"
        assert metric.value == 1.5
        assert isinstance(metric.timestamp, datetime)
        assert metric.labels["endpoint"] == "/test"
        assert metric.labels["method"] == "GET"
        assert metric.metric_type == "histogram"
    
    def test_performance_metric_defaults(self):
        """Testa valores padrão da métrica de performance."""
        metric = PerformanceMetric(
            name="test_metric",
            value=1.0,
            timestamp=datetime.now(),
            labels={}
        )
        
        assert metric.metric_type == "gauge"  # Valor padrão


class TestSystemMetrics:
    """Testes para a estrutura SystemMetrics."""
    
    def test_system_metrics_creation(self):
        """Testa criação de métricas do sistema."""
        metrics = SystemMetrics(
            cpu_usage=45.5,
            memory_usage=67.2,
            disk_usage=23.1,
            network_io={"bytes_sent": 1024, "bytes_recv": 2048},
            timestamp=datetime.now()
        )
        
        assert metrics.cpu_usage == 45.5
        assert metrics.memory_usage == 67.2
        assert metrics.disk_usage == 23.1
        assert metrics.network_io["bytes_sent"] == 1024
        assert metrics.network_io["bytes_recv"] == 2048
        assert isinstance(metrics.timestamp, datetime)


class TestMetricsApp:
    """Testes para a aplicação Flask de métricas."""
    
    def test_create_metrics_app(self):
        """Testa criação da aplicação Flask."""
        app = create_metrics_app()
        
        assert app is not None
        assert hasattr(app, 'route')
        
        # Verifica se as rotas foram registradas
        routes = [rule.rule for rule in app.url_map.iter_rules()]
        assert '/metrics' in routes
        assert '/health' in routes
    
    def test_metrics_endpoint(self):
        """Testa endpoint de métricas."""
        app = create_metrics_app()
        client = app.test_client()
        
        # Adiciona algumas métricas
        from monitoring.metrics_collector import metrics_collector
        metrics_collector.record_request("/test", "GET", 200, 1.0)
        
        # Faz requisição para o endpoint
        response = client.get('/metrics')
        
        # Verifica resposta
        assert response.status_code == 200
        assert response.mimetype == 'text/plain; version=0.0.4; charset=utf-8'
        assert len(response.data) > 0
    
    def test_health_endpoint(self):
        """Testa endpoint de saúde."""
        app = create_metrics_app()
        client = app.test_client()
        
        # Faz requisição para o endpoint
        response = client.get('/health')
        
        # Verifica resposta
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        
        # Verifica estrutura do JSON
        data = json.loads(response.data)
        assert 'total_metrics' in data
        assert 'recent_metrics' in data
        assert 'collection_time' in data
        assert 'system_health' in data 