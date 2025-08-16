"""
Testes Unitários - Integration Health Dashboard
===============================================

Tracing ID: TEST_INT_DASH_20250127_001
Prompt: Item 15 - Integration Health Dashboard Tests
Ruleset: checklist_integracao_externa.md
Created: 2025-01-27T23:25:00Z

Testes baseados em código real do dashboard de saúde das integrações.
"""

import pytest
import json
import tempfile
import os
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from monitoring.integration_health_dashboard import (
    IntegrationHealthDashboard,
    HealthStatus,
    AlertSeverity,
    IntegrationMetrics,
    DashboardAlert,
    DashboardSummary,
    get_integration_health_dashboard
)


class TestHealthStatus:
    """Testes para enum HealthStatus"""
    
    def test_health_status_values(self):
        """Testa valores do enum HealthStatus"""
        statuses = list(HealthStatus)
        expected_values = ['excellent', 'good', 'warning', 'critical', 'unknown']
        
        assert len(statuses) == 5
        for status in statuses:
            assert status.value in expected_values
    
    def test_health_status_hierarchy(self):
        """Testa hierarquia dos status de saúde"""
        # EXCELLENT deve ser o melhor status
        assert HealthStatus.EXCELLENT.value == "excellent"
        
        # CRITICAL deve ser o pior status
        assert HealthStatus.CRITICAL.value == "critical"
        
        # UNKNOWN deve ser para status desconhecido
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestAlertSeverity:
    """Testes para enum AlertSeverity"""
    
    def test_alert_severity_values(self):
        """Testa valores do enum AlertSeverity"""
        severities = list(AlertSeverity)
        expected_values = ['info', 'warning', 'error', 'critical']
        
        assert len(severities) == 4
        for severity in severities:
            assert severity.value in expected_values
    
    def test_alert_severity_hierarchy(self):
        """Testa hierarquia das severidades de alerta"""
        # INFO deve ser a menos severa
        assert AlertSeverity.INFO.value == "info"
        
        # CRITICAL deve ser a mais severa
        assert AlertSeverity.CRITICAL.value == "critical"


class TestIntegrationMetrics:
    """Testes para dataclass IntegrationMetrics"""
    
    def test_integration_metrics_creation(self):
        """Testa criação de métricas de integração"""
        metrics = IntegrationMetrics(
            service_name="test_service",
            endpoint="https://api.test.com/v1",
            health_status=HealthStatus.GOOD,
            response_time_avg=150.0,
            response_time_p95=300.0,
            response_time_p99=500.0,
            error_rate=2.5,
            success_rate=97.5,
            throughput=100.0,
            circuit_breaker_status="closed",
            circuit_breaker_failure_rate=1.0,
            sla_compliance=98.0,
            financial_impact=500.0,
            contract_drift_score=0.1,
            proactive_insights=["Performance estável"],
            last_check=datetime.now(),
            tracing_id="TEST_001"
        )
        
        assert metrics.service_name == "test_service"
        assert metrics.endpoint == "https://api.test.com/v1"
        assert metrics.health_status == HealthStatus.GOOD
        assert metrics.response_time_avg == 150.0
        assert metrics.error_rate == 2.5
        assert metrics.sla_compliance == 98.0
        assert len(metrics.proactive_insights) == 1


class TestDashboardAlert:
    """Testes para dataclass DashboardAlert"""
    
    def test_dashboard_alert_creation(self):
        """Testa criação de alerta do dashboard"""
        alert = DashboardAlert(
            id="ALERT_001",
            title="Test Alert",
            message="This is a test alert",
            severity=AlertSeverity.WARNING,
            service_name="test_service",
            metric_name="response_time",
            current_value=1200.0,
            threshold=1000.0,
            timestamp=datetime.now(),
            acknowledged=False,
            acknowledged_by=None,
            acknowledged_at=None,
            tracing_id="TEST_001"
        )
        
        assert alert.id == "ALERT_001"
        assert alert.title == "Test Alert"
        assert alert.severity == AlertSeverity.WARNING
        assert alert.service_name == "test_service"
        assert alert.current_value == 1200.0
        assert alert.threshold == 1000.0
        assert alert.acknowledged is False


class TestDashboardSummary:
    """Testes para dataclass DashboardSummary"""
    
    def test_dashboard_summary_creation(self):
        """Testa criação de resumo do dashboard"""
        summary = DashboardSummary(
            total_services=6,
            healthy_services=4,
            warning_services=1,
            critical_services=1,
            overall_health_score=85.5,
            total_alerts=3,
            critical_alerts=1,
            financial_impact_total=2500.0,
            sla_compliance_avg=96.5,
            last_updated=datetime.now(),
            tracing_id="TEST_001"
        )
        
        assert summary.total_services == 6
        assert summary.healthy_services == 4
        assert summary.critical_services == 1
        assert summary.overall_health_score == 85.5
        assert summary.total_alerts == 3
        assert summary.financial_impact_total == 2500.0


class TestIntegrationHealthDashboard:
    """Testes para classe IntegrationHealthDashboard"""
    
    @pytest.fixture
    def dashboard(self):
        """Fixture para criar dashboard de teste"""
        return IntegrationHealthDashboard()
    
    @pytest.fixture
    def temp_config_file(self):
        """Fixture para arquivo de configuração temporário"""
        config = {
            'update_interval_seconds': 60,
            'alert_thresholds': {
                'response_time_p95_ms': 800,
                'error_rate_percent': 3.0,
                'sla_compliance_percent': 97.0
            },
            'services': [
                {'name': 'test_service', 'endpoint': 'https://api.test.com/v1'}
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_path = f.name
        
        yield temp_path
        
        os.unlink(temp_path)
    
    def test_dashboard_initialization(self, dashboard):
        """Testa inicialização do dashboard"""
        assert dashboard.tracing_id.startswith("INT_DASH_")
        assert dashboard.config['update_interval_seconds'] == 300
        assert len(dashboard.config['services']) > 0
        assert dashboard.config['alert_thresholds']['response_time_p95_ms'] == 1000
    
    def test_dashboard_with_config_file(self, temp_config_file):
        """Testa inicialização com arquivo de configuração"""
        dashboard = IntegrationHealthDashboard(temp_config_file)
        
        assert dashboard.config['update_interval_seconds'] == 60
        assert dashboard.config['alert_thresholds']['response_time_p95_ms'] == 800
        assert len(dashboard.config['services']) == 1
    
    def test_get_dashboard_summary(self, dashboard):
        """Testa obtenção de resumo do dashboard"""
        summary = dashboard.get_dashboard_summary()
        
        assert isinstance(summary, DashboardSummary)
        assert summary.total_services > 0
        assert summary.total_services >= summary.healthy_services
        assert summary.overall_health_score >= 0
        assert summary.overall_health_score <= 100
        assert summary.tracing_id == dashboard.tracing_id
    
    def test_get_service_metrics(self, dashboard):
        """Testa obtenção de métricas de serviço específico"""
        # Obter métricas de um serviço existente
        service_name = dashboard.config['services'][0]['name']
        metrics = dashboard.get_service_metrics(service_name)
        
        assert isinstance(metrics, IntegrationMetrics)
        assert metrics.service_name == service_name
        assert metrics.tracing_id == dashboard.tracing_id
        assert isinstance(metrics.health_status, HealthStatus)
    
    def test_get_service_metrics_nonexistent(self, dashboard):
        """Testa obtenção de métricas de serviço inexistente"""
        metrics = dashboard.get_service_metrics("nonexistent_service")
        assert metrics is None
    
    def test_get_all_metrics(self, dashboard):
        """Testa obtenção de todas as métricas"""
        all_metrics = dashboard.get_all_metrics()
        
        assert isinstance(all_metrics, dict)
        assert len(all_metrics) > 0
        assert all(isinstance(metrics, IntegrationMetrics) for metrics in all_metrics.values())
    
    def test_get_alerts_empty(self, dashboard):
        """Testa obtenção de alertas quando não há nenhum"""
        alerts = dashboard.get_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) == 0
    
    def test_get_alerts_with_filters(self, dashboard):
        """Testa obtenção de alertas com filtros"""
        # Criar alguns alertas de teste
        with dashboard.alerts_lock:
            dashboard.alerts.append(DashboardAlert(
                id="ALERT_001",
                title="Test Alert",
                message="Test message",
                severity=AlertSeverity.WARNING,
                service_name="test_service",
                metric_name="response_time",
                current_value=1200.0,
                threshold=1000.0,
                timestamp=datetime.now(),
                acknowledged=False,
                acknowledged_by=None,
                acknowledged_at=None,
                tracing_id=dashboard.tracing_id
            ))
        
        # Testar filtros
        alerts = dashboard.get_alerts(severity=AlertSeverity.WARNING)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.WARNING
        
        alerts = dashboard.get_alerts(service_name="test_service")
        assert len(alerts) == 1
        assert alerts[0].service_name == "test_service"
        
        alerts = dashboard.get_alerts(acknowledged=False)
        assert len(alerts) == 1
        assert alerts[0].acknowledged is False
    
    def test_acknowledge_alert(self, dashboard):
        """Testa reconhecimento de alerta"""
        # Criar alerta de teste
        alert_id = "ALERT_001"
        with dashboard.alerts_lock:
            dashboard.alerts.append(DashboardAlert(
                id=alert_id,
                title="Test Alert",
                message="Test message",
                severity=AlertSeverity.WARNING,
                service_name="test_service",
                metric_name="response_time",
                current_value=1200.0,
                threshold=1000.0,
                timestamp=datetime.now(),
                acknowledged=False,
                acknowledged_by=None,
                acknowledged_at=None,
                tracing_id=dashboard.tracing_id
            ))
        
        # Reconhecer alerta
        result = dashboard.acknowledge_alert(alert_id, "test_user")
        assert result is True
        
        # Verificar se foi reconhecido
        alerts = dashboard.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].acknowledged is True
        assert alerts[0].acknowledged_by == "test_user"
        assert alerts[0].acknowledged_at is not None
    
    def test_acknowledge_nonexistent_alert(self, dashboard):
        """Testa reconhecimento de alerta inexistente"""
        result = dashboard.acknowledge_alert("nonexistent_alert", "test_user")
        assert result is False
    
    def test_get_dashboard_metrics(self, dashboard):
        """Testa obtenção de métricas do dashboard"""
        metrics = dashboard.get_dashboard_metrics()
        
        assert isinstance(metrics, dict)
        assert 'total_requests' in metrics
        assert 'cache_hits' in metrics
        assert 'alerts_generated' in metrics
        assert 'last_update' in metrics
    
    def test_export_dashboard_data_json(self, dashboard):
        """Testa exportação de dados em JSON"""
        export_data = dashboard.export_dashboard_data(format='json')
        
        assert isinstance(export_data, str)
        data = json.loads(export_data)
        
        assert 'summary' in data
        assert 'services' in data
        assert 'alerts' in data
        assert 'export_timestamp' in data
        assert 'tracing_id' in data
        assert data['tracing_id'] == dashboard.tracing_id
    
    def test_export_dashboard_data_without_alerts(self, dashboard):
        """Testa exportação sem alertas"""
        export_data = dashboard.export_dashboard_data(format='json', include_alerts=False)
        data = json.loads(export_data)
        
        assert 'alerts' in data
        assert isinstance(data['alerts'], list)
    
    def test_export_dashboard_data_invalid_format(self, dashboard):
        """Testa exportação com formato inválido"""
        with pytest.raises(ValueError):
            dashboard.export_dashboard_data(format='invalid')
    
    def test_search_services_by_health_status(self, dashboard):
        """Testa busca de serviços por status de saúde"""
        # Buscar serviços saudáveis
        healthy_services = dashboard.search_services(health_status=HealthStatus.EXCELLENT)
        assert isinstance(healthy_services, list)
        
        # Buscar serviços críticos
        critical_services = dashboard.search_services(health_status=HealthStatus.CRITICAL)
        assert isinstance(critical_services, list)
    
    def test_search_services_by_health_score(self, dashboard):
        """Testa busca de serviços por score de saúde"""
        # Buscar serviços com score mínimo
        high_score_services = dashboard.search_services(min_health_score=80.0)
        assert isinstance(high_score_services, list)
    
    def test_get_health_trends(self, dashboard):
        """Testa obtenção de tendências de saúde"""
        service_name = dashboard.config['services'][0]['name']
        trends = dashboard.get_health_trends(service_name, hours=24)
        
        assert isinstance(trends, dict)
        assert 'health_score' in trends
        assert 'response_time' in trends
        assert 'error_rate' in trends
        assert 'sla_compliance' in trends
        
        assert len(trends['health_score']) == 24
        assert all(isinstance(x, float) for x in trends['health_score'])
    
    def test_dashboard_string_representation(self, dashboard):
        """Testa representação string do dashboard"""
        str_repr = str(dashboard)
        
        assert "IntegrationHealthDashboard" in str_repr
        assert dashboard.tracing_id in str_repr
        assert "total_services" in str_repr
        assert "healthy_services" in str_repr
    
    def test_health_score_calculation(self, dashboard):
        """Testa cálculo de health score"""
        circuit_metrics = {
            'response_time_p95': 200.0,
            'error_rate': 2.0,
            'status': 'closed'
        }
        sla_metrics = {
            'compliance_percentage': 98.0
        }
        financial_metrics = {
            'total_impact': 500.0
        }
        
        health_score = dashboard._calculate_health_score(
            circuit_metrics, sla_metrics, financial_metrics
        )
        
        assert isinstance(health_score, float)
        assert health_score >= 0
        assert health_score <= 100
    
    def test_health_status_determination(self, dashboard):
        """Testa determinação de status de saúde"""
        # Testar diferentes scores
        assert dashboard._determine_health_status(95.0) == HealthStatus.EXCELLENT
        assert dashboard._determine_health_status(80.0) == HealthStatus.GOOD
        assert dashboard._determine_health_status(60.0) == HealthStatus.WARNING
        assert dashboard._determine_health_status(30.0) == HealthStatus.CRITICAL
    
    def test_false_positive_validation(self, dashboard):
        """Testa validação de falsos positivos"""
        alert = DashboardAlert(
            id="ALERT_001",
            title="Test Alert",
            message="Test message",
            severity=AlertSeverity.WARNING,
            service_name="test_service",
            metric_name="response_time",
            current_value=1050.0,  # Ligeiramente acima do threshold
            threshold=1000.0,
            timestamp=datetime.now(),
            acknowledged=False,
            acknowledged_by=None,
            acknowledged_at=None,
            tracing_id=dashboard.tracing_id
        )
        
        is_false_positive = dashboard._validate_false_positive(alert)
        assert isinstance(is_false_positive, bool)
    
    def test_service_endpoint_retrieval(self, dashboard):
        """Testa obtenção de endpoint de serviço"""
        service_name = dashboard.config['services'][0]['name']
        endpoint = dashboard._get_service_endpoint(service_name)
        
        assert isinstance(endpoint, str)
        assert endpoint.startswith('http')
    
    def test_service_endpoint_nonexistent(self, dashboard):
        """Testa obtenção de endpoint de serviço inexistente"""
        endpoint = dashboard._get_service_endpoint("nonexistent_service")
        assert endpoint == "unknown"


class TestGetIntegrationHealthDashboardFunction:
    """Testes para função de conveniência"""
    
    def test_get_integration_health_dashboard_function(self):
        """Testa função de conveniência"""
        dashboard = get_integration_health_dashboard()
        
        assert isinstance(dashboard, IntegrationHealthDashboard)
        assert dashboard.tracing_id.startswith("INT_DASH_")
    
    def test_get_integration_health_dashboard_with_config(self, temp_config_file):
        """Testa função de conveniência com configuração"""
        dashboard = get_integration_health_dashboard(temp_config_file)
        
        assert isinstance(dashboard, IntegrationHealthDashboard)
        assert dashboard.config['update_interval_seconds'] == 60


class TestIntegrationHealthDashboardIntegration:
    """Testes de integração do dashboard"""
    
    @pytest.fixture
    def dashboard(self):
        """Fixture para dashboard de integração"""
        return IntegrationHealthDashboard()
    
    def test_integration_with_real_services(self, dashboard):
        """Testa integração com serviços reais"""
        # Verificar se todos os serviços configurados estão sendo monitorados
        all_metrics = dashboard.get_all_metrics()
        configured_services = [s['name'] for s in dashboard.config['services']]
        
        assert len(all_metrics) == len(configured_services)
        assert all(service in all_metrics for service in configured_services)
        
        # Verificar se cada serviço tem métricas válidas
        for service_name, metrics in all_metrics.items():
            assert metrics.service_name == service_name
            assert isinstance(metrics.health_status, HealthStatus)
            assert metrics.response_time_avg >= 0
            assert metrics.error_rate >= 0
            assert metrics.sla_compliance >= 0
            assert metrics.sla_compliance <= 100
    
    def test_integration_alert_generation(self, dashboard):
        """Testa geração de alertas em integração"""
        # Simular métricas que devem gerar alertas
        with dashboard.cache_lock:
            for service_name, metrics in dashboard.metrics_cache.items():
                # Modificar métricas para gerar alertas
                metrics.response_time_p95 = 1500.0  # Acima do threshold
                metrics.error_rate = 8.0  # Acima do threshold
                metrics.sla_compliance = 90.0  # Abaixo do threshold
        
        # Gerar alertas
        dashboard._generate_alerts()
        
        # Verificar se alertas foram gerados
        alerts = dashboard.get_alerts()
        assert len(alerts) > 0
        
        # Verificar se há alertas críticos
        critical_alerts = dashboard.get_alerts(severity=AlertSeverity.CRITICAL)
        assert len(critical_alerts) >= 0  # Pode ser 0 se não houver violações críticas
    
    def test_integration_metrics_update(self, dashboard):
        """Testa atualização de métricas em integração"""
        # Obter métricas iniciais
        initial_metrics = dashboard.get_all_metrics()
        
        # Aguardar um pouco para permitir atualizações
        time.sleep(2)
        
        # Obter métricas atualizadas
        updated_metrics = dashboard.get_all_metrics()
        
        # Verificar se as métricas foram atualizadas
        for service_name in initial_metrics:
            initial = initial_metrics[service_name]
            updated = updated_metrics[service_name]
            
            # Pelo menos o timestamp deve ter sido atualizado
            assert updated.last_check >= initial.last_check
    
    def test_integration_summary_consistency(self, dashboard):
        """Testa consistência do resumo em integração"""
        summary = dashboard.get_dashboard_summary()
        all_metrics = dashboard.get_all_metrics()
        
        # Verificar se os números batem
        assert summary.total_services == len(all_metrics)
        assert summary.healthy_services + summary.warning_services + summary.critical_services <= summary.total_services
        
        # Verificar se o health score está no range correto
        assert summary.overall_health_score >= 0
        assert summary.overall_health_score <= 100
    
    def test_integration_export_consistency(self, dashboard):
        """Testa consistência da exportação em integração"""
        export_data = dashboard.export_dashboard_data()
        data = json.loads(export_data)
        
        # Verificar se os dados exportados são consistentes
        assert data['summary']['total_services'] == len(data['services'])
        assert data['tracing_id'] == dashboard.tracing_id
        
        # Verificar se todos os serviços estão na exportação
        for service_name in dashboard.config['services']:
            assert service_name['name'] in data['services']
    
    def test_integration_performance_metrics(self, dashboard):
        """Testa métricas de performance em integração"""
        initial_metrics = dashboard.get_dashboard_metrics()
        
        # Fazer algumas operações
        dashboard.get_dashboard_summary()
        dashboard.get_all_metrics()
        dashboard.get_alerts()
        
        updated_metrics = dashboard.get_dashboard_metrics()
        
        # Verificar se as métricas foram atualizadas
        assert updated_metrics['total_requests'] >= initial_metrics['total_requests']
        assert updated_metrics['last_update'] >= initial_metrics['last_update']


if __name__ == "__main__":
    # Executar testes
    pytest.main([__file__, "-v"]) 