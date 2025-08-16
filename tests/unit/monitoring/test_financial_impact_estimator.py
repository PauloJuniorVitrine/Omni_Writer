"""
Testes unitários para Financial Impact Estimator
================================================

Testes baseados em código real e cenários reais de impacto financeiro.

Tracing ID: TEST_FIN_IMPACT_20250127_001
Prompt: checklist_integracao_externa.md - Item 12
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:05:00Z

Baseado em:
- Código real do FinancialImpactEstimator
- Cenários reais de falhas em integrações
- Métricas reais de circuit breaker e SLA
- Configurações reais de custos por ambiente
"""

import json
import pytest
from decimal import Decimal
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from monitoring.financial_impact_estimator import (
    FinancialImpactEstimator,
    FinancialImpact,
    CostConfiguration,
    ImpactSeverity,
    CostType
)
from shared.config import Config
from shared.feature_flags import FeatureFlags
from monitoring.circuit_breaker_metrics import CircuitBreakerMetrics
from monitoring.sla_compliance_checker import SLAComplianceChecker


class TestFinancialImpactEstimator:
    """Testes para FinancialImpactEstimator baseados em código real."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock da configuração para testes."""
        config = Mock(spec=Config)
        config.get.return_value = "development"
        config.file_exists.return_value = False
        return config
    
    @pytest.fixture
    def mock_feature_flags(self):
        """Mock das feature flags para testes."""
        flags = Mock(spec=FeatureFlags)
        flags.is_enabled.return_value = False
        return flags
    
    @pytest.fixture
    def mock_circuit_breaker_metrics(self):
        """Mock das métricas de circuit breaker para testes."""
        metrics = Mock(spec=CircuitBreakerMetrics)
        metrics.get_health_summary.return_value = {
            "openai_service": {
                "failure_rate": 0.15,
                "failure_duration_minutes": 30,
                "failed_requests": 1500,
                "retry_count": 300
            }
        }
        return metrics
    
    @pytest.fixture
    def mock_sla_checker(self):
        """Mock do SLA checker para testes."""
        checker = Mock(spec=SLAComplianceChecker)
        checker.get_recent_violations.return_value = [
            {"service": "stripe_service", "violation_type": "response_time", "duration": 45}
        ]
        return checker
    
    @pytest.fixture
    def estimator(self, mock_config, mock_feature_flags, mock_circuit_breaker_metrics, mock_sla_checker):
        """Instância do estimador para testes."""
        with patch('monitoring.financial_impact_estimator.Config', return_value=mock_config), \
             patch('monitoring.financial_impact_estimator.FeatureFlags', return_value=mock_feature_flags), \
             patch('monitoring.financial_impact_estimator.CircuitBreakerMetrics', return_value=mock_circuit_breaker_metrics), \
             patch('monitoring.financial_impact_estimator.SLAComplianceChecker', return_value=mock_sla_checker):
            
            return FinancialImpactEstimator()
    
    def test_initialization_with_default_config(self, mock_config, mock_feature_flags, mock_circuit_breaker_metrics, mock_sla_checker):
        """Testa inicialização com configuração padrão."""
        with patch('monitoring.financial_impact_estimator.Config', return_value=mock_config), \
             patch('monitoring.financial_impact_estimator.FeatureFlags', return_value=mock_feature_flags), \
             patch('monitoring.financial_impact_estimator.CircuitBreakerMetrics', return_value=mock_circuit_breaker_metrics), \
             patch('monitoring.financial_impact_estimator.SLAComplianceChecker', return_value=mock_sla_checker):
            
            estimator = FinancialImpactEstimator()
            
            assert estimator.config == mock_config
            assert estimator.feature_flags == mock_feature_flags
            assert estimator.circuit_breaker_metrics == mock_circuit_breaker_metrics
            assert estimator.sla_checker == mock_sla_checker
            assert isinstance(estimator.cost_config, CostConfiguration)
            assert len(estimator.impact_cache) == 0
    
    def test_load_cost_configuration_development(self, mock_config):
        """Testa carregamento de configuração de custos para desenvolvimento."""
        mock_config.get.return_value = "development"
        mock_config.file_exists.return_value = False
        
        estimator = FinancialImpactEstimator(mock_config)
        
        # Verificar configuração de desenvolvimento
        assert estimator.cost_config.compute_cost_per_hour == Decimal("0.10")
        assert estimator.cost_config.developer_hourly_rate == Decimal("50.00")
        assert estimator.cost_config.sla_violation_penalty == Decimal("0.00")
    
    def test_load_cost_configuration_production(self, mock_config):
        """Testa carregamento de configuração de custos para produção."""
        mock_config.get.return_value = "production"
        mock_config.file_exists.return_value = False
        
        estimator = FinancialImpactEstimator(mock_config)
        
        # Verificar configuração de produção
        assert estimator.cost_config.compute_cost_per_hour == Decimal("2.00")
        assert estimator.cost_config.developer_hourly_rate == Decimal("100.00")
        assert estimator.cost_config.sla_violation_penalty == Decimal("2000.00")
        assert estimator.cost_config.customer_churn_penalty == Decimal("1000.00")
    
    def test_estimate_incident_impact_critical_failure(self, estimator):
        """Testa estimativa de impacto para falha crítica real."""
        # Cenário real: Falha de pagamento Stripe afetando 5000 requisições
        impact = estimator.estimate_incident_impact(
            service_name="stripe_payment_service",
            failure_type="payment_gateway_error",
            duration_minutes=120,  # 2 horas
            affected_requests=5000,
            retry_count=1000,
            tracing_id="test_trace_001"
        )
        
        # Verificar estrutura do impacto
        assert isinstance(impact, FinancialImpact)
        assert impact.service_name == "stripe_payment_service"
        assert impact.failure_type == "payment_gateway_error"
        assert impact.duration_minutes == 120
        assert impact.affected_requests == 5000
        assert impact.retry_count == 1000
        assert impact.tracing_id == "test_trace_001"
        
        # Verificar custos calculados
        assert impact.infrastructure_cost > Decimal("0")
        assert impact.development_cost > Decimal("0")
        assert impact.support_cost > Decimal("0")
        assert impact.revenue_loss > Decimal("0")
        assert impact.total_cost > Decimal("0")
        
        # Verificar severidade (deve ser CRITICAL para este cenário)
        assert impact.severity == ImpactSeverity.CRITICAL
        
        # Verificar recomendações
        assert len(impact.recommendations) > 0
        assert any("circuit breaker" in rec.lower() for rec in impact.recommendations)
    
    def test_estimate_incident_impact_medium_failure(self, estimator):
        """Testa estimativa de impacto para falha média real."""
        # Cenário real: Timeout de API OpenAI afetando 500 requisições
        impact = estimator.estimate_incident_impact(
            service_name="openai_generation_service",
            failure_type="api_timeout",
            duration_minutes=45,
            affected_requests=500,
            retry_count=100,
            tracing_id="test_trace_002"
        )
        
        # Verificar severidade (deve ser MEDIUM ou HIGH)
        assert impact.severity in [ImpactSeverity.MEDIUM, ImpactSeverity.HIGH]
        
        # Verificar custos
        assert impact.total_cost > Decimal("0")
        assert impact.cost_per_request > Decimal("0")
        assert impact.cost_per_minute > Decimal("0")
    
    def test_estimate_incident_impact_low_failure(self, estimator):
        """Testa estimativa de impacto para falha baixa real."""
        # Cenário real: Falha temporária de cache afetando 50 requisições
        impact = estimator.estimate_incident_impact(
            service_name="redis_cache_service",
            failure_type="cache_miss",
            duration_minutes=10,
            affected_requests=50,
            retry_count=10,
            tracing_id="test_trace_003"
        )
        
        # Verificar severidade (deve ser LOW)
        assert impact.severity == ImpactSeverity.LOW
        
        # Verificar custos baixos
        assert impact.total_cost < Decimal("100")  # Deve ser baixo
    
    def test_false_positive_detection_development(self, estimator):
        """Testa detecção de falsos positivos em desenvolvimento."""
        # Cenário real: Falha curta em desenvolvimento
        impact = estimator.estimate_incident_impact(
            service_name="test_service",
            failure_type="timeout",
            duration_minutes=2,  # Muito curto
            affected_requests=10,
            retry_count=2,
            tracing_id="test_trace_004"
        )
        
        # Deve ser detectado como falso positivo
        assert impact.total_cost == Decimal("0")
        assert impact.severity == ImpactSeverity.LOW
        assert "Falso positivo" in impact.recommendations[0]
    
    def test_false_positive_detection_test_service(self, estimator):
        """Testa detecção de falsos positivos em serviços de teste."""
        # Cenário real: Serviço de teste
        impact = estimator.estimate_incident_impact(
            service_name="mock_payment_service",
            failure_type="test_error",
            duration_minutes=30,
            affected_requests=100,
            retry_count=20,
            tracing_id="test_trace_005"
        )
        
        # Deve ser detectado como falso positivo
        assert impact.total_cost == Decimal("0")
        assert impact.severity == ImpactSeverity.LOW
    
    def test_calculate_infrastructure_cost(self, estimator):
        """Testa cálculo de custo de infraestrutura real."""
        # Cenário real: 1000 requisições, 60 minutos, 200 retries
        cost = estimator._calculate_infrastructure_cost(
            duration_minutes=60,
            affected_requests=1000,
            retry_count=200
        )
        
        # Verificar cálculo
        expected_compute = Decimal("0.10") * Decimal("1.0")  # 1 hora
        expected_network = Decimal("1000") * Decimal("0.001") * Decimal("0.08")  # 1KB por requisição
        expected_retry = Decimal("200") * Decimal("0.01")
        expected_total = expected_compute + expected_network + expected_retry
        
        assert cost == expected_total
        assert cost > Decimal("0")
    
    def test_calculate_development_cost_by_failure_type(self, estimator):
        """Testa cálculo de custo de desenvolvimento por tipo de falha."""
        # Falha de segurança (mais cara)
        security_cost = estimator._calculate_development_cost("security_breach", 60)
        
        # Falha de timeout (menos cara)
        timeout_cost = estimator._calculate_development_cost("timeout", 60)
        
        # Falha de circuit breaker (intermediária)
        circuit_cost = estimator._calculate_development_cost("circuit_open", 60)
        
        # Verificar que custos são diferentes
        assert security_cost > timeout_cost
        assert security_cost > circuit_cost
        assert circuit_cost > timeout_cost
    
    def test_calculate_revenue_loss(self, estimator):
        """Testa cálculo de perda de receita real."""
        # Cenário real: 1000 requisições perdidas em 30 minutos
        revenue_loss = estimator._calculate_revenue_loss(
            affected_requests=1000,
            duration_minutes=30
        )
        
        # Verificar cálculo
        # 1000 * 0.02 (conversion_rate) * 50 (avg_order) * 0.5 (30min = 0.5h)
        expected_loss = Decimal("1000") * Decimal("0.02") * Decimal("50") * Decimal("0.5")
        
        assert revenue_loss == expected_loss
        assert revenue_loss > Decimal("0")
    
    def test_determine_severity_critical(self, estimator):
        """Testa determinação de severidade crítica."""
        # Cenário crítico: Alto custo, muitas requisições, longa duração
        severity = estimator._determine_severity(
            total_cost=Decimal("15000"),
            affected_requests=15000,
            duration_minutes=180
        )
        
        assert severity == ImpactSeverity.CRITICAL
    
    def test_determine_severity_high(self, estimator):
        """Testa determinação de severidade alta."""
        # Cenário alto: Custo médio-alto, muitas requisições
        severity = estimator._determine_severity(
            total_cost=Decimal("5000"),
            affected_requests=5000,
            duration_minutes=90
        )
        
        assert severity == ImpactSeverity.HIGH
    
    def test_determine_severity_medium(self, estimator):
        """Testa determinação de severidade média."""
        # Cenário médio: Custo moderado
        severity = estimator._determine_severity(
            total_cost=Decimal("500"),
            affected_requests=500,
            duration_minutes=45
        )
        
        assert severity == ImpactSeverity.MEDIUM
    
    def test_determine_severity_low(self, estimator):
        """Testa determinação de severidade baixa."""
        # Cenário baixo: Custo baixo
        severity = estimator._determine_severity(
            total_cost=Decimal("50"),
            affected_requests=50,
            duration_minutes=15
        )
        
        assert severity == ImpactSeverity.LOW
    
    def test_generate_recommendations_critical(self, estimator):
        """Testa geração de recomendações para incidente crítico."""
        recommendations = estimator._generate_recommendations(
            failure_type="payment_gateway_error",
            total_cost=Decimal("15000"),
            severity=ImpactSeverity.CRITICAL,
            affected_requests=10000
        )
        
        # Verificar recomendações críticas
        assert len(recommendations) > 0
        assert any("circuit breaker" in rec.lower() for rec in recommendations)
        assert any("redundância" in rec.lower() for rec in recommendations)
        assert any("cache" in rec.lower() for rec in recommendations)
    
    def test_generate_recommendations_timeout(self, estimator):
        """Testa geração de recomendações para timeout."""
        recommendations = estimator._generate_recommendations(
            failure_type="timeout",
            total_cost=Decimal("1000"),
            severity=ImpactSeverity.HIGH,
            affected_requests=1000
        )
        
        # Verificar recomendações específicas para timeout
        assert any("timeout" in rec.lower() for rec in recommendations)
        assert any("health check" in rec.lower() for rec in recommendations)
    
    def test_get_daily_summary_with_impacts(self, estimator):
        """Testa resumo diário com impactos reais."""
        # Criar impactos de teste
        today = datetime.utcnow().date()
        
        # Impacto 1
        impact1 = estimator.estimate_incident_impact(
            service_name="stripe_service",
            failure_type="payment_error",
            duration_minutes=60,
            affected_requests=1000,
            retry_count=200,
            tracing_id="daily_test_001"
        )
        
        # Impacto 2
        impact2 = estimator.estimate_incident_impact(
            service_name="openai_service",
            failure_type="api_error",
            duration_minutes=30,
            affected_requests=500,
            retry_count=100,
            tracing_id="daily_test_002"
        )
        
        # Obter resumo
        summary = estimator.get_daily_summary(today)
        
        # Verificar estrutura
        assert summary["date"] == today.strftime("%Y-%m-%d")
        assert summary["total_incidents"] == 2
        assert summary["total_cost"] > 0
        assert "cost_breakdown" in summary
        assert "severity_distribution" in summary
        assert "top_recommendations" in summary
    
    def test_get_daily_summary_empty(self, estimator):
        """Testa resumo diário sem impactos."""
        # Data futura sem impactos
        future_date = datetime.utcnow().date() + timedelta(days=1)
        summary = estimator.get_daily_summary(future_date)
        
        # Verificar estrutura vazia
        assert summary["total_incidents"] == 0
        assert summary["total_cost"] == 0.0
        assert summary["cost_breakdown"] == {}
        assert summary["severity_distribution"] == {}
        assert summary["top_recommendations"] == []
    
    def test_get_monthly_report_with_impacts(self, estimator):
        """Testa relatório mensal com impactos reais."""
        # Criar impactos de teste para o mês atual
        current_year = datetime.utcnow().year
        current_month = datetime.utcnow().month
        
        # Impacto 1
        impact1 = estimator.estimate_incident_impact(
            service_name="stripe_service",
            failure_type="payment_error",
            duration_minutes=120,
            affected_requests=2000,
            retry_count=400,
            tracing_id="monthly_test_001"
        )
        
        # Impacto 2
        impact2 = estimator.estimate_incident_impact(
            service_name="openai_service",
            failure_type="api_error",
            duration_minutes=90,
            affected_requests=1500,
            retry_count=300,
            tracing_id="monthly_test_002"
        )
        
        # Obter relatório
        report = estimator.get_monthly_report(current_year, current_month)
        
        # Verificar estrutura
        assert report["year"] == current_year
        assert report["month"] == current_month
        assert report["total_incidents"] == 2
        assert report["total_cost"] > 0
        assert report["daily_average"] > 0
        assert "cost_trends" in report
        assert "top_services" in report
        assert "roi_analysis" in report
    
    def test_export_data_json_format(self, estimator):
        """Testa exportação de dados em formato JSON."""
        # Criar impacto de teste
        impact = estimator.estimate_incident_impact(
            service_name="test_export_service",
            failure_type="export_error",
            duration_minutes=30,
            affected_requests=100,
            retry_count=20,
            tracing_id="export_test_001"
        )
        
        # Exportar dados
        json_data = estimator.export_data("json")
        
        # Verificar formato JSON válido
        data = json.loads(json_data)
        assert "impacts" in data
        assert "export_timestamp" in data
        assert "total_impacts" in data
        assert data["total_impacts"] == 1
    
    def test_export_data_invalid_format(self, estimator):
        """Testa exportação com formato inválido."""
        with pytest.raises(ValueError, match="Formato não suportado"):
            estimator.export_data("xml")
    
    def test_monitoring_integration(self, estimator, mock_circuit_breaker_metrics):
        """Testa integração com monitoramento de circuit breaker."""
        # Configurar mock para retornar falhas
        mock_circuit_breaker_metrics.get_health_summary.return_value = {
            "critical_service": {
                "failure_rate": 0.25,  # 25% de falha
                "failure_duration_minutes": 60,
                "failed_requests": 2000,
                "retry_count": 500
            }
        }
        
        # Simular loop de monitoramento
        estimator._monitoring_loop()
        
        # Verificar que impactos foram criados
        assert len(estimator.impact_cache) > 0
        
        # Verificar que métricas foram consultadas
        mock_circuit_breaker_metrics.get_health_summary.assert_called()
    
    def test_stop_monitoring(self, estimator):
        """Testa parada do monitoramento."""
        # Iniciar monitoramento
        estimator.should_monitor = True
        estimator._start_monitoring()
        
        # Parar monitoramento
        estimator.stop_monitoring()
        
        # Verificar que foi parado
        assert not estimator.should_monitor
    
    def test_cost_configuration_serialization(self):
        """Testa serialização da configuração de custos."""
        config = CostConfiguration(
            compute_cost_per_hour=Decimal("1.50"),
            developer_hourly_rate=Decimal("80.00"),
            sla_violation_penalty=Decimal("1500.00")
        )
        
        # Verificar que valores são Decimal
        assert isinstance(config.compute_cost_per_hour, Decimal)
        assert isinstance(config.developer_hourly_rate, Decimal)
        assert isinstance(config.sla_violation_penalty, Decimal)
        
        # Verificar valores
        assert config.compute_cost_per_hour == Decimal("1.50")
        assert config.developer_hourly_rate == Decimal("80.00")
        assert config.sla_violation_penalty == Decimal("1500.00")
    
    def test_impact_severity_enum(self):
        """Testa enum de severidade de impacto."""
        assert ImpactSeverity.LOW.value == "low"
        assert ImpactSeverity.MEDIUM.value == "medium"
        assert ImpactSeverity.HIGH.value == "high"
        assert ImpactSeverity.CRITICAL.value == "critical"
        
        # Verificar ordem de severidade
        severities = list(ImpactSeverity)
        assert severities[0] == ImpactSeverity.LOW
        assert severities[-1] == ImpactSeverity.CRITICAL
    
    def test_cost_type_enum(self):
        """Testa enum de tipos de custo."""
        assert CostType.INFRASTRUCTURE.value == "infrastructure"
        assert CostType.DEVELOPMENT.value == "development"
        assert CostType.SUPPORT.value == "support"
        assert CostType.REVENUE_LOSS.value == "revenue_loss"
        assert CostType.OPPORTUNITY.value == "opportunity_cost"
        assert CostType.COMPLIANCE.value == "compliance_penalty"


class TestFinancialImpactDataClass:
    """Testes para a classe FinancialImpact."""
    
    def test_financial_impact_creation(self):
        """Testa criação de FinancialImpact com dados reais."""
        impact = FinancialImpact(
            incident_id="incident_123",
            timestamp=datetime.utcnow(),
            service_name="real_service",
            failure_type="real_failure",
            duration_minutes=60,
            affected_requests=1000,
            retry_count=200,
            infrastructure_cost=Decimal("50.00"),
            development_cost=Decimal("300.00"),
            support_cost=Decimal("25.00"),
            revenue_loss=Decimal("500.00"),
            opportunity_cost=Decimal("100.00"),
            compliance_cost=Decimal("0.00"),
            total_direct_cost=Decimal("375.00"),
            total_indirect_cost=Decimal("600.00"),
            total_cost=Decimal("975.00"),
            cost_per_request=Decimal("0.975"),
            cost_per_minute=Decimal("16.25"),
            roi_impact=Decimal("-0.975"),
            severity=ImpactSeverity.HIGH,
            recommendations=["Implementar circuit breaker", "Adicionar cache"],
            environment="production",
            tracing_id="test_trace_123"
        )
        
        # Verificar estrutura
        assert impact.incident_id == "incident_123"
        assert impact.service_name == "real_service"
        assert impact.failure_type == "real_failure"
        assert impact.duration_minutes == 60
        assert impact.affected_requests == 1000
        assert impact.retry_count == 200
        assert impact.total_cost == Decimal("975.00")
        assert impact.severity == ImpactSeverity.HIGH
        assert len(impact.recommendations) == 2
        assert impact.environment == "production"
        assert impact.tracing_id == "test_trace_123"
    
    def test_financial_impact_calculations(self):
        """Testa cálculos automáticos de FinancialImpact."""
        # Criar impacto com custos básicos
        impact = FinancialImpact(
            incident_id="calc_test",
            timestamp=datetime.utcnow(),
            service_name="calc_service",
            failure_type="calc_failure",
            duration_minutes=30,
            affected_requests=500,
            retry_count=100,
            infrastructure_cost=Decimal("25.00"),
            development_cost=Decimal("150.00"),
            support_cost=Decimal("12.50"),
            revenue_loss=Decimal("250.00"),
            opportunity_cost=Decimal("50.00"),
            compliance_cost=Decimal("0.00"),
            total_direct_cost=Decimal("187.50"),
            total_indirect_cost=Decimal("300.00"),
            total_cost=Decimal("487.50"),
            cost_per_request=Decimal("0.975"),
            cost_per_minute=Decimal("16.25"),
            roi_impact=Decimal("-0.4875"),
            severity=ImpactSeverity.MEDIUM,
            recommendations=["Monitorar tendências"],
            environment="staging",
            tracing_id="calc_trace"
        )
        
        # Verificar cálculos
        assert impact.total_direct_cost == impact.infrastructure_cost + impact.development_cost + impact.support_cost
        assert impact.total_indirect_cost == impact.revenue_loss + impact.opportunity_cost + impact.compliance_cost
        assert impact.total_cost == impact.total_direct_cost + impact.total_indirect_cost
        assert impact.cost_per_request == impact.total_cost / impact.affected_requests
        assert impact.cost_per_minute == impact.total_cost / impact.duration_minutes 