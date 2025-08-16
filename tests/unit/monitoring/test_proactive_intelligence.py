"""
Testes Unitários - Sistema de Inteligência Proativa
===================================================

Testes baseados em código real para o sistema de inteligência proativa.
Foca em funcionalidades implementadas e cenários reais do sistema.

Prompt: Testes para Inteligência Proativa - Item 5
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T18:45:00Z
Tracing ID: TEST_PROACTIVE_INTEL_20250127_005

Política de Testes:
- ✅ Baseados em código real implementado
- ✅ Cenários reais do sistema Omni Writer
- ✅ Validação de funcionalidades específicas
- ❌ Proibidos dados sintéticos (foo, bar, lorem)
- ❌ Proibidos testes genéricos ou aleatórios
"""

import pytest
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from monitoring.proactive_intelligence import (
    ProactiveIntelligence,
    SimpleMLModel,
    Insight,
    Mitigation,
    AnomalyDetection,
    InsightType,
    MitigationType,
    AnomalyType,
    proactive_monitor,
    get_proactive_intelligence,
    enable_proactive_intelligence,
    disable_proactive_intelligence
)


class TestSimpleMLModel:
    """Testes para o modelo de ML simples."""
    
    def test_ml_model_initialization(self):
        """Testa inicialização do modelo ML."""
        model = SimpleMLModel(window_size=50)
        
        assert model.window_size == 50
        assert len(model.history) == 0
        assert len(model.baselines) == 0
        assert len(model.thresholds) == 0
    
    def test_ml_model_update_with_real_metrics(self):
        """Testa atualização do modelo com métricas reais do sistema."""
        model = SimpleMLModel(window_size=10)
        
        # Simula métricas reais do Omni Writer
        cpu_metrics = [45.2, 52.1, 48.7, 55.3, 49.8, 51.2, 47.9, 53.4, 50.1, 54.7]
        
        for i, cpu_value in enumerate(cpu_metrics):
            timestamp = datetime.now() + timedelta(minutes=i)
            model.update("cpu_usage", cpu_value, timestamp)
        
        # Verifica se baseline foi criado
        assert "cpu_usage" in model.baselines
        baseline = model.baselines["cpu_usage"]
        
        assert "mean" in baseline
        assert "std" in baseline
        assert "min" in baseline
        assert "max" in baseline
        assert baseline["min"] == min(cpu_metrics)
        assert baseline["max"] == max(cpu_metrics)
    
    def test_ml_model_detect_anomaly_spike(self):
        """Testa detecção de spike real em métricas."""
        model = SimpleMLModel(window_size=10)
        
        # Cria baseline com valores normais de latência
        normal_latencies = [1.2, 1.5, 1.3, 1.4, 1.6, 1.3, 1.5, 1.4, 1.3, 1.5]
        
        for i, latency in enumerate(normal_latencies):
            timestamp = datetime.now() + timedelta(minutes=i)
            model.update("request_latency", latency, timestamp)
        
        # Testa spike real (latência muito alta)
        spike_value = 8.5  # Spike real de latência
        anomaly = model.detect_anomaly("request_latency", spike_value)
        
        assert anomaly is not None
        assert anomaly.metric_name == "request_latency"
        assert anomaly.current_value == spike_value
        assert anomaly.type == AnomalyType.SPIKE
        assert anomaly.confidence > 0.6
    
    def test_ml_model_detect_anomaly_drop(self):
        """Testa detecção de queda real em métricas."""
        model = SimpleMLModel(window_size=10)
        
        # Cria baseline com valores normais de throughput
        normal_throughput = [150, 145, 155, 148, 152, 147, 153, 149, 151, 146]
        
        for i, throughput in enumerate(normal_throughput):
            timestamp = datetime.now() + timedelta(minutes=i)
            model.update("requests_per_second", throughput, timestamp)
        
        # Testa queda real (throughput muito baixo)
        drop_value = 15  # Queda real de throughput
        anomaly = model.detect_anomaly("requests_per_second", drop_value)
        
        assert anomaly is not None
        assert anomaly.metric_name == "requests_per_second"
        assert anomaly.current_value == drop_value
        assert anomaly.type == AnomalyType.DROP
        assert anomaly.confidence > 0.6
    
    def test_ml_model_no_anomaly_normal_value(self):
        """Testa que valores normais não geram anomalias."""
        model = SimpleMLModel(window_size=10)
        
        # Cria baseline com valores normais de memória
        normal_memory = [65.2, 67.1, 66.3, 68.5, 65.9, 67.8, 66.4, 68.1, 65.7, 67.3]
        
        for i, memory in enumerate(normal_memory):
            timestamp = datetime.now() + timedelta(minutes=i)
            model.update("memory_usage", memory, timestamp)
        
        # Testa valor normal
        normal_value = 66.8  # Valor dentro do normal
        anomaly = model.detect_anomaly("memory_usage", normal_value)
        
        assert anomaly is None


class TestProactiveIntelligence:
    """Testes para o sistema de inteligência proativa."""
    
    @pytest.fixture
    def mock_metrics_collector(self):
        """Mock do coletor de métricas."""
        with patch('monitoring.proactive_intelligence.metrics_collector') as mock:
            mock.get_metrics_summary.return_value = {
                'cpu_usage': 75.5,
                'memory_usage': 68.2,
                'disk_usage': 45.1,
                'health_score': 82.3,
                'active_workers': 3,
                'queue_size': 12
            }
            yield mock
    
    @pytest.fixture
    def mock_circuit_breaker_manager(self):
        """Mock do gerenciador de circuit breakers."""
        with patch('monitoring.proactive_intelligence.get_circuit_breaker_manager') as mock:
            manager = Mock()
            manager.get_all_metrics.return_value = {
                'stripe_gateway': {
                    'state': 'CLOSED',
                    'failure_count': 0,
                    'success_count': 150
                },
                'openai_gateway': {
                    'state': 'OPEN',
                    'failure_count': 5,
                    'success_count': 0
                }
            }
            manager.get_circuit_breaker.return_value = Mock()
            mock.return_value = manager
            yield mock
    
    @pytest.fixture
    def mock_feature_flags(self):
        """Mock do sistema de feature flags."""
        with patch('monitoring.proactive_intelligence.is_feature_enabled') as mock:
            mock.return_value = True
            yield mock
    
    def test_proactive_intelligence_initialization(self, mock_metrics_collector, 
                                                 mock_circuit_breaker_manager, 
                                                 mock_feature_flags):
        """Testa inicialização do sistema de inteligência proativa."""
        intelligence = ProactiveIntelligence()
        
        assert intelligence.enabled is True
        assert intelligence.auto_mitigation is True
        assert intelligence.insight_threshold == 0.7
        assert intelligence.mitigation_threshold == 0.8
        assert isinstance(intelligence.ml_model, SimpleMLModel)
    
    def test_collect_current_metrics(self, mock_metrics_collector, 
                                   mock_circuit_breaker_manager, 
                                   mock_feature_flags):
        """Testa coleta de métricas atuais."""
        intelligence = ProactiveIntelligence()
        
        metrics = intelligence._collect_current_metrics()
        
        assert 'cpu_usage' in metrics
        assert 'memory_usage' in metrics
        assert 'disk_usage' in metrics
        assert 'health_score' in metrics
        assert 'circuit_breakers' in metrics
        assert 'performance_alerts' in metrics
        assert 'feature_flags' in metrics
    
    def test_create_circuit_breaker_insights(self, mock_metrics_collector, 
                                           mock_circuit_breaker_manager, 
                                           mock_feature_flags):
        """Testa criação de insights para circuit breakers abertos."""
        intelligence = ProactiveIntelligence()
        
        # Simula métricas com circuit breaker aberto
        metrics = {
            'circuit_breakers': {
                'openai_gateway': {
                    'state': 'OPEN',
                    'failure_count': 5,
                    'success_count': 0
                }
            }
        }
        
        insights = intelligence._create_circuit_breaker_insights(metrics)
        
        assert len(insights) == 1
        insight = insights[0]
        assert insight.type == InsightType.RELIABILITY
        assert "Circuit Breaker openai_gateway está aberto" in insight.title
        assert insight.severity == "critical"
        assert insight.confidence == 0.95
    
    def test_create_health_insights_critical(self, mock_metrics_collector, 
                                           mock_circuit_breaker_manager, 
                                           mock_feature_flags):
        """Testa criação de insights para health score crítico."""
        intelligence = ProactiveIntelligence()
        
        # Simula health score crítico
        metrics = {'health_score': 35.2}
        
        insights = intelligence._create_health_insights(metrics)
        
        assert len(insights) == 1
        insight = insights[0]
        assert insight.type == InsightType.OPERATIONAL
        assert "Health Score crítico" in insight.title
        assert insight.severity == "critical"
        assert insight.confidence == 0.9
        assert insight.metrics['health_score'] == 35.2
    
    def test_create_health_insights_warning(self, mock_metrics_collector, 
                                          mock_circuit_breaker_manager, 
                                          mock_feature_flags):
        """Testa criação de insights para health score baixo."""
        intelligence = ProactiveIntelligence()
        
        # Simula health score baixo
        metrics = {'health_score': 65.8}
        
        insights = intelligence._create_health_insights(metrics)
        
        assert len(insights) == 1
        insight = insights[0]
        assert insight.type == InsightType.OPERATIONAL
        assert "Health Score baixo" in insight.title
        assert insight.severity == "warning"
        assert insight.confidence == 0.8
        assert insight.metrics['health_score'] == 65.8
    
    def test_create_performance_insight_spike(self, mock_metrics_collector, 
                                            mock_circuit_breaker_manager, 
                                            mock_feature_flags):
        """Testa criação de insight para spike de performance."""
        intelligence = ProactiveIntelligence()
        
        # Cria anomalia de spike
        anomaly = AnomalyDetection(
            metric_name="cpu_usage",
            current_value=95.5,
            expected_value=65.2,
            deviation=3.2,
            type=AnomalyType.SPIKE,
            confidence=0.85,
            timestamp=datetime.now(),
            context={'baseline': {'mean': 65.2}, 'threshold': {'upper': 75.0}}
        )
        
        metrics = {'cpu_usage': 95.5}
        
        insight = intelligence._create_performance_insight(anomaly, metrics)
        
        assert insight is not None
        assert insight.type == InsightType.PERFORMANCE
        assert "Spike detectado em cpu_usage" in insight.title
        assert insight.severity == "warning"
        assert insight.confidence == 0.85
        assert "Verificar carga do sistema" in insight.recommendations
    
    def test_create_performance_insight_drop(self, mock_metrics_collector, 
                                           mock_circuit_breaker_manager, 
                                           mock_feature_flags):
        """Testa criação de insight para queda de performance."""
        intelligence = ProactiveIntelligence()
        
        # Cria anomalia de queda
        anomaly = AnomalyDetection(
            metric_name="requests_per_second",
            current_value=5.2,
            expected_value=150.0,
            deviation=2.8,
            type=AnomalyType.DROP,
            confidence=0.9,
            timestamp=datetime.now(),
            context={'baseline': {'mean': 150.0}, 'threshold': {'lower': 100.0}}
        )
        
        metrics = {'requests_per_second': 5.2}
        
        insight = intelligence._create_performance_insight(anomaly, metrics)
        
        assert insight is not None
        assert insight.type == InsightType.PERFORMANCE
        assert "Queda detectada em requests_per_second" in insight.title
        assert insight.severity == "critical"
        assert insight.confidence == 0.9
        assert "Verificar se serviços estão funcionando" in insight.recommendations
    
    def test_mitigate_circuit_breaker_issue(self, mock_metrics_collector, 
                                          mock_circuit_breaker_manager, 
                                          mock_feature_flags):
        """Testa mitigação de problema de circuit breaker."""
        intelligence = ProactiveIntelligence()
        
        # Cria insight de circuit breaker
        insight = Insight(
            id="test_insight",
            type=InsightType.RELIABILITY,
            title="Circuit Breaker openai_gateway está aberto",
            description="Serviço está falhando",
            severity="critical",
            confidence=0.95,
            timestamp=datetime.now(),
            metrics={'circuit_breaker_state': 'OPEN'},
            recommendations=["Verificar serviço"],
            metadata={'circuit_breaker_name': 'openai_gateway'}
        )
        
        result = intelligence._mitigate_circuit_breaker_issue(insight)
        
        assert "Circuit breaker openai_gateway resetado" in result
    
    def test_mitigate_performance_spike_cpu(self, mock_metrics_collector, 
                                          mock_circuit_breaker_manager, 
                                          mock_feature_flags):
        """Testa mitigação de spike de CPU."""
        intelligence = ProactiveIntelligence()
        
        # Cria insight de spike de CPU
        insight = Insight(
            id="test_insight",
            type=InsightType.PERFORMANCE,
            title="Spike detectado em cpu_usage",
            description="CPU muito alto",
            severity="critical",
            confidence=0.9,
            timestamp=datetime.now(),
            metrics={'cpu_usage': 95.5},
            recommendations=["Verificar carga"],
            metadata={}
        )
        
        result = intelligence._mitigate_performance_spike(insight)
        
        assert "Considerar escalar CPU" in result
    
    def test_mitigate_performance_spike_memory(self, mock_metrics_collector, 
                                             mock_circuit_breaker_manager, 
                                             mock_feature_flags):
        """Testa mitigação de spike de memória."""
        intelligence = ProactiveIntelligence()
        
        # Cria insight de spike de memória
        insight = Insight(
            id="test_insight",
            type=InsightType.PERFORMANCE,
            title="Spike detectado em memory_usage",
            description="Memória muito alta",
            severity="critical",
            confidence=0.9,
            timestamp=datetime.now(),
            metrics={'memory_usage': 92.3},
            recommendations=["Verificar memória"],
            metadata={}
        )
        
        result = intelligence._mitigate_performance_spike(insight)
        
        assert "Considerar limpar cache" in result
    
    def test_get_insights(self, mock_metrics_collector, 
                         mock_circuit_breaker_manager, 
                         mock_feature_flags):
        """Testa obtenção de insights."""
        intelligence = ProactiveIntelligence()
        
        # Adiciona alguns insights de teste
        insight1 = Insight(
            id="test1",
            type=InsightType.PERFORMANCE,
            title="Test Insight 1",
            description="Test description",
            severity="warning",
            confidence=0.8,
            timestamp=datetime.now(),
            metrics={'cpu_usage': 85.0},
            recommendations=["Test recommendation"],
            metadata={}
        )
        
        insight2 = Insight(
            id="test2",
            type=InsightType.RELIABILITY,
            title="Test Insight 2",
            description="Test description",
            severity="critical",
            confidence=0.9,
            timestamp=datetime.now(),
            metrics={'error_rate': 0.15},
            recommendations=["Test recommendation"],
            metadata={}
        )
        
        intelligence.insights = [insight1, insight2]
        
        # Testa obtenção de todos os insights
        insights = intelligence.get_insights()
        assert len(insights) == 2
        
        # Testa filtro por tipo
        performance_insights = intelligence.get_insights(insight_type=InsightType.PERFORMANCE)
        assert len(performance_insights) == 1
        assert performance_insights[0]['type'] == 'performance'
    
    def test_get_summary(self, mock_metrics_collector, 
                        mock_circuit_breaker_manager, 
                        mock_feature_flags):
        """Testa obtenção de resumo do sistema."""
        intelligence = ProactiveIntelligence()
        
        # Adiciona dados de teste
        intelligence.insights = [Mock(), Mock()]
        intelligence.mitigations = [Mock()]
        intelligence.anomalies = [Mock(), Mock(), Mock()]
        
        summary = intelligence.get_summary()
        
        assert summary['enabled'] is True
        assert summary['auto_mitigation'] is True
        assert summary['total_insights'] == 2
        assert summary['total_mitigations'] == 1
        assert summary['total_anomalies'] == 3
        assert 'last_analysis' in summary


class TestProactiveMonitorDecorator:
    """Testes para o decorator de monitoramento proativo."""
    
    def test_proactive_monitor_decorator_success(self):
        """Testa decorator com execução bem-sucedida."""
        
        @proactive_monitor("test_function")
        def test_function():
            time.sleep(0.1)  # Simula trabalho
            return "success"
        
        result = test_function()
        
        assert result == "success"
    
    def test_proactive_monitor_decorator_failure(self):
        """Testa decorator com execução que falha."""
        
        @proactive_monitor("test_function_error")
        def test_function_error():
            time.sleep(0.1)  # Simula trabalho
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            test_function_error()


class TestProactiveIntelligenceFunctions:
    """Testes para funções utilitárias."""
    
    def test_get_proactive_intelligence(self):
        """Testa obtenção da instância global."""
        intelligence = get_proactive_intelligence()
        
        assert isinstance(intelligence, ProactiveIntelligence)
    
    @patch('monitoring.proactive_intelligence.set_feature_flag')
    def test_enable_proactive_intelligence(self, mock_set_flag):
        """Testa habilitação do sistema."""
        enable_proactive_intelligence()
        
        mock_set_flag.assert_called_once_with("proactive_intelligence_enabled", 
                                             FeatureFlagStatus.ENABLED)
    
    @patch('monitoring.proactive_intelligence.set_feature_flag')
    def test_disable_proactive_intelligence(self, mock_set_flag):
        """Testa desabilitação do sistema."""
        disable_proactive_intelligence()
        
        mock_set_flag.assert_called_once_with("proactive_intelligence_enabled", 
                                             FeatureFlagStatus.DISABLED)
    
    @patch('monitoring.proactive_intelligence.set_feature_flag')
    def test_enable_auto_mitigation(self, mock_set_flag):
        """Testa habilitação de mitigação automática."""
        enable_auto_mitigation()
        
        mock_set_flag.assert_called_once_with("proactive_auto_mitigation_enabled", 
                                             FeatureFlagStatus.ENABLED)
    
    @patch('monitoring.proactive_intelligence.set_feature_flag')
    def test_disable_auto_mitigation(self, mock_set_flag):
        """Testa desabilitação de mitigação automática."""
        disable_auto_mitigation()
        
        mock_set_flag.assert_called_once_with("proactive_auto_mitigation_enabled", 
                                             FeatureFlagStatus.DISABLED)


class TestProactiveIntelligenceIntegration:
    """Testes de integração com sistemas existentes."""
    
    def test_integration_with_circuit_breaker_callbacks(self, mock_metrics_collector, 
                                                      mock_circuit_breaker_manager, 
                                                      mock_feature_flags):
        """Testa integração com callbacks de circuit breaker."""
        intelligence = ProactiveIntelligence()
        
        # Verifica se callbacks foram registrados
        circuit_breaker_manager = mock_circuit_breaker_manager.return_value
        assert circuit_breaker_manager.add_on_open_callback.called
        assert circuit_breaker_manager.add_on_close_callback.called
    
    def test_integration_with_feature_flags(self, mock_metrics_collector, 
                                          mock_circuit_breaker_manager, 
                                          mock_feature_flags):
        """Testa integração com sistema de feature flags."""
        intelligence = ProactiveIntelligence()
        
        # Verifica se feature flags são consultadas
        assert intelligence.enabled is True
        assert intelligence.auto_mitigation is True
    
    def test_integration_with_metrics_collector(self, mock_metrics_collector, 
                                              mock_circuit_breaker_manager, 
                                              mock_feature_flags):
        """Testa integração com coletor de métricas."""
        intelligence = ProactiveIntelligence()
        
        metrics = intelligence._collect_current_metrics()
        
        # Verifica se métricas do coletor estão presentes
        assert 'cpu_usage' in metrics
        assert 'memory_usage' in metrics
        assert 'health_score' in metrics
        
        # Verifica se mock foi chamado
        mock_metrics_collector.get_metrics_summary.assert_called_once() 