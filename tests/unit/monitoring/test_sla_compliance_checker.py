"""
Testes Unitários - SLA Compliance Checker
========================================

Testes baseados em código real para o sistema de verificação de compliance de SLA.
Testa funcionalidades específicas implementadas no sla_compliance_checker.py.

Prompt: SLA Compliance Checker - Item 11
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T21:20:00Z
Tracing ID: SLA_COMPLIANCE_CHECKER_TEST_20250127_011

Regras de Teste:
- ✅ Baseado em código real implementado
- ✅ Testa funcionalidades específicas
- ❌ Proibido: dados fictícios, testes genéricos
- ❌ Proibido: foo, bar, lorem, random
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from monitoring.sla_compliance_checker import (
    SLAComplianceChecker,
    SLADefinition,
    SLAComplianceResult,
    SLAViolation,
    SLAReport,
    SLAStatus,
    SLAMetricType,
    SLAViolationSeverity,
    check_sla_compliance,
    generate_sla_report,
    get_sla_status_summary,
    get_sla_compliance_checker
)
from shared.feature_flags import FeatureFlagsManager


class TestSLAComplianceChecker:
    """Testes para a classe SLAComplianceChecker."""
    
    def setup_method(self):
        """Configuração para cada teste."""
        self.checker = SLAComplianceChecker("TEST_SLA_001")
        self.checker.enabled = True
        self.checker.alerting_enabled = True
    
    def test_checker_initialization(self):
        """Testa inicialização correta do checker."""
        assert self.checker.tracing_id.startswith("SLA_CHECKER_")
        assert self.checker.enabled is True
        assert self.checker.alerting_enabled is True
        assert len(self.checker.sla_definitions) > 0
        assert "availability_99_9" in self.checker.sla_definitions
        assert "response_time_2s" in self.checker.sla_definitions
    
    def test_default_sla_definitions(self):
        """Testa definições padrão de SLA."""
        slas = self.checker.sla_definitions
        
        # Verifica SLA de disponibilidade
        availability_sla = slas["availability_99_9"]
        assert availability_sla.name == "99.9% Uptime"
        assert availability_sla.metric_type == SLAMetricType.AVAILABILITY
        assert availability_sla.target_value == 99.9
        assert availability_sla.warning_threshold == 99.5
        assert availability_sla.critical_threshold == 99.0
        assert availability_sla.enabled is True
        
        # Verifica SLA de tempo de resposta
        response_sla = slas["response_time_2s"]
        assert response_sla.name == "Response Time < 2s"
        assert response_sla.metric_type == SLAMetricType.RESPONSE_TIME
        assert response_sla.target_value == 2.0
        assert response_sla.warning_threshold == 1.5
        assert response_sla.critical_threshold == 3.0
    
    def test_check_sla_compliance_availability_compliant(self):
        """Testa verificação de SLA de disponibilidade em compliance."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=99.95):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.sla_name == "99.9% Uptime"
            assert result.metric_type == SLAMetricType.AVAILABILITY
            assert result.current_value == 99.95
            assert result.status == SLAStatus.COMPLIANT
            assert result.compliance_percentage > 100.0
            assert result.violation_severity is None
    
    def test_check_sla_compliance_availability_warning(self):
        """Testa verificação de SLA de disponibilidade com warning."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=99.3):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.status == SLAStatus.WARNING
            assert result.violation_severity == SLAViolationSeverity.HIGH
            assert result.compliance_percentage < 100.0
    
    def test_check_sla_compliance_availability_violated(self):
        """Testa verificação de SLA de disponibilidade violado."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=98.5):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.status == SLAStatus.VIOLATED
            assert result.violation_severity == SLAViolationSeverity.CRITICAL
            assert result.compliance_percentage < 100.0
    
    def test_check_sla_compliance_response_time_compliant(self):
        """Testa verificação de SLA de tempo de resposta em compliance."""
        sla_def = self.checker.sla_definitions["response_time_2s"]
        
        with patch.object(self.checker, '_get_average_response_time', return_value=1.2):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.sla_name == "Response Time < 2s"
            assert result.metric_type == SLAMetricType.RESPONSE_TIME
            assert result.current_value == 1.2
            assert result.status == SLAStatus.COMPLIANT
            assert result.compliance_percentage > 100.0
    
    def test_check_sla_compliance_response_time_warning(self):
        """Testa verificação de SLA de tempo de resposta com warning."""
        sla_def = self.checker.sla_definitions["response_time_2s"]
        
        with patch.object(self.checker, '_get_average_response_time', return_value=1.8):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.status == SLAStatus.WARNING
            assert result.violation_severity == SLAViolationSeverity.HIGH
    
    def test_check_sla_compliance_response_time_violated(self):
        """Testa verificação de SLA de tempo de resposta violado."""
        sla_def = self.checker.sla_definitions["response_time_2s"]
        
        with patch.object(self.checker, '_get_average_response_time', return_value=3.5):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.status == SLAStatus.VIOLATED
            assert result.violation_severity == SLAViolationSeverity.CRITICAL
    
    def test_check_sla_compliance_error_rate_compliant(self):
        """Testa verificação de SLA de taxa de erro em compliance."""
        sla_def = self.checker.sla_definitions["error_rate_1_percent"]
        
        with patch.object(self.checker, '_get_error_rate', return_value=0.3):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.sla_name == "Error Rate < 1%"
            assert result.metric_type == SLAMetricType.ERROR_RATE
            assert result.current_value == 0.3
            assert result.status == SLAStatus.COMPLIANT
            assert result.compliance_percentage > 100.0
    
    def test_check_sla_compliance_error_rate_violated(self):
        """Testa verificação de SLA de taxa de erro violado."""
        sla_def = self.checker.sla_definitions["error_rate_1_percent"]
        
        with patch.object(self.checker, '_get_error_rate', return_value=2.5):
            result = self.checker._check_sla_compliance(sla_def)
            
            assert result.status == SLAStatus.VIOLATED
            assert result.violation_severity == SLAViolationSeverity.CRITICAL
    
    def test_calculate_compliance_percentage_availability(self):
        """Testa cálculo de compliance para disponibilidade."""
        # Disponibilidade: valor maior é melhor
        compliance = self.checker._calculate_compliance_percentage(99.5, 99.9, SLAMetricType.AVAILABILITY)
        assert compliance < 100.0  # Menor que meta
        
        compliance = self.checker._calculate_compliance_percentage(99.95, 99.9, SLAMetricType.AVAILABILITY)
        assert compliance > 100.0  # Maior que meta
    
    def test_calculate_compliance_percentage_response_time(self):
        """Testa cálculo de compliance para tempo de resposta."""
        # Tempo de resposta: valor menor é melhor
        compliance = self.checker._calculate_compliance_percentage(1.5, 2.0, SLAMetricType.RESPONSE_TIME)
        assert compliance > 100.0  # Menor que meta
        
        compliance = self.checker._calculate_compliance_percentage(2.5, 2.0, SLAMetricType.RESPONSE_TIME)
        assert compliance < 100.0  # Maior que meta
    
    def test_determine_sla_status_availability(self):
        """Testa determinação de status para disponibilidade."""
        # Disponibilidade: valor maior é melhor
        status = self.checker._determine_sla_status(99.95, 99.5, 99.0, SLAMetricType.AVAILABILITY)
        assert status == SLAStatus.COMPLIANT
        
        status = self.checker._determine_sla_status(99.3, 99.5, 99.0, SLAMetricType.AVAILABILITY)
        assert status == SLAStatus.WARNING
        
        status = self.checker._determine_sla_status(98.5, 99.5, 99.0, SLAMetricType.AVAILABILITY)
        assert status == SLAStatus.VIOLATED
    
    def test_determine_sla_status_response_time(self):
        """Testa determinação de status para tempo de resposta."""
        # Tempo de resposta: valor menor é melhor
        status = self.checker._determine_sla_status(1.2, 1.5, 3.0, SLAMetricType.RESPONSE_TIME)
        assert status == SLAStatus.COMPLIANT
        
        status = self.checker._determine_sla_status(1.8, 1.5, 3.0, SLAMetricType.RESPONSE_TIME)
        assert status == SLAStatus.WARNING
        
        status = self.checker._determine_sla_status(3.5, 1.5, 3.0, SLAMetricType.RESPONSE_TIME)
        assert status == SLAStatus.VIOLATED
    
    def test_determine_violation_severity(self):
        """Testa determinação de severidade de violação."""
        # Teste para disponibilidade
        severity = self.checker._determine_violation_severity(98.5, 99.5, 99.0, SLAMetricType.AVAILABILITY)
        assert severity == SLAViolationSeverity.CRITICAL
        
        severity = self.checker._determine_violation_severity(99.3, 99.5, 99.0, SLAMetricType.AVAILABILITY)
        assert severity == SLAViolationSeverity.HIGH
        
        # Teste para tempo de resposta
        severity = self.checker._determine_violation_severity(3.5, 1.5, 3.0, SLAMetricType.RESPONSE_TIME)
        assert severity == SLAViolationSeverity.CRITICAL
        
        severity = self.checker._determine_violation_severity(1.8, 1.5, 3.0, SLAMetricType.RESPONSE_TIME)
        assert severity == SLAViolationSeverity.HIGH
    
    def test_record_violation(self):
        """Testa registro de violação."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=98.5):
            result = self.checker._check_sla_compliance(sla_def)
            self.checker._record_violation(result)
            
            assert len(self.checker.violations) > 0
            violation = self.checker.violations[-1]
            assert violation.sla_name == "99.9% Uptime"
            assert violation.severity == SLAViolationSeverity.CRITICAL
            assert len(violation.recommendations) > 0
    
    def test_generate_violation_description(self):
        """Testa geração de descrição de violação."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=98.5):
            result = self.checker._check_sla_compliance(sla_def)
            description = self.checker._generate_violation_description(result)
            
            assert "Disponibilidade atual: 98.50%" in description
            assert "meta: 99.90%" in description
    
    def test_generate_violation_recommendations(self):
        """Testa geração de recomendações de violação."""
        sla_def = self.checker.sla_definitions["availability_99_9"]
        
        with patch.object(self.checker, '_calculate_availability', return_value=98.5):
            result = self.checker._check_sla_compliance(sla_def)
            recommendations = self.checker._generate_violation_recommendations(result)
            
            assert len(recommendations) > 0
            assert "Verificar health checks dos serviços" in recommendations
            assert "Analisar logs de erro recentes" in recommendations
    
    def test_check_all_slas(self):
        """Testa verificação de todos os SLAs."""
        with patch.object(self.checker, '_calculate_availability', return_value=99.95), \
             patch.object(self.checker, '_get_average_response_time', return_value=1.2), \
             patch.object(self.checker, '_get_error_rate', return_value=0.3), \
             patch.object(self.checker, '_get_throughput', return_value=85.0), \
             patch.object(self.checker, '_get_average_latency', return_value=350.0):
            
            results = self.checker.check_all_slas()
            
            assert len(results) == 5  # 5 SLAs padrão
            assert all(isinstance(result, SLAComplianceResult) for result in results)
            assert all(result.status == SLAStatus.COMPLIANT for result in results)
    
    def test_generate_compliance_report(self):
        """Testa geração de relatório de compliance."""
        with patch.object(self.checker, '_calculate_availability', return_value=99.95), \
             patch.object(self.checker, '_get_average_response_time', return_value=1.2), \
             patch.object(self.checker, '_get_error_rate', return_value=0.3), \
             patch.object(self.checker, '_get_throughput', return_value=85.0), \
             patch.object(self.checker, '_get_average_latency', return_value=350.0):
            
            report = self.checker.generate_compliance_report()
            
            assert isinstance(report, SLAReport)
            assert report.overall_compliance > 0
            assert len(report.sla_results) == 5
            assert report.summary['total_slas'] == 5
            assert report.summary['compliant_slas'] == 5
            assert len(report.recommendations) > 0
    
    def test_generate_compliance_report_with_violations(self):
        """Testa geração de relatório com violações."""
        with patch.object(self.checker, '_calculate_availability', return_value=98.5), \
             patch.object(self.checker, '_get_average_response_time', return_value=3.5), \
             patch.object(self.checker, '_get_error_rate', return_value=2.5), \
             patch.object(self.checker, '_get_throughput', return_value=45.0), \
             patch.object(self.checker, '_get_average_latency', return_value=800.0):
            
            # Gera violações primeiro
            self.checker.check_all_slas()
            
            report = self.checker.generate_compliance_report()
            
            assert report.overall_compliance < 100.0
            assert report.summary['violated_slas'] > 0
            assert len(report.violations) > 0
            assert len(report.recommendations) > 0
    
    def test_get_sla_status_summary(self):
        """Testa obtenção de resumo de status."""
        with patch.object(self.checker, '_calculate_availability', return_value=99.95), \
             patch.object(self.checker, '_get_average_response_time', return_value=1.2), \
             patch.object(self.checker, '_get_error_rate', return_value=0.3), \
             patch.object(self.checker, '_get_throughput', return_value=85.0), \
             patch.object(self.checker, '_get_average_latency', return_value=350.0):
            
            summary = self.checker.get_sla_status_summary()
            
            assert 'timestamp' in summary
            assert summary['total_slas'] == 5
            assert summary['compliant'] == 5
            assert summary['warning'] == 0
            assert summary['violated'] == 0
            assert summary['overall_compliance'] > 0
    
    def test_cleanup_old_data(self):
        """Testa limpeza de dados antigos."""
        # Adiciona violação antiga
        old_violation = SLAViolation(
            sla_name="test_sla",
            metric_type=SLAMetricType.AVAILABILITY,
            current_value=98.0,
            threshold_value=99.0,
            severity=SLAViolationSeverity.CRITICAL,
            duration=3600,
            timestamp=datetime.now() - timedelta(days=10),
            description="Test violation",
            recommendations=["Test recommendation"]
        )
        
        self.checker.violations.append(old_violation)
        initial_count = len(self.checker.violations)
        
        # Executa limpeza
        self.checker._cleanup_old_data()
        
        # Verifica se dados antigos foram removidos
        assert len(self.checker.violations) < initial_count


class TestSLAComplianceResult:
    """Testes para a classe SLAComplianceResult."""
    
    def test_sla_compliance_result_creation(self):
        """Testa criação de resultado de compliance."""
        result = SLAComplianceResult(
            sla_name="Test SLA",
            metric_type=SLAMetricType.AVAILABILITY,
            current_value=99.5,
            target_value=99.9,
            warning_threshold=99.5,
            critical_threshold=99.0,
            status=SLAStatus.WARNING,
            compliance_percentage=95.0,
            violation_severity=SLAViolationSeverity.HIGH,
            violation_duration=300
        )
        
        assert result.sla_name == "Test SLA"
        assert result.metric_type == SLAMetricType.AVAILABILITY
        assert result.current_value == 99.5
        assert result.target_value == 99.9
        assert result.status == SLAStatus.WARNING
        assert result.compliance_percentage == 95.0
        assert result.violation_severity == SLAViolationSeverity.HIGH
        assert result.violation_duration == 300
        assert isinstance(result.timestamp, datetime)


class TestSLAViolation:
    """Testes para a classe SLAViolation."""
    
    def test_sla_violation_creation(self):
        """Testa criação de violação de SLA."""
        violation = SLAViolation(
            sla_name="Test SLA",
            metric_type=SLAMetricType.AVAILABILITY,
            current_value=98.5,
            threshold_value=99.0,
            severity=SLAViolationSeverity.CRITICAL,
            duration=3600,
            timestamp=datetime.now(),
            description="Test violation description",
            recommendations=["Recommendation 1", "Recommendation 2"]
        )
        
        assert violation.sla_name == "Test SLA"
        assert violation.metric_type == SLAMetricType.AVAILABILITY
        assert violation.current_value == 98.5
        assert violation.threshold_value == 99.0
        assert violation.severity == SLAViolationSeverity.CRITICAL
        assert violation.duration == 3600
        assert violation.description == "Test violation description"
        assert len(violation.recommendations) == 2


class TestSLAReport:
    """Testes para a classe SLAReport."""
    
    def test_sla_report_creation(self):
        """Testa criação de relatório de SLA."""
        report = SLAReport(
            report_id="TEST_REPORT_001",
            timestamp=datetime.now(),
            overall_compliance=95.5,
            sla_results=[],
            violations=[],
            summary={'total_slas': 5, 'compliant_slas': 4},
            recommendations=["Recommendation 1"]
        )
        
        assert report.report_id == "TEST_REPORT_001"
        assert report.overall_compliance == 95.5
        assert report.summary['total_slas'] == 5
        assert report.summary['compliant_slas'] == 4
        assert len(report.recommendations) == 1


class TestFunctions:
    """Testes para funções utilitárias."""
    
    def test_get_sla_compliance_checker(self):
        """Testa função factory para obter checker."""
        checker = get_sla_compliance_checker("TEST_FUNCTION_001")
        
        assert isinstance(checker, SLAComplianceChecker)
        assert checker.tracing_id == "TEST_FUNCTION_001"
    
    def test_check_sla_compliance_function(self):
        """Testa função de verificação de SLA específico."""
        with patch.object(SLAComplianceChecker, '_check_sla_compliance') as mock_check:
            mock_result = SLAComplianceResult(
                sla_name="Test SLA",
                metric_type=SLAMetricType.AVAILABILITY,
                current_value=99.5,
                target_value=99.9,
                warning_threshold=99.5,
                critical_threshold=99.0,
                status=SLAStatus.WARNING,
                compliance_percentage=95.0
            )
            mock_check.return_value = mock_result
            
            result = check_sla_compliance("availability_99_9")
            
            assert result is not None
            assert result.sla_name == "Test SLA"
            assert result.status == SLAStatus.WARNING
    
    def test_generate_sla_report_function(self):
        """Testa função de geração de relatório."""
        with patch.object(SLAComplianceChecker, 'generate_compliance_report') as mock_generate:
            mock_report = SLAReport(
                report_id="TEST_REPORT_001",
                timestamp=datetime.now(),
                overall_compliance=95.5,
                sla_results=[],
                violations=[],
                summary={'total_slas': 5}
            )
            mock_generate.return_value = mock_report
            
            report = generate_sla_report()
            
            assert report.report_id == "TEST_REPORT_001"
            assert report.overall_compliance == 95.5
    
    def test_get_sla_status_summary_function(self):
        """Testa função de obtenção de resumo."""
        with patch.object(SLAComplianceChecker, 'get_sla_status_summary') as mock_summary:
            mock_summary.return_value = {
                'timestamp': '2025-01-27T21:20:00Z',
                'total_slas': 5,
                'compliant': 4,
                'warning': 1,
                'violated': 0,
                'overall_compliance': 95.0
            }
            
            summary = get_sla_status_summary()
            
            assert summary['total_slas'] == 5
            assert summary['compliant'] == 4
            assert summary['warning'] == 1
            assert summary['overall_compliance'] == 95.0


class TestFeatureFlags:
    """Testes para integração com feature flags."""
    
    def test_feature_flag_disabled(self):
        """Testa comportamento quando feature flag está desabilitado."""
        with patch.object(FeatureFlagsManager, 'is_enabled', return_value=False):
            checker = SLAComplianceChecker("TEST_FEATURE_FLAG_001")
            
            assert checker.enabled is False
            assert checker.alerting_enabled is False
    
    def test_feature_flag_enabled(self):
        """Testa comportamento quando feature flag está habilitado."""
        with patch.object(FeatureFlagsManager, 'is_enabled', return_value=True):
            checker = SLAComplianceChecker("TEST_FEATURE_FLAG_002")
            
            assert checker.enabled is True
            assert checker.alerting_enabled is True


class TestIntegration:
    """Testes de integração."""
    
    def test_full_sla_workflow(self):
        """Testa workflow completo de SLA."""
        checker = SLAComplianceChecker("TEST_WORKFLOW_001")
        
        # Simula métricas
        with patch.object(checker, '_calculate_availability', return_value=98.5), \
             patch.object(checker, '_get_average_response_time', return_value=1.2), \
             patch.object(checker, '_get_error_rate', return_value=0.3), \
             patch.object(checker, '_get_throughput', return_value=85.0), \
             patch.object(checker, '_get_average_latency', return_value=350.0):
            
            # Verifica todos os SLAs
            results = checker.check_all_slas()
            assert len(results) == 5
            
            # Gera relatório
            report = checker.generate_compliance_report()
            assert isinstance(report, SLAReport)
            assert report.overall_compliance > 0
            
            # Obtém resumo
            summary = checker.get_sla_status_summary()
            assert summary['total_slas'] == 5
    
    def test_violation_detection_and_alerting(self):
        """Testa detecção de violação e geração de alertas."""
        checker = SLAComplianceChecker("TEST_VIOLATION_001")
        
        # Simula violação de disponibilidade
        with patch.object(checker, '_calculate_availability', return_value=98.0), \
             patch.object(checker, '_get_average_response_time', return_value=1.2), \
             patch.object(checker, '_get_error_rate', return_value=0.3), \
             patch.object(checker, '_get_throughput', return_value=85.0), \
             patch.object(checker, '_get_average_latency', return_value=350.0):
            
            # Verifica SLAs
            results = checker.check_all_slas()
            
            # Verifica se violação foi detectada
            violated_results = [r for r in results if r.status == SLAStatus.VIOLATED]
            assert len(violated_results) > 0
            
            # Verifica se violação foi registrada
            assert len(checker.violations) > 0
            
            # Verifica se alerta foi gerado
            violation = checker.violations[-1]
            assert violation.severity == SLAViolationSeverity.CRITICAL
            assert len(violation.recommendations) > 0 