#!/usr/bin/env python3
"""
🧪 TESTES UNITÁRIOS - SEMANTIC DRIFT REPORTER
Tracing ID: TEST_SEMANTIC_DRIFT_REPORTER_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Testar funcionalidades do sistema de relatórios de drift semântico
baseado no código real implementado em scripts/semantic_drift_reporter.py
"""

import pytest
import json
import numpy as np
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os

# Adiciona o diretório scripts ao path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts'))

from semantic_drift_reporter import (
    SemanticDriftReporter,
    DriftTrend,
    DriftImpact
)
from semantic_validator import SemanticField, SemanticDriftReport

class TestDriftTrend:
    """Testes para a classe DriftTrend."""
    
    def test_drift_trend_initialization(self):
        """Testa inicialização correta de DriftTrend."""
        dates = [datetime.now(), datetime.now() + timedelta(days=1)]
        drift_scores = [0.1, 0.2]
        field_counts = [5, 6]
        
        trend = DriftTrend(
            schema_name="user_schema",
            dates=dates,
            drift_scores=drift_scores,
            field_counts=field_counts,
            trend_direction="increasing",
            trend_strength=0.8
        )
        
        assert trend.schema_name == "user_schema"
        assert trend.dates == dates
        assert trend.drift_scores == drift_scores
        assert trend.field_counts == field_counts
        assert trend.trend_direction == "increasing"
        assert trend.trend_strength == 0.8

class TestDriftImpact:
    """Testes para a classe DriftImpact."""
    
    def test_drift_impact_initialization(self):
        """Testa inicialização correta de DriftImpact."""
        impact = DriftImpact(
            schema_name="user_schema",
            impact_level="high",
            affected_endpoints=["/api/users", "/api/profile"],
            risk_score=0.75,
            mitigation_effort="medium",
            estimated_issues=10
        )
        
        assert impact.schema_name == "user_schema"
        assert impact.impact_level == "high"
        assert impact.affected_endpoints == ["/api/users", "/api/profile"]
        assert impact.risk_score == 0.75
        assert impact.mitigation_effort == "medium"
        assert impact.estimated_issues == 10

class TestSemanticDriftReporter:
    """Testes para a classe SemanticDriftReporter."""
    
    @pytest.fixture
    def reporter(self, tmp_path):
        """Fixture para criar instância de SemanticDriftReporter."""
        reports_path = tmp_path / "reports"
        return SemanticDriftReporter(reports_path=str(reports_path))
    
    def test_reporter_initialization(self, reporter):
        """Testa inicialização correta do SemanticDriftReporter."""
        assert reporter.history_days == 30
        assert isinstance(reporter.validator, SemanticValidator)
        assert reporter.reports_path.exists()
    
    def test_calculate_trend_increasing(self, reporter):
        """Testa cálculo de tendência crescente."""
        values = [0.1, 0.2, 0.3, 0.4, 0.5]
        direction, strength = reporter._calculate_trend(values)
        
        assert direction == "increasing"
        assert strength > 0.5  # Correlação positiva forte
    
    def test_calculate_trend_decreasing(self, reporter):
        """Testa cálculo de tendência decrescente."""
        values = [0.5, 0.4, 0.3, 0.2, 0.1]
        direction, strength = reporter._calculate_trend(values)
        
        assert direction == "decreasing"
        assert strength > 0.5  # Correlação negativa forte
    
    def test_calculate_trend_stable(self, reporter):
        """Testa cálculo de tendência estável."""
        values = [0.3, 0.3, 0.3, 0.3, 0.3]
        direction, strength = reporter._calculate_trend(values)
        
        assert direction == "stable"
        assert strength < 0.1  # Correlação muito baixa
    
    def test_calculate_trend_single_value(self, reporter):
        """Testa cálculo de tendência com valor único."""
        values = [0.5]
        direction, strength = reporter._calculate_trend(values)
        
        assert direction == "stable"
        assert strength == 0.0
    
    def test_calculate_drift_impact_low(self, reporter):
        """Testa cálculo de impacto baixo."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=0.1,
            affected_fields=["field1"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "low"
        assert impact.risk_score < 0.5
        assert impact.mitigation_effort == "low"
    
    def test_calculate_drift_impact_medium(self, reporter):
        """Testa cálculo de impacto médio."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=0.4,
            affected_fields=["field1", "field2", "field3"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "medium"
        assert 0.2 <= impact.risk_score < 0.8
        assert impact.mitigation_effort == "medium"
    
    def test_calculate_drift_impact_high(self, reporter):
        """Testa cálculo de impacto alto."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=0.7,
            affected_fields=["field1", "field2", "field3", "field4", "field5"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "high"
        assert impact.risk_score >= 0.5
        assert impact.mitigation_effort == "high"
    
    def test_calculate_drift_impact_critical(self, reporter):
        """Testa cálculo de impacto crítico."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=0.9,
            affected_fields=["field1", "field2", "field3", "field4", "field5", "field6"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "critical"
        assert impact.risk_score >= 0.8
        assert impact.mitigation_effort == "high"
    
    def test_calculate_drift_impact_with_endpoints(self, reporter):
        """Testa cálculo de impacto com endpoints afetados."""
        drift_report = SemanticDriftReport(
            schema_name="user_schema",
            drift_detected=True,
            drift_score=0.5,
            affected_fields=["user_id", "email"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        schema_usage = {
            "user_schema": ["/api/users", "/api/profile", "/api/auth"]
        }
        
        impact = reporter.calculate_drift_impact(drift_report, schema_usage)
        
        assert impact.affected_endpoints == ["/api/users", "/api/profile", "/api/auth"]
    
    @patch('matplotlib.pyplot.savefig')
    @patch('matplotlib.pyplot.close')
    def test_generate_drift_visualization(self, mock_close, mock_savefig, reporter):
        """Testa geração de visualização de drift."""
        # Cria tendência de teste
        dates = [datetime.now(), datetime.now() + timedelta(days=1)]
        drift_trend = DriftTrend(
            schema_name="test_schema",
            dates=dates,
            drift_scores=[0.1, 0.2],
            field_counts=[5, 6],
            trend_direction="increasing",
            trend_strength=0.8
        )
        
        # Gera visualização
        output_path = reporter.generate_drift_visualization(drift_trend)
        
        # Verifica se foi salva
        assert mock_savefig.called
        assert mock_close.called
    
    def test_generate_drift_visualization_no_data(self, reporter):
        """Testa geração de visualização sem dados."""
        drift_trend = DriftTrend(
            schema_name="test_schema",
            dates=[],
            drift_scores=[],
            field_counts=[],
            trend_direction="stable",
            trend_strength=0.0
        )
        
        output_path = reporter.generate_drift_visualization(drift_trend)
        
        assert output_path == ""
    
    @patch('pathlib.Path.glob')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    def test_analyze_drift_history(self, mock_json_load, mock_file, mock_glob, reporter):
        """Testa análise de histórico de drift."""
        # Mock de arquivos históricos
        mock_file1 = Mock()
        mock_file1.stem = "test_schema_20250101_120000"
        mock_file2 = Mock()
        mock_file2.stem = "test_schema_20250102_120000"
        mock_glob.return_value = [mock_file1, mock_file2]
        
        # Mock de dados JSON
        mock_json_load.side_effect = [
            {"drift_score": 0.1, "affected_fields": ["field1"]},
            {"drift_score": 0.2, "affected_fields": ["field1", "field2"]}
        ]
        
        trend = reporter.analyze_drift_history("test_schema")
        
        assert isinstance(trend, DriftTrend)
        assert trend.schema_name == "test_schema"
        assert len(trend.dates) == 2
        assert len(trend.drift_scores) == 2
        assert len(trend.field_counts) == 2
    
    @patch('pathlib.Path.glob')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    def test_get_reference_schema(self, mock_json_load, mock_file, mock_glob, reporter):
        """Testa obtenção de schema de referência."""
        # Mock de arquivo histórico
        mock_history_file = Mock()
        mock_history_file.stat.return_value.st_mtime = 1234567890
        mock_glob.return_value = [mock_history_file]
        
        # Mock de dados JSON
        mock_json_load.return_value = {
            "reference_fields": [
                {
                    "field_name": "user_id",
                    "field_type": "integer",
                    "description": "ID do usuário"
                }
            ]
        }
        
        reference_fields = reporter._get_reference_schema("test_schema")
        
        assert isinstance(reference_fields, list)
        assert len(reference_fields) == 1
        assert isinstance(reference_fields[0], SemanticField)
        assert reference_fields[0].field_name == "user_id"
    
    def test_get_reference_schema_no_history(self, reporter):
        """Testa obtenção de schema de referência sem histórico."""
        with patch('pathlib.Path.glob', return_value=[]):
            reference_fields = reporter._get_reference_schema("test_schema")
        
        assert reference_fields == []
    
    @patch('pathlib.Path.glob')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('yaml.safe_load')
    def test_generate_comprehensive_report(self, mock_yaml_load, mock_json_load, mock_file, mock_glob, reporter):
        """Testa geração de relatório abrangente."""
        # Mock de arquivos de schema
        mock_schema_file = Mock()
        mock_schema_file.suffix = '.json'
        mock_schema_file.stem = 'test_schema'
        mock_glob.return_value = [mock_schema_file]
        
        # Mock de dados de schema
        schema_data = {
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Identificador do usuário"
                }
            }
        }
        mock_json_load.return_value = schema_data
        
        # Mock de análise semântica
        with patch.object(reporter.validator, 'analyze_schema_semantics') as mock_analyze:
            mock_analyze.return_value = [
                SemanticField("user_id", "integer", "Identificador do usuário")
            ]
            
            # Mock de detecção de drift
            with patch.object(reporter.validator, 'detect_semantic_drift') as mock_drift:
                mock_drift.return_value = SemanticDriftReport(
                    schema_name="test_schema",
                    drift_detected=True,
                    drift_score=0.5,
                    affected_fields=["user_id"],
                    drift_details=[],
                    timestamp=datetime.now(),
                    recommendations=[]
                )
                
                # Mock de análise de histórico
                with patch.object(reporter, 'analyze_drift_history') as mock_history:
                    mock_history.return_value = DriftTrend(
                        schema_name="test_schema",
                        dates=[datetime.now()],
                        drift_scores=[0.5],
                        field_counts=[1],
                        trend_direction="stable",
                        trend_strength=0.0
                    )
                    
                    report = reporter.generate_comprehensive_report()
        
        assert isinstance(report, dict)
        assert 'generated_at' in report
        assert 'summary' in report
        assert 'drift_reports' in report
        assert 'impact_analyses' in report
        assert 'drift_trends' in report
        assert 'recommendations' in report
        assert 'priority_actions' in report
    
    def test_generate_drift_recommendations(self, reporter):
        """Testa geração de recomendações de drift."""
        # Relatórios de drift de teste
        drift_reports = [
            SemanticDriftReport(
                schema_name="schema1",
                drift_detected=True,
                drift_score=0.8,
                affected_fields=["field1", "field2"],
                drift_details=[],
                timestamp=datetime.now(),
                recommendations=[]
            ),
            SemanticDriftReport(
                schema_name="schema2",
                drift_detected=True,
                drift_score=0.3,
                affected_fields=["field3"],
                drift_details=[],
                timestamp=datetime.now(),
                recommendations=[]
            )
        ]
        
        # Análises de impacto de teste
        impact_analyses = [
            DriftImpact(
                schema_name="schema1",
                impact_level="critical",
                affected_endpoints=[],
                risk_score=0.9,
                mitigation_effort="high",
                estimated_issues=10
            ),
            DriftImpact(
                schema_name="schema2",
                impact_level="medium",
                affected_endpoints=[],
                risk_score=0.5,
                mitigation_effort="medium",
                estimated_issues=5
            )
        ]
        
        recommendations = reporter._generate_drift_recommendations(drift_reports, impact_analyses)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Verifica se contém recomendações para impacto crítico
        critical_recommendations = [r for r in recommendations if "crítico" in r.lower()]
        assert len(critical_recommendations) > 0
    
    def test_generate_priority_actions(self, reporter):
        """Testa geração de ações prioritárias."""
        # Análises de impacto de teste
        impact_analyses = [
            DriftImpact(
                schema_name="schema1",
                impact_level="critical",
                affected_endpoints=["/api/users"],
                risk_score=0.9,
                mitigation_effort="high",
                estimated_issues=10
            ),
            DriftImpact(
                schema_name="schema2",
                impact_level="medium",
                affected_endpoints=["/api/profile"],
                risk_score=0.5,
                mitigation_effort="medium",
                estimated_issues=5
            ),
            DriftImpact(
                schema_name="schema3",
                impact_level="low",
                affected_endpoints=[],
                risk_score=0.2,
                mitigation_effort="low",
                estimated_issues=2
            )
        ]
        
        priority_actions = reporter._generate_priority_actions(impact_analyses)
        
        assert isinstance(priority_actions, list)
        assert len(priority_actions) <= 5  # Top 5
        
        # Verifica ordenação por prioridade
        priorities = [action['priority'] for action in priority_actions]
        assert priorities == sorted(priorities)
        
        # Verifica se primeiro item tem maior score de risco
        if priority_actions:
            assert priority_actions[0]['risk_score'] == 0.9
    
    def test_get_action_for_impact_critical(self, reporter):
        """Testa determinação de ação para impacto crítico."""
        impact = DriftImpact(
            schema_name="test_schema",
            impact_level="critical",
            affected_endpoints=[],
            risk_score=0.9,
            mitigation_effort="high",
            estimated_issues=10
        )
        
        action = reporter._get_action_for_impact(impact)
        
        assert "imediata" in action.lower()
        assert "corrigir" in action.lower()
    
    def test_get_action_for_impact_high(self, reporter):
        """Testa determinação de ação para impacto alto."""
        impact = DriftImpact(
            schema_name="test_schema",
            impact_level="high",
            affected_endpoints=[],
            risk_score=0.7,
            mitigation_effort="high",
            estimated_issues=8
        )
        
        action = reporter._get_action_for_impact(impact)
        
        assert "urgente" in action.lower()
        assert "revisar" in action.lower()
    
    def test_get_action_for_impact_medium(self, reporter):
        """Testa determinação de ação para impacto médio."""
        impact = DriftImpact(
            schema_name="test_schema",
            impact_level="medium",
            affected_endpoints=[],
            risk_score=0.5,
            mitigation_effort="medium",
            estimated_issues=5
        )
        
        action = reporter._get_action_for_impact(impact)
        
        assert "monitoramento" in action.lower()
        assert "acompanhar" in action.lower()
    
    def test_get_action_for_impact_low(self, reporter):
        """Testa determinação de ação para impacto baixo."""
        impact = DriftImpact(
            schema_name="test_schema",
            impact_level="low",
            affected_endpoints=[],
            risk_score=0.2,
            mitigation_effort="low",
            estimated_issues=2
        )
        
        action = reporter._get_action_for_impact(impact)
        
        assert "manutenção" in action.lower()
        assert "revisar" in action.lower()
    
    def test_save_drift_snapshot(self, reporter):
        """Testa salvamento de snapshot de drift."""
        # Campos de teste
        current_fields = [
            SemanticField("user_id", "integer", "Identificador do usuário"),
            SemanticField("email", "string", "Email do usuário")
        ]
        
        # Relatório de drift de teste
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=0.5,
            affected_fields=["user_id"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        # Salva snapshot
        snapshot_path = reporter.save_drift_snapshot("test_schema", current_fields, drift_report)
        
        assert isinstance(snapshot_path, str)
        assert "test_schema" in snapshot_path
        assert snapshot_path.endswith(".json")
        
        # Verifica se arquivo foi criado
        assert Path(snapshot_path).exists()

class TestSemanticDriftReporterIntegration:
    """Testes de integração para SemanticDriftReporter."""
    
    @pytest.fixture
    def reporter(self, tmp_path):
        """Fixture para reporter com diretório temporário."""
        reports_path = tmp_path / "reports"
        return SemanticDriftReporter(reports_path=str(reports_path))
    
    def test_end_to_end_drift_analysis_workflow(self, reporter):
        """Testa workflow completo de análise de drift."""
        # 1. Cria campos de teste
        current_fields = [
            reporter.validator.analyze_field_semantics("user_id", "integer", "Identificador único do usuário"),
            reporter.validator.analyze_field_semantics("email", "string", "Email do usuário")
        ]
        
        reference_fields = [
            reporter.validator.analyze_field_semantics("user_id", "integer", "ID do usuário"),
            reporter.validator.analyze_field_semantics("email", "string", "Endereço de email")
        ]
        
        # 2. Detecta drift
        drift_report = reporter.validator.detect_semantic_drift(
            current_fields, reference_fields, "test_schema"
        )
        
        # 3. Calcula impacto
        impact = reporter.calculate_drift_impact(drift_report)
        
        # 4. Verifica resultados
        assert isinstance(drift_report, SemanticDriftReport)
        assert isinstance(impact, DriftImpact)
        assert drift_report.schema_name == "test_schema"
        assert impact.schema_name == "test_schema"
    
    def test_comprehensive_report_generation_workflow(self, reporter):
        """Testa workflow de geração de relatório abrangente."""
        # Mock de arquivos de schema
        with patch('pathlib.Path.glob') as mock_glob:
            mock_schema_file = Mock()
            mock_schema_file.suffix = '.json'
            mock_schema_file.stem = 'test_schema'
            mock_glob.return_value = [mock_schema_file]
            
            # Mock de leitura de arquivo
            with patch('builtins.open', mock_open(read_data='{"properties": {"user_id": {"type": "integer", "description": "ID"}}}')):
                with patch('json.load', return_value={"properties": {"user_id": {"type": "integer", "description": "ID"}}}):
                    # Mock de análise semântica
                    with patch.object(reporter.validator, 'analyze_schema_semantics') as mock_analyze:
                        mock_analyze.return_value = [
                            SemanticField("user_id", "integer", "Identificador do usuário")
                        ]
                        
                        # Mock de detecção de drift
                        with patch.object(reporter.validator, 'detect_semantic_drift') as mock_drift:
                            mock_drift.return_value = SemanticDriftReport(
                                schema_name="test_schema",
                                drift_detected=True,
                                drift_score=0.5,
                                affected_fields=["user_id"],
                                drift_details=[],
                                timestamp=datetime.now(),
                                recommendations=[]
                            )
                            
                            # Mock de análise de histórico
                            with patch.object(reporter, 'analyze_drift_history') as mock_history:
                                mock_history.return_value = DriftTrend(
                                    schema_name="test_schema",
                                    dates=[datetime.now()],
                                    drift_scores=[0.5],
                                    field_counts=[1],
                                    trend_direction="stable",
                                    trend_strength=0.0
                                )
                                
                                # Gera relatório
                                report = reporter.generate_comprehensive_report()
                                
                                # Verifica estrutura do relatório
                                assert 'summary' in report
                                assert 'drift_reports' in report
                                assert 'impact_analyses' in report
                                assert 'recommendations' in report
                                assert 'priority_actions' in report

class TestSemanticDriftReporterEdgeCases:
    """Testes para casos extremos do SemanticDriftReporter."""
    
    @pytest.fixture
    def reporter(self, tmp_path):
        """Fixture para reporter."""
        reports_path = tmp_path / "reports"
        return SemanticDriftReporter(reports_path=str(reports_path))
    
    def test_calculate_trend_empty_values(self, reporter):
        """Testa cálculo de tendência com valores vazios."""
        direction, strength = reporter._calculate_trend([])
        
        assert direction == "stable"
        assert strength == 0.0
    
    def test_calculate_trend_single_value(self, reporter):
        """Testa cálculo de tendência com valor único."""
        direction, strength = reporter._calculate_trend([0.5])
        
        assert direction == "stable"
        assert strength == 0.0
    
    def test_calculate_trend_constant_values(self, reporter):
        """Testa cálculo de tendência com valores constantes."""
        direction, strength = reporter._calculate_trend([0.5, 0.5, 0.5, 0.5, 0.5])
        
        assert direction == "stable"
        assert strength < 0.1
    
    def test_calculate_drift_impact_zero_drift(self, reporter):
        """Testa cálculo de impacto com drift zero."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=False,
            drift_score=0.0,
            affected_fields=[],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "low"
        assert impact.risk_score < 0.2
    
    def test_calculate_drift_impact_maximum_drift(self, reporter):
        """Testa cálculo de impacto com drift máximo."""
        drift_report = SemanticDriftReport(
            schema_name="test_schema",
            drift_detected=True,
            drift_score=1.0,
            affected_fields=["field1", "field2", "field3", "field4", "field5", "field6", "field7", "field8", "field9", "field10"],
            drift_details=[],
            timestamp=datetime.now(),
            recommendations=[]
        )
        
        impact = reporter.calculate_drift_impact(drift_report)
        
        assert impact.impact_level == "critical"
        assert impact.risk_score >= 0.8
        assert impact.mitigation_effort == "high"

if __name__ == "__main__":
    # Executa testes se chamado diretamente
    pytest.main([__file__, "-v"]) 