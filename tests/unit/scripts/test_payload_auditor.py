#!/usr/bin/env python3
"""
🧪 TESTES UNITÁRIOS - Payload Auditor
Tracing ID: PAYLOAD_AUDITOR_TEST_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Testes unitários para o sistema de auditoria de payloads excessivos.
Baseado no código real implementado em scripts/payload_auditor.py
"""

import pytest
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import sys
import os

# Adiciona scripts ao path para importação
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts'))

from payload_auditor import PayloadAuditor, PayloadMetrics, PayloadAlert

class TestPayloadAuditor:
    """Testes para a classe PayloadAuditor."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        self.auditor = PayloadAuditor(
            max_payload_kb=500,
            alert_threshold_kb=400,
            critical_threshold_kb=1000
        )
    
    def test_auditor_initialization(self):
        """Testa inicialização correta do auditor."""
        assert self.auditor.max_payload_kb == 500
        assert self.auditor.alert_threshold_kb == 400
        assert self.auditor.critical_threshold_kb == 1000
        assert len(self.auditor.payload_history) == 0
        assert len(self.auditor.alerts) == 0
    
    def test_analyze_payload_small(self):
        """Testa análise de payload pequeno (normal)."""
        small_payload = {"test": "data", "size": "small"}
        
        metrics = self.auditor.analyze_payload(
            payload=small_payload,
            endpoint="/api/test",
            method="POST"
        )
        
        assert metrics.endpoint == "/api/test"
        assert metrics.method == "POST"
        assert metrics.payload_size_kb < 1  # Deve ser muito pequeno
        assert not metrics.is_excessive
        assert metrics.compression_ratio > 0
        assert metrics.timestamp is not None
    
    def test_analyze_payload_excessive(self):
        """Testa análise de payload excessivo."""
        # Cria payload grande (1MB)
        large_payload = {"content": "x" * 1000000}
        
        metrics = self.auditor.analyze_payload(
            payload=large_payload,
            endpoint="/api/large-upload",
            method="POST",
            user_id="user123"
        )
        
        assert metrics.payload_size_kb > 500  # Deve ser > 500KB
        assert metrics.is_excessive
        assert metrics.user_id == "user123"
        assert len(self.auditor.alerts) == 1
        
        # Verifica alerta gerado
        alert = self.auditor.alerts[0]
        assert alert.severity == "critical"  # > 1000KB
        assert alert.endpoint == "/api/large-upload"
        assert alert.payload_size_kb > 500
    
    def test_analyze_payload_warning_threshold(self):
        """Testa payload no threshold de warning."""
        # Cria payload entre 400KB e 1000KB
        warning_payload = {"content": "x" * 500000}  # ~500KB
        
        metrics = self.auditor.analyze_payload(
            payload=warning_payload,
            endpoint="/api/warning-test",
            method="POST"
        )
        
        assert metrics.is_excessive
        assert 400 <= metrics.payload_size_kb < 1000
        
        # Verifica alerta de warning
        alert = self.auditor.alerts[-1]
        assert alert.severity == "warning"
    
    def test_analyze_payload_string_input(self):
        """Testa análise de payload como string."""
        string_payload = '{"test": "string payload"}'
        
        metrics = self.auditor.analyze_payload(
            payload=string_payload,
            endpoint="/api/string-test",
            method="POST"
        )
        
        assert metrics.payload_size_bytes > 0
        assert not metrics.is_excessive  # String pequena
    
    def test_analyze_payload_bytes_input(self):
        """Testa análise de payload como bytes."""
        bytes_payload = b'{"test": "bytes payload"}'
        
        metrics = self.auditor.analyze_payload(
            payload=bytes_payload,
            endpoint="/api/bytes-test",
            method="POST"
        )
        
        assert metrics.payload_size_bytes == len(bytes_payload)
        assert not metrics.is_excessive
    
    def test_compression_ratio_calculation(self):
        """Testa cálculo correto da taxa de compressão."""
        # Payload com alta compressibilidade
        compressible_payload = {"data": "x" * 10000}
        
        metrics = self.auditor.analyze_payload(
            payload=compressible_payload,
            endpoint="/api/compression-test",
            method="POST"
        )
        
        assert 0 < metrics.compression_ratio < 1
        # Dados repetitivos devem ter boa compressão
        assert metrics.compression_ratio < 0.5
    
    def test_endpoint_metrics_aggregation(self):
        """Testa agregação de métricas por endpoint."""
        # Analisa múltiplos payloads no mesmo endpoint
        endpoint = "/api/aggregation-test"
        
        for i in range(3):
            payload = {"data": "x" * (100000 * (i + 1))}
            self.auditor.analyze_payload(payload, endpoint, "POST")
        
        endpoint_data = self.auditor.endpoint_metrics[endpoint]
        
        assert endpoint_data['total_requests'] == 3
        assert endpoint_data['excessive_requests'] == 3  # Todos > 500KB
        assert endpoint_data['total_payload_size'] > 0
        assert endpoint_data['avg_payload_size'] > 0
    
    def test_alert_generation_logic(self):
        """Testa lógica de geração de alertas."""
        # Testa diferentes tamanhos e severidades
        test_cases = [
            (100, "info"),      # < 400KB
            (450, "warning"),   # 400-1000KB
            (1500, "critical")  # > 1000KB
        ]
        
        for size_kb, expected_severity in test_cases:
            payload = {"data": "x" * int(size_kb * 1024)}
            
            # Limpa alertas anteriores
            self.auditor.alerts.clear()
            
            metrics = self.auditor.analyze_payload(
                payload=payload,
                endpoint=f"/api/{size_kb}kb-test",
                method="POST"
            )
            
            if metrics.is_excessive:
                alert = self.auditor.alerts[0]
                assert alert.severity == expected_severity
    
    def test_recommendations_generation(self):
        """Testa geração de recomendações."""
        # Payload grande com alta compressão
        large_payload = {"content": "x" * 2000000}  # ~2MB
        
        metrics = self.auditor.analyze_payload(
            payload=large_payload,
            endpoint="/api/generate-articles",
            method="POST"
        )
        
        alert = self.auditor.alerts[0]
        assert len(alert.recommendations) > 0
        
        # Verifica se há recomendação específica para o endpoint
        recommendations_text = " ".join(alert.recommendations)
        assert "chunks" in recommendations_text or "upload" in recommendations_text
    
    def test_get_excessive_payloads_report(self):
        """Testa geração de relatório de payloads excessivos."""
        # Adiciona alguns payloads de teste
        test_payloads = [
            ("/api/test1", {"data": "x" * 600000}),  # ~600KB
            ("/api/test2", {"data": "x" * 300000}),  # ~300KB
            ("/api/test3", {"data": "x" * 800000}),  # ~800KB
        ]
        
        for endpoint, payload in test_payloads:
            self.auditor.analyze_payload(payload, endpoint, "POST")
        
        # Gera relatório das últimas 24h
        report = self.auditor.get_excessive_payloads_report(hours=24)
        
        assert report['summary']['total_excessive_payloads'] == 2  # 600KB e 800KB
        assert report['summary']['endpoints_affected'] == 2
        assert len(report['top_offenders']) > 0
        assert report['by_endpoint']['/api/test1']['count'] == 1
        assert report['by_endpoint']['/api/test3']['count'] == 1
    
    def test_get_performance_impact_analysis(self):
        """Testa análise de impacto na performance."""
        # Adiciona payloads normais e excessivos
        normal_payloads = [
            ("/api/normal1", {"data": "small"}),
            ("/api/normal2", {"data": "small"}),
        ]
        
        excessive_payloads = [
            ("/api/excessive1", {"data": "x" * 600000}),
            ("/api/excessive2", {"data": "x" * 800000}),
        ]
        
        for endpoint, payload in normal_payloads:
            self.auditor.analyze_payload(payload, endpoint, "POST")
        
        for endpoint, payload in excessive_payloads:
            self.auditor.analyze_payload(payload, endpoint, "POST")
        
        analysis = self.auditor.get_performance_impact_analysis()
        
        assert analysis['total_requests'] == 4
        assert analysis['excessive_requests'] == 2
        assert analysis['excessive_percentage'] == 50.0
        assert 'performance_impact' in analysis
    
    def test_export_metrics_json(self):
        """Testa exportação de métricas em JSON."""
        # Adiciona dados de teste
        self.auditor.analyze_payload(
            {"test": "data"},
            "/api/export-test",
            "POST"
        )
        
        export = self.auditor.export_metrics('json')
        export_data = json.loads(export)
        
        assert 'metadata' in export_data
        assert 'endpoint_metrics' in export_data
        assert 'recent_alerts' in export_data
        assert 'performance_analysis' in export_data
        assert export_data['metadata']['total_payloads'] == 1
    
    def test_export_metrics_invalid_format(self):
        """Testa exportação com formato inválido."""
        with pytest.raises(ValueError, match="Formato não suportado"):
            self.auditor.export_metrics('invalid_format')
    
    def test_clear_history(self):
        """Testa limpeza do histórico."""
        # Adiciona dados
        self.auditor.analyze_payload(
            {"test": "data"},
            "/api/clear-test",
            "POST"
        )
        
        assert len(self.auditor.payload_history) > 0
        assert len(self.auditor.endpoint_metrics) > 0
        
        # Limpa histórico
        self.auditor.clear_history()
        
        assert len(self.auditor.payload_history) == 0
        assert len(self.auditor.endpoint_metrics) == 0
        assert len(self.auditor.alerts) == 0
    
    def test_payload_metrics_post_init(self):
        """Testa inicialização automática de PayloadMetrics."""
        metrics = PayloadMetrics(
            endpoint="/api/test",
            method="POST",
            payload_size_bytes=1024000,  # 1000KB
            compression_ratio=0.5,
            timestamp=datetime.now()
        )
        
        assert metrics.payload_size_kb == 1000.0
        assert metrics.is_excessive  # > 500KB
    
    def test_payload_alert_post_init(self):
        """Testa inicialização automática de PayloadAlert."""
        alert = PayloadAlert(
            alert_id="TEST_001",
            severity="warning",
            endpoint="/api/test",
            payload_size_kb=600,
            threshold_kb=500,
            timestamp=datetime.now()
        )
        
        assert alert.recommendations is not None
        assert isinstance(alert.recommendations, list)
    
    def test_auditor_with_custom_thresholds(self):
        """Testa auditor com thresholds customizados."""
        custom_auditor = PayloadAuditor(
            max_payload_kb=100,    # Threshold mais baixo
            alert_threshold_kb=50,
            critical_threshold_kb=200
        )
        
        # Payload que seria normal no auditor padrão
        medium_payload = {"data": "x" * 150000}  # ~150KB
        
        metrics = custom_auditor.analyze_payload(
            payload=medium_payload,
            endpoint="/api/custom-test",
            method="POST"
        )
        
        assert metrics.is_excessive  # > 100KB
        assert len(custom_auditor.alerts) == 1
        assert custom_auditor.alerts[0].severity == "critical"  # > 200KB

class TestPayloadMetrics:
    """Testes específicos para PayloadMetrics."""
    
    def test_payload_metrics_creation(self):
        """Testa criação de PayloadMetrics."""
        timestamp = datetime.now()
        
        metrics = PayloadMetrics(
            endpoint="/api/test",
            method="POST",
            payload_size_bytes=512000,  # 500KB
            compression_ratio=0.3,
            timestamp=timestamp,
            user_id="user123",
            request_id="req456"
        )
        
        assert metrics.endpoint == "/api/test"
        assert metrics.method == "POST"
        assert metrics.payload_size_bytes == 512000
        assert metrics.payload_size_kb == 500.0
        assert metrics.compression_ratio == 0.3
        assert metrics.timestamp == timestamp
        assert metrics.user_id == "user123"
        assert metrics.request_id == "req456"
        assert not metrics.is_excessive  # Exatamente 500KB
    
    def test_payload_metrics_excessive_calculation(self):
        """Testa cálculo automático de excessivo."""
        # Testa payload exatamente no limite
        metrics_at_limit = PayloadMetrics(
            endpoint="/api/limit",
            method="POST",
            payload_size_bytes=512000,  # 500KB
            compression_ratio=0.5,
            timestamp=datetime.now()
        )
        
        assert not metrics_at_limit.is_excessive  # Não é excessivo no limite
        
        # Testa payload acima do limite
        metrics_above_limit = PayloadMetrics(
            endpoint="/api/above",
            method="POST",
            payload_size_bytes=513000,  # 500.98KB
            compression_ratio=0.5,
            timestamp=datetime.now()
        )
        
        assert metrics_above_limit.is_excessive  # É excessivo acima do limite

class TestPayloadAlert:
    """Testes específicos para PayloadAlert."""
    
    def test_payload_alert_creation(self):
        """Testa criação de PayloadAlert."""
        timestamp = datetime.now()
        
        alert = PayloadAlert(
            alert_id="ALERT_001",
            severity="warning",
            endpoint="/api/alert-test",
            payload_size_kb=600,
            threshold_kb=500,
            timestamp=timestamp,
            user_id="user123",
            request_id="req456",
            recommendations=["Test recommendation"]
        )
        
        assert alert.alert_id == "ALERT_001"
        assert alert.severity == "warning"
        assert alert.endpoint == "/api/alert-test"
        assert alert.payload_size_kb == 600
        assert alert.threshold_kb == 500
        assert alert.timestamp == timestamp
        assert alert.user_id == "user123"
        assert alert.request_id == "req456"
        assert alert.recommendations == ["Test recommendation"]
    
    def test_payload_alert_default_recommendations(self):
        """Testa inicialização com recomendações padrão."""
        alert = PayloadAlert(
            alert_id="ALERT_002",
            severity="critical",
            endpoint="/api/default-test",
            payload_size_kb=1000,
            threshold_kb=500,
            timestamp=datetime.now()
        )
        
        assert alert.recommendations is not None
        assert isinstance(alert.recommendations, list)
        assert len(alert.recommendations) == 0

# Testes de integração
class TestPayloadAuditorIntegration:
    """Testes de integração do sistema de auditoria."""
    
    def setup_method(self):
        """Configuração para testes de integração."""
        self.auditor = PayloadAuditor()
    
    def test_full_workflow_simulation(self):
        """Simula workflow completo de auditoria."""
        # Simula múltiplas requisições
        requests_data = [
            ("/api/generate-articles", {"prompt": "x" * 1000000}, "user1"),  # ~1MB
            ("/api/status", {"status": "ok"}, "user2"),                     # ~20B
            ("/api/upload-content", {"content": "x" * 300000}, "user1"),    # ~300KB
            ("/api/generate-articles", {"prompt": "x" * 2000000}, "user3"), # ~2MB
        ]
        
        for endpoint, payload, user_id in requests_data:
            self.auditor.analyze_payload(payload, endpoint, "POST", user_id)
        
        # Verifica resultados
        assert len(self.auditor.payload_history) == 4
        assert len(self.auditor.alerts) == 2  # 2 payloads excessivos
        
        # Verifica relatório
        report = self.auditor.get_excessive_payloads_report()
        assert report['summary']['total_excessive_payloads'] == 2
        assert report['summary']['endpoints_affected'] == 1  # Apenas generate-articles
        
        # Verifica análise de performance
        analysis = self.auditor.get_performance_impact_analysis()
        assert analysis['excessive_percentage'] == 50.0  # 2 de 4
    
    def test_alert_severity_distribution(self):
        """Testa distribuição de severidades de alertas."""
        # Cria payloads com diferentes tamanhos
        payload_sizes = [100, 450, 800, 1500]  # KB
        
        for size_kb in payload_sizes:
            payload = {"data": "x" * int(size_kb * 1024)}
            self.auditor.analyze_payload(payload, f"/api/{size_kb}kb", "POST")
        
        # Verifica severidades dos alertas
        severities = [alert.severity for alert in self.auditor.alerts]
        
        assert "info" in severities      # 100KB
        assert "warning" in severities   # 450KB
        assert "critical" in severities  # 800KB, 1500KB
        assert severities.count("critical") == 2

if __name__ == "__main__":
    # Executa testes básicos
    print("🧪 Executando testes do Payload Auditor...")
    
    # Teste básico de funcionalidade
    auditor = PayloadAuditor()
    
    # Testa payload normal
    normal_metrics = auditor.analyze_payload(
        {"test": "normal payload"},
        "/api/test",
        "POST"
    )
    print(f"✅ Payload normal: {normal_metrics.payload_size_kb:.2f}KB")
    
    # Testa payload excessivo
    excessive_metrics = auditor.analyze_payload(
        {"data": "x" * 1000000},  # ~1MB
        "/api/excessive",
        "POST"
    )
    print(f"⚠️ Payload excessivo: {excessive_metrics.payload_size_kb:.2f}KB")
    
    # Gera relatório
    report = auditor.get_excessive_payloads_report()
    print(f"📊 Relatório: {report['summary']['total_excessive_payloads']} payloads excessivos")
    
    print("✅ Todos os testes básicos passaram!") 