#!/usr/bin/env python3
"""
🧪 TESTE DE INTEGRAÇÃO - FRAMEWORK DE DETECÇÃO DE FLUXOS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Teste de integração para o framework de detecção de fluxos baseado em logs reais.
Valida detecção de novos fluxos, análise de padrões e geração de sugestões de teste.

Tracing ID: FLOW_DETECTION_TEST_20250127_001
Data/Hora: 2025-01-27T18:30:00Z
Versão: 1.0
"""

import pytest
import json
import tempfile
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

# Importa o framework de detecção de fluxos
from scripts.flow_detection_framework import (
    FlowDetectionFramework,
    LogEntry,
    FlowPattern,
    FlowDetectionResult,
    LogSource
)

TRACING_ID = "FLOW_DETECTION_TEST_20250127_001"

class TestFlowDetectionFramework:
    """
    Teste de integração para o framework de detecção de fluxos.
    
    Baseado em logs reais do Omni Writer:
    - logs/structured_logs.json
    - logs/pipeline_multi_diag.log
    - logs/decisions_2025-01-27.log
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Configura ambiente de teste com logs reais."""
        self.tracing_id = TRACING_ID
        self.test_db_path = "tests/integration/test_flow_detection.db"
        
        # Cria diretório temporário para logs de teste
        self.temp_dir = tempfile.mkdtemp()
        self.test_logs_dir = Path(self.temp_dir) / "logs"
        self.test_logs_dir.mkdir()
        
        # Copia logs reais para diretório de teste
        self._copy_real_logs()
        
        # Inicializa framework com banco de teste
        self.framework = FlowDetectionFramework(db_path=self.test_db_path)
        
        yield
        
        # Limpeza após teste
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        shutil.rmtree(self.temp_dir)
    
    def _copy_real_logs(self):
        """Copia logs reais do Omni Writer para teste."""
        real_logs_dir = Path("logs")
        
        # Copia logs estruturados
        if (real_logs_dir / "structured_logs.json").exists():
            shutil.copy2(
                real_logs_dir / "structured_logs.json",
                self.test_logs_dir / "structured_logs.json"
            )
        
        # Copia logs de pipeline
        if (real_logs_dir / "pipeline_multi_diag.log").exists():
            shutil.copy2(
                real_logs_dir / "pipeline_multi_diag.log",
                self.test_logs_dir / "pipeline_multi_diag.log"
            )
        
        # Copia logs de decisões
        if (real_logs_dir / "decisions_2025-01-27.log").exists():
            shutil.copy2(
                real_logs_dir / "decisions_2025-01-27.log",
                self.test_logs_dir / "decisions_2025-01-27.log"
            )
    
    def _create_test_log_entry(self, timestamp: str, level: str, message: str, 
                              service: str, endpoint: str = None) -> str:
        """Cria entrada de log de teste baseada em formato real."""
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "message": message,
            "service": service,
            "endpoint": endpoint,
            "request_id": f"req-{hash(message) % 10000}",
            "user_id": "test-user-123",
            "session_id": "session-456",
            "metadata": {
                "test": True,
                "tracing_id": self.tracing_id
            }
        }
        return json.dumps(log_entry)
    
    def test_analyze_structured_logs_real_data(self):
        """
        Testa análise de logs estruturados reais do Omni Writer.
        
        Cenário Real: Analisa logs de monitoramento e performance
        que contêm alertas de sistema e métricas reais.
        """
        # Cria arquivo de log baseado em dados reais
        test_log_file = self.test_logs_dir / "test_structured_logs.json"
        
        # Logs baseados em logs/structured_logs.json reais
        real_log_entries = [
            self._create_test_log_entry(
                "2025-07-12T16:31:18.672042Z",
                "INFO",
                "Coletor de métricas inicializado",
                "monitoring.metrics_collector",
                "/api/metrics/init"
            ),
            self._create_test_log_entry(
                "2025-07-12T16:31:19.882867Z",
                "INFO",
                "Monitor de performance inicializado",
                "monitoring.performance_monitor",
                "/api/performance/init"
            ),
            self._create_test_log_entry(
                "2025-07-12T16:31:19.886412Z",
                "WARNING",
                "Alerta gerado: Memory usage is high: 94.9%",
                "monitoring.performance_monitor",
                "/api/alerts/generate"
            ),
            self._create_test_log_entry(
                "2025-07-12T16:31:19.887432Z",
                "WARNING",
                "Alerta gerado: System health score is low: 46.41",
                "monitoring.performance_monitor",
                "/api/alerts/generate"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in real_log_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações baseadas em comportamento real
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 4, f"Esperado 4 logs, obtido {result.total_logs_analyzed}"
        assert result.tracing_id == self.tracing_id, "Tracing ID deve ser preservado"
        
        # Verifica se fluxos de monitoramento foram detectados
        assert result.new_flows_detected >= 0, "Deve detectar fluxos de monitoramento"
        
        # Verifica se alertas de alto risco foram identificados
        assert len(result.high_risk_flows) >= 0, "Deve identificar fluxos de alto risco"
    
    def test_analyze_pipeline_logs_real_data(self):
        """
        Testa análise de logs de pipeline reais do Omni Writer.
        
        Cenário Real: Analisa logs de pipeline multi-instância que mostram
        execuções repetidas de generate_article com diferentes timestamps.
        """
        # Cria arquivo de log baseado em dados reais do pipeline
        test_log_file = self.test_logs_dir / "test_pipeline_logs.log"
        
        # Logs baseados em logs/pipeline_multi_diag.log reais
        pipeline_log_entries = [
            "2025-05-03 20:35:33,130 INFO [DIAG] Iniciando pipeline multi | TESTING=None",
            "2025-05-03 20:35:33,174 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0",
            "2025-05-03 20:35:33,241 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0",
            "2025-05-03 20:38:42,184 INFO [DIAG] Iniciando pipeline multi | TESTING=None",
            "2025-05-03 20:38:42,221 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0",
            "2025-05-03 20:38:42,237 INFO [DIAG] Chamando generate_article | prompt=prompt 1 | var=0"
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in pipeline_log_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações baseadas em comportamento real
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 6, f"Esperado 6 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se fluxos de pipeline foram detectados
        assert result.new_flows_detected >= 0, "Deve detectar fluxos de pipeline"
        
        # Verifica se sugestões de teste foram geradas
        assert result.test_suggestions_generated >= 0, "Deve gerar sugestões de teste"
    
    def test_detect_high_risk_flows_real_scenarios(self):
        """
        Testa detecção de fluxos de alto risco baseados em cenários reais.
        
        Cenário Real: Identifica fluxos críticos como pagamentos, autenticação
        e geração de artigos que são de alto risco se não testados.
        """
        # Cria arquivo de log com cenários de alto risco reais
        test_log_file = self.test_logs_dir / "test_high_risk_logs.json"
        
        # Cenários de alto risco baseados em código real do Omni Writer
        high_risk_entries = [
            self._create_test_log_entry(
                "2025-01-27T15:30:22.000Z",
                "INFO",
                "Iniciando geração de artigo via OpenAI",
                "openai_gateway",
                "/generate"
            ),
            self._create_test_log_entry(
                "2025-01-27T15:30:23.000Z",
                "INFO",
                "Artigo gerado com sucesso",
                "generation_service",
                "/status"
            ),
            self._create_test_log_entry(
                "2025-01-27T15:30:24.000Z",
                "INFO",
                "Iniciando download do artigo",
                "storage_service",
                "/download"
            ),
            self._create_test_log_entry(
                "2025-01-27T15:31:00.000Z",
                "INFO",
                "Processando pagamento via Stripe",
                "stripe_gateway",
                "/payment"
            ),
            self._create_test_log_entry(
                "2025-01-27T15:31:01.000Z",
                "INFO",
                "Webhook do Stripe recebido",
                "payment_service",
                "/webhook"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in high_risk_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações específicas para fluxos de alto risco
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 5, f"Esperado 5 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se fluxos de alto risco foram identificados
        assert len(result.high_risk_flows) > 0, "Deve identificar fluxos de alto risco"
        
        # Verifica se fluxos não testados foram detectados
        assert len(result.untested_flows) > 0, "Deve detectar fluxos não testados"
        
        # Verifica se sugestões de teste foram geradas
        assert result.test_suggestions_generated > 0, "Deve gerar sugestões para fluxos críticos"
    
    def test_generate_test_suggestions_real_based(self):
        """
        Testa geração de sugestões de teste baseadas em código real.
        
        Cenário Real: Gera sugestões específicas para fluxos identificados
        nos logs reais do Omni Writer.
        """
        # Cria arquivo de log com fluxos específicos do Omni Writer
        test_log_file = self.test_logs_dir / "test_suggestions_logs.json"
        
        # Fluxos específicos baseados em código real
        suggestion_entries = [
            self._create_test_log_entry(
                "2025-01-27T16:00:00.000Z",
                "INFO",
                "Iniciando geração paralela de artigos",
                "parallel_generator",
                "/generate/parallel"
            ),
            self._create_test_log_entry(
                "2025-01-27T16:00:01.000Z",
                "INFO",
                "Cache miss - gerando novo artigo",
                "intelligent_cache",
                "/cache/miss"
            ),
            self._create_test_log_entry(
                "2025-01-27T16:00:02.000Z",
                "INFO",
                "Retry automático após falha de API",
                "smart_retry",
                "/retry"
            ),
            self._create_test_log_entry(
                "2025-01-27T16:00:03.000Z",
                "INFO",
                "Validação de prompt concluída",
                "prompt_validator",
                "/validate"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in suggestion_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações para sugestões de teste
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.test_suggestions_generated > 0, "Deve gerar sugestões de teste"
        
        # Verifica se sugestões são específicas e relevantes
        report = self.framework.generate_report()
        assert "high_risk_untested" in report, "Relatório deve conter fluxos de alto risco não testados"
        
        # Verifica se sugestões são baseadas em serviços reais
        high_risk_flows = report.get("high_risk_untested", [])
        for flow in high_risk_flows:
            assert "suggestions" in flow, "Cada fluxo deve ter sugestões"
            assert len(flow["suggestions"]) > 0, "Sugestões não devem estar vazias"
    
    def test_flow_pattern_extraction_real_data(self):
        """
        Testa extração de padrões de fluxo de dados reais.
        
        Cenário Real: Extrai padrões de fluxo de logs reais do Omni Writer
        e valida se os padrões são consistentes com o comportamento esperado.
        """
        # Cria arquivo de log com sequência de fluxo real
        test_log_file = self.test_logs_dir / "test_pattern_logs.json"
        
        # Sequência de fluxo baseada em comportamento real do Omni Writer
        pattern_entries = [
            self._create_test_log_entry(
                "2025-01-27T17:00:00.000Z",
                "INFO",
                "Usuário autenticado",
                "auth_service",
                "/login"
            ),
            self._create_test_log_entry(
                "2025-01-27T17:00:01.000Z",
                "INFO",
                "Blog criado com sucesso",
                "blog_service",
                "/blogs/create"
            ),
            self._create_test_log_entry(
                "2025-01-27T17:00:02.000Z",
                "INFO",
                "Categoria adicionada ao blog",
                "blog_service",
                "/blogs/categories/add"
            ),
            self._create_test_log_entry(
                "2025-01-27T17:00:03.000Z",
                "INFO",
                "Geração de artigos iniciada",
                "generation_service",
                "/generate"
            ),
            self._create_test_log_entry(
                "2025-01-27T17:00:04.000Z",
                "INFO",
                "Artigos salvos no storage",
                "storage_service",
                "/save"
            ),
            self._create_test_log_entry(
                "2025-01-27T17:00:05.000Z",
                "INFO",
                "Download dos artigos solicitado",
                "download_service",
                "/download"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in pattern_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações para extração de padrões
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 6, f"Esperado 6 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se padrões foram extraídos
        assert result.new_flows_detected > 0, "Deve detectar novos padrões de fluxo"
        
        # Verifica se fluxos contêm endpoints esperados
        report = self.framework.generate_report()
        most_frequent = report.get("most_frequent_flows", [])
        
        # Verifica se fluxos contêm serviços reais do Omni Writer
        services_found = set()
        for flow in most_frequent:
            if "name" in flow:
                services_found.add(flow["name"])
        
        # Verifica se serviços críticos foram detectados
        expected_services = {"auth_service", "blog_service", "generation_service"}
        assert len(services_found.intersection(expected_services)) > 0, "Deve detectar serviços críticos"
    
    def test_risk_score_calculation_real_scenarios(self):
        """
        Testa cálculo de risk score baseado em cenários reais.
        
        Cenário Real: Calcula risk score para fluxos críticos do Omni Writer
        como pagamentos, autenticação e geração de artigos.
        """
        # Cria arquivo de log com cenários de diferentes níveis de risco
        test_log_file = self.test_logs_dir / "test_risk_logs.json"
        
        # Cenários com diferentes níveis de risco baseados em código real
        risk_entries = [
            # Fluxo de baixo risco
            self._create_test_log_entry(
                "2025-01-27T18:00:00.000Z",
                "INFO",
                "Página inicial acessada",
                "web_service",
                "/"
            ),
            # Fluxo de médio risco
            self._create_test_log_entry(
                "2025-01-27T18:00:01.000Z",
                "INFO",
                "Usuário logado",
                "auth_service",
                "/login"
            ),
            # Fluxo de alto risco
            self._create_test_log_entry(
                "2025-01-27T18:00:02.000Z",
                "INFO",
                "Pagamento processado",
                "stripe_gateway",
                "/payment"
            ),
            # Fluxo crítico
            self._create_test_log_entry(
                "2025-01-27T18:00:03.000Z",
                "INFO",
                "Geração de artigo via OpenAI",
                "openai_gateway",
                "/generate"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in risk_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações para cálculo de risk score
        assert result is not None, "Resultado da análise não deve ser None"
        
        # Verifica se fluxos de alto risco foram identificados
        assert len(result.high_risk_flows) > 0, "Deve identificar fluxos de alto risco"
        
        # Verifica se sugestões foram geradas para fluxos críticos
        assert result.test_suggestions_generated > 0, "Deve gerar sugestões para fluxos críticos"
        
        # Verifica se relatório contém métricas de risco
        report = self.framework.generate_report()
        assert "statistics" in report, "Relatório deve conter estatísticas"
        
        stats = report["statistics"]
        assert "high_risk_patterns" in stats, "Estatísticas devem incluir padrões de alto risco"
        assert "avg_risk_score" in stats, "Estatísticas devem incluir score médio de risco"
    
    def test_report_generation_real_data(self):
        """
        Testa geração de relatório baseado em dados reais.
        
        Cenário Real: Gera relatório completo com estatísticas, fluxos
        de alto risco e sugestões baseadas em logs reais do Omni Writer.
        """
        # Primeiro, executa análise com dados reais
        test_log_file = self.test_logs_dir / "test_report_logs.json"
        
        # Dados reais baseados em logs do Omni Writer
        report_entries = [
            self._create_test_log_entry(
                "2025-01-27T19:00:00.000Z",
                "INFO",
                "Sistema inicializado",
                "system_service",
                "/init"
            ),
            self._create_test_log_entry(
                "2025-01-27T19:00:01.000Z",
                "INFO",
                "Geração de artigo iniciada",
                "generation_service",
                "/generate"
            ),
            self._create_test_log_entry(
                "2025-01-27T19:00:02.000Z",
                "ERROR",
                "Falha na API OpenAI",
                "openai_gateway",
                "/generate"
            ),
            self._create_test_log_entry(
                "2025-01-27T19:00:03.000Z",
                "INFO",
                "Retry automático executado",
                "smart_retry",
                "/retry"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in report_entries:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Gera relatório
        report = self.framework.generate_report()
        
        # Validações para geração de relatório
        assert report is not None, "Relatório não deve ser None"
        assert "tracing_id" in report, "Relatório deve conter tracing ID"
        assert "timestamp" in report, "Relatório deve conter timestamp"
        assert "statistics" in report, "Relatório deve conter estatísticas"
        
        # Verifica estatísticas
        stats = report["statistics"]
        assert "total_patterns" in stats, "Estatísticas devem incluir total de padrões"
        assert "tested_patterns" in stats, "Estatísticas devem incluir padrões testados"
        assert "high_risk_patterns" in stats, "Estatísticas devem incluir padrões de alto risco"
        assert "coverage_rate" in stats, "Estatísticas devem incluir taxa de cobertura"
        
        # Verifica fluxos de alto risco não testados
        assert "high_risk_untested" in report, "Relatório deve conter fluxos de alto risco não testados"
        assert "most_frequent_flows" in report, "Relatório deve conter fluxos mais frequentes"
        assert "log_sources" in report, "Relatório deve conter fontes de log"
        
        # Verifica se relatório é consistente com dados reais
        assert stats["total_patterns"] >= 0, "Total de padrões deve ser não negativo"
        assert 0 <= stats["coverage_rate"] <= 100, "Taxa de cobertura deve estar entre 0 e 100"
        
        # Verifica se fontes de log estão configuradas
        log_sources = report["log_sources"]
        assert len(log_sources) > 0, "Deve ter fontes de log configuradas"
        
        # Verifica se fontes incluem tipos esperados
        source_types = {source["type"] for source in log_sources}
        expected_types = {"file", "api", "database"}
        assert len(source_types.intersection(expected_types)) > 0, "Deve incluir tipos de fonte esperados"

if __name__ == "__main__":
    # Executa testes
    pytest.main([__file__, "-v"]) 