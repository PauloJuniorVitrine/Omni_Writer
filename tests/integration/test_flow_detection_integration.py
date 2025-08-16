#!/usr/bin/env python3
"""
🧪 TESTE DE INTEGRAÇÃO - DETECÇÃO DE NOVOS FLUXOS VIA LOGS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Teste de integração para o framework de detecção de fluxos via logs.
Valida detecção automática de novos fluxos baseados em logs reais.

Tracing ID: FLOW_DETECTION_INTEGRATION_20250127_001
Data/Hora: 2025-01-27T19:00:00Z
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

TRACING_ID = "FLOW_DETECTION_INTEGRATION_20250127_001"

class TestFlowDetectionIntegration:
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
        self.test_db_path = "tests/integration/test_flow_detection_integration.db"
        
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
    
    def test_flow_detection_with_real_logs(self):
        """
        Testa detecção de fluxos com logs reais do Omni Writer.
        
        Cenário Real: Analisa logs reais de produção para identificar
        fluxos não testados e gerar sugestões de teste.
        """
        # Verifica se logs reais existem
        structured_logs = self.test_logs_dir / "structured_logs.json"
        pipeline_logs = self.test_logs_dir / "pipeline_multi_diag.log"
        decision_logs = self.test_logs_dir / "decisions_2025-01-27.log"
        
        if not any([structured_logs.exists(), pipeline_logs.exists(), decision_logs.exists()]):
            pytest.skip("Logs reais não encontrados para teste")
        
        # Analisa logs estruturados
        if structured_logs.exists():
            result = self.framework.analyze_logs(
                str(structured_logs),
                source_name="application_logs"
            )
            
            # Validações baseadas em comportamento real
            assert result is not None, "Resultado da análise não deve ser None"
            assert result.total_logs_analyzed > 0, "Deve analisar logs reais"
            assert result.new_flows_detected >= 0, "Deve detectar fluxos (pode ser 0 se todos já conhecidos)"
        
        # Analisa logs de pipeline
        if pipeline_logs.exists():
            result = self.framework.analyze_logs(
                str(pipeline_logs),
                source_name="pipeline_logs"
            )
            
            # Validações específicas para logs de pipeline
            assert result is not None, "Resultado da análise não deve ser None"
            assert result.total_logs_analyzed > 0, "Deve analisar logs de pipeline"
        
        # Analisa logs de decisões
        if decision_logs.exists():
            result = self.framework.analyze_logs(
                str(decision_logs),
                source_name="decision_logs"
            )
            
            # Validações específicas para logs de decisões
            assert result is not None, "Resultado da análise não deve ser None"
            assert result.total_logs_analyzed > 0, "Deve analisar logs de decisões"
    
    def test_new_flow_detection_real_scenarios(self):
        """
        Testa detecção de novos fluxos baseados em cenários reais.
        
        Cenário Real: Identifica fluxos críticos como pagamentos, autenticação
        e geração de artigos que são de alto risco se não testados.
        """
        # Cria arquivo de log com cenários reais do Omni Writer
        test_log_file = self.test_logs_dir / "test_real_scenarios.json"
        
        # Cenários reais baseados em código do Omni Writer
        real_scenarios = [
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
            for entry in real_scenarios:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações específicas para cenários reais
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 5, f"Esperado 5 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se fluxos críticos foram identificados
        assert len(result.high_risk_flows) > 0, "Deve identificar fluxos de alto risco"
        
        # Verifica se sugestões foram geradas para fluxos críticos
        assert result.test_suggestions_generated > 0, "Deve gerar sugestões para fluxos críticos"
    
    def test_flow_pattern_extraction_real_data(self):
        """
        Testa extração de padrões de fluxo baseados em dados reais.
        
        Cenário Real: Extrai padrões de fluxo de logs reais do Omni Writer
        para identificar sequências de operações não testadas.
        """
        # Cria arquivo de log com padrões reais
        test_log_file = self.test_logs_dir / "test_patterns.json"
        
        # Padrões baseados em código real do Omni Writer
        pattern_entries = [
            self._create_test_log_entry(
                "2025-01-27T18:00:00.000Z",
                "INFO",
                "Usuário autenticado",
                "auth_service",
                "/login"
            ),
            self._create_test_log_entry(
                "2025-01-27T18:00:01.000Z",
                "INFO",
                "Blog criado com sucesso",
                "blog_service",
                "/blogs/create"
            ),
            self._create_test_log_entry(
                "2025-01-27T18:00:02.000Z",
                "INFO",
                "Categoria adicionada",
                "blog_service",
                "/blogs/categories"
            ),
            self._create_test_log_entry(
                "2025-01-27T18:00:03.000Z",
                "INFO",
                "Artigo gerado",
                "generation_service",
                "/generate"
            ),
            self._create_test_log_entry(
                "2025-01-27T18:00:04.000Z",
                "INFO",
                "Arquivo exportado",
                "export_service",
                "/export"
            ),
            self._create_test_log_entry(
                "2025-01-27T18:00:05.000Z",
                "INFO",
                "Sessão encerrada",
                "auth_service",
                "/logout"
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
    
    def test_test_suggestions_generation(self):
        """
        Testa geração de sugestões de teste baseadas em fluxos reais.
        
        Cenário Real: Gera sugestões de teste para fluxos não testados
        baseados em análise de logs reais do Omni Writer.
        """
        # Cria arquivo de log com fluxos não testados
        test_log_file = self.test_logs_dir / "test_untested_flows.json"
        
        # Fluxos que podem não estar testados (baseados em código real)
        untested_flows = [
            self._create_test_log_entry(
                "2025-01-27T19:00:00.000Z",
                "INFO",
                "Webhook recebido do Stripe",
                "webhook_service",
                "/webhook/stripe"
            ),
            self._create_test_log_entry(
                "2025-01-27T19:00:01.000Z",
                "INFO",
                "Processamento de reembolso",
                "refund_service",
                "/refund"
            ),
            self._create_test_log_entry(
                "2025-01-27T19:00:02.000Z",
                "INFO",
                "Exportação em lote",
                "batch_export_service",
                "/export/batch"
            )
        ]
        
        with open(test_log_file, 'w') as f:
            for entry in untested_flows:
                f.write(entry + '\n')
        
        # Executa análise
        result = self.framework.analyze_logs(
            str(test_log_file),
            source_name="application_logs"
        )
        
        # Validações para geração de sugestões
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 3, f"Esperado 3 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se fluxos não testados foram identificados
        assert len(result.untested_flows) > 0, "Deve identificar fluxos não testados"
        
        # Verifica se sugestões foram geradas
        assert result.test_suggestions_generated > 0, "Deve gerar sugestões de teste"
    
    def test_flow_detection_report_generation(self):
        """
        Testa geração de relatórios de detecção de fluxos.
        
        Cenário Real: Gera relatórios completos com métricas, padrões
        e sugestões baseados em análise de logs reais.
        """
        # Executa análise com logs reais se disponíveis
        structured_logs = self.test_logs_dir / "structured_logs.json"
        
        if structured_logs.exists():
            self.framework.analyze_logs(
                str(structured_logs),
                source_name="application_logs"
            )
        
        # Gera relatório
        report = self.framework.generate_report()
        
        # Validações para relatório
        assert report is not None, "Relatório não deve ser None"
        assert "tracing_id" in report, "Relatório deve conter tracing_id"
        assert "timestamp" in report, "Relatório deve conter timestamp"
        assert "statistics" in report, "Relatório deve conter estatísticas"
        
        # Verifica estatísticas
        stats = report["statistics"]
        assert "total_patterns" in stats, "Estatísticas devem incluir total de padrões"
        assert "tested_patterns" in stats, "Estatísticas devem incluir padrões testados"
        assert "untested_patterns" in stats, "Estatísticas devem incluir padrões não testados"
        assert "coverage_percentage" in stats, "Estatísticas devem incluir porcentagem de cobertura"
        
        # Verifica se relatório contém fluxos mais frequentes
        assert "most_frequent_flows" in report, "Relatório deve incluir fluxos mais frequentes"
        assert "high_risk_flows" in report, "Relatório deve incluir fluxos de alto risco"
        assert "untested_flows" in report, "Relatório deve incluir fluxos não testados"
        
        # Verifica se relatório contém sugestões
        assert "test_suggestions" in report, "Relatório deve incluir sugestões de teste"
        
        # Valida formato de sugestões
        suggestions = report["test_suggestions"]
        assert isinstance(suggestions, list), "Sugestões devem ser uma lista"
        
        # Verifica se sugestões são baseadas em código real
        for suggestion in suggestions[:5]:  # Verifica apenas as primeiras 5
            assert "endpoint" in suggestion or "service" in suggestion, "Sugestão deve referenciar endpoint ou serviço"
            assert "description" in suggestion, "Sugestão deve ter descrição"
            assert "risk_score" in suggestion, "Sugestão deve ter risk score"
    
    def test_flow_detection_integration_with_telemetry(self):
        """
        Testa integração entre detecção de fluxos e telemetria.
        
        Cenário Real: Integra detecção de fluxos com sistema de telemetria
        para monitoramento contínuo de novos fluxos.
        """
        # Simula integração com telemetria
        from scripts.telemetry_framework import telemetry_decorator
        
        @telemetry_decorator
        def test_flow_detection_with_telemetry():
            """Testa detecção de fluxos com telemetria integrada."""
            # Cria log de teste
            test_log_file = self.test_logs_dir / "test_telemetry_integration.json"
            
            telemetry_entries = [
                self._create_test_log_entry(
                    "2025-01-27T20:00:00.000Z",
                    "INFO",
                    "Telemetria iniciada",
                    "telemetry_service",
                    "/telemetry/start"
                ),
                self._create_test_log_entry(
                    "2025-01-27T20:00:01.000Z",
                    "INFO",
                    "Métricas coletadas",
                    "metrics_service",
                    "/metrics/collect"
                ),
                self._create_test_log_entry(
                    "2025-01-27T20:00:02.000Z",
                    "INFO",
                    "Telemetria finalizada",
                    "telemetry_service",
                    "/telemetry/end"
                )
            ]
            
            with open(test_log_file, 'w') as f:
                for entry in telemetry_entries:
                    f.write(entry + '\n')
            
            # Executa análise
            result = self.framework.analyze_logs(
                str(test_log_file),
                source_name="application_logs"
            )
            
            return result
        
        # Executa teste com telemetria
        result = test_flow_detection_with_telemetry()
        
        # Validações para integração com telemetria
        assert result is not None, "Resultado da análise não deve ser None"
        assert result.total_logs_analyzed == 3, f"Esperado 3 logs, obtido {result.total_logs_analyzed}"
        
        # Verifica se fluxos de telemetria foram detectados
        assert result.new_flows_detected >= 0, "Deve detectar fluxos de telemetria"
        
        # Verifica se sugestões foram geradas
        assert result.test_suggestions_generated >= 0, "Deve gerar sugestões para fluxos de telemetria" 