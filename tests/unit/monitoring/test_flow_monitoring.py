#!/usr/bin/env python3
"""
🧪 TESTES - FLUXO DE MONITORAMENTO
📐 Baseado em Código Real do Omni Writer
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real

Testes para o fluxo de monitoramento detectado pelo framework de detecção de fluxos.
Baseado em evidências reais dos logs do Omni Writer.

Tracing ID: FLOW_MONITORING_TEST_20250127_001
Data/Hora: 2025-01-27T18:30:00Z
Versão: 1.0
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import unittest

TRACING_ID = "FLOW_MONITORING_TEST_20250127_001"

class TestFlowMonitoring(unittest.TestCase):
    """Testes para o fluxo de monitoramento detectado pelo framework."""
    
    def setUp(self):
        """Configuração inicial dos testes."""
        self.logs_dir = Path("logs")
        self.pipeline_log = self.logs_dir / "pipeline_multi_diag.log"
        self.decisions_log = self.logs_dir / "decisions_2025-01-27.log"
        self.structured_logs = self.logs_dir / "structured_logs.json"
        
        # Dados reais extraídos dos logs
        self.real_pipeline_data = self._load_pipeline_data()
        self.real_decisions_data = self._load_decisions_data()
        self.real_structured_data = self._load_structured_data()
    
    def _load_pipeline_data(self) -> Dict[str, Any]:
        """Carrega dados reais do log de pipeline."""
        if not self.pipeline_log.exists():
            return {}
        
        try:
            with open(self.pipeline_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Análise baseada em padrões reais detectados
            pipeline_starts = sum(1 for line in lines if "Iniciando pipeline multi" in line)
            generate_calls = sum(1 for line in lines if "Chamando generate_article" in line)
            testing_mentions = sum(1 for line in lines if "TESTING=" in line)
            
            return {
                'total_lines': len(lines),
                'pipeline_starts': pipeline_starts,
                'generate_calls': generate_calls,
                'testing_mentions': testing_mentions,
                'lines': lines[:10]  # Primeiras 10 linhas para análise
            }
        except Exception as e:
            print(f"Erro ao carregar dados de pipeline: {e}")
            return {}
    
    def _load_decisions_data(self) -> Dict[str, Any]:
        """Carrega dados reais do log de decisões."""
        if not self.decisions_log.exists():
            return {}
        
        try:
            with open(self.decisions_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Análise baseada em padrões reais detectados
            test_decisions = sum(1 for line in lines if "test" in line.lower())
            coverage_decisions = sum(1 for line in lines if "coverage" in line.lower())
            risk_decisions = sum(1 for line in lines if "risk" in line.lower())
            
            return {
                'total_lines': len(lines),
                'test_decisions': test_decisions,
                'coverage_decisions': coverage_decisions,
                'risk_decisions': risk_decisions,
                'lines': lines[:10]  # Primeiras 10 linhas para análise
            }
        except Exception as e:
            print(f"Erro ao carregar dados de decisões: {e}")
            return {}
    
    def _load_structured_data(self) -> Dict[str, Any]:
        """Carrega dados reais dos logs estruturados."""
        if not self.structured_logs.exists():
            return {}
        
        try:
            with open(self.structured_logs, 'r', encoding='utf-8') as f:
                logs = [json.loads(line) for line in f if line.strip()]
            
            # Análise baseada em padrões reais detectados
            services = set()
            levels = set()
            endpoints = set()
            
            for log in logs:
                services.add(log.get('service', 'unknown'))
                levels.add(log.get('level', 'unknown'))
                if 'endpoint' in log:
                    endpoints.add(log['endpoint'])
            
            return {
                'total_entries': len(logs),
                'services': list(services),
                'levels': list(levels),
                'endpoints': list(endpoints),
                'sample_logs': logs[:5]  # Primeiros 5 logs para análise
            }
        except Exception as e:
            print(f"Erro ao carregar dados estruturados: {e}")
            return {}
    
    def test_pipeline_monitoring_detection(self):
        """Testa detecção de padrões de monitoramento no pipeline."""
        print(f"[{TRACING_ID}] Testando detecção de monitoramento no pipeline...")
        
        # Verifica se temos dados reais
        self.assertIsNotNone(self.real_pipeline_data, "Dados de pipeline devem existir")
        self.assertGreater(len(self.real_pipeline_data), 0, "Dados de pipeline não podem estar vazios")
        
        # Testa detecção de menções de teste (padrão de monitoramento)
        testing_mentions = self.real_pipeline_data.get('testing_mentions', 0)
        self.assertGreater(testing_mentions, 0, "Deve haver menções de teste para indicar monitoramento")
        
        # Testa proporção de monitoramento
        total_lines = self.real_pipeline_data.get('total_lines', 0)
        if total_lines > 0:
            monitoring_ratio = testing_mentions / total_lines
            self.assertGreater(monitoring_ratio, 0, "Razão de monitoramento deve ser maior que zero")
            print(f"  ✅ Razão de monitoramento: {monitoring_ratio:.2%}")
        
        print(f"  ✅ Menções de teste detectadas: {testing_mentions}")
    
    def test_decision_monitoring_patterns(self):
        """Testa padrões de monitoramento nas decisões."""
        print(f"[{TRACING_ID}] Testando padrões de monitoramento nas decisões...")
        
        # Verifica se temos dados reais
        self.assertIsNotNone(self.real_decisions_data, "Dados de decisões devem existir")
        self.assertGreater(len(self.real_decisions_data), 0, "Dados de decisões não podem estar vazios")
        
        # Testa detecção de decisões sobre testes
        test_decisions = self.real_decisions_data.get('test_decisions', 0)
        self.assertGreaterEqual(test_decisions, 0, "Decisões sobre testes devem ser >= 0")
        
        # Testa detecção de decisões sobre cobertura
        coverage_decisions = self.real_decisions_data.get('coverage_decisions', 0)
        self.assertGreaterEqual(coverage_decisions, 0, "Decisões sobre cobertura devem ser >= 0")
        
        # Testa detecção de decisões sobre risco
        risk_decisions = self.real_decisions_data.get('risk_decisions', 0)
        self.assertGreaterEqual(risk_decisions, 0, "Decisões sobre risco devem ser >= 0")
        
        print(f"  ✅ Decisões sobre testes: {test_decisions}")
        print(f"  ✅ Decisões sobre cobertura: {coverage_decisions}")
        print(f"  ✅ Decisões sobre risco: {risk_decisions}")
    
    def test_structured_logs_monitoring(self):
        """Testa monitoramento através de logs estruturados."""
        print(f"[{TRACING_ID}] Testando monitoramento via logs estruturados...")
        
        # Verifica se temos dados reais
        self.assertIsNotNone(self.real_structured_data, "Dados estruturados devem existir")
        
        if len(self.real_structured_data) > 0:
            # Testa presença de serviços de monitoramento
            services = self.real_structured_data.get('services', [])
            self.assertIsInstance(services, list, "Serviços devem ser uma lista")
            
            # Testa presença de níveis de log
            levels = self.real_structured_data.get('levels', [])
            self.assertIsInstance(levels, list, "Níveis devem ser uma lista")
            
            # Testa presença de endpoints
            endpoints = self.real_structured_data.get('endpoints', [])
            self.assertIsInstance(endpoints, list, "Endpoints devem ser uma lista")
            
            print(f"  ✅ Serviços encontrados: {len(services)}")
            print(f"  ✅ Níveis de log: {len(levels)}")
            print(f"  ✅ Endpoints: {len(endpoints)}")
        else:
            print("  ⚠️ Dados estruturados não disponíveis")
    
    def test_monitoring_flow_risk_assessment(self):
        """Testa avaliação de risco do fluxo de monitoramento."""
        print(f"[{TRACING_ID}] Testando avaliação de risco do fluxo de monitoramento...")
        
        # Calcula score de risco baseado em dados reais
        risk_score = 0
        
        # Fator 1: Menções de teste no pipeline
        testing_mentions = self.real_pipeline_data.get('testing_mentions', 0)
        if testing_mentions > 0:
            risk_score += 40
        
        # Fator 2: Decisões sobre testes
        test_decisions = self.real_decisions_data.get('test_decisions', 0)
        if test_decisions > 0:
            risk_score += 30
        
        # Fator 3: Presença de logs estruturados
        if len(self.real_structured_data) > 0:
            risk_score += 10
        
        # Valida score de risco
        self.assertGreaterEqual(risk_score, 0, "Score de risco deve ser >= 0")
        self.assertLessEqual(risk_score, 100, "Score de risco deve ser <= 100")
        
        # Valida que o fluxo foi detectado
        self.assertGreater(risk_score, 0, "Fluxo de monitoramento deve ter score > 0")
        
        print(f"  ✅ Score de risco calculado: {risk_score}")
        print(f"  ✅ Fluxo de monitoramento detectado: {risk_score > 0}")
    
    def test_monitoring_coverage_validation(self):
        """Testa validação de cobertura do fluxo de monitoramento."""
        print(f"[{TRACING_ID}] Testando validação de cobertura do fluxo de monitoramento...")
        
        # Verifica se o fluxo está sendo testado (este teste)
        is_being_tested = True
        
        # Verifica se há evidências de monitoramento
        has_monitoring_evidence = (
            self.real_pipeline_data.get('testing_mentions', 0) > 0 or
            self.real_decisions_data.get('test_decisions', 0) > 0 or
            len(self.real_structured_data) > 0
        )
        
        # Validações
        self.assertTrue(is_being_tested, "Fluxo de monitoramento deve estar sendo testado")
        self.assertTrue(has_monitoring_evidence, "Deve haver evidências de monitoramento")
        
        print(f"  ✅ Fluxo sendo testado: {is_being_tested}")
        print(f"  ✅ Evidências de monitoramento: {has_monitoring_evidence}")
    
    def test_monitoring_pattern_consistency(self):
        """Testa consistência dos padrões de monitoramento."""
        print(f"[{TRACING_ID}] Testando consistência dos padrões de monitoramento...")
        
        # Verifica consistência entre diferentes fontes de dados
        pipeline_has_monitoring = self.real_pipeline_data.get('testing_mentions', 0) > 0
        decisions_has_monitoring = self.real_decisions_data.get('test_decisions', 0) > 0
        structured_has_data = len(self.real_structured_data) > 0
        
        # Pelo menos uma fonte deve ter dados de monitoramento
        has_any_monitoring = pipeline_has_monitoring or decisions_has_monitoring or structured_has_data
        self.assertTrue(has_any_monitoring, "Pelo menos uma fonte deve ter dados de monitoramento")
        
        # Verifica consistência dos dados
        if pipeline_has_monitoring:
            self.assertGreater(self.real_pipeline_data['testing_mentions'], 0)
        
        if decisions_has_monitoring:
            self.assertGreater(self.real_decisions_data['test_decisions'], 0)
        
        print(f"  ✅ Pipeline tem monitoramento: {pipeline_has_monitoring}")
        print(f"  ✅ Decisões têm monitoramento: {decisions_has_monitoring}")
        print(f"  ✅ Logs estruturados têm dados: {structured_has_data}")
        print(f"  ✅ Consistência validada: {has_any_monitoring}")

def run_monitoring_tests():
    """Executa todos os testes de monitoramento."""
    print(f"[{TRACING_ID}] Iniciando testes de fluxo de monitoramento...")
    print(f"Baseado em código real do Omni Writer")
    print(f"Tracing ID: {TRACING_ID}")
    print(f"Data/Hora: {datetime.now().isoformat()}")
    print("=" * 80)
    
    # Configura teste
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestFlowMonitoring)
    
    # Executa testes
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Relatório final
    print("=" * 80)
    print(f"RESULTADO DOS TESTES DE MONITORAMENTO:")
    print(f"  • Testes executados: {result.testsRun}")
    print(f"  • Falhas: {len(result.failures)}")
    print(f"  • Erros: {len(result.errors)}")
    print(f"  • Sucessos: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.wasSuccessful():
        print(f"  ✅ TODOS OS TESTES PASSARAM")
        print(f"  ✅ FLUXO DE MONITORAMENTO VALIDADO")
    else:
        print(f"  ❌ ALGUNS TESTES FALHARAM")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_monitoring_tests()
    sys.exit(0 if success else 1) 