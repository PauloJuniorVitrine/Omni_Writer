#!/usr/bin/env python3
"""
🤖 DETECÇÃO AUTOMATIZADA DE FLUXOS - INTEGRAÇÃO CI/CD
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Script automatizado para detecção de novos fluxos via logs.
Integra com CI/CD pipeline para monitoramento contínuo.

Tracing ID: AUTOMATED_FLOW_DETECTION_20250127_001
Data/Hora: 2025-01-27T19:30:00Z
Versão: 1.0
"""

import sys
import os
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.flow_detection_framework import FlowDetectionFramework
from scripts.telemetry_framework import telemetry_decorator

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "AUTOMATED_FLOW_DETECTION_20250127_001"

class AutomatedFlowDetection:
    """
    Sistema automatizado de detecção de fluxos.
    
    Monitora logs continuamente e gera alertas para novos fluxos
    não testados baseados em código real do Omni Writer.
    """
    
    def __init__(self, config_path: str = "tests/integration/flow_detection_config.json"):
        """
        Inicializa o sistema automatizado.
        
        Args:
            config_path: Caminho para arquivo de configuração
        """
        self.tracing_id = TRACING_ID
        self.config = self._load_config(config_path)
        self.framework = FlowDetectionFramework()
        self.last_analysis = None
        self.analysis_results = []
        
        logger.info(f"[{self.tracing_id}] Sistema automatizado inicializado")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Carrega configuração do sistema."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao carregar configuração: {e}")
            return {}
    
    @telemetry_decorator
    def analyze_all_log_sources(self) -> Dict[str, Any]:
        """
        Analisa todas as fontes de log configuradas.
        
        Returns:
            Resultado consolidado da análise
        """
        logger.info(f"[{self.tracing_id}] Iniciando análise de todas as fontes de log")
        
        results = {}
        total_new_flows = 0
        total_high_risk_flows = 0
        total_suggestions = 0
        
        # Analisa cada fonte de log configurada
        log_sources = self.config.get("log_sources", {})
        
        for source_name, source_config in log_sources.items():
            if not source_config.get("enabled", True):
                logger.info(f"[{self.tracing_id}] Fonte {source_name} desabilitada, pulando")
                continue
            
            source_path = source_config.get("source_path")
            if not source_path or not Path(source_path).exists():
                logger.warning(f"[{self.tracing_id}] Fonte {source_name} não encontrada: {source_path}")
                continue
            
            try:
                logger.info(f"[{self.tracing_id}] Analisando fonte: {source_name}")
                
                result = self.framework.analyze_logs(
                    source_path,
                    source_name=source_name
                )
                
                results[source_name] = {
                    "total_logs": result.total_logs_analyzed,
                    "new_flows": result.new_flows_detected,
                    "high_risk_flows": len(result.high_risk_flows),
                    "untested_flows": len(result.untested_flows),
                    "suggestions": result.test_suggestions_generated,
                    "status": "success"
                }
                
                total_new_flows += result.new_flows_detected
                total_high_risk_flows += len(result.high_risk_flows)
                total_suggestions += result.test_suggestions_generated
                
                logger.info(f"[{self.tracing_id}] {source_name}: {result.new_flows_detected} novos fluxos detectados")
                
            except Exception as e:
                logger.error(f"[{self.tracing_id}] Erro ao analisar {source_name}: {e}")
                results[source_name] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Resultado consolidado
        consolidated_result = {
            "tracing_id": self.tracing_id,
            "timestamp": datetime.now().isoformat(),
            "total_sources_analyzed": len([r for r in results.values() if r.get("status") == "success"]),
            "total_new_flows": total_new_flows,
            "total_high_risk_flows": total_high_risk_flows,
            "total_suggestions": total_suggestions,
            "source_results": results,
            "coverage_percentage": self._calculate_coverage_percentage(),
            "risk_assessment": self._assess_overall_risk(total_high_risk_flows, total_new_flows)
        }
        
        self.last_analysis = consolidated_result
        self.analysis_results.append(consolidated_result)
        
        logger.info(f"[{self.tracing_id}] Análise concluída: {total_new_flows} novos fluxos, {total_high_risk_flows} de alto risco")
        
        return consolidated_result
    
    def _calculate_coverage_percentage(self) -> float:
        """Calcula porcentagem de cobertura de testes."""
        try:
            report = self.framework.generate_report()
            stats = report.get("statistics", {})
            return stats.get("coverage_percentage", 0.0)
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao calcular cobertura: {e}")
            return 0.0
    
    def _assess_overall_risk(self, high_risk_flows: int, new_flows: int) -> Dict[str, Any]:
        """Avalia risco geral baseado nos fluxos detectados."""
        risk_score = (high_risk_flows * 25) + (new_flows * 10)
        
        if risk_score >= 100:
            risk_level = "CRITICAL"
            action_required = "IMMEDIATE"
        elif risk_score >= 50:
            risk_level = "HIGH"
            action_required = "URGENT"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
            action_required = "PLANNED"
        else:
            risk_level = "LOW"
            action_required = "MONITOR"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "action_required": action_required,
            "high_risk_flows": high_risk_flows,
            "new_flows": new_flows
        }
    
    def generate_ci_cd_report(self) -> Dict[str, Any]:
        """
        Gera relatório formatado para CI/CD.
        
        Returns:
            Relatório em formato compatível com CI/CD
        """
        if not self.last_analysis:
            logger.warning(f"[{self.tracing_id}] Nenhuma análise executada ainda")
            return {}
        
        # Gera relatório do framework
        framework_report = self.framework.generate_report()
        
        # Formata para CI/CD
        ci_cd_report = {
            "tracing_id": self.tracing_id,
            "timestamp": datetime.now().isoformat(),
            "status": "SUCCESS" if self.last_analysis["total_high_risk_flows"] == 0 else "WARNING",
            "summary": {
                "total_new_flows": self.last_analysis["total_new_flows"],
                "high_risk_flows": self.last_analysis["total_high_risk_flows"],
                "coverage_percentage": self.last_analysis["coverage_percentage"],
                "risk_level": self.last_analysis["risk_assessment"]["risk_level"]
            },
            "details": {
                "source_analysis": self.last_analysis["source_results"],
                "risk_assessment": self.last_analysis["risk_assessment"],
                "framework_statistics": framework_report.get("statistics", {}),
                "most_frequent_flows": framework_report.get("most_frequent_flows", []),
                "high_risk_flows": framework_report.get("high_risk_flows", []),
                "untested_flows": framework_report.get("untested_flows", []),
                "test_suggestions": framework_report.get("test_suggestions", [])
            },
            "recommendations": self._generate_recommendations(),
            "next_actions": self._generate_next_actions()
        }
        
        return ci_cd_report
    
    def _generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas na análise."""
        recommendations = []
        
        if not self.last_analysis:
            return recommendations
        
        risk_assessment = self.last_analysis["risk_assessment"]
        coverage = self.last_analysis["coverage_percentage"]
        
        # Recomendações baseadas em risco
        if risk_assessment["risk_level"] == "CRITICAL":
            recommendations.append("🚨 CRÍTICO: Implementar testes imediatamente para fluxos de alto risco")
            recommendations.append("🔍 Revisar todos os fluxos não testados identificados")
        
        elif risk_assessment["risk_level"] == "HIGH":
            recommendations.append("⚠️ ALTO RISCO: Priorizar testes para fluxos críticos")
            recommendations.append("📊 Analisar padrões de uso para identificar prioridades")
        
        # Recomendações baseadas em cobertura
        if coverage < 80:
            recommendations.append(f"📈 Cobertura baixa ({coverage:.1f}%): Aumentar cobertura de testes")
        
        if coverage < 60:
            recommendations.append("🚨 Cobertura crítica: Revisar estratégia de testes")
        
        # Recomendações baseadas em novos fluxos
        if self.last_analysis["total_new_flows"] > 0:
            recommendations.append(f"🆕 {self.last_analysis['total_new_flows']} novos fluxos detectados: Implementar testes")
        
        # Recomendações baseadas em sugestões
        if self.last_analysis["total_suggestions"] > 0:
            recommendations.append(f"💡 {self.last_analysis['total_suggestions']} sugestões de teste geradas: Revisar e implementar")
        
        return recommendations
    
    def _generate_next_actions(self) -> List[Dict[str, str]]:
        """Gera próximas ações baseadas na análise."""
        actions = []
        
        if not self.last_analysis:
            return actions
        
        risk_assessment = self.last_analysis["risk_assessment"]
        
        # Ações baseadas no nível de risco
        if risk_assessment["risk_level"] in ["CRITICAL", "HIGH"]:
            actions.append({
                "priority": "IMMEDIATE",
                "action": "Implementar testes para fluxos de alto risco",
                "description": "Criar testes para fluxos identificados como críticos"
            })
            
            actions.append({
                "priority": "URGENT",
                "action": "Revisar logs de produção",
                "description": "Analisar logs para identificar padrões de falha"
            })
        
        # Ações baseadas em novos fluxos
        if self.last_analysis["total_new_flows"] > 0:
            actions.append({
                "priority": "HIGH",
                "action": "Analisar novos fluxos detectados",
                "description": "Revisar fluxos não testados e priorizar testes"
            })
        
        # Ações baseadas em cobertura
        if self.last_analysis["coverage_percentage"] < 80:
            actions.append({
                "priority": "MEDIUM",
                "action": "Aumentar cobertura de testes",
                "description": "Implementar testes para aumentar cobertura"
            })
        
        return actions
    
    def save_report(self, report: Dict[str, Any], output_path: str = None) -> str:
        """
        Salva relatório em arquivo.
        
        Args:
            report: Relatório a ser salvo
            output_path: Caminho do arquivo de saída
            
        Returns:
            Caminho do arquivo salvo
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"tests/integration/flow_detection_report_{timestamp}.json"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"[{self.tracing_id}] Relatório salvo em: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar relatório: {e}")
            return ""
    
    def run_continuous_monitoring(self, interval_minutes: int = 60, max_iterations: int = None):
        """
        Executa monitoramento contínuo.
        
        Args:
            interval_minutes: Intervalo entre análises em minutos
            max_iterations: Número máximo de iterações (None para infinito)
        """
        logger.info(f"[{self.tracing_id}] Iniciando monitoramento contínuo (intervalo: {interval_minutes}min)")
        
        iteration = 0
        
        while max_iterations is None or iteration < max_iterations:
            try:
                logger.info(f"[{self.tracing_id}] Iteração {iteration + 1}")
                
                # Executa análise
                analysis_result = self.analyze_all_log_sources()
                
                # Gera relatório
                report = self.generate_ci_cd_report()
                
                # Salva relatório
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = f"tests/integration/flow_detection_continuous_{timestamp}.json"
                self.save_report(report, report_path)
                
                # Verifica se há alertas críticos
                if analysis_result["risk_assessment"]["risk_level"] == "CRITICAL":
                    logger.critical(f"[{self.tracing_id}] 🚨 ALERTA CRÍTICO: {analysis_result['total_high_risk_flows']} fluxos de alto risco detectados!")
                
                # Aguarda próximo ciclo
                if max_iterations is None or iteration < max_iterations - 1:
                    logger.info(f"[{self.tracing_id}] Aguardando {interval_minutes} minutos para próxima análise...")
                    time.sleep(interval_minutes * 60)
                
                iteration += 1
                
            except KeyboardInterrupt:
                logger.info(f"[{self.tracing_id}] Monitoramento interrompido pelo usuário")
                break
            except Exception as e:
                logger.error(f"[{self.tracing_id}] Erro no monitoramento: {e}")
                time.sleep(60)  # Aguarda 1 minuto antes de tentar novamente
        
        logger.info(f"[{self.tracing_id}] Monitoramento concluído após {iteration} iterações")

def main():
    """Função principal do script."""
    parser = argparse.ArgumentParser(description="Detecção automatizada de fluxos via logs")
    parser.add_argument("--config", default="tests/integration/flow_detection_config.json", 
                       help="Caminho para arquivo de configuração")
    parser.add_argument("--output", help="Caminho para arquivo de saída")
    parser.add_argument("--continuous", action="store_true", 
                       help="Executa monitoramento contínuo")
    parser.add_argument("--interval", type=int, default=60,
                       help="Intervalo em minutos para monitoramento contínuo")
    parser.add_argument("--max-iterations", type=int,
                       help="Número máximo de iterações para monitoramento contínuo")
    
    args = parser.parse_args()
    
    print(f"[{TRACING_ID}] 🤖 INICIANDO DETECÇÃO AUTOMATIZADA DE FLUXOS")
    print("=" * 70)
    
    try:
        # Inicializa sistema
        detector = AutomatedFlowDetection(args.config)
        
        if args.continuous:
            # Executa monitoramento contínuo
            detector.run_continuous_monitoring(
                interval_minutes=args.interval,
                max_iterations=args.max_iterations
            )
        else:
            # Executa análise única
            print("🔍 Executando análise única...")
            analysis_result = detector.analyze_all_log_sources()
            
            # Gera relatório
            report = detector.generate_ci_cd_report()
            
            # Salva relatório
            output_path = args.output or f"tests/integration/flow_detection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            detector.save_report(report, output_path)
            
            # Imprime resumo
            print("\n📊 RESUMO DA ANÁLISE:")
            print("-" * 50)
            print(f"📈 Fontes analisadas: {analysis_result['total_sources_analyzed']}")
            print(f"🆕 Novos fluxos: {analysis_result['total_new_flows']}")
            print(f"🚨 Fluxos de alto risco: {analysis_result['total_high_risk_flows']}")
            print(f"💡 Sugestões geradas: {analysis_result['total_suggestions']}")
            print(f"📊 Cobertura: {analysis_result['coverage_percentage']:.1f}%")
            print(f"⚠️ Nível de risco: {analysis_result['risk_assessment']['risk_level']}")
            
            # Imprime recomendações
            if report.get("recommendations"):
                print(f"\n💡 RECOMENDAÇÕES:")
                print("-" * 50)
                for rec in report["recommendations"]:
                    print(f"  • {rec}")
            
            # Imprime próximas ações
            if report.get("next_actions"):
                print(f"\n🎯 PRÓXIMAS AÇÕES:")
                print("-" * 50)
                for action in report["next_actions"]:
                    print(f"  • [{action['priority']}] {action['action']}")
                    print(f"    {action['description']}")
            
            print(f"\n✅ Análise concluída! Relatório salvo em: {output_path}")
        
    except Exception as e:
        logger.error(f"[{TRACING_ID}] Erro na execução: {e}")
        print(f"\n❌ Erro na execução: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 