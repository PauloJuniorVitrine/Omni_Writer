#!/usr/bin/env python3
"""
🎯 DEMONSTRAÇÃO - FRAMEWORK DE DETECÇÃO DE FLUXOS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Script de demonstração do framework de detecção de fluxos.
Analisa logs reais do Omni Writer e gera relatórios de fluxos não testados.

Tracing ID: FLOW_DETECTION_DEMO_20250127_001
Data/Hora: 2025-01-27T18:30:00Z
Versão: 1.0
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.flow_detection_framework import FlowDetectionFramework

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "FLOW_DETECTION_DEMO_20250127_001"

def load_config() -> Dict[str, Any]:
    """Carrega configuração do framework."""
    config_path = Path("tests/integration/flow_detection_config.json")
    
    if not config_path.exists():
        logger.error(f"Arquivo de configuração não encontrado: {config_path}")
        return {}
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Erro ao carregar configuração: {e}")
        return {}

def analyze_real_logs(framework: FlowDetectionFramework) -> Dict[str, Any]:
    """
    Analisa logs reais do Omni Writer.
    
    Cenário Real: Analisa logs estruturados, pipeline e decisões
    para identificar fluxos não testados.
    """
    logger.info(f"[{TRACING_ID}] Iniciando análise de logs reais")
    
    results = {}
    logs_dir = Path("logs")
    
    # Analisa logs estruturados
    structured_logs = logs_dir / "structured_logs.json"
    if structured_logs.exists():
        logger.info(f"[{TRACING_ID}] Analisando logs estruturados: {structured_logs}")
        try:
            result = framework.analyze_logs(
                str(structured_logs),
                source_name="application_logs"
            )
            results["structured_logs"] = result
            logger.info(f"[{TRACING_ID}] Logs estruturados analisados: {result.total_logs_analyzed} entradas")
        except Exception as e:
            logger.error(f"[{TRACING_ID}] Erro ao analisar logs estruturados: {e}")
    
    # Analisa logs de pipeline
    pipeline_logs = logs_dir / "pipeline_multi_diag.log"
    if pipeline_logs.exists():
        logger.info(f"[{TRACING_ID}] Analisando logs de pipeline: {pipeline_logs}")
        try:
            result = framework.analyze_logs(
                str(pipeline_logs),
                source_name="pipeline_logs"
            )
            results["pipeline_logs"] = result
            logger.info(f"[{TRACING_ID}] Logs de pipeline analisados: {result.total_logs_analyzed} entradas")
        except Exception as e:
            logger.error(f"[{TRACING_ID}] Erro ao analisar logs de pipeline: {e}")
    
    # Analisa logs de decisões
    decision_logs = logs_dir / "decisions_2025-01-27.log"
    if decision_logs.exists():
        logger.info(f"[{TRACING_ID}] Analisando logs de decisões: {decision_logs}")
        try:
            result = framework.analyze_logs(
                str(decision_logs),
                source_name="decision_logs"
            )
            results["decision_logs"] = result
            logger.info(f"[{TRACING_ID}] Logs de decisões analisados: {result.total_logs_analyzed} entradas")
        except Exception as e:
            logger.error(f"[{TRACING_ID}] Erro ao analisar logs de decisões: {e}")
    
    return results

def generate_demo_report(framework: FlowDetectionFramework, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Gera relatório de demonstração baseado em análise real.
    
    Cenário Real: Gera relatório com estatísticas, fluxos de alto risco
    e sugestões de teste baseadas em logs reais.
    """
    logger.info(f"[{TRACING_ID}] Gerando relatório de demonstração")
    
    # Gera relatório completo
    report = framework.generate_report()
    
    # Adiciona informações de demonstração
    demo_report = {
        "demo_info": {
            "tracing_id": TRACING_ID,
            "timestamp": datetime.now().isoformat(),
            "description": "Demonstração do Framework de Detecção de Fluxos",
            "based_on_real_logs": True,
            "analysis_results": analysis_results
        },
        "summary": {
            "total_analyses": len(analysis_results),
            "total_logs_analyzed": sum(
                result.total_logs_analyzed 
                for result in analysis_results.values() 
                if hasattr(result, 'total_logs_analyzed')
            ),
            "new_flows_detected": sum(
                result.new_flows_detected 
                for result in analysis_results.values() 
                if hasattr(result, 'new_flows_detected')
            ),
            "high_risk_flows": sum(
                len(result.high_risk_flows) 
                for result in analysis_results.values() 
                if hasattr(result, 'high_risk_flows')
            )
        },
        "framework_report": report
    }
    
    return demo_report

def print_demo_summary(demo_report: Dict[str, Any]):
    """Imprime resumo da demonstração."""
    print("\n" + "="*80)
    print("🎯 DEMONSTRAÇÃO - FRAMEWORK DE DETECÇÃO DE FLUXOS")
    print("="*80)
    
    demo_info = demo_report["demo_info"]
    summary = demo_report["summary"]
    framework_report = demo_report["framework_report"]
    
    print(f"📊 Tracing ID: {demo_info['tracing_id']}")
    print(f"🕒 Timestamp: {demo_info['timestamp']}")
    print(f"📝 Baseado em logs reais: {demo_info['based_on_real_logs']}")
    
    print(f"\n📈 RESUMO DA ANÁLISE:")
    print(f"   • Análises realizadas: {summary['total_analyses']}")
    print(f"   • Logs analisados: {summary['total_logs_analyzed']}")
    print(f"   • Novos fluxos detectados: {summary['new_flows_detected']}")
    print(f"   • Fluxos de alto risco: {summary['high_risk_flows']}")
    
    if "statistics" in framework_report:
        stats = framework_report["statistics"]
        print(f"\n📊 ESTATÍSTICAS GERAIS:")
        print(f"   • Total de padrões: {stats.get('total_patterns', 0)}")
        print(f"   • Padrões testados: {stats.get('tested_patterns', 0)}")
        print(f"   • Padrões de alto risco: {stats.get('high_risk_patterns', 0)}")
        print(f"   • Score médio de risco: {stats.get('avg_risk_score', 0):.2f}")
        print(f"   • Taxa de cobertura: {stats.get('coverage_rate', 0):.1f}%")
    
    if "high_risk_untested" in framework_report:
        high_risk = framework_report["high_risk_untested"]
        if high_risk:
            print(f"\n⚠️  FLUXOS DE ALTO RISCO NÃO TESTADOS:")
            for i, flow in enumerate(high_risk[:5], 1):  # Mostra apenas os 5 primeiros
                print(f"   {i}. {flow['name']} (Risk: {flow['risk_score']})")
                if flow.get('suggestions'):
                    for suggestion in flow['suggestions'][:2]:  # Mostra apenas 2 sugestões
                        print(f"      💡 {suggestion}")
        else:
            print(f"\n✅ Nenhum fluxo de alto risco não testado encontrado!")
    
    if "most_frequent_flows" in framework_report:
        frequent = framework_report["most_frequent_flows"]
        if frequent:
            print(f"\n🔄 FLUXOS MAIS FREQUENTES:")
            for i, flow in enumerate(frequent[:3], 1):  # Mostra apenas os 3 primeiros
                tested_status = "✅" if flow.get('is_tested') else "❌"
                print(f"   {i}. {tested_status} {flow['name']} (Freq: {flow['frequency']})")
    
    print("\n" + "="*80)

def save_demo_report(demo_report: Dict[str, Any]):
    """Salva relatório de demonstração em arquivo."""
    output_dir = Path("tests/integration/reports")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    output_file = output_dir / f"flow_detection_demo_{timestamp}.json"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(demo_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[{TRACING_ID}] Relatório salvo: {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"[{TRACING_ID}] Erro ao salvar relatório: {e}")
        return None

def main():
    """Função principal da demonstração."""
    logger.info(f"[{TRACING_ID}] Iniciando demonstração do framework de detecção de fluxos")
    
    try:
        # Carrega configuração
        config = load_config()
        if not config:
            logger.error("Não foi possível carregar configuração. Abortando.")
            return 1
        
        # Inicializa framework
        framework = FlowDetectionFramework()
        logger.info(f"[{TRACING_ID}] Framework inicializado com sucesso")
        
        # Analisa logs reais
        analysis_results = analyze_real_logs(framework)
        
        if not analysis_results:
            logger.warning("Nenhum log foi analisado. Verifique se os arquivos de log existem.")
            return 1
        
        # Gera relatório de demonstração
        demo_report = generate_demo_report(framework, analysis_results)
        
        # Imprime resumo
        print_demo_summary(demo_report)
        
        # Salva relatório
        output_file = save_demo_report(demo_report)
        
        if output_file:
            print(f"\n💾 Relatório completo salvo em: {output_file}")
        
        logger.info(f"[{TRACING_ID}] Demonstração concluída com sucesso")
        return 0
        
    except Exception as e:
        logger.error(f"[{TRACING_ID}] Erro na demonstração: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 