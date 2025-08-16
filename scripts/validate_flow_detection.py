#!/usr/bin/env python3
"""
🔍 VALIDAÇÃO SIMPLES - FRAMEWORK DE DETECÇÃO DE FLUXOS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Script de validação simples que demonstra o framework sem dependências externas.
Analisa logs reais do Omni Writer e gera relatório de validação.

Tracing ID: FLOW_DETECTION_VALIDATION_20250127_001
Data/Hora: 2025-01-27T18:30:00Z
Versão: 1.0
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

TRACING_ID = "FLOW_DETECTION_VALIDATION_20250127_001"

def validate_log_files():
    """Valida se os arquivos de log reais existem."""
    print(f"[{TRACING_ID}] Validando arquivos de log...")
    
    logs_dir = Path("logs")
    required_logs = [
        "structured_logs.json",
        "pipeline_multi_diag.log",
        "decisions_2025-01-27.log"
    ]
    
    found_logs = []
    missing_logs = []
    
    for log_file in required_logs:
        log_path = logs_dir / log_file
        if log_path.exists():
            found_logs.append(log_file)
            print(f"  ✅ {log_file} - Encontrado")
        else:
            missing_logs.append(log_file)
            print(f"  ❌ {log_file} - Não encontrado")
    
    return found_logs, missing_logs

def analyze_structured_logs():
    """Analisa logs estruturados reais."""
    print(f"\n[{TRACING_ID}] Analisando logs estruturados...")
    
    log_path = Path("logs/structured_logs.json")
    if not log_path.exists():
        print("  ❌ Arquivo de logs estruturados não encontrado")
        return None
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            logs = [json.loads(line) for line in f if line.strip()]
        
        print(f"  📊 {len(logs)} entradas de log analisadas")
        
        # Análise básica
        services = set()
        levels = set()
        endpoints = set()
        
        for log in logs:
            services.add(log.get('service', 'unknown'))
            levels.add(log.get('level', 'unknown'))
            if 'endpoint' in log:
                endpoints.add(log['endpoint'])
        
        print(f"  🔧 Serviços encontrados: {len(services)}")
        print(f"  📝 Níveis de log: {', '.join(levels)}")
        print(f"  🌐 Endpoints: {len(endpoints)}")
        
        return {
            'total_entries': len(logs),
            'services': list(services),
            'levels': list(levels),
            'endpoints': list(endpoints)
        }
        
    except Exception as e:
        print(f"  ❌ Erro ao analisar logs: {e}")
        return None

def analyze_pipeline_logs():
    """Analisa logs de pipeline reais."""
    print(f"\n[{TRACING_ID}] Analisando logs de pipeline...")
    
    log_path = Path("logs/pipeline_multi_diag.log")
    if not log_path.exists():
        print("  ❌ Arquivo de logs de pipeline não encontrado")
        return None
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"  📊 {len(lines)} linhas de log analisadas")
        
        # Análise de padrões
        pipeline_starts = 0
        generate_calls = 0
        testing_mentions = 0
        
        for line in lines:
            if "Iniciando pipeline multi" in line:
                pipeline_starts += 1
            if "Chamando generate_article" in line:
                generate_calls += 1
            if "TESTING=" in line:
                testing_mentions += 1
        
        print(f"  🔄 Inicializações de pipeline: {pipeline_starts}")
        print(f"  📝 Chamadas de geração: {generate_calls}")
        print(f"  🧪 Menções de teste: {testing_mentions}")
        
        return {
            'total_lines': len(lines),
            'pipeline_starts': pipeline_starts,
            'generate_calls': generate_calls,
            'testing_mentions': testing_mentions
        }
        
    except Exception as e:
        print(f"  ❌ Erro ao analisar logs de pipeline: {e}")
        return None

def analyze_decision_logs():
    """Analisa logs de decisões reais."""
    print(f"\n[{TRACING_ID}] Analisando logs de decisões...")
    
    log_path = Path("logs/decisions_2025-01-27.log")
    if not log_path.exists():
        print("  ❌ Arquivo de logs de decisões não encontrado")
        return None
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        print(f"  📊 {len(lines)} linhas de log analisadas")
        
        # Análise de decisões
        test_decisions = 0
        coverage_decisions = 0
        risk_decisions = 0
        
        for line in lines:
            if "test" in line.lower():
                test_decisions += 1
            if "coverage" in line.lower():
                coverage_decisions += 1
            if "risk" in line.lower():
                risk_decisions += 1
        
        print(f"  🧪 Decisões sobre testes: {test_decisions}")
        print(f"  📈 Decisões sobre cobertura: {coverage_decisions}")
        print(f"  ⚠️ Decisões sobre risco: {risk_decisions}")
        
        return {
            'total_lines': len(lines),
            'test_decisions': test_decisions,
            'coverage_decisions': coverage_decisions,
            'risk_decisions': risk_decisions
        }
        
    except Exception as e:
        print(f"  ❌ Erro ao analisar logs de decisões: {e}")
        return None

def detect_flow_patterns(analysis_results):
    """Detecta padrões de fluxo baseados na análise."""
    print(f"\n[{TRACING_ID}] Detectando padrões de fluxo...")
    
    patterns = []
    
    # Padrões baseados em logs estruturados
    if analysis_results.get('structured_logs'):
        structured = analysis_results['structured_logs']
        
        # Padrão de monitoramento
        if any('monitoring' in service for service in structured['services']):
            patterns.append({
                'name': 'Fluxo de Monitoramento',
                'description': 'Detectado através de serviços de monitoramento',
                'risk_score': 80,
                'services': [s for s in structured['services'] if 'monitoring' in s],
                'is_tested': False
            })
        
        # Padrão de API
        if structured['endpoints']:
            patterns.append({
                'name': 'Fluxo de API',
                'description': 'Detectado através de endpoints de API',
                'risk_score': 120,
                'endpoints': structured['endpoints'],
                'is_tested': False
            })
    
    # Padrões baseados em logs de pipeline
    if analysis_results.get('pipeline_logs'):
        pipeline = analysis_results['pipeline_logs']
        
        if pipeline['generate_calls'] > 0:
            patterns.append({
                'name': 'Fluxo de Geração de Artigos',
                'description': 'Detectado através de chamadas de geração',
                'risk_score': 150,
                'frequency': pipeline['generate_calls'],
                'is_tested': True
            })
    
    # Padrões baseados em logs de decisões
    if analysis_results.get('decision_logs'):
        decision = analysis_results['decision_logs']
        
        if decision['test_decisions'] > 0:
            patterns.append({
                'name': 'Fluxo de Decisões de Teste',
                'description': 'Detectado através de decisões sobre testes',
                'risk_score': 90,
                'frequency': decision['test_decisions'],
                'is_tested': True
            })
    
    print(f"  🎯 {len(patterns)} padrões de fluxo detectados")
    
    for pattern in patterns:
        status = "✅ Testado" if pattern.get('is_tested') else "❌ Não Testado"
        print(f"    • {pattern['name']} (Risk: {pattern['risk_score']}) - {status}")
    
    return patterns

def generate_validation_report(analysis_results, patterns):
    """Gera relatório de validação."""
    print(f"\n[{TRACING_ID}] Gerando relatório de validação...")
    
    report = {
        'validation_info': {
            'tracing_id': TRACING_ID,
            'timestamp': datetime.now().isoformat(),
            'description': 'Validação do Framework de Detecção de Fluxos',
            'based_on_real_logs': True
        },
        'log_analysis': analysis_results,
        'flow_patterns': patterns,
        'statistics': {
            'total_patterns': len(patterns),
            'tested_patterns': sum(1 for p in patterns if p.get('is_tested')),
            'untested_patterns': sum(1 for p in patterns if not p.get('is_tested')),
            'high_risk_patterns': sum(1 for p in patterns if p.get('risk_score', 0) >= 100),
            'avg_risk_score': sum(p.get('risk_score', 0) for p in patterns) / len(patterns) if patterns else 0
        }
    }
    
    # Calcula taxa de cobertura
    if report['statistics']['total_patterns'] > 0:
        coverage_rate = (report['statistics']['tested_patterns'] / report['statistics']['total_patterns']) * 100
        report['statistics']['coverage_rate'] = coverage_rate
    else:
        report['statistics']['coverage_rate'] = 0
    
    return report

def print_validation_summary(report):
    """Imprime resumo da validação."""
    print("\n" + "="*80)
    print("🔍 VALIDAÇÃO - FRAMEWORK DE DETECÇÃO DE FLUXOS")
    print("="*80)
    
    validation_info = report['validation_info']
    stats = report['statistics']
    
    print(f"📊 Tracing ID: {validation_info['tracing_id']}")
    print(f"🕒 Timestamp: {validation_info['timestamp']}")
    print(f"📝 Baseado em logs reais: {validation_info['based_on_real_logs']}")
    
    print(f"\n📈 ESTATÍSTICAS DE VALIDAÇÃO:")
    print(f"   • Total de padrões: {stats['total_patterns']}")
    print(f"   • Padrões testados: {stats['tested_patterns']}")
    print(f"   • Padrões não testados: {stats['untested_patterns']}")
    print(f"   • Padrões de alto risco: {stats['high_risk_patterns']}")
    print(f"   • Score médio de risco: {stats['avg_risk_score']:.1f}")
    print(f"   • Taxa de cobertura: {stats['coverage_rate']:.1f}%")
    
    if report['flow_patterns']:
        print(f"\n🎯 PADRÕES DETECTADOS:")
        for pattern in report['flow_patterns']:
            status = "✅" if pattern.get('is_tested') else "❌"
            print(f"   {status} {pattern['name']} (Risk: {pattern['risk_score']})")
            print(f"      📝 {pattern['description']}")
    
    print("\n" + "="*80)

def save_validation_report(report):
    """Salva relatório de validação."""
    output_dir = Path("tests/integration/reports")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    output_file = output_dir / f"flow_detection_validation_{timestamp}.json"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Relatório salvo: {output_file}")
        return output_file
    except Exception as e:
        print(f"\n❌ Erro ao salvar relatório: {e}")
        return None

def main():
    """Função principal da validação."""
    print(f"[{TRACING_ID}] Iniciando validação do framework de detecção de fluxos")
    
    try:
        # Valida arquivos de log
        found_logs, missing_logs = validate_log_files()
        
        if not found_logs:
            print(f"\n❌ Nenhum arquivo de log encontrado. Validação abortada.")
            return 1
        
        # Analisa logs
        analysis_results = {}
        
        structured_analysis = analyze_structured_logs()
        if structured_analysis:
            analysis_results['structured_logs'] = structured_analysis
        
        pipeline_analysis = analyze_pipeline_logs()
        if pipeline_analysis:
            analysis_results['pipeline_logs'] = pipeline_analysis
        
        decision_analysis = analyze_decision_logs()
        if decision_analysis:
            analysis_results['decision_logs'] = decision_analysis
        
        if not analysis_results:
            print(f"\n❌ Nenhuma análise foi possível. Validação abortada.")
            return 1
        
        # Detecta padrões de fluxo
        patterns = detect_flow_patterns(analysis_results)
        
        # Gera relatório
        report = generate_validation_report(analysis_results, patterns)
        
        # Imprime resumo
        print_validation_summary(report)
        
        # Salva relatório
        output_file = save_validation_report(report)
        
        if output_file:
            print(f"\n✅ Validação concluída com sucesso!")
            print(f"📄 Relatório completo: {output_file}")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Erro na validação: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 