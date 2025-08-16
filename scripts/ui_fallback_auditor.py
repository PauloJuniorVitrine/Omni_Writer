#!/usr/bin/env python3
"""
UI Fallback Auditor - Omni Writer
================================

Sistema de auditoria de fallbacks de UI para garantir degradação graciosa
e experiência do usuário consistente em cenários de falha.

Tracing ID: UI_FALLBACK_AUDIT_20250127_001
Ruleset: enterprise_control_layer.yaml
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import ast
import logging

@dataclass
class UIFallback:
    """Representa um fallback de UI identificado."""
    component: str
    fallback_type: str  # 'error', 'loading', 'empty', 'offline'
    implementation: str
    file_path: str
    line_number: int
    coverage: bool
    accessibility: bool
    performance_impact: str  # 'low', 'medium', 'high'

@dataclass
class FallbackAuditResult:
    """Resultado da auditoria de fallbacks de UI."""
    timestamp: datetime
    total_components: int
    components_with_fallbacks: int
    missing_fallbacks: int
    accessibility_issues: int
    performance_issues: int
    recommendations: List[str]
    coverage_score: float

class UIFallbackAuditor:
    """Auditor de fallbacks de UI com análise de degradação graciosa."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.audit_log_path = self.project_root / "logs" / "ui_fallback_audit.log"
        self.results_path = self.project_root / "monitoring" / "ui_fallback_audit_results.json"
        self.tracing_id = f"UI_FALLBACK_AUDIT_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configurar logging estruturado
        self._setup_logging()
        
        # Padrões de detecção
        self.fallback_patterns = {
            'error': [
                r'ErrorBoundary',
                r'catch.*error',
                r'\.catch\(',
                r'error.*fallback',
                r'ErrorComponent',
                r'ErrorPage'
            ],
            'loading': [
                r'LoadingSpinner',
                r'LoadingComponent',
                r'isLoading',
                r'skeleton',
                r'placeholder',
                r'Spinner'
            ],
            'empty': [
                r'EmptyState',
                r'NoData',
                r'empty.*state',
                r'no.*data',
                r'EmptyComponent'
            ],
            'offline': [
                r'OfflineIndicator',
                r'navigator\.onLine',
                r'offline.*mode',
                r'OfflineComponent'
            ]
        }
        
    def _setup_logging(self):
        """Configura logging estruturado para auditoria."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] [UI_FALLBACK_AUDIT] %(message)s',
            handlers=[
                logging.FileHandler(self.audit_log_path),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _log_audit_event(self, event: str, details: Dict = None):
        """Registra evento de auditoria com metadados."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": self.tracing_id,
            "event": event,
            "details": details or {}
        }
        self.logger.info(f"UI Fallback Audit Event: {json.dumps(log_entry)}")
        
    def find_ui_components(self) -> List[Path]:
        """Encontra todos os componentes de UI no projeto."""
        self._log_audit_event("finding_ui_components")
        
        ui_extensions = {'.tsx', '.ts', '.jsx', '.js', '.vue', '.svelte'}
        ui_components = []
        
        # Diretórios de UI
        ui_dirs = [
            self.project_root / "ui",
            self.project_root / "static" / "js",
            self.project_root / "templates"
        ]
        
        for ui_dir in ui_dirs:
            if ui_dir.exists():
                for file_path in ui_dir.rglob('*'):
                    if file_path.suffix in ui_extensions:
                        ui_components.append(file_path)
        
        self._log_audit_event("ui_components_found", {"count": len(ui_components)})
        return ui_components
    
    def analyze_component_fallbacks(self, file_path: Path) -> List[UIFallback]:
        """Analisa fallbacks em um componente específico."""
        fallbacks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Analisar cada tipo de fallback
            for fallback_type, patterns in self.fallback_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        
                        # Verificar se é uma implementação real
                        if self._is_real_implementation(content, match.start(), match.end()):
                            fallback = UIFallback(
                                component=file_path.stem,
                                fallback_type=fallback_type,
                                implementation=match.group(),
                                file_path=str(file_path),
                                line_number=line_number,
                                coverage=self._check_test_coverage(file_path),
                                accessibility=self._check_accessibility(content, line_number),
                                performance_impact=self._assess_performance_impact(fallback_type)
                            )
                            fallbacks.append(fallback)
                            
        except Exception as e:
            self.logger.warning(f"Erro ao analisar componente {file_path}: {e}")
            
        return fallbacks
    
    def _is_real_implementation(self, content: str, start: int, end: int) -> bool:
        """Verifica se é uma implementação real, não apenas comentário ou string."""
        # Verificar se não está em comentário
        before_content = content[:start]
        after_content = content[end:]
        
        # Verificar comentários de linha
        line_start = before_content.rfind('\n') + 1
        line_content = content[line_start:end]
        
        if '//' in line_content and line_content.find('//') < line_content.find(content[start:end]):
            return False
            
        # Verificar comentários de bloco
        comment_start = before_content.rfind('/*')
        comment_end = after_content.find('*/')
        
        if comment_start != -1 and comment_end != -1:
            if start > comment_start and end < (start + comment_end):
                return False
                
        return True
    
    def _check_test_coverage(self, file_path: Path) -> bool:
        """Verifica se o componente tem cobertura de testes."""
        # Procurar por arquivos de teste correspondentes
        test_patterns = [
            file_path.parent / f"{file_path.stem}.test.{file_path.suffix}",
            file_path.parent / f"{file_path.stem}.spec.{file_path.suffix}",
            file_path.parent / "__tests__" / f"{file_path.name}",
            file_path.parent.parent / "tests" / f"{file_path.stem}.test.{file_path.suffix}"
        ]
        
        for test_path in test_patterns:
            if test_path.exists():
                return True
                
        return False
    
    def _check_accessibility(self, content: str, line_number: int) -> bool:
        """Verifica se o fallback tem considerações de acessibilidade."""
        # Padrões de acessibilidade
        a11y_patterns = [
            r'aria-',
            r'role=',
            r'alt=',
            r'title=',
            r'aria-label',
            r'aria-describedby',
            r'aria-live'
        ]
        
        lines = content.split('\n')
        if line_number <= len(lines):
            line_content = lines[line_number - 1]
            
            for pattern in a11y_patterns:
                if re.search(pattern, line_content, re.IGNORECASE):
                    return True
                    
        return False
    
    def _assess_performance_impact(self, fallback_type: str) -> str:
        """Avalia o impacto de performance do tipo de fallback."""
        impact_map = {
            'error': 'low',
            'loading': 'low',
            'empty': 'low',
            'offline': 'medium'
        }
        
        return impact_map.get(fallback_type, 'low')
    
    def identify_missing_fallbacks(self, components: List[Path]) -> List[Dict]:
        """Identifica componentes que não têm fallbacks adequados."""
        missing_fallbacks = []
        
        critical_components = [
            'api', 'network', 'data', 'form', 'navigation', 'authentication'
        ]
        
        for component_path in components:
            component_name = component_path.stem.lower()
            
            # Verificar se é um componente crítico
            is_critical = any(critical in component_name for critical in critical_components)
            
            if is_critical:
                # Verificar se tem fallbacks
                fallbacks = self.analyze_component_fallbacks(component_path)
                
                if not fallbacks:
                    missing_fallbacks.append({
                        'component': component_path.stem,
                        'file_path': str(component_path),
                        'critical': True,
                        'recommended_fallbacks': ['error', 'loading']
                    })
                elif len(fallbacks) < 2:  # Componentes críticos devem ter múltiplos fallbacks
                    existing_types = [f.fallback_type for f in fallbacks]
                    missing_types = [t for t in ['error', 'loading'] if t not in existing_types]
                    
                    if missing_types:
                        missing_fallbacks.append({
                            'component': component_path.stem,
                            'file_path': str(component_path),
                            'critical': True,
                            'existing_fallbacks': existing_types,
                            'recommended_fallbacks': missing_types
                        })
        
        return missing_fallbacks
    
    def analyze_fallback_consistency(self, fallbacks: List[UIFallback]) -> Dict:
        """Analisa consistência dos fallbacks implementados."""
        consistency_analysis = {
            'error_fallbacks': 0,
            'loading_fallbacks': 0,
            'empty_fallbacks': 0,
            'offline_fallbacks': 0,
            'accessibility_issues': 0,
            'performance_issues': 0,
            'inconsistent_patterns': []
        }
        
        # Contar por tipo
        for fallback in fallbacks:
            consistency_analysis[f'{fallback.fallback_type}_fallbacks'] += 1
            
            if not fallback.accessibility:
                consistency_analysis['accessibility_issues'] += 1
                
            if fallback.performance_impact == 'high':
                consistency_analysis['performance_issues'] += 1
        
        # Identificar padrões inconsistentes
        implementations = {}
        for fallback in fallbacks:
            key = f"{fallback.fallback_type}_{fallback.implementation}"
            if key in implementations:
                consistency_analysis['inconsistent_patterns'].append({
                    'type': fallback.fallback_type,
                    'pattern': fallback.implementation,
                    'components': [f.component for f in fallbacks if f.implementation == fallback.implementation]
                })
            else:
                implementations[key] = fallback
        
        return consistency_analysis
    
    def generate_fallback_recommendations(self, fallbacks: List[UIFallback], missing_fallbacks: List[Dict]) -> List[str]:
        """Gera recomendações para melhorar fallbacks de UI."""
        recommendations = []
        
        # Recomendações baseadas em fallbacks ausentes
        if missing_fallbacks:
            critical_missing = [m for m in missing_fallbacks if m.get('critical', False)]
            if critical_missing:
                recommendations.append(f"🚨 {len(critical_missing)} componente(s) crítico(s) sem fallbacks adequados. Implementar urgente.")
        
        # Recomendações baseadas em acessibilidade
        accessibility_issues = [f for f in fallbacks if not f.accessibility]
        if accessibility_issues:
            recommendations.append(f"♿ {len(accessibility_issues)} fallback(s) sem considerações de acessibilidade. Adicionar atributos ARIA.")
        
        # Recomendações baseadas em performance
        performance_issues = [f for f in fallbacks if f.performance_impact == 'high']
        if performance_issues:
            recommendations.append(f"⚡ {len(performance_issues)} fallback(s) com alto impacto de performance. Otimizar implementação.")
        
        # Recomendações baseadas em cobertura de testes
        untested_fallbacks = [f for f in fallbacks if not f.coverage]
        if untested_fallbacks:
            recommendations.append(f"🧪 {len(untested_fallbacks)} fallback(s) sem cobertura de testes. Implementar testes unitários.")
        
        # Recomendações específicas por tipo
        fallback_counts = {}
        for fallback in fallbacks:
            fallback_counts[fallback.fallback_type] = fallback_counts.get(fallback.fallback_type, 0) + 1
        
        if fallback_counts.get('error', 0) < 5:
            recommendations.append("⚠️ Poucos fallbacks de erro implementados. Considerar implementar ErrorBoundary global.")
            
        if fallback_counts.get('offline', 0) < 2:
            recommendations.append("📡 Fallbacks offline limitados. Implementar indicadores de conectividade.")
        
        return recommendations
    
    def run_audit(self) -> FallbackAuditResult:
        """Executa auditoria completa de fallbacks de UI."""
        self._log_audit_event("starting_ui_fallback_audit")
        
        # Encontrar componentes de UI
        ui_components = self.find_ui_components()
        
        # Analisar fallbacks em cada componente
        all_fallbacks = []
        for component in ui_components:
            fallbacks = self.analyze_component_fallbacks(component)
            all_fallbacks.extend(fallbacks)
        
        # Identificar fallbacks ausentes
        missing_fallbacks = self.identify_missing_fallbacks(ui_components)
        
        # Analisar consistência
        consistency_analysis = self.analyze_fallback_consistency(all_fallbacks)
        
        # Gerar recomendações
        recommendations = self.generate_fallback_recommendations(all_fallbacks, missing_fallbacks)
        
        # Calcular métricas
        total_components = len(ui_components)
        components_with_fallbacks = len(set(f.component for f in all_fallbacks))
        missing_fallbacks_count = len(missing_fallbacks)
        accessibility_issues = consistency_analysis['accessibility_issues']
        performance_issues = consistency_analysis['performance_issues']
        
        # Calcular score de cobertura
        coverage_score = (components_with_fallbacks / total_components * 100) if total_components > 0 else 0
        
        # Criar resultado
        result = FallbackAuditResult(
            timestamp=datetime.now(),
            total_components=total_components,
            components_with_fallbacks=components_with_fallbacks,
            missing_fallbacks=missing_fallbacks_count,
            accessibility_issues=accessibility_issues,
            performance_issues=performance_issues,
            recommendations=recommendations,
            coverage_score=coverage_score
        )
        
        # Salvar resultados
        self._save_results(all_fallbacks, missing_fallbacks, consistency_analysis, result)
        
        self._log_audit_event("ui_fallback_audit_completed", {
            "total_components": total_components,
            "components_with_fallbacks": components_with_fallbacks,
            "missing_fallbacks": missing_fallbacks_count,
            "coverage_score": coverage_score
        })
        
        return result
    
    def _save_results(self, fallbacks: List[UIFallback], missing_fallbacks: List[Dict], 
                     consistency_analysis: Dict, audit_result: FallbackAuditResult):
        """Salva resultados da auditoria."""
        results_data = {
            "audit_result": asdict(audit_result),
            "fallbacks": [asdict(fallback) for fallback in fallbacks],
            "missing_fallbacks": missing_fallbacks,
            "consistency_analysis": consistency_analysis,
            "metadata": {
                "tracing_id": self.tracing_id,
                "generated_at": datetime.now().isoformat(),
                "ruleset": "enterprise_control_layer.yaml"
            }
        }
        
        # Converter datetime para string
        results_data["audit_result"]["timestamp"] = results_data["audit_result"]["timestamp"].isoformat()
        
        # Salvar em JSON
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self._log_audit_event("results_saved", {"path": str(self.results_path)})
    
    def generate_report(self) -> str:
        """Gera relatório em markdown da auditoria."""
        if not self.results_path.exists():
            return "❌ Nenhum resultado de auditoria encontrado."
        
        with open(self.results_path, 'r') as f:
            data = json.load(f)
        
        audit_result = data["audit_result"]
        fallbacks = data["fallbacks"]
        missing_fallbacks = data["missing_fallbacks"]
        consistency_analysis = data["consistency_analysis"]
        
        report = f"""# 🎨 UI Fallback Audit Report

**Tracing ID:** {data['metadata']['tracing_id']}  
**Generated:** {data['metadata']['generated_at']}  
**Ruleset:** {data['metadata']['ruleset']}

## 📊 Summary

- **Total Components:** {audit_result['total_components']}
- **Components with Fallbacks:** {audit_result['components_with_fallbacks']}
- **Missing Fallbacks:** {audit_result['missing_fallbacks']}
- **Accessibility Issues:** {audit_result['accessibility_issues']}
- **Performance Issues:** {audit_result['performance_issues']}
- **Coverage Score:** {audit_result['coverage_score']:.1f}%

## 🚨 Recommendations

"""
        
        for rec in audit_result['recommendations']:
            report += f"- {rec}\n"
        
        report += f"""

## 📋 Fallback Distribution

- **Error Fallbacks:** {consistency_analysis['error_fallbacks']}
- **Loading Fallbacks:** {consistency_analysis['loading_fallbacks']}
- **Empty State Fallbacks:** {consistency_analysis['empty_fallbacks']}
- **Offline Fallbacks:** {consistency_analysis['offline_fallbacks']}

## ⚠️ Missing Fallbacks

"""
        
        for missing in missing_fallbacks:
            report += f"- **{missing['component']}** ({missing['file_path']})\n"
            if missing.get('critical'):
                report += f"  - 🚨 **CRÍTICO** - Recomendado: {', '.join(missing['recommended_fallbacks'])}\n"
            else:
                report += f"  - Recomendado: {', '.join(missing['recommended_fallbacks'])}\n"
        
        report += "\n## 📋 Implemented Fallbacks\n\n"
        report += "| Component | Type | Implementation | Accessibility | Performance | Tested |\n"
        report += "|-----------|------|----------------|---------------|-------------|--------|\n"
        
        for fallback in fallbacks:
            report += f"| {fallback['component']} | {fallback['fallback_type']} | {fallback['implementation']} | {'✅' if fallback['accessibility'] else '❌'} | {fallback['performance_impact']} | {'✅' if fallback['coverage'] else '❌'} |\n"
        
        return report

def main():
    """Função principal para execução da auditoria."""
    project_root = os.getcwd()
    auditor = UIFallbackAuditor(project_root)
    
    print("🎨 Iniciando auditoria de fallbacks de UI...")
    result = auditor.run_audit()
    
    print(f"\n📊 Resultados da Auditoria:")
    print(f"   Total Components: {result.total_components}")
    print(f"   Components with Fallbacks: {result.components_with_fallbacks}")
    print(f"   Missing Fallbacks: {result.missing_fallbacks}")
    print(f"   Coverage Score: {result.coverage_score:.1f}%")
    
    print(f"\n🚨 Recomendações:")
    for rec in result.recommendations:
        print(f"   {rec}")
    
    # Gerar relatório
    report = auditor.generate_report()
    report_path = Path(project_root) / "docs" / f"ui_fallback_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\n📄 Relatório salvo em: {report_path}")
    print(f"📊 Resultados JSON: {auditor.results_path}")

if __name__ == "__main__":
    main() 