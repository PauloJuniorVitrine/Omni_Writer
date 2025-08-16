#!/usr/bin/env python3
"""
Advanced Improvements Runner - Omni Writer
=========================================

Script principal para executar todas as melhorias avançadas implementadas:
- SDK Version Audit
- UI Fallback Auditoria
- Multitenancy Awareness
- Chaos Testing

Tracing ID: ADVANCED_IMPROVEMENTS_20250127_001
Ruleset: enterprise_control_layer.yaml
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging
import subprocess

@dataclass
class ImprovementResult:
    """Resultado de uma melhoria avançada."""
    name: str
    status: str  # 'success', 'failed', 'skipped'
    duration: float
    output: str
    error_message: Optional[str]
    impact_score: float

@dataclass
class ImprovementsSummary:
    """Resumo de todas as melhorias executadas."""
    timestamp: datetime
    total_improvements: int
    successful_improvements: int
    failed_improvements: int
    skipped_improvements: int
    total_duration: float
    average_impact_score: float
    recommendations: List[str]

class AdvancedImprovementsRunner:
    """Runner para executar todas as melhorias avançadas."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.log_path = self.project_root / "logs" / "advanced_improvements.log"
        self.results_path = self.project_root / "monitoring" / "advanced_improvements_results.json"
        self.tracing_id = f"ADVANCED_IMPROVEMENTS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configurar logging estruturado
        self._setup_logging()
        
        # Lista de melhorias a serem executadas
        self.improvements = [
            {
                "name": "SDK Version Audit",
                "script": "scripts/sdk_version_audit.py",
                "description": "Auditoria de versões de SDK para detectar breaking changes",
                "category": "security",
                "priority": "high"
            },
            {
                "name": "UI Fallback Auditoria",
                "script": "scripts/ui_fallback_auditor.py",
                "description": "Auditoria de fallbacks de UI para degradação graciosa",
                "category": "ux",
                "priority": "medium"
            },
            {
                "name": "Multitenancy Awareness",
                "script": "scripts/multitenancy_auditor.py",
                "description": "Auditoria de isolamento de dados por tenant",
                "category": "security",
                "priority": "high"
            },
            {
                "name": "Chaos Testing",
                "script": "scripts/chaos_testing_framework.py",
                "description": "Framework de chaos testing para resiliência",
                "category": "reliability",
                "priority": "medium"
            }
        ]
        
        self.results = []
        
    def _setup_logging(self):
        """Configura logging estruturado."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] [ADVANCED_IMPROVEMENTS] %(message)s',
            handlers=[
                logging.FileHandler(self.log_path),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _log_event(self, event: str, details: Dict = None):
        """Registra evento com metadados."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": self.tracing_id,
            "event": event,
            "details": details or {}
        }
        self.logger.info(f"Advanced Improvements Event: {json.dumps(log_entry)}")
        
    def check_prerequisites(self) -> bool:
        """Verifica pré-requisitos para execução das melhorias."""
        self._log_event("checking_prerequisites")
        
        # Verificar se os scripts existem
        missing_scripts = []
        for improvement in self.improvements:
            script_path = self.project_root / improvement["script"]
            if not script_path.exists():
                missing_scripts.append(improvement["script"])
        
        if missing_scripts:
            self.logger.error(f"Scripts ausentes: {missing_scripts}")
            return False
        
        # Verificar dependências Python
        required_packages = [
            "requests", "psutil", "semver"
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            self.logger.warning(f"Pacotes Python ausentes: {missing_packages}")
            self.logger.info("Instalando dependências...")
            
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install"
                ] + missing_packages, check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Erro ao instalar dependências: {e}")
                return False
        
        # Verificar se o sistema está saudável
        try:
            # Verificar se a aplicação está rodando
            import requests
            response = requests.get("http://localhost:5000/health", timeout=5)
            if response.status_code != 200:
                self.logger.warning("Aplicação não está respondendo corretamente")
        except Exception as e:
            self.logger.warning(f"Não foi possível verificar saúde da aplicação: {e}")
        
        self._log_event("prerequisites_check_completed", {"status": "success"})
        return True
    
    def run_improvement(self, improvement: Dict) -> ImprovementResult:
        """Executa uma melhoria específica."""
        self._log_event("running_improvement", {"name": improvement["name"]})
        
        start_time = time.time()
        script_path = self.project_root / improvement["script"]
        
        try:
            # Executar script
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=300  # 5 minutos de timeout
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            if result.returncode == 0:
                status = "success"
                error_message = None
                impact_score = self._calculate_impact_score(improvement, result.stdout)
            else:
                status = "failed"
                error_message = result.stderr
                impact_score = 0.0
            
            improvement_result = ImprovementResult(
                name=improvement["name"],
                status=status,
                duration=duration,
                output=result.stdout,
                error_message=error_message,
                impact_score=impact_score
            )
            
            self._log_event("improvement_completed", {
                "name": improvement["name"],
                "status": status,
                "duration": duration,
                "impact_score": impact_score
            })
            
            return improvement_result
            
        except subprocess.TimeoutExpired:
            end_time = time.time()
            duration = end_time - start_time
            
            self._log_event("improvement_timeout", {"name": improvement["name"]})
            
            return ImprovementResult(
                name=improvement["name"],
                status="failed",
                duration=duration,
                output="",
                error_message="Timeout após 5 minutos",
                impact_score=0.0
            )
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            self._log_event("improvement_error", {"name": improvement["name"], "error": str(e)})
            
            return ImprovementResult(
                name=improvement["name"],
                status="failed",
                duration=duration,
                output="",
                error_message=str(e),
                impact_score=0.0
            )
    
    def _calculate_impact_score(self, improvement: Dict, output: str) -> float:
        """Calcula score de impacto baseado na saída da melhoria."""
        base_score = 50.0
        
        # Ajustar score baseado na categoria e prioridade
        category_weights = {
            "security": 1.2,
            "reliability": 1.1,
            "ux": 1.0,
            "performance": 1.0
        }
        
        priority_weights = {
            "high": 1.3,
            "medium": 1.0,
            "low": 0.8
        }
        
        category_weight = category_weights.get(improvement["category"], 1.0)
        priority_weight = priority_weights.get(improvement["priority"], 1.0)
        
        # Analisar saída para detectar problemas encontrados
        issues_found = 0
        if "breaking changes" in output.lower():
            issues_found += 3
        if "missing fallbacks" in output.lower():
            issues_found += 2
        if "isolation gaps" in output.lower():
            issues_found += 3
        if "chaos testing" in output.lower() and "successful" in output.lower():
            issues_found += 1
        
        # Calcular score final
        impact_score = base_score * category_weight * priority_weight + issues_found * 10
        return min(impact_score, 100.0)
    
    def generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas nos resultados."""
        recommendations = []
        
        # Contar melhorias por status
        successful = [r for r in self.results if r.status == "success"]
        failed = [r for r in self.results if r.status == "failed"]
        skipped = [r for r in self.results if r.status == "skipped"]
        
        if failed:
            recommendations.append(f"🚨 {len(failed)} melhoria(s) falharam. Revisar logs e corrigir problemas.")
        
        if skipped:
            recommendations.append(f"⚠️ {len(skipped)} melhoria(s) foram puladas. Verificar pré-requisitos.")
        
        # Recomendações específicas baseadas nos resultados
        for result in self.results:
            if result.status == "success":
                if result.impact_score < 50:
                    recommendations.append(f"📊 {result.name}: Score de impacto baixo ({result.impact_score:.1f}). Considerar otimizações.")
                elif result.impact_score > 80:
                    recommendations.append(f"✅ {result.name}: Excelente score de impacto ({result.impact_score:.1f}). Manter monitoramento.")
        
        # Recomendações gerais
        if len(successful) == len(self.improvements):
            recommendations.append("🎉 Todas as melhorias avançadas executadas com sucesso. Sistema está otimizado.")
        
        if not recommendations:
            recommendations.append("📋 Melhorias executadas. Continuar monitoramento regular.")
        
        return recommendations
    
    def run_all_improvements(self) -> ImprovementsSummary:
        """Executa todas as melhorias avançadas."""
        self._log_event("starting_all_improvements")
        
        print("🚀 Iniciando execução das melhorias avançadas...")
        
        # Verificar pré-requisitos
        if not self.check_prerequisites():
            print("❌ Pré-requisitos não atendidos. Abortando execução.")
            return self._create_summary()
        
        print("✅ Pré-requisitos atendidos. Executando melhorias...")
        
        # Executar cada melhoria
        for i, improvement in enumerate(self.improvements, 1):
            print(f"\n📋 [{i}/{len(self.improvements)}] Executando: {improvement['name']}")
            print(f"   Descrição: {improvement['description']}")
            print(f"   Categoria: {improvement['category']} | Prioridade: {improvement['priority']}")
            
            result = self.run_improvement(improvement)
            self.results.append(result)
            
            # Exibir resultado
            if result.status == "success":
                print(f"   ✅ Sucesso em {result.duration:.1f}s | Impacto: {result.impact_score:.1f}/100")
            else:
                print(f"   ❌ Falha em {result.duration:.1f}s | Erro: {result.error_message}")
            
            # Aguardar entre melhorias
            if i < len(self.improvements):
                print("   ⏳ Aguardando 5 segundos antes da próxima melhoria...")
                time.sleep(5)
        
        # Gerar resumo
        summary = self._create_summary()
        
        # Salvar resultados
        self._save_results(summary)
        
        # Gerar relatório
        self._generate_report(summary)
        
        self._log_event("all_improvements_completed", {
            "total": len(self.improvements),
            "successful": summary.successful_improvements,
            "failed": summary.failed_improvements,
            "average_impact": summary.average_impact_score
        })
        
        return summary
    
    def _create_summary(self) -> ImprovementsSummary:
        """Cria resumo dos resultados."""
        total_improvements = len(self.results)
        successful_improvements = len([r for r in self.results if r.status == "success"])
        failed_improvements = len([r for r in self.results if r.status == "failed"])
        skipped_improvements = len([r for r in self.results if r.status == "skipped"])
        
        total_duration = sum(r.duration for r in self.results)
        
        impact_scores = [r.impact_score for r in self.results if r.status == "success"]
        average_impact_score = sum(impact_scores) / len(impact_scores) if impact_scores else 0.0
        
        recommendations = self.generate_recommendations()
        
        return ImprovementsSummary(
            timestamp=datetime.now(),
            total_improvements=total_improvements,
            successful_improvements=successful_improvements,
            failed_improvements=failed_improvements,
            skipped_improvements=skipped_improvements,
            total_duration=total_duration,
            average_impact_score=average_impact_score,
            recommendations=recommendations
        )
    
    def _save_results(self, summary: ImprovementsSummary):
        """Salva resultados em JSON."""
        results_data = {
            "summary": asdict(summary),
            "improvement_results": [asdict(result) for result in self.results],
            "metadata": {
                "tracing_id": self.tracing_id,
                "generated_at": datetime.now().isoformat(),
                "ruleset": "enterprise_control_layer.yaml"
            }
        }
        
        # Converter datetime para string
        results_data["summary"]["timestamp"] = results_data["summary"]["timestamp"].isoformat()
        
        # Salvar em JSON
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self._log_event("results_saved", {"path": str(self.results_path)})
    
    def _generate_report(self, summary: ImprovementsSummary):
        """Gera relatório em markdown."""
        report = f"""# 🚀 Advanced Improvements Report

**Tracing ID:** {self.tracing_id}  
**Generated:** {datetime.now().isoformat()}  
**Ruleset:** enterprise_control_layer.yaml

## 📊 Summary

- **Total Improvements:** {summary.total_improvements}
- **Successful:** {summary.successful_improvements}
- **Failed:** {summary.failed_improvements}
- **Skipped:** {summary.skipped_improvements}
- **Success Rate:** {(summary.successful_improvements / summary.total_improvements * 100):.1f}%
- **Total Duration:** {summary.total_duration:.1f}s
- **Average Impact Score:** {summary.average_impact_score:.1f}/100

## 🚨 Recommendations

"""
        
        for rec in summary.recommendations:
            report += f"- {rec}\n"
        
        report += "\n## 📋 Improvement Details\n\n"
        report += "| Improvement | Status | Duration | Impact Score | Error |\n"
        report += "|-------------|--------|----------|--------------|-------|\n"
        
        for result in self.results:
            status_icon = "✅" if result.status == "success" else "❌" if result.status == "failed" else "⏭️"
            error_msg = result.error_message[:50] + "..." if result.error_message and len(result.error_message) > 50 else result.error_message or ""
            report += f"| {result.name} | {status_icon} {result.status} | {result.duration:.1f}s | {result.impact_score:.1f} | {error_msg} |\n"
        
        # Salvar relatório
        report_path = self.project_root / "docs" / f"advanced_improvements_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        self._log_event("report_generated", {"path": str(report_path)})
        
        return report_path

def main():
    """Função principal para execução das melhorias avançadas."""
    project_root = os.getcwd()
    runner = AdvancedImprovementsRunner(project_root)
    
    print("🚀 Advanced Improvements Runner - Omni Writer")
    print("=" * 50)
    
    # Executar todas as melhorias
    summary = runner.run_all_improvements()
    
    # Exibir resumo final
    print("\n" + "=" * 50)
    print("📊 RESUMO FINAL")
    print("=" * 50)
    print(f"   Total de Melhorias: {summary.total_improvements}")
    print(f"   Sucessos: {summary.successful_improvements}")
    print(f"   Falhas: {summary.failed_improvements}")
    print(f"   Puladas: {summary.skipped_improvements}")
    print(f"   Taxa de Sucesso: {(summary.successful_improvements / summary.total_improvements * 100):.1f}%")
    print(f"   Duração Total: {summary.total_duration:.1f}s")
    print(f"   Score Médio de Impacto: {summary.average_impact_score:.1f}/100")
    
    print(f"\n🚨 Recomendações:")
    for rec in summary.recommendations:
        print(f"   {rec}")
    
    print(f"\n📄 Relatórios gerados:")
    print(f"   - JSON: {runner.results_path}")
    print(f"   - Markdown: docs/advanced_improvements_report_*.md")
    
    if summary.successful_improvements == summary.total_improvements:
        print(f"\n🎉 Todas as melhorias avançadas foram implementadas com sucesso!")
    else:
        print(f"\n⚠️ Algumas melhorias falharam. Verificar logs para detalhes.")

if __name__ == "__main__":
    main() 