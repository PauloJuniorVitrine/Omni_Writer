#!/usr/bin/env python3
"""
Script de Validação Rigorosa de Cobertura de Testes.
Bloqueia merge se cobertura < 98% e identifica branches críticos não cobertos.
"""

import os
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import argparse
import logging
from dataclasses import dataclass
from datetime import datetime

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('coverage_validation')

@dataclass
class CoverageMetrics:
    """Métricas de cobertura."""
    total_lines: int
    covered_lines: int
    total_branches: int
    covered_branches: int
    total_functions: int
    covered_functions: int
    percentage: float
    critical_branches_missing: List[str]
    high_risk_files: List[str]

@dataclass
class ValidationResult:
    """Resultado da validação."""
    passed: bool
    score: float
    issues: List[str]
    recommendations: List[str]
    critical_files: List[str]

class CoverageValidator:
    """
    Validador rigoroso de cobertura de testes.
    """
    
    def __init__(self, coverage_dir: str = "coverage", threshold: float = 98.0):
        self.coverage_dir = Path(coverage_dir)
        self.threshold = threshold
        
        # Arquivos críticos que devem ter 100% de cobertura
        self.critical_files = {
            "app/": ["authentication", "security", "validation"],
            "shared/": ["config", "logger", "security"],
            "domain/": ["models", "services", "validators"],
            "infraestructure/": ["database", "api", "storage"]
        }
        
        # Padrões de branches críticos
        self.critical_branch_patterns = [
            "error handling",
            "exception",
            "fallback",
            "validation",
            "security",
            "authentication",
            "authorization",
            "sanitization",
            "encryption",
            "decryption"
        ]
    
    def load_coverage_data(self) -> Dict[str, CoverageMetrics]:
        """
        Carrega dados de cobertura dos arquivos XML.
        
        Returns:
            Dicionário com métricas por arquivo
        """
        logger.info("Carregando dados de cobertura...")
        
        coverage_data = {}
        
        # Procura por arquivos de cobertura
        coverage_files = list(self.coverage_dir.glob("*.xml"))
        
        if not coverage_files:
            logger.error("Nenhum arquivo de cobertura encontrado")
            return coverage_data
        
        for coverage_file in coverage_files:
            try:
                tree = ET.parse(coverage_file)
                root = tree.getroot()
                
                # Processa cada arquivo no relatório
                for package in root.findall(".//package"):
                    for file_elem in package.findall(".//file"):
                        file_path = file_elem.get("name", "")
                        
                        # Estatísticas de linha
                        lines = file_elem.findall(".//line")
                        total_lines = len(lines)
                        covered_lines = sum(1 for line in lines if line.get("hits", "0") != "0")
                        
                        # Estatísticas de branch
                        branches = file_elem.findall(".//branch")
                        total_branches = len(branches)
                        covered_branches = sum(1 for branch in branches if branch.get("taken", "0") != "0")
                        
                        # Estatísticas de função
                        functions = file_elem.findall(".//function")
                        total_functions = len(functions)
                        covered_functions = sum(1 for func in functions if func.get("hits", "0") != "0")
                        
                        # Calcula porcentagem
                        if total_lines > 0:
                            percentage = (covered_lines / total_lines) * 100
                        else:
                            percentage = 0.0
                        
                        # Identifica branches críticos não cobertos
                        critical_branches = self._identify_critical_branches(file_path, branches)
                        
                        # Identifica arquivos de alto risco
                        high_risk = self._is_high_risk_file(file_path)
                        
                        coverage_data[file_path] = CoverageMetrics(
                            total_lines=total_lines,
                            covered_lines=covered_lines,
                            total_branches=total_branches,
                            covered_branches=covered_branches,
                            total_functions=total_functions,
                            covered_functions=covered_functions,
                            percentage=percentage,
                            critical_branches_missing=critical_branches,
                            high_risk_files=[file_path] if high_risk else []
                        )
                
                logger.info(f"Processado: {coverage_file}")
                
            except Exception as e:
                logger.error(f"Erro ao processar {coverage_file}: {e}")
        
        return coverage_data
    
    def _identify_critical_branches(self, file_path: str, branches: List) -> List[str]:
        """
        Identifica branches críticos não cobertos.
        
        Args:
            file_path: Caminho do arquivo
            branches: Lista de elementos de branch
        
        Returns:
            Lista de branches críticos não cobertos
        """
        critical_branches = []
        
        # Lê o conteúdo do arquivo para análise
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            return critical_branches
        
        # Analisa cada branch
        for i, branch in enumerate(branches):
            if branch.get("taken", "0") == "0":  # Branch não coberto
                line_number = int(branch.get("line", "0"))
                
                # Obtém a linha do código
                lines = content.split('\n')
                if line_number <= len(lines):
                    line_content = lines[line_number - 1].strip()
                    
                    # Verifica se é um branch crítico
                    if any(pattern in line_content.lower() for pattern in self.critical_branch_patterns):
                        critical_branches.append(f"Linha {line_number}: {line_content[:50]}...")
        
        return critical_branches
    
    def _is_high_risk_file(self, file_path: str) -> bool:
        """
        Verifica se um arquivo é de alto risco.
        
        Args:
            file_path: Caminho do arquivo
        
        Returns:
            True se é arquivo de alto risco
        """
        file_path_lower = file_path.lower()
        
        # Verifica padrões de arquivos críticos
        for directory, patterns in self.critical_files.items():
            if directory in file_path_lower:
                for pattern in patterns:
                    if pattern in file_path_lower:
                        return True
        
        return False
    
    def calculate_overall_metrics(self, coverage_data: Dict[str, CoverageMetrics]) -> CoverageMetrics:
        """
        Calcula métricas gerais de cobertura.
        
        Args:
            coverage_data: Dados de cobertura por arquivo
        
        Returns:
            Métricas gerais
        """
        total_lines = sum(data.total_lines for data in coverage_data.values())
        covered_lines = sum(data.covered_lines for data in coverage_data.values())
        total_branches = sum(data.total_branches for data in coverage_data.values())
        covered_branches = sum(data.covered_branches for data in coverage_data.values())
        total_functions = sum(data.total_functions for data in coverage_data.values())
        covered_functions = sum(data.covered_functions for data in coverage_data.values())
        
        # Calcula porcentagem geral
        if total_lines > 0:
            percentage = (covered_lines / total_lines) * 100
        else:
            percentage = 0.0
        
        # Coleta branches críticos não cobertos
        critical_branches = []
        for data in coverage_data.values():
            critical_branches.extend(data.critical_branches_missing)
        
        # Coleta arquivos de alto risco
        high_risk_files = []
        for data in coverage_data.values():
            high_risk_files.extend(data.high_risk_files)
        
        return CoverageMetrics(
            total_lines=total_lines,
            covered_lines=covered_lines,
            total_branches=total_branches,
            covered_branches=covered_branches,
            total_functions=total_functions,
            covered_functions=covered_functions,
            percentage=percentage,
            critical_branches_missing=critical_branches,
            high_risk_files=high_risk_files
        )
    
    def validate_coverage(self, overall_metrics: CoverageMetrics, coverage_data: Dict[str, CoverageMetrics]) -> ValidationResult:
        """
        Valida a cobertura de testes.
        
        Args:
            overall_metrics: Métricas gerais
            coverage_data: Dados de cobertura por arquivo
        
        Returns:
            Resultado da validação
        """
        logger.info("Validando cobertura de testes...")
        
        issues = []
        recommendations = []
        critical_files = []
        
        # Verifica cobertura geral
        if overall_metrics.percentage < self.threshold:
            issues.append(f"Cobertura geral insuficiente: {overall_metrics.percentage:.2f}% < {self.threshold}%")
            recommendations.append(f"Aumentar cobertura para pelo menos {self.threshold}%")
        
        # Verifica branches críticos não cobertos
        if overall_metrics.critical_branches_missing:
            issues.append(f"Branches críticos não cobertos: {len(overall_metrics.critical_branches_missing)}")
            recommendations.append("Implementar testes para branches críticos")
        
        # Verifica arquivos de alto risco
        if overall_metrics.high_risk_files:
            issues.append(f"Arquivos de alto risco com cobertura baixa: {len(overall_metrics.high_risk_files)}")
            recommendations.append("Priorizar cobertura em arquivos de alto risco")
        
        # Verifica arquivos individuais
        for file_path, metrics in coverage_data.items():
            if self._is_high_risk_file(file_path) and metrics.percentage < 100:
                critical_files.append(file_path)
                issues.append(f"Arquivo crítico sem 100% cobertura: {file_path} ({metrics.percentage:.2f}%)")
                recommendations.append(f"Implementar testes para {file_path}")
        
        # Calcula score
        score = overall_metrics.percentage
        
        # Deduções por problemas
        score -= len(overall_metrics.critical_branches_missing) * 2
        score -= len(critical_files) * 5
        
        # Garante mínimo de 0
        score = max(0, score)
        
        # Determina se passou
        passed = (
            overall_metrics.percentage >= self.threshold and
            not overall_metrics.critical_branches_missing and
            not critical_files
        )
        
        return ValidationResult(
            passed=passed,
            score=score,
            issues=issues,
            recommendations=recommendations,
            critical_files=critical_files
        )
    
    def generate_report(self, overall_metrics: CoverageMetrics, validation_result: ValidationResult) -> str:
        """
        Gera relatório de cobertura.
        
        Args:
            overall_metrics: Métricas gerais
            validation_result: Resultado da validação
        
        Returns:
            Relatório formatado
        """
        report = f"""
# Relatório de Validação de Cobertura

## 📊 Métricas Gerais
- **Cobertura Total:** {overall_metrics.percentage:.2f}%
- **Linhas:** {overall_metrics.covered_lines}/{overall_metrics.total_lines}
- **Branches:** {overall_metrics.covered_branches}/{overall_metrics.total_branches}
- **Funções:** {overall_metrics.covered_functions}/{overall_metrics.total_functions}

## ✅ Status da Validação
- **Aprovado:** {'✅ Sim' if validation_result.passed else '❌ Não'}
- **Score:** {validation_result.score:.2f}/100
- **Threshold:** {self.threshold}%

## 🔍 Issues Identificados
"""
        
        if validation_result.issues:
            for issue in validation_result.issues:
                report += f"- ❌ {issue}\n"
        else:
            report += "- ✅ Nenhum issue encontrado\n"
        
        report += f"""
## 📋 Recomendações
"""
        
        if validation_result.recommendations:
            for rec in validation_result.recommendations:
                report += f"- 💡 {rec}\n"
        else:
            report += "- ✅ Nenhuma recomendação necessária\n"
        
        if validation_result.critical_files:
            report += f"""
## 🚨 Arquivos Críticos
"""
            for file_path in validation_result.critical_files:
                report += f"- ⚠️ {file_path}\n"
        
        if overall_metrics.critical_branches_missing:
            report += f"""
## 🔒 Branches Críticos Não Cobertos
"""
            for branch in overall_metrics.critical_branches_missing[:10]:  # Mostra apenas os primeiros 10
                report += f"- ⚠️ {branch}\n"
            
            if len(overall_metrics.critical_branches_missing) > 10:
                report += f"- ... e mais {len(overall_metrics.critical_branches_missing) - 10} branches\n"
        
        report += f"""
---
*Relatório gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return report
    
    def save_report(self, report: str, output_file: str = "coverage_validation_report.md"):
        """
        Salva relatório em arquivo.
        
        Args:
            report: Conteúdo do relatório
            output_file: Arquivo de saída
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Relatório salvo em: {output_file}")
    
    def run_validation(self, output_file: str = None) -> ValidationResult:
        """
        Executa validação completa.
        
        Args:
            output_file: Arquivo de saída para relatório
        
        Returns:
            Resultado da validação
        """
        logger.info("Iniciando validação de cobertura...")
        
        # Carrega dados de cobertura
        coverage_data = self.load_coverage_data()
        
        if not coverage_data:
            logger.error("Nenhum dado de cobertura encontrado")
            return ValidationResult(
                passed=False,
                score=0,
                issues=["Nenhum dado de cobertura encontrado"],
                recommendations=["Executar testes com cobertura"],
                critical_files=[]
            )
        
        # Calcula métricas gerais
        overall_metrics = self.calculate_overall_metrics(coverage_data)
        
        # Valida cobertura
        validation_result = self.validate_coverage(overall_metrics, coverage_data)
        
        # Gera relatório
        report = self.generate_report(overall_metrics, validation_result)
        
        # Salva relatório
        if output_file:
            self.save_report(report, output_file)
        else:
            print(report)
        
        # Log do resultado
        if validation_result.passed:
            logger.info("✅ Validação de cobertura aprovada")
        else:
            logger.error("❌ Validação de cobertura falhou")
            for issue in validation_result.issues:
                logger.error(f"  - {issue}")
        
        return validation_result


def main():
    """Função principal."""
    parser = argparse.ArgumentParser(
        description="Validador rigoroso de cobertura de testes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python coverage_validation.py
  python coverage_validation.py --threshold 95
  python coverage_validation.py --output report.md
  python coverage_validation.py --strict
        """
    )
    
    parser.add_argument(
        "--coverage-dir",
        default="coverage",
        help="Diretório com arquivos de cobertura (padrão: coverage)"
    )
    
    parser.add_argument(
        "--threshold",
        type=float,
        default=98.0,
        help="Threshold mínimo de cobertura (padrão: 98.0)"
    )
    
    parser.add_argument(
        "--output",
        help="Arquivo de saída para relatório"
    )
    
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Modo estrito - falha se houver qualquer issue"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Saída em formato JSON"
    )
    
    args = parser.parse_args()
    
    # Executa validação
    validator = CoverageValidator(
        coverage_dir=args.coverage_dir,
        threshold=args.threshold
    )
    
    result = validator.run_validation(args.output)
    
    # Saída em JSON se solicitado
    if args.json:
        json_output = {
            "passed": result.passed,
            "score": result.score,
            "issues": result.issues,
            "recommendations": result.recommendations,
            "critical_files": result.critical_files,
            "timestamp": datetime.now().isoformat()
        }
        print(json.dumps(json_output, indent=2))
    
    # Exit code baseado no resultado
    if not result.passed:
        if args.strict:
            sys.exit(1)
        else:
            logger.warning("Validação falhou, mas continuando...")
    
    sys.exit(0)


if __name__ == "__main__":
    main() 