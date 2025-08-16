#!/usr/bin/env python3
"""
Script para análise automática de branches não cobertos em código crítico.
Identifica branches críticos (try/except, if/else, raise) e verifica cobertura de testes.
"""
import os
import re
import ast
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple

class BranchAnalyzer:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.critical_files = [
            "app/controller.py",
            "app/routes.py", 
            "app/pipeline.py",
            "infraestructure/openai_gateway.py",
            "infraestructure/deepseek_gateway.py",
            "infraestructure/storage.py",
            "shared/distributed_storage.py"
        ]
        self.branch_patterns = {
            'try_except': r'try:.*?except.*?:',
            'if_else': r'if\s+.*?:.*?else:',
            'raise': r'raise\s+\w+',
            'return': r'return\s+.*?',
            'fallback': r'fallback|except.*?return|except.*?continue'
        }
        
    def find_critical_branches(self, file_path: str) -> Dict[str, List[Tuple[int, str]]]:
        """Encontra branches críticos em um arquivo Python."""
        full_path = self.project_root / file_path
        if not full_path.exists():
            return {}
            
        branches = {
            'try_except': [],
            'if_else': [],
            'raise': [],
            'return': [],
            'fallback': []
        }
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            # Análise por regex para padrões críticos
            for i, line in enumerate(lines, 1):
                line_stripped = line.strip()
                
                # Try/except
                if line_stripped.startswith('try:'):
                    branches['try_except'].append((i, line_stripped))
                elif line_stripped.startswith('except'):
                    branches['try_except'].append((i, line_stripped))
                    
                # If/else
                if line_stripped.startswith('if ') and ':' in line_stripped:
                    branches['if_else'].append((i, line_stripped))
                elif line_stripped.startswith('else:') or line_stripped.startswith('elif '):
                    branches['if_else'].append((i, line_stripped))
                    
                # Raise
                if line_stripped.startswith('raise '):
                    branches['raise'].append((i, line_stripped))
                    
                # Return
                if line_stripped.startswith('return '):
                    branches['return'].append((i, line_stripped))
                    
                # Fallback patterns
                if any(pattern in line_stripped.lower() for pattern in ['fallback', 'except', 'return', 'continue']):
                    if 'except' in line_stripped and ('return' in line_stripped or 'continue' in line_stripped):
                        branches['fallback'].append((i, line_stripped))
                        
        except Exception as e:
            print(f"Erro ao analisar {file_path}: {e}")
            
        return branches
    
    def check_test_coverage(self, file_path: str) -> Dict[str, bool]:
        """Verifica se há testes para o arquivo."""
        test_file = file_path.replace('.py', '_test.spec.py')
        test_path = self.project_root / 'tests' / 'unit' / test_file
        
        # Verifica se existe teste específico
        has_specific_test = test_path.exists()
        
        # Verifica se há testes de integração
        integration_test = self.project_root / 'tests' / 'integration' / f'test_{file_path.replace("/", "_")}'
        has_integration_test = integration_test.exists()
        
        return {
            'has_specific_test': has_specific_test,
            'has_integration_test': has_integration_test,
            'test_path': str(test_path) if has_specific_test else None
        }
    
    def analyze_all_critical_files(self) -> Dict[str, Dict]:
        """Analisa todos os arquivos críticos."""
        results = {}
        
        for file_path in self.critical_files:
            print(f"Analisando: {file_path}")
            
            branches = self.find_critical_branches(file_path)
            test_coverage = self.check_test_coverage(file_path)
            
            results[file_path] = {
                'branches': branches,
                'test_coverage': test_coverage,
                'total_branches': sum(len(b) for b in branches.values()),
                'critical_branches': len(branches.get('try_except', [])) + len(branches.get('fallback', []))
            }
            
        return results
    
    def generate_report(self, results: Dict[str, Dict]) -> str:
        """Gera relatório em formato markdown."""
        report = "# Relatório de Análise de Branches Críticos\n\n"
        report += f"Data: {os.popen('date').read().strip()}\n\n"
        
        total_files = len(results)
        total_branches = sum(r['total_branches'] for r in results.values())
        total_critical = sum(r['critical_branches'] for r in results.values())
        files_with_tests = sum(1 for r in results.values() if r['test_coverage']['has_specific_test'])
        
        report += f"## Resumo\n"
        report += f"- Arquivos analisados: {total_files}\n"
        report += f"- Total de branches: {total_branches}\n"
        report += f"- Branches críticos: {total_critical}\n"
        report += f"- Arquivos com testes específicos: {files_with_tests}\n"
        report += f"- Cobertura de testes: {(files_with_tests/total_files)*100:.1f}%\n\n"
        
        report += "## Análise Detalhada\n\n"
        
        for file_path, data in results.items():
            report += f"### {file_path}\n"
            report += f"- **Teste específico**: {'✅' if data['test_coverage']['has_specific_test'] else '❌'}\n"
            report += f"- **Teste de integração**: {'✅' if data['test_coverage']['has_integration_test'] else '❌'}\n"
            report += f"- **Total de branches**: {data['total_branches']}\n"
            report += f"- **Branches críticos**: {data['critical_branches']}\n\n"
            
            if data['branches']['try_except']:
                report += "#### Try/Except Branches:\n"
                for line_num, line in data['branches']['try_except'][:5]:  # Mostra apenas os primeiros 5
                    report += f"- Linha {line_num}: `{line}`\n"
                report += "\n"
                
            if data['branches']['fallback']:
                report += "#### Fallback Branches:\n"
                for line_num, line in data['branches']['fallback'][:5]:  # Mostra apenas os primeiros 5
                    report += f"- Linha {line_num}: `{line}`\n"
                report += "\n"
                
            if not data['test_coverage']['has_specific_test']:
                report += "⚠️ **ATENÇÃO**: Arquivo sem teste específico!\n\n"
                
        return report
    
    def save_report(self, report: str, output_file: str = "branch_analysis_report.md"):
        """Salva o relatório em arquivo."""
        output_path = self.project_root / output_file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Relatório salvo em: {output_path}")

def main():
    """Função principal."""
    analyzer = BranchAnalyzer()
    
    print("🔍 Iniciando análise de branches críticos...")
    results = analyzer.analyze_all_critical_files()
    
    print("📊 Gerando relatório...")
    report = analyzer.generate_report(results)
    
    print("💾 Salvando relatório...")
    analyzer.save_report(report)
    
    print("✅ Análise concluída!")
    
    # Resumo rápido
    total_critical = sum(r['critical_branches'] for r in results.values())
    files_with_tests = sum(1 for r in results.values() if r['test_coverage']['has_specific_test'])
    
    print(f"\n📈 Resumo:")
    print(f"- Branches críticos encontrados: {total_critical}")
    print(f"- Arquivos com testes: {files_with_tests}/{len(results)}")
    
    if total_critical > 0:
        print(f"🎯 Meta: 100% cobertura de branches críticos")

if __name__ == "__main__":
    main() 