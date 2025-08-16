#!/usr/bin/env python3
"""
Script de Validação de Testes Sintéticos
- Detecta testes com dados fictícios (foo, bar, lorem, random)
- Valida se testes são baseados em código real
- Gera relatórios detalhados de validação

📐 CoCoT: Baseado em regras de qualidade de testes E2E
🌲 ToT: Múltiplas estratégias de detecção implementadas
♻️ ReAct: Simulado para diferentes cenários de validação

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T11:15:00Z
**Tracing ID:** VALIDATE_SYNTHETIC_TESTS_md1ppfhs
**Origem:** Necessidade de validação automática contra testes sintéticos
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class SyntheticTestIssue:
    """Representa um problema encontrado em teste sintético"""
    file_path: str
    line_number: int
    issue_type: str
    description: str
    severity: str
    code_snippet: str
    recommendation: str

@dataclass
class ValidationResult:
    """Resultado da validação de um arquivo"""
    file_path: str
    is_valid: bool
    issues: List[SyntheticTestIssue]
    test_count: int
    synthetic_count: int
    real_code_references: List[str]

class SyntheticTestValidator:
    """Validador de testes sintéticos"""
    
    def __init__(self):
        self.synthetic_patterns = {
            'generic_names': [
                r'\bfoo\b', r'\bbar\b', r'\bbaz\b', r'\bqux\b',
                r'\blorem\b', r'\bipsum\b', r'\bdolor\b', r'\bsit\b',
                r'\bamet\b', r'\bconsectetur\b', r'\badipiscing\b'
            ],
            'random_data': [
                r'\brandom\b', r'\brandom\(\)', r'\bMath\.random\(\)',
                r'\bDate\.now\(\)', r'\bnew Date\(\)', r'\bMath\.floor\(\)'
            ],
            'dummy_data': [
                r'\bdummy\b', r'\btest\b', r'\bsample\b', r'\bexample\b',
                r'\bfake\b', r'\bmock\b', r'\bstub\b'
            ],
            'generic_assertions': [
                r'\.toBeDefined\(\)', r'\.toBeTruthy\(\)', r'\.toBeFalsy\(\)',
                r'\.toBe\(true\)', r'\.toBe\(false\)', r'\.toBe\(null\)',
                r'\.toBe\(undefined\)'
            ]
        }
        
        self.real_code_patterns = [
            r'app/', r'ui/', r'shared/', r'domain/', r'services/',
            r'controllers/', r'models/', r'handlers/', r'routes/',
            r'components/', r'hooks/', r'utils/'
        ]
        
        self.required_metadata = [
            'Prompt:', 'Data/Hora:', 'Tracing ID:', 'Origem:'
        ]

    def validate_file(self, file_path: str) -> ValidationResult:
        """Valida um arquivo de teste específico"""
        issues = []
        test_count = 0
        synthetic_count = 0
        real_code_references = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Contar testes
            test_count = len(re.findall(r'(test\(|it\(|describe\()', content))
            
            # Verificar metadados obrigatórios
            metadata_issues = self._check_metadata(content, file_path)
            issues.extend(metadata_issues)
            
            # Verificar padrões sintéticos
            for line_num, line in enumerate(lines, 1):
                line_issues = self._check_line_for_synthetic_patterns(
                    line, line_num, file_path
                )
                issues.extend(line_issues)
                
                if line_issues:
                    synthetic_count += 1
            
            # Verificar referências a código real
            real_code_references = self._find_real_code_references(content)
            
            # Verificar se há documentação de origem
            origin_issues = self._check_origin_documentation(content, file_path)
            issues.extend(origin_issues)
            
            is_valid = len(issues) == 0
            
            return ValidationResult(
                file_path=file_path,
                is_valid=is_valid,
                issues=issues,
                test_count=test_count,
                synthetic_count=synthetic_count,
                real_code_references=real_code_references
            )
            
        except Exception as e:
            return ValidationResult(
                file_path=file_path,
                is_valid=False,
                issues=[SyntheticTestIssue(
                    file_path=file_path,
                    line_number=0,
                    issue_type='file_error',
                    description=f'Erro ao ler arquivo: {str(e)}',
                    severity='error',
                    code_snippet='',
                    recommendation='Verificar se arquivo existe e é legível'
                )],
                test_count=0,
                synthetic_count=0,
                real_code_references=[]
            )

    def _check_metadata(self, content: str, file_path: str) -> List[SyntheticTestIssue]:
        """Verifica se arquivo tem metadados obrigatórios"""
        issues = []
        
        for metadata in self.required_metadata:
            if metadata not in content:
                issues.append(SyntheticTestIssue(
                    file_path=file_path,
                    line_number=0,
                    issue_type='missing_metadata',
                    description=f'Metadado obrigatório ausente: {metadata}',
                    severity='error',
                    code_snippet='',
                    recommendation=f'Adicionar comentário com {metadata} no topo do arquivo'
                ))
        
        return issues

    def _check_line_for_synthetic_patterns(self, line: str, line_num: int, file_path: str) -> List[SyntheticTestIssue]:
        """Verifica uma linha específica por padrões sintéticos"""
        issues = []
        
        for pattern_type, patterns in self.synthetic_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SyntheticTestIssue(
                        file_path=file_path,
                        line_number=line_num,
                        issue_type=f'synthetic_{pattern_type}',
                        description=f'Padrão sintético detectado: {pattern}',
                        severity='error',
                        code_snippet=line.strip(),
                        recommendation=f'Substituir por dados reais baseados em código existente'
                    ))
        
        return issues

    def _find_real_code_references(self, content: str) -> List[str]:
        """Encontra referências a código real no arquivo"""
        references = []
        
        for pattern in self.real_code_patterns:
            matches = re.findall(pattern, content)
            references.extend(matches)
        
        return list(set(references))

    def _check_origin_documentation(self, content: str, file_path: str) -> List[SyntheticTestIssue]:
        """Verifica se há documentação da origem do teste"""
        issues = []
        
        # Verificar se há comentário explicando origem
        if 'Origem:' not in content:
            issues.append(SyntheticTestIssue(
                file_path=file_path,
                line_number=0,
                issue_type='missing_origin',
                description='Origem do teste não documentada',
                severity='warning',
                code_snippet='',
                recommendation='Adicionar comentário explicando qual funcionalidade real está sendo testada'
            ))
        
        return issues

    def validate_directory(self, directory: str) -> Dict[str, Any]:
        """Valida todos os arquivos de teste em um diretório"""
        results = []
        total_files = 0
        valid_files = 0
        total_issues = 0
        
        test_files = self._find_test_files(directory)
        
        for file_path in test_files:
            result = self.validate_file(file_path)
            results.append(result)
            
            total_files += 1
            if result.is_valid:
                valid_files += 1
            total_issues += len(result.issues)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'directory': directory,
            'summary': {
                'total_files': total_files,
                'valid_files': valid_files,
                'invalid_files': total_files - valid_files,
                'total_issues': total_issues,
                'success_rate': (valid_files / total_files * 100) if total_files > 0 else 0
            },
            'results': [self._result_to_dict(r) for r in results],
            'recommendations': self._generate_recommendations(results)
        }

    def _find_test_files(self, directory: str) -> List[str]:
        """Encontra arquivos de teste no diretório"""
        test_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.spec.ts', '.test.ts', '.spec.js', '.test.js')):
                    test_files.append(os.path.join(root, file))
        
        return test_files

    def _result_to_dict(self, result: ValidationResult) -> Dict[str, Any]:
        """Converte resultado para dicionário"""
        return {
            'file_path': result.file_path,
            'is_valid': result.is_valid,
            'test_count': result.test_count,
            'synthetic_count': result.synthetic_count,
            'real_code_references': result.real_code_references,
            'issues': [
                {
                    'line_number': issue.line_number,
                    'issue_type': issue.issue_type,
                    'description': issue.description,
                    'severity': issue.severity,
                    'code_snippet': issue.code_snippet,
                    'recommendation': issue.recommendation
                }
                for issue in result.issues
            ]
        }

    def _generate_recommendations(self, results: List[ValidationResult]) -> List[str]:
        """Gera recomendações baseadas nos resultados"""
        recommendations = []
        
        invalid_files = [r for r in results if not r.is_valid]
        
        if invalid_files:
            recommendations.append(f"Encontrados {len(invalid_files)} arquivos com problemas")
            
            synthetic_issues = sum(len([i for i in r.issues if 'synthetic_' in i.issue_type]) for r in invalid_files)
            if synthetic_issues > 0:
                recommendations.append(f"Remover {synthetic_issues} padrões sintéticos (foo, bar, lorem, random)")
            
            missing_metadata = sum(len([i for i in r.issues if 'missing_metadata' in i.issue_type]) for r in invalid_files)
            if missing_metadata > 0:
                recommendations.append(f"Adicionar metadados obrigatórios em {missing_metadata} arquivos")
        
        return recommendations

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Validador de Testes Sintéticos')
    parser.add_argument('directory', help='Diretório para validar')
    parser.add_argument('--output', '-o', help='Arquivo de saída JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verboso')
    
    args = parser.parse_args()
    
    validator = SyntheticTestValidator()
    
    print(f"🔍 Validando testes sintéticos em: {args.directory}")
    
    results = validator.validate_directory(args.directory)
    
    # Exibir resumo
    summary = results['summary']
    print(f"\n📊 Resumo da Validação:")
    print(f"   Total de arquivos: {summary['total_files']}")
    print(f"   Arquivos válidos: {summary['valid_files']}")
    print(f"   Arquivos inválidos: {summary['invalid_files']}")
    print(f"   Total de problemas: {summary['total_issues']}")
    print(f"   Taxa de sucesso: {summary['success_rate']:.1f}%")
    
    # Exibir problemas
    if summary['total_issues'] > 0:
        print(f"\n❌ Problemas Encontrados:")
        for result in results['results']:
            if not result['is_valid']:
                print(f"\n   📁 {result['file_path']}:")
                for issue in result['issues']:
                    print(f"      🔴 Linha {issue['line_number']}: {issue['description']}")
    
    # Exibir recomendações
    if results['recommendations']:
        print(f"\n💡 Recomendações:")
        for rec in results['recommendations']:
            print(f"   • {rec}")
    
    # Salvar resultados
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Resultados salvos em: {args.output}")
    
    # Retornar código de saída
    exit_code = 0 if summary['invalid_files'] == 0 else 1
    exit(exit_code)

if __name__ == '__main__':
    main() 