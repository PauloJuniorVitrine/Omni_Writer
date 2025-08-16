"""
Política de Testes Rigorosa - Omni Writer
=========================================

Implementa validação da política rigorosa de testes:
- Verificação de que testes são baseados em código real
- Validação de que não há testes sintéticos ou genéricos
- Garantia de correspondência direta com funcionalidade
- Validação de dados de teste realistas
- Auditoria automática de qualidade de testes

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import ast
import os
import re
from typing import List, Dict, Set
from pathlib import Path

class RigorousTestPolicyValidator:
    """Validador da política rigorosa de testes"""
    
    def __init__(self):
        self.forbidden_patterns = [
            # Padrões sintéticos proibidos
            r'foo\b',
            r'bar\b', 
            r'baz\b',
            r'lorem\b',
            r'ipsum\b',
            r'dolor\b',
            r'sit\b',
            r'amet\b',
            r'test\s+data',
            r'sample\s+data',
            r'mock\s+data',
            r'fake\s+data',
            r'dummy\s+data',
            r'placeholder\s+data',
            r'example\s+data',
            r'random\s+string',
            r'random\s+number',
            r'random\s+value',
            r'arbitrary\s+value',
            r'generic\s+value',
            r'synthetic\s+value',
            r'artificial\s+value',
            r'fictitious\s+value',
            r'imaginary\s+value',
            r'fictional\s+value',
            r'fake\s+value',
            r'dummy\s+value',
            r'mock\s+value',
            r'test\s+value',
            r'sample\s+value',
            r'placeholder\s+value',
            r'example\s+value'
        ]
        
        self.required_patterns = [
            # Padrões que devem estar presentes (código real)
            r'categoria_id',
            r'api_key',
            r'prompt',
            r'generation',
            r'blog',
            r'article',
            r'upload',
            r'validation',
            r'authentication',
            r'authorization',
            r'rate_limit',
            r'cache',
            r'retry',
            r'circuit_breaker',
            r'parallel',
            r'intelligent',
            r'smart',
            r'integrated',
            r'domain',
            r'repository',
            r'service',
            r'controller',
            r'route',
            r'endpoint',
            r'response',
            r'request',
            r'status_code',
            r'json',
            r'error',
            r'success',
            r'failure',
            r'exception',
            r'timeout',
            r'permission',
            r'security',
            r'validation',
            r'constraint',
            r'transaction',
            r'database',
            r'connection',
            r'file',
            r'upload',
            r'download',
            r'storage',
            r'memory',
            r'cpu',
            r'network',
            r'configuration',
            r'environment',
            r'feature_flag'
        ]
        
        self.real_data_patterns = [
            # Padrões de dados realistas
            r'\d+',  # Números
            r'[A-Za-zÀ-ÿ]+',  # Palavras com acentos
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',  # Emails
            r'https?://[^\s]+',  # URLs
            r'\d{4}-\d{2}-\d{2}',  # Datas
            r'\d{2}:\d{2}:\d{2}',  # Horários
            r'[A-Z]{2,}',  # Siglas
            r'[a-z]+_[a-z]+',  # snake_case
            r'[a-z]+[A-Z][a-z]+',  # camelCase
            r'[A-Z][a-z]+[A-Z][a-z]+',  # PascalCase
            r'[A-Z_]+',  # CONSTANTES
            r'[a-z]+-[a-z]+',  # kebab-case
            r'[a-z]+\.[a-z]+',  # Extensões de arquivo
            r'[A-Za-z0-9/]+\.(py|js|ts|html|css|json|xml|yaml|yml|sql|md|txt)',  # Arquivos
            r'[A-Za-z0-9/]+\.(jpg|jpeg|png|gif|svg|webp|ico)',  # Imagens
            r'[A-Za-z0-9/]+\.(mp4|avi|mov|wmv|flv|webm)',  # Vídeos
            r'[A-Za-z0-9/]+\.(mp3|wav|flac|aac|ogg)',  # Áudios
            r'[A-Za-z0-9/]+\.(pdf|doc|docx|xls|xlsx|ppt|pptx)',  # Documentos
            r'[A-Za-z0-9/]+\.(zip|rar|7z|tar|gz|bz2)',  # Arquivos compactados
            r'[A-Za-z0-9/]+\.(py|js|ts|html|css|json|xml|yaml|yml|sql|md|txt|jpg|jpeg|png|gif|svg|webp|ico|mp4|avi|mov|wmv|flv|webm|mp3|wav|flac|aac|ogg|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|bz2)'  # Todos os tipos
        ]
    
    def validate_test_file(self, file_path: str) -> Dict[str, any]:
        """Valida um arquivo de teste individual"""
        results = {
            'file_path': file_path,
            'is_valid': True,
            'issues': [],
            'warnings': [],
            'forbidden_patterns_found': [],
            'required_patterns_missing': [],
            'real_data_score': 0.0
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Verifica padrões proibidos
            for pattern in self.forbidden_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    results['forbidden_patterns_found'].extend(matches)
                    results['issues'].append(f"Padrão proibido encontrado: {pattern}")
                    results['is_valid'] = False
            
            # Verifica padrões obrigatórios
            found_required = 0
            for pattern in self.required_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_required += 1
            
            if found_required < 5:  # Mínimo de 5 padrões obrigatórios
                results['required_patterns_missing'] = [p for p in self.required_patterns 
                                                       if not re.search(p, content, re.IGNORECASE)]
                results['issues'].append(f"Poucos padrões obrigatórios encontrados: {found_required}/5")
                results['is_valid'] = False
            
            # Calcula score de dados realistas
            real_data_matches = 0
            total_patterns = len(self.real_data_patterns)
            
            for pattern in self.real_data_patterns:
                if re.search(pattern, content):
                    real_data_matches += 1
            
            results['real_data_score'] = real_data_matches / total_patterns
            
            if results['real_data_score'] < 0.3:  # Mínimo 30% de dados realistas
                results['warnings'].append(f"Score de dados realistas baixo: {results['real_data_score']:.2f}")
            
            # Verifica estrutura do teste
            if not self._validate_test_structure(content):
                results['issues'].append("Estrutura de teste inválida")
                results['is_valid'] = False
            
            # Verifica correspondência com código real
            if not self._validate_code_correspondence(file_path, content):
                results['issues'].append("Teste não corresponde a funcionalidade real")
                results['is_valid'] = False
            
        except Exception as e:
            results['issues'].append(f"Erro ao validar arquivo: {str(e)}")
            results['is_valid'] = False
        
        return results
    
    def _validate_test_structure(self, content: str) -> bool:
        """Valida estrutura básica do teste"""
        # Deve ter imports
        if not re.search(r'import\s+', content):
            return False
        
        # Deve ter classe de teste
        if not re.search(r'class\s+\w+Test', content):
            return False
        
        # Deve ter métodos de teste
        if not re.search(r'def\s+test_', content):
            return False
        
        # Deve ter assertions
        if not re.search(r'assert\s+', content):
            return False
        
        return True
    
    def _validate_code_correspondence(self, test_file: str, content: str) -> bool:
        """Valida se o teste corresponde a código real"""
        # Extrai nome do arquivo de teste
        test_name = Path(test_file).stem
        
        # Remove prefixo 'test_' e sufixo '_test'
        module_name = test_name.replace('test_', '').replace('_test', '')
        
        # Procura por imports que correspondem ao módulo
        if re.search(rf'from.*{module_name}', content) or re.search(rf'import.*{module_name}', content):
            return True
        
        # Procura por referências a classes/funções do módulo
        if re.search(rf'{module_name}\.', content):
            return True
        
        return False
    
    def validate_test_directory(self, directory: str) -> Dict[str, any]:
        """Valida diretório completo de testes"""
        results = {
            'directory': directory,
            'total_files': 0,
            'valid_files': 0,
            'invalid_files': 0,
            'file_results': [],
            'summary': {
                'forbidden_patterns_total': 0,
                'required_patterns_missing_total': 0,
                'average_real_data_score': 0.0,
                'critical_issues': 0,
                'warnings': 0
            }
        }
        
        test_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        results['total_files'] = len(test_files)
        
        for test_file in test_files:
            file_result = self.validate_test_file(test_file)
            results['file_results'].append(file_result)
            
            if file_result['is_valid']:
                results['valid_files'] += 1
            else:
                results['invalid_files'] += 1
                results['summary']['critical_issues'] += len(file_result['issues'])
            
            results['summary']['warnings'] += len(file_result['warnings'])
            results['summary']['forbidden_patterns_total'] += len(file_result['forbidden_patterns_found'])
            results['summary']['required_patterns_missing_total'] += len(file_result['required_patterns_missing'])
        
        # Calcula score médio
        if results['file_results']:
            scores = [r['real_data_score'] for r in results['file_results']]
            results['summary']['average_real_data_score'] = sum(scores) / len(scores)
        
        return results

class TestRigorousPolicy:
    """Testes para validar a política rigorosa"""
    
    def test_no_synthetic_data_in_tests(self):
        """Testa que não há dados sintéticos nos testes"""
        validator = RigorousTestPolicyValidator()
        
        # Valida diretório de testes
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Não deve haver padrões proibidos
        assert results['summary']['forbidden_patterns_total'] == 0, \
            f"Encontrados {results['summary']['forbidden_patterns_total']} padrões proibidos"
    
    def test_all_tests_have_real_data(self):
        """Testa que todos os testes têm dados realistas"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Score médio deve ser alto
        assert results['summary']['average_real_data_score'] >= 0.3, \
            f"Score médio de dados realistas muito baixo: {results['summary']['average_real_data_score']:.2f}"
    
    def test_all_tests_correspond_to_real_code(self):
        """Testa que todos os testes correspondem a código real"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Todos os arquivos devem ser válidos
        assert results['invalid_files'] == 0, \
            f"{results['invalid_files']} arquivos de teste inválidos encontrados"
    
    def test_no_generic_test_names(self):
        """Testa que não há nomes genéricos de testes"""
        test_files = []
        for root, dirs, files in os.walk("tests"):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        generic_names = [
            'test_generic',
            'test_sample',
            'test_example',
            'test_dummy',
            'test_fake',
            'test_mock',
            'test_stub',
            'test_placeholder',
            'test_random',
            'test_arbitrary'
        ]
        
        for test_file in test_files:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for generic_name in generic_names:
                    assert generic_name not in content, \
                        f"Nome genérico encontrado em {test_file}: {generic_name}"
    
    def test_all_tests_have_specific_assertions(self):
        """Testa que todos os testes têm assertions específicas"""
        test_files = []
        for root, dirs, files in os.walk("tests"):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        generic_assertions = [
            'assert True',
            'assert False',
            'assert None',
            'assert 0',
            'assert 1',
            'assert ""',
            'assert []',
            'assert {}',
            'assert ()',
            'assert foo',
            'assert bar',
            'assert baz'
        ]
        
        for test_file in test_files:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for generic_assertion in generic_assertions:
                    assert generic_assertion not in content, \
                        f"Assertion genérica encontrada em {test_file}: {generic_assertion}"
    
    def test_no_hardcoded_test_data(self):
        """Testa que não há dados de teste hardcoded genéricos"""
        test_files = []
        for root, dirs, files in os.walk("tests"):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        hardcoded_patterns = [
            r'test_data\s*=\s*\[.*\]',
            r'test_data\s*=\s*\{.*\}',
            r'test_data\s*=\s*".*"',
            r'test_data\s*=\s*\'.*\'',
            r'sample_data\s*=\s*\[.*\]',
            r'sample_data\s*=\s*\{.*\}',
            r'sample_data\s*=\s*".*"',
            r'sample_data\s*=\s*\'.*\'',
            r'mock_data\s*=\s*\[.*\]',
            r'mock_data\s*=\s*\{.*\}',
            r'mock_data\s*=\s*".*"',
            r'mock_data\s*=\s*\'.*\''
        ]
        
        for test_file in test_files:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for pattern in hardcoded_patterns:
                    matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
                    assert len(matches) == 0, \
                        f"Dados hardcoded encontrados em {test_file}: {matches}"
    
    def test_all_tests_use_real_functionality(self):
        """Testa que todos os testes usam funcionalidade real"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Deve ter pelo menos alguns padrões obrigatórios
        assert results['summary']['required_patterns_missing_total'] < len(results['file_results']) * 10, \
            f"Muitos padrões obrigatórios faltando: {results['summary']['required_patterns_missing_total']}"
    
    def test_no_placeholder_comments(self):
        """Testa que não há comentários placeholder"""
        test_files = []
        for root, dirs, files in os.walk("tests"):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        placeholder_patterns = [
            r'TODO.*test',
            r'FIXME.*test',
            r'XXX.*test',
            r'HACK.*test',
            r'NOTE.*test',
            r'#.*placeholder',
            r'#.*todo',
            r'#.*fixme',
            r'#.*xxx',
            r'#.*hack'
        ]
        
        for test_file in test_files:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for pattern in placeholder_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    assert len(matches) == 0, \
                        f"Comentários placeholder encontrados em {test_file}: {matches}"
    
    def test_all_tests_have_meaningful_names(self):
        """Testa que todos os testes têm nomes significativos"""
        test_files = []
        for root, dirs, files in os.walk("tests"):
            for file in files:
                if file.endswith('.py') and 'test' in file.lower():
                    test_files.append(os.path.join(root, file))
        
        meaningless_patterns = [
            r'def\s+test_\d+',
            r'def\s+test_[a-z]{1,2}$',
            r'def\s+test_[a-z]{1,2}_\d+',
            r'def\s+test_test',
            r'def\s+test_sample',
            r'def\s+test_example',
            r'def\s+test_dummy',
            r'def\s+test_fake',
            r'def\s+test_mock',
            r'def\s+test_stub'
        ]
        
        for test_file in test_files:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for pattern in meaningless_patterns:
                    matches = re.findall(pattern, content)
                    assert len(matches) == 0, \
                        f"Nomes de teste sem significado encontrados em {test_file}: {matches}"

class TestPolicyEnforcement:
    """Testes para validar aplicação da política"""
    
    def test_policy_validates_all_test_files(self):
        """Testa que a política valida todos os arquivos de teste"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Deve ter encontrado arquivos de teste
        assert results['total_files'] > 0, "Nenhum arquivo de teste encontrado"
        
        # Deve ter validado todos os arquivos
        assert len(results['file_results']) == results['total_files'], \
            "Nem todos os arquivos foram validados"
    
    def test_policy_reports_detailed_issues(self):
        """Testa que a política reporta issues detalhados"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Deve ter informações detalhadas
        assert 'file_results' in results, "Resultados detalhados não encontrados"
        assert 'summary' in results, "Resumo não encontrado"
        
        for file_result in results['file_results']:
            assert 'issues' in file_result, "Issues não reportados"
            assert 'warnings' in file_result, "Warnings não reportados"
    
    def test_policy_enforces_real_data_requirement(self):
        """Testa que a política força uso de dados reais"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Score médio deve ser aceitável
        assert results['summary']['average_real_data_score'] >= 0.3, \
            "Política não está forçando uso de dados reais"
    
    def test_policy_prevents_synthetic_tests(self):
        """Testa que a política previne testes sintéticos"""
        validator = RigorousTestPolicyValidator()
        
        test_dir = "tests"
        results = validator.validate_test_directory(test_dir)
        
        # Não deve haver padrões proibidos
        assert results['summary']['forbidden_patterns_total'] == 0, \
            "Política não está prevenindo testes sintéticos"

if __name__ == "__main__":
    # Executa validação da política rigorosa
    validator = RigorousTestPolicyValidator()
    
    print("🔍 Validando política rigorosa de testes...")
    
    test_dir = "tests"
    results = validator.validate_test_directory(test_dir)
    
    print(f"📊 Resumo da validação:")
    print(f"  📁 Total de arquivos: {results['total_files']}")
    print(f"  ✅ Arquivos válidos: {results['valid_files']}")
    print(f"  ❌ Arquivos inválidos: {results['invalid_files']}")
    print(f"  🚨 Issues críticos: {results['summary']['critical_issues']}")
    print(f"  ⚠️  Warnings: {results['summary']['warnings']}")
    print(f"  📈 Score médio de dados reais: {results['summary']['average_real_data_score']:.2f}")
    
    if results['invalid_files'] == 0:
        print("🎉 Política rigorosa validada com sucesso!")
    else:
        print("❌ Violações da política encontradas!")
        for file_result in results['file_results']:
            if not file_result['is_valid']:
                print(f"  📄 {file_result['file_path']}:")
                for issue in file_result['issues']:
                    print(f"    ❌ {issue}")
    
    # Executa testes
    pytest.main([__file__, "-v", "--tb=short"]) 