#!/usr/bin/env python3
"""
Sistema de Testes Incrementais E2E
- Executa apenas testes que mudaram
- Análise de dependências entre testes
- Cache de resultados
- Otimização de execução

📐 CoCoT: Baseado em boas práticas de testes incrementais
🌲 ToT: Múltiplas estratégias de análise implementadas
♻️ ReAct: Simulado para diferentes cenários de mudanças

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T11:45:00Z
**Tracing ID:** INCREMENTAL_TESTS_md1ppfhs
**Origem:** Necessidade de otimização de execução de testes E2E
"""

import os
import json
import hashlib
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
from datetime import datetime
try:
    import git
except ImportError:
    git = None

@dataclass
class TestFile:
    """Arquivo de teste"""
    path: str
    hash: str
    dependencies: List[str]
    last_modified: datetime
    last_executed: Optional[datetime]
    execution_time: float
    status: str  # 'passed', 'failed', 'skipped'

@dataclass
class ChangeSet:
    """Conjunto de mudanças"""
    modified_files: List[str]
    added_files: List[str]
    deleted_files: List[str]
    commit_hash: str
    timestamp: datetime

class IncrementalTestRunner:
    """Executor de testes incrementais"""
    
    def __init__(self, test_dir: str = 'tests/e2e', cache_dir: str = '.incremental-cache'):
        self.test_dir = Path(test_dir)
        self.cache_dir = Path(cache_dir)
        self.metadata_file = self.cache_dir / 'test-metadata.json'
        self.changes_file = self.cache_dir / 'changes.json'
        
        # Configurações
        self.config = {
            'enable_incremental': True,
            'max_cache_age': 24 * 60 * 60,  # 24 horas
            'dependency_analysis': True,
            'parallel_execution': True,
            'fallback_to_full': True
        }
        
        # Inicializar
        self._init_cache()
        self.test_files: Dict[str, TestFile] = self._load_metadata()
        self.changes: ChangeSet = self._load_changes()
    
    def _init_cache(self) -> None:
        """Inicializar cache"""
        if not self.cache_dir.exists():
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            print(f"📁 Cache incremental criado em: {self.cache_dir}")
    
    def _load_metadata(self) -> Dict[str, TestFile]:
        """Carregar metadados dos testes"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                test_files = {}
                for path, file_data in data.items():
                    test_files[path] = TestFile(
                        path=file_data['path'],
                        hash=file_data['hash'],
                        dependencies=file_data.get('dependencies', []),
                        last_modified=datetime.fromisoformat(file_data['last_modified']),
                        last_executed=datetime.fromisoformat(file_data['last_executed']) if file_data.get('last_executed') else None,
                        execution_time=file_data.get('execution_time', 0),
                        status=file_data.get('status', 'unknown')
                    )
                return test_files
            except Exception as e:
                print(f"⚠️ Erro ao carregar metadados: {e}")
                return {}
        return {}
    
    def _save_metadata(self) -> None:
        """Salvar metadados dos testes"""
        try:
            data = {}
            for path, test_file in self.test_files.items():
                data[path] = {
                    'path': test_file.path,
                    'hash': test_file.hash,
                    'dependencies': test_file.dependencies,
                    'last_modified': test_file.last_modified.isoformat(),
                    'last_executed': test_file.last_executed.isoformat() if test_file.last_executed else None,
                    'execution_time': test_file.execution_time,
                    'status': test_file.status
                }
            
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️ Erro ao salvar metadados: {e}")
    
    def _load_changes(self) -> ChangeSet:
        """Carregar informações de mudanças"""
        if self.changes_file.exists():
            try:
                with open(self.changes_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                return ChangeSet(
                    modified_files=data.get('modified_files', []),
                    added_files=data.get('added_files', []),
                    deleted_files=data.get('deleted_files', []),
                    commit_hash=data.get('commit_hash', ''),
                    timestamp=datetime.fromisoformat(data['timestamp'])
                )
            except Exception as e:
                print(f"⚠️ Erro ao carregar mudanças: {e}")
        
        return ChangeSet([], [], [], '', datetime.now())
    
    def _save_changes(self) -> None:
        """Salvar informações de mudanças"""
        try:
            data = {
                'modified_files': self.changes.modified_files,
                'added_files': self.changes.added_files,
                'deleted_files': self.changes.deleted_files,
                'commit_hash': self.changes.commit_hash,
                'timestamp': self.changes.timestamp.isoformat()
            }
            
            with open(self.changes_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️ Erro ao salvar mudanças: {e}")
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calcular hash do arquivo"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ''
    
    def _analyze_dependencies(self, test_file: Path) -> List[str]:
        """Analisar dependências do arquivo de teste"""
        dependencies = []
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Dependências baseadas em imports
            import_patterns = [
                r'import.*from\s+[\'"]([^\'"]+)[\'"]',
                r'require\s*\(\s*[\'"]([^\'"]+)[\'"]',
                r'from\s+[\'"]([^\'"]+)[\'"]'
            ]
            
            import re
            for pattern in import_patterns:
                matches = re.findall(pattern, content)
                dependencies.extend(matches)
            
            # Dependências baseadas em referências de código
            code_patterns = [
                r'app/([^\s\'"`]+)',
                r'ui/([^\s\'"`]+)',
                r'shared/([^\s\'"`]+)',
                r'services/([^\s\'"`]+)'
            ]
            
            for pattern in code_patterns:
                matches = re.findall(pattern, content)
                dependencies.extend(matches)
            
            # Remover duplicatas
            return list(set(dependencies))
            
        except Exception as e:
            print(f"⚠️ Erro ao analisar dependências de {test_file}: {e}")
            return []
    
    def _detect_changes(self, base_commit: str = None) -> ChangeSet:
        """Detectar mudanças no repositório"""
        if git is None:
            print("⚠️ GitPython não instalado, usando detecção básica de mudanças")
            return self._detect_changes_basic()
        
        try:
            repo = git.Repo('.')
            
            if base_commit:
                # Comparar com commit específico
                diff = repo.commit(base_commit).diff(repo.head.commit)
            else:
                # Comparar com último commit
                commits = list(repo.iter_commits(max_count=2))
                if len(commits) > 1:
                    diff = commits[1].diff(commits[0])
                else:
                    # Primeiro commit
                    diff = []
            
            modified_files = []
            added_files = []
            deleted_files = []
            
            for change in diff:
                if change.change_type == 'M':
                    modified_files.append(change.a_path)
                elif change.change_type == 'A':
                    added_files.append(change.a_path)
                elif change.change_type == 'D':
                    deleted_files.append(change.b_path)
            
            changes = ChangeSet(
                modified_files=modified_files,
                added_files=added_files,
                deleted_files=deleted_files,
                commit_hash=repo.head.commit.hexsha,
                timestamp=datetime.now()
            )
            
            self.changes = changes
            self._save_changes()
            
            return changes
            
        except Exception as e:
            print(f"⚠️ Erro ao detectar mudanças: {e}")
            return self._detect_changes_basic()
    
    def _detect_changes_basic(self) -> ChangeSet:
        """Detecção básica de mudanças baseada em timestamp"""
        modified_files = []
        
        # Verificar arquivos modificados baseado em timestamp
        for test_file in self.test_dir.rglob('*.spec.ts'):
            if str(test_file) in self.test_files:
                cached_file = self.test_files[str(test_file)]
                if test_file.stat().st_mtime > cached_file.last_modified.timestamp():
                    modified_files.append(str(test_file))
        
        return ChangeSet(
            modified_files=modified_files,
            added_files=[],
            deleted_files=[],
            commit_hash='',
            timestamp=datetime.now()
        )
    
    def _scan_test_files(self) -> Dict[str, TestFile]:
        """Escaneiar arquivos de teste"""
        test_files = {}
        
        for test_file in self.test_dir.rglob('*.spec.ts'):
            try:
                file_hash = self._get_file_hash(test_file)
                dependencies = self._analyze_dependencies(test_file)
                last_modified = datetime.fromtimestamp(test_file.stat().st_mtime)
                
                # Verificar se já existe no cache
                if str(test_file) in self.test_files:
                    cached_file = self.test_files[str(test_file)]
                    last_executed = cached_file.last_executed
                    execution_time = cached_file.execution_time
                    status = cached_file.status
                else:
                    last_executed = None
                    execution_time = 0
                    status = 'unknown'
                
                test_files[str(test_file)] = TestFile(
                    path=str(test_file),
                    hash=file_hash,
                    dependencies=dependencies,
                    last_modified=last_modified,
                    last_executed=last_executed,
                    execution_time=execution_time,
                    status=status
                )
                
            except Exception as e:
                print(f"⚠️ Erro ao escanear {test_file}: {e}")
        
        return test_files
    
    def _get_affected_tests(self) -> Set[str]:
        """Obter testes afetados pelas mudanças"""
        affected_tests = set()
        
        # Testes que mudaram diretamente
        for modified_file in self.changes.modified_files:
            if modified_file.endswith('.spec.ts'):
                affected_tests.add(modified_file)
        
        # Testes que dependem de arquivos modificados
        for test_path, test_file in self.test_files.items():
            for dependency in test_file.dependencies:
                for modified_file in self.changes.modified_files:
                    if dependency in modified_file or modified_file in dependency:
                        affected_tests.add(test_path)
                        break
        
        # Testes que dependem de dependências modificadas
        for test_path, test_file in self.test_files.items():
            for dependency in test_file.dependencies:
                for modified_file in self.changes.modified_files:
                    if any(dep in modified_file for dep in dependency.split('/')):
                        affected_tests.add(test_path)
                        break
        
        return affected_tests
    
    def _get_tests_to_run(self, force_full: bool = False) -> List[str]:
        """Determinar quais testes executar"""
        if force_full or not self.config['enable_incremental']:
            print("🔄 Executando suite completa de testes")
            return list(self.test_files.keys())
        
        # Escanear arquivos de teste
        self.test_files = self._scan_test_files()
        
        # Detectar mudanças
        changes = self._detect_changes()
        
        if not any([changes.modified_files, changes.added_files, changes.deleted_files]):
            print("✅ Nenhuma mudança detectada")
            return []
        
        # Obter testes afetados
        affected_tests = self._get_affected_tests()
        
        # Verificar se há mudanças significativas
        if len(affected_tests) > len(self.test_files) * 0.5:
            print("⚠️ Muitos testes afetados, executando suite completa")
            return list(self.test_files.keys())
        
        # Verificar se há mudanças em arquivos críticos
        critical_files = ['package.json', 'playwright.config.ts', 'global-setup.ts']
        if any(critical in changes.modified_files for critical in critical_files):
            print("⚠️ Mudanças em arquivos críticos, executando suite completa")
            return list(self.test_files.keys())
        
        print(f"🎯 Executando {len(affected_tests)} testes incrementais")
        return list(affected_tests)
    
    def run_tests(self, test_files: List[str], parallel: bool = True) -> Dict[str, Any]:
        """Executar testes"""
        if not test_files:
            return {'success': True, 'message': 'Nenhum teste para executar'}
        
        results = {
            'total': len(test_files),
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'execution_time': 0,
            'details': {}
        }
        
        start_time = datetime.now()
        
        try:
            # Construir comando
            test_paths = ' '.join(test_files)
            cmd = f"npx playwright test {test_paths}"
            
            if parallel:
                cmd += " --workers=auto"
            
            print(f"🚀 Executando: {cmd}")
            
            # Executar testes
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hora timeout
            )
            
            # Analisar resultados
            execution_time = (datetime.now() - start_time).total_seconds()
            results['execution_time'] = execution_time
            
            if result.returncode == 0:
                results['success'] = True
                results['passed'] = len(test_files)
                print(f"✅ Testes executados com sucesso em {execution_time:.2f}s")
            else:
                results['success'] = False
                results['failed'] = len(test_files)
                print(f"❌ Testes falharam em {execution_time:.2f}s")
            
            # Atualizar metadados
            for test_file in test_files:
                if test_file in self.test_files:
                    self.test_files[test_file].last_executed = datetime.now()
                    self.test_files[test_file].execution_time = execution_time / len(test_files)
                    self.test_files[test_file].status = 'passed' if results['success'] else 'failed'
            
            self._save_metadata()
            
        except subprocess.TimeoutExpired:
            results['success'] = False
            results['message'] = 'Timeout na execução dos testes'
            print("⏰ Timeout na execução dos testes")
        except Exception as e:
            results['success'] = False
            results['message'] = str(e)
            print(f"❌ Erro na execução: {e}")
        
        return results
    
    def run_incremental(self, force_full: bool = False, parallel: bool = True) -> Dict[str, Any]:
        """Executar testes incrementais"""
        print("🔍 Analisando mudanças para execução incremental...")
        
        # Obter testes para executar
        test_files = self._get_tests_to_run(force_full)
        
        if not test_files:
            return {
                'success': True,
                'message': 'Nenhum teste para executar',
                'incremental': True,
                'tests_executed': 0
            }
        
        # Executar testes
        results = self.run_tests(test_files, parallel)
        results['incremental'] = True
        results['tests_executed'] = len(test_files)
        
        return results
    
    def print_summary(self) -> None:
        """Exibir resumo dos testes"""
        total_tests = len(self.test_files)
        executed_tests = len([tf for tf in self.test_files.values() if tf.last_executed])
        passed_tests = len([tf for tf in self.test_files.values() if tf.status == 'passed'])
        failed_tests = len([tf for tf in self.test_files.values() if tf.status == 'failed'])
        
        print("\n📊 RESUMO DOS TESTES INCREMENTAIS")
        print("=" * 40)
        print(f"Total de testes: {total_tests}")
        print(f"Testes executados: {executed_tests}")
        print(f"Testes passaram: {passed_tests}")
        print(f"Testes falharam: {failed_tests}")
        
        if self.changes.commit_hash:
            print(f"Último commit: {self.changes.commit_hash[:8]}")
            print(f"Arquivos modificados: {len(self.changes.modified_files)}")
            print(f"Arquivos adicionados: {len(self.changes.added_files)}")
            print(f"Arquivos removidos: {len(self.changes.deleted_files)}")

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Executor de Testes Incrementais E2E')
    parser.add_argument('--test-dir', default='tests/e2e', help='Diretório de testes')
    parser.add_argument('--cache-dir', default='.incremental-cache', help='Diretório do cache')
    parser.add_argument('--force-full', action='store_true', help='Forçar execução completa')
    parser.add_argument('--no-parallel', action='store_true', help='Desabilitar execução paralela')
    parser.add_argument('--base-commit', help='Commit base para comparação')
    parser.add_argument('--summary', action='store_true', help='Exibir resumo')
    
    args = parser.parse_args()
    
    runner = IncrementalTestRunner(args.test_dir, args.cache_dir)
    
    if args.summary:
        runner.print_summary()
    else:
        # Executar testes incrementais
        results = runner.run_incremental(
            force_full=args.force_full,
            parallel=not args.no_parallel
        )
        
        # Exibir resultados
        if results['success']:
            print(f"✅ Execução concluída: {results['tests_executed']} testes executados")
        else:
            print(f"❌ Execução falhou: {results.get('message', 'Erro desconhecido')}")
        
        # Exibir resumo
        runner.print_summary()

if __name__ == '__main__':
    main() 