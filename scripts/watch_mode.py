#!/usr/bin/env python3
"""
Watch Mode para Desenvolvimento E2E
- Hot reload de testes
- Execução automática em mudanças
- Filtros inteligentes
- Notificações em tempo real

📐 CoCoT: Baseado em boas práticas de watch mode para desenvolvimento
🌲 ToT: Múltiplas estratégias de monitoramento implementadas
♻️ ReAct: Simulado para diferentes cenários de desenvolvimento

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T12:00:00Z
**Tracing ID:** WATCH_MODE_DEVELOPMENT_md1ppfhs
**Origem:** Necessidade de watch mode para desenvolvimento eficiente de testes E2E
"""

import os
import time
import json
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

@dataclass
class WatchConfig:
    """Configuração do watch mode"""
    test_dir: str = 'tests/e2e'
    app_dir: str = 'app'
    ui_dir: str = 'ui'
    shared_dir: str = 'shared'
    debounce_time: float = 2.0
    auto_run: bool = True
    notifications: bool = True
    parallel: bool = True
    browser: str = 'chromium'

@dataclass
class FileChange:
    """Mudança de arquivo detectada"""
    path: str
    event_type: str  # 'created', 'modified', 'deleted'
    timestamp: datetime
    file_type: str  # 'test', 'app', 'ui', 'shared', 'config'

class E2EWatchMode:
    """Watch mode para desenvolvimento E2E"""
    
    def __init__(self, config: WatchConfig):
        self.config = config
        self.observer = Observer()
        self.last_run = datetime.now()
        self.debounce_timer = None
        self.running_tests = False
        self.changed_files: Set[str] = set()
        
        # Configurar diretórios para monitorar
        self.watch_dirs = [
            self.config.test_dir,
            self.config.app_dir,
            self.config.ui_dir,
            self.config.shared_dir
        ]
        
        # Configurar filtros de arquivos
        self.test_patterns = ['*.spec.ts', '*.test.ts', '*.spec.js', '*.test.js']
        self.app_patterns = ['*.py', '*.js', '*.ts', '*.json', '*.yaml', '*.yml']
        self.config_patterns = ['playwright.config.ts', 'package.json', 'requirements.txt']
        
        # Histórico de execuções
        self.execution_history: List[Dict[str, Any]] = []
    
    def start(self) -> None:
        """Iniciar watch mode"""
        print("👀 Iniciando Watch Mode para E2E...")
        print(f"📁 Monitorando: {', '.join(self.watch_dirs)}")
        print(f"⚡ Debounce: {self.config.debounce_time}s")
        print(f"🔄 Auto-run: {'Sim' if self.config.auto_run else 'Não'}")
        print(f"🌐 Browser: {self.config.browser}")
        print("=" * 60)
        
        # Configurar event handler
        event_handler = E2EFileHandler(self)
        
        # Adicionar observadores para cada diretório
        for directory in self.watch_dirs:
            if Path(directory).exists():
                self.observer.schedule(event_handler, directory, recursive=True)
                print(f"👁️ Monitorando: {directory}")
            else:
                print(f"⚠️ Diretório não encontrado: {directory}")
        
        # Iniciar observer
        self.observer.start()
        
        try:
            # Loop principal
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Watch mode interrompido pelo usuário")
            self.stop()
    
    def stop(self) -> None:
        """Parar watch mode"""
        print("🛑 Parando watch mode...")
        self.observer.stop()
        self.observer.join()
        
        # Gerar relatório final
        self._generate_watch_report()
    
    def on_file_change(self, file_path: str, event_type: str) -> None:
        """Processar mudança de arquivo"""
        file_type = self._get_file_type(file_path)
        
        change = FileChange(
            path=file_path,
            event_type=event_type,
            timestamp=datetime.now(),
            file_type=file_type
        )
        
        print(f"📝 {event_type.upper()}: {file_path} ({file_type})")
        
        # Adicionar à lista de mudanças
        self.changed_files.add(file_path)
        
        # Debounce para evitar execuções excessivas
        if self.config.auto_run:
            self._schedule_test_run()
    
    def _get_file_type(self, file_path: str) -> str:
        """Determinar tipo do arquivo"""
        path = Path(file_path)
        
        # Verificar se é arquivo de teste
        if any(path.match(pattern) for pattern in self.test_patterns):
            return 'test'
        
        # Verificar se é arquivo de configuração
        if any(path.match(pattern) for pattern in self.config_patterns):
            return 'config'
        
        # Verificar se é arquivo da aplicação
        if any(path.match(pattern) for pattern in self.app_patterns):
            if self.config.app_dir in file_path:
                return 'app'
            elif self.config.ui_dir in file_path:
                return 'ui'
            elif self.config.shared_dir in file_path:
                return 'shared'
        
        return 'other'
    
    def _schedule_test_run(self) -> None:
        """Agendar execução de testes com debounce"""
        if self.running_tests:
            print("⏳ Testes já em execução, aguardando...")
            return
        
        # Cancelar timer anterior se existir
        if self.debounce_timer:
            self.debounce_timer.cancel()
        
        # Criar novo timer
        self.debounce_timer = threading.Timer(
            self.config.debounce_time,
            self._run_tests
        )
        self.debounce_timer.start()
        
        print(f"⏰ Agendando execução de testes em {self.config.debounce_time}s...")
    
    def _run_tests(self) -> None:
        """Executar testes baseado nas mudanças"""
        if not self.changed_files:
            return
        
        print(f"\n🚀 Executando testes para {len(self.changed_files)} arquivos modificados...")
        
        self.running_tests = True
        start_time = datetime.now()
        
        try:
            # Determinar quais testes executar
            test_files = self._get_affected_tests()
            
            if not test_files:
                print("✅ Nenhum teste afetado pelas mudanças")
                return
            
            # Executar testes
            results = self._execute_tests(test_files)
            
            # Registrar execução
            execution_record = {
                'timestamp': start_time.isoformat(),
                'changed_files': list(self.changed_files),
                'test_files': test_files,
                'results': results,
                'duration': (datetime.now() - start_time).total_seconds()
            }
            
            self.execution_history.append(execution_record)
            
            # Exibir resultados
            self._display_results(results)
            
            # Notificações
            if self.config.notifications:
                self._send_notification(results)
            
        except Exception as e:
            print(f"❌ Erro na execução: {e}")
        finally:
            self.running_tests = False
            self.changed_files.clear()
            self.last_run = datetime.now()
    
    def _get_affected_tests(self) -> List[str]:
        """Determinar quais testes executar baseado nas mudanças"""
        affected_tests = set()
        
        for changed_file in self.changed_files:
            file_type = self._get_file_type(changed_file)
            
            if file_type == 'test':
                # Arquivo de teste modificado
                affected_tests.add(changed_file)
            elif file_type in ['app', 'ui', 'shared']:
                # Arquivo da aplicação modificado - executar testes relacionados
                related_tests = self._find_related_tests(changed_file)
                affected_tests.update(related_tests)
            elif file_type == 'config':
                # Arquivo de configuração modificado - executar todos os testes
                all_tests = self._get_all_test_files()
                affected_tests.update(all_tests)
        
        return list(affected_tests)
    
    def _find_related_tests(self, app_file: str) -> List[str]:
        """Encontrar testes relacionados a um arquivo da aplicação"""
        related_tests = []
        
        # Padrões de busca baseados no nome do arquivo
        app_path = Path(app_file)
        app_name = app_path.stem
        
        # Buscar testes que referenciam este arquivo
        for test_file in Path(self.config.test_dir).rglob('*.spec.ts'):
            try:
                with open(test_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Verificar se o teste referencia o arquivo modificado
                if app_name in content or app_path.name in content:
                    related_tests.append(str(test_file))
                    
            except Exception:
                continue
        
        return related_tests
    
    def _get_all_test_files(self) -> List[str]:
        """Obter todos os arquivos de teste"""
        test_files = []
        
        for pattern in self.test_patterns:
            for test_file in Path(self.config.test_dir).rglob(pattern):
                test_files.append(str(test_file))
        
        return test_files
    
    def _execute_tests(self, test_files: List[str]) -> Dict[str, Any]:
        """Executar testes específicos"""
        if not test_files:
            return {'success': True, 'message': 'Nenhum teste para executar'}
        
        # Construir comando
        test_paths = ' '.join(test_files)
        cmd = f"npx playwright test {test_paths} --project={self.config.browser}"
        
        if self.config.parallel:
            cmd += " --workers=auto"
        
        print(f"🔧 Executando: {cmd}")
        
        try:
            # Executar testes
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos timeout
            )
            
            return {
                'success': result.returncode == 0,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'test_files': test_files,
                'command': cmd
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout na execução',
                'test_files': test_files,
                'command': cmd
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'test_files': test_files,
                'command': cmd
            }
    
    def _display_results(self, results: Dict[str, Any]) -> None:
        """Exibir resultados da execução"""
        print("\n📊 RESULTADOS DA EXECUÇÃO")
        print("=" * 40)
        
        if results['success']:
            print("✅ Testes executados com sucesso!")
            print(f"📁 Testes executados: {len(results['test_files'])}")
        else:
            print("❌ Testes falharam!")
            if 'error' in results:
                print(f"🔴 Erro: {results['error']}")
            if results.get('stderr'):
                print(f"🔴 Stderr: {results['stderr'][:200]}...")
        
        print(f"⏱️ Comando: {results['command']}")
        print("=" * 40)
    
    def _send_notification(self, results: Dict[str, Any]) -> None:
        """Enviar notificação dos resultados"""
        if results['success']:
            print("🔔 Notificação: Testes passaram com sucesso!")
        else:
            print("🔔 Notificação: Testes falharam!")
    
    def _generate_watch_report(self) -> None:
        """Gerar relatório do watch mode"""
        if not self.execution_history:
            return
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'config': {
                'test_dir': self.config.test_dir,
                'debounce_time': self.config.debounce_time,
                'auto_run': self.config.auto_run,
                'browser': self.config.browser
            },
            'summary': {
                'total_executions': len(self.execution_history),
                'successful_executions': len([e for e in self.execution_history if e['results']['success']]),
                'failed_executions': len([e for e in self.execution_history if not e['results']['success']]),
                'total_duration': sum(e['duration'] for e in self.execution_history),
                'avg_duration': sum(e['duration'] for e in self.execution_history) / len(self.execution_history)
            },
            'executions': self.execution_history
        }
        
        # Salvar relatório
        report_path = 'test-results/watch-mode-report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n📊 Relatório do watch mode salvo em: {report_path}")
        
        # Exibir resumo
        summary = report['summary']
        print(f"\n📈 RESUMO DO WATCH MODE")
        print(f"   Execuções totais: {summary['total_executions']}")
        print(f"   Execuções bem-sucedidas: {summary['successful_executions']}")
        print(f"   Execuções com falha: {summary['failed_executions']}")
        print(f"   Tempo total: {summary['total_duration']:.2f}s")
        print(f"   Tempo médio: {summary['avg_duration']:.2f}s")

class E2EFileHandler(FileSystemEventHandler):
    """Handler para eventos de arquivo"""
    
    def __init__(self, watch_mode: E2EWatchMode):
        self.watch_mode = watch_mode
    
    def on_created(self, event):
        if not event.is_directory:
            self.watch_mode.on_file_change(event.src_path, 'created')
    
    def on_modified(self, event):
        if not event.is_directory:
            self.watch_mode.on_file_change(event.src_path, 'modified')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.watch_mode.on_file_change(event.src_path, 'deleted')

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description='Watch Mode para Desenvolvimento E2E')
    parser.add_argument('--test-dir', default='tests/e2e', help='Diretório de testes')
    parser.add_argument('--app-dir', default='app', help='Diretório da aplicação')
    parser.add_argument('--ui-dir', default='ui', help='Diretório da UI')
    parser.add_argument('--shared-dir', default='shared', help='Diretório compartilhado')
    parser.add_argument('--debounce', type=float, default=2.0, help='Tempo de debounce em segundos')
    parser.add_argument('--no-auto-run', action='store_true', help='Desabilitar execução automática')
    parser.add_argument('--no-notifications', action='store_true', help='Desabilitar notificações')
    parser.add_argument('--no-parallel', action='store_true', help='Desabilitar execução paralela')
    parser.add_argument('--browser', default='chromium', choices=['chromium', 'firefox', 'webkit'], help='Browser para usar')
    
    args = parser.parse_args()
    
    config = WatchConfig(
        test_dir=args.test_dir,
        app_dir=args.app_dir,
        ui_dir=args.ui_dir,
        shared_dir=args.shared_dir,
        debounce_time=args.debounce,
        auto_run=not args.no_auto_run,
        notifications=not args.no_notifications,
        parallel=not args.no_parallel,
        browser=args.browser
    )
    
    watch_mode = E2EWatchMode(config)
    
    try:
        watch_mode.start()
    except KeyboardInterrupt:
        print("\n🛑 Watch mode interrompido")
    finally:
        watch_mode.stop()

if __name__ == '__main__':
    main() 