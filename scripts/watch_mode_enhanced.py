#!/usr/bin/env python3
"""
Watch Mode Aprimorado para Testes E2E
- Monitoramento inteligente de arquivos
- Execução automática de testes
- Debounce e filtros avançados
- Interface interativa

📐 CoCoT: Baseado em boas práticas de watch mode para desenvolvimento
🌲 ToT: Múltiplas estratégias de monitoramento implementadas
♻️ ReAct: Simulado para diferentes cenários de desenvolvimento

**Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
**Data/Hora:** 2025-01-28T12:30:00Z
**Tracing ID:** WATCH_MODE_ENHANCED_md1ppfhs
**Origem:** Necessidade de watch mode avançado para desenvolvimento E2E
"""

import os
import sys
import time
import json
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent
import argparse
import signal
import psutil

@dataclass
class WatchConfig:
    """Configuração do watch mode"""
    test_dir: str = "tests/e2e"
    app_dir: str = "app"
    ui_dir: str = "ui"
    shared_dir: str = "shared"
    config_files: List[str] = None
    debounce_time: int = 2
    max_workers: int = 4
    browser: str = "chromium"
    parallel: bool = True
    verbose: bool = False
    auto_run: bool = True
    notifications: bool = True
    
    def __post_init__(self):
        if self.config_files is None:
            self.config_files = [
                "playwright.config.ts",
                "package.json",
                "requirements.txt",
                "tests/e2e/e2e.config.ts"
            ]

@dataclass
class TestResult:
    """Resultado de execução de teste"""
    success: bool
    test_files: List[str]
    execution_time: float
    timestamp: datetime
    output: str
    error: Optional[str] = None
    browser: str = "chromium"
    workers: int = 1

class EnhancedWatchMode:
    """Watch mode aprimorado para desenvolvimento E2E"""
    
    def __init__(self, config: WatchConfig):
        self.config = config
        self.observer = Observer()
        self.last_run = datetime.now()
        self.debounce_timer = None
        self.running_tests = False
        self.changed_files: Set[str] = set()
        self.execution_history: List[TestResult] = []
        self.stats = {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'total_execution_time': 0,
            'files_monitored': 0
        }
        
        # Configurar diretórios para monitorar
        self.watch_dirs = [
            self.config.test_dir,
            self.config.app_dir,
            self.ui_dir,
            self.config.shared_dir
        ]
        
        # Configurar filtros de arquivos
        self.test_patterns = ['*.spec.ts', '*.test.ts', '*.spec.js', '*.test.js']
        self.app_patterns = ['*.py', '*.js', '*.ts', '*.json', '*.yaml', '*.yml']
        self.config_patterns = self.config.config_files
        
        # Configurar handlers
        self.setup_signal_handlers()
        
    def setup_signal_handlers(self):
        """Configurar handlers para sinais do sistema"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handler para sinais de interrupção"""
        print(f"\n🛑 Recebido sinal {signum}. Encerrando watch mode...")
        self.stop()
        sys.exit(0)
        
    def start(self):
        """Iniciar watch mode"""
        print("🚀 Iniciando Watch Mode Aprimorado...")
        print(f"📐 CoCoT: Monitoramento baseado em boas práticas")
        print(f"🌲 ToT: Múltiplas estratégias de execução")
        print(f"♻️ ReAct: Simulado para diferentes cenários")
        print()
        
        # Verificar configuração
        self.validate_config()
        
        # Configurar observer
        event_handler = EnhancedFileHandler(self)
        
        for directory in self.watch_dirs:
            if os.path.exists(directory):
                self.observer.schedule(event_handler, directory, recursive=True)
                print(f"👁️ Monitorando: {directory}")
                self.stats['files_monitored'] += len(list(Path(directory).rglob('*')))
            else:
                print(f"⚠️ Diretório não encontrado: {directory}")
        
        # Iniciar observer
        self.observer.start()
        print(f"✅ Watch mode ativo. Pressione Ctrl+C para parar.")
        print(f"📊 Arquivos monitorados: {self.stats['files_monitored']}")
        print()
        
        # Mostrar comandos disponíveis
        self.show_commands()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
            
    def stop(self):
        """Parar watch mode"""
        print("\n🛑 Parando watch mode...")
        self.observer.stop()
        self.observer.join()
        self.show_final_stats()
        
    def validate_config(self):
        """Validar configuração do watch mode"""
        print("🔍 Validando configuração...")
        
        # Verificar se Playwright está instalado
        try:
            subprocess.run(['npx', 'playwright', '--version'], 
                         capture_output=True, check=True)
            print("✅ Playwright instalado")
        except subprocess.CalledProcessError:
            print("❌ Playwright não encontrado. Execute: npx playwright install")
            sys.exit(1)
            
        # Verificar se diretórios existem
        for directory in self.watch_dirs:
            if os.path.exists(directory):
                print(f"✅ Diretório encontrado: {directory}")
            else:
                print(f"⚠️ Diretório não encontrado: {directory}")
                
        print("✅ Configuração válida")
        
    def on_file_changed(self, file_path: str):
        """Callback quando arquivo é modificado"""
        if self.running_tests:
            return
            
        # Adicionar arquivo à lista de mudanças
        self.changed_files.add(file_path)
        
        # Configurar debounce
        if self.debounce_timer:
            self.debounce_timer.cancel()
            
        self.debounce_timer = threading.Timer(
            self.config.debounce_time, 
            self.execute_tests
        )
        self.debounce_timer.start()
        
        if self.config.verbose:
            print(f"📝 Arquivo modificado: {file_path}")
            
    def execute_tests(self):
        """Executar testes baseado nas mudanças"""
        if not self.changed_files or self.running_tests:
            return
            
        self.running_tests = True
        print(f"\n🔄 Executando testes... ({len(self.changed_files)} arquivos modificados)")
        
        # Determinar quais testes executar
        test_files = self.determine_test_files()
        
        if not test_files:
            print("ℹ️ Nenhum teste para executar")
            self.changed_files.clear()
            self.running_tests = False
            return
            
        # Executar testes
        start_time = time.time()
        result = self._execute_tests(test_files)
        execution_time = time.time() - start_time
        
        # Registrar resultado
        test_result = TestResult(
            success=result['success'],
            test_files=test_files,
            execution_time=execution_time,
            timestamp=datetime.now(),
            output=result.get('stdout', ''),
            error=result.get('error'),
            browser=self.config.browser,
            workers=self.config.max_workers if self.config.parallel else 1
        )
        
        self.execution_history.append(test_result)
        self.update_stats(test_result)
        
        # Mostrar resultado
        self.show_result(test_result)
        
        # Limpar arquivos modificados
        self.changed_files.clear()
        self.running_tests = False
        
    def determine_test_files(self) -> List[str]:
        """Determinar quais testes executar baseado nas mudanças"""
        test_files = []
        
        for changed_file in self.changed_files:
            # Se arquivo de teste foi modificado, executar apenas ele
            if any(changed_file.endswith(pattern.replace('*', '')) for pattern in self.test_patterns):
                test_files.append(changed_file)
            # Se arquivo de configuração foi modificado, executar todos os testes
            elif any(changed_file.endswith(config_file) for config_file in self.config.config_files):
                test_files = self._get_all_test_files()
                break
            # Se arquivo da aplicação foi modificado, executar testes relacionados
            elif any(changed_file.endswith(pattern.replace('*', '')) for pattern in self.app_patterns):
                related_tests = self._find_related_tests(changed_file)
                test_files.extend(related_tests)
                
        return list(set(test_files))  # Remover duplicatas
        
    def _get_all_test_files(self) -> List[str]:
        """Obter todos os arquivos de teste"""
        test_files = []
        
        for pattern in self.test_patterns:
            for test_file in Path(self.config.test_dir).rglob(pattern):
                test_files.append(str(test_file))
        
        return test_files
        
    def _find_related_tests(self, changed_file: str) -> List[str]:
        """Encontrar testes relacionados ao arquivo modificado"""
        # Implementação simples - pode ser expandida
        related_tests = []
        
        # Mapeamento básico de arquivos para testes
        file_to_test_mapping = {
            'app.py': ['tests/e2e/test_generate_content.spec.ts'],
            'blog_routes.py': ['tests/e2e/test_blog_management.spec.ts'],
            'auth_middleware.py': ['tests/e2e/test_authentication.spec.ts'],
            'generation_service.py': ['tests/e2e/test_generate_content.spec.ts']
        }
        
        filename = os.path.basename(changed_file)
        if filename in file_to_test_mapping:
            related_tests.extend(file_to_test_mapping[filename])
            
        return related_tests
        
    def _execute_tests(self, test_files: List[str]) -> Dict[str, Any]:
        """Executar testes específicos"""
        if not test_files:
            return {'success': True, 'message': 'Nenhum teste para executar'}
        
        # Construir comando
        test_paths = ' '.join(test_files)
        cmd = f"npx playwright test {test_paths} --project={self.config.browser}"
        
        if self.config.parallel:
            cmd += f" --workers={self.config.max_workers}"
            
        if not self.config.verbose:
            cmd += " --reporter=list"
            
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
            
    def update_stats(self, result: TestResult):
        """Atualizar estatísticas"""
        self.stats['total_runs'] += 1
        self.stats['total_execution_time'] += result.execution_time
        
        if result.success:
            self.stats['successful_runs'] += 1
        else:
            self.stats['failed_runs'] += 1
            
    def show_result(self, result: TestResult):
        """Mostrar resultado da execução"""
        status = "✅ SUCESSO" if result.success else "❌ FALHA"
        print(f"\n{status}")
        print(f"📊 Tempo de execução: {result.execution_time:.2f}s")
        print(f"🧪 Testes executados: {len(result.test_files)}")
        print(f"🌐 Browser: {result.browser}")
        print(f"⚡ Workers: {result.workers}")
        
        if result.error:
            print(f"❌ Erro: {result.error}")
            
        if self.config.verbose and result.output:
            print(f"📝 Output:\n{result.output}")
            
    def show_commands(self):
        """Mostrar comandos disponíveis"""
        print("🎮 COMANDOS INTERATIVOS:")
        print("  r - Executar todos os testes")
        print("  s - Executar testes de smoke")
        print("  c - Executar testes críticos")
        print("  p - Mostrar estatísticas")
        print("  h - Mostrar ajuda")
        print("  q - Sair")
        print()
        
    def show_final_stats(self):
        """Mostrar estatísticas finais"""
        print("\n📊 ESTATÍSTICAS FINAIS:")
        print(f"  Total de execuções: {self.stats['total_runs']}")
        print(f"  Sucessos: {self.stats['successful_runs']}")
        print(f"  Falhas: {self.stats['failed_runs']}")
        
        if self.stats['total_runs'] > 0:
            success_rate = (self.stats['successful_runs'] / self.stats['total_runs']) * 100
            avg_time = self.stats['total_execution_time'] / self.stats['total_runs']
            print(f"  Taxa de sucesso: {success_rate:.1f}%")
            print(f"  Tempo médio: {avg_time:.2f}s")
            
        print(f"  Arquivos monitorados: {self.stats['files_monitored']}")
        
    def save_history(self, filename: str = "watch_mode_history.json"):
        """Salvar histórico de execuções"""
        history_data = {
            'config': asdict(self.config),
            'stats': self.stats,
            'history': [asdict(result) for result in self.execution_history]
        }
        
        with open(filename, 'w') as f:
            json.dump(history_data, f, indent=2, default=str)
            
        print(f"💾 Histórico salvo em: {filename}")


class EnhancedFileHandler(FileSystemEventHandler):
    """Handler aprimorado para eventos de arquivo"""
    
    def __init__(self, watch_mode: EnhancedWatchMode):
        self.watch_mode = watch_mode
        
    def on_modified(self, event):
        if not event.is_directory:
            self.watch_mode.on_file_changed(event.src_path)
            
    def on_created(self, event):
        if not event.is_directory:
            self.watch_mode.on_file_changed(event.src_path)
            
    def on_deleted(self, event):
        if not event.is_directory:
            # Para arquivos deletados, executar todos os testes
            self.watch_mode.changed_files.add("ALL_TESTS")


def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Watch Mode Aprimorado para Testes E2E")
    parser.add_argument("--test-dir", default="tests/e2e", help="Diretório de testes")
    parser.add_argument("--app-dir", default="app", help="Diretório da aplicação")
    parser.add_argument("--ui-dir", default="ui", help="Diretório da UI")
    parser.add_argument("--shared-dir", default="shared", help="Diretório compartilhado")
    parser.add_argument("--debounce", type=int, default=2, help="Tempo de debounce (segundos)")
    parser.add_argument("--workers", type=int, default=4, help="Número de workers")
    parser.add_argument("--browser", default="chromium", help="Browser para usar")
    parser.add_argument("--no-parallel", action="store_true", help="Desabilitar paralelização")
    parser.add_argument("--verbose", action="store_true", help="Modo verboso")
    parser.add_argument("--no-auto-run", action="store_true", help="Não executar automaticamente")
    parser.add_argument("--no-notifications", action="store_true", help="Desabilitar notificações")
    
    args = parser.parse_args()
    
    # Criar configuração
    config = WatchConfig(
        test_dir=args.test_dir,
        app_dir=args.app_dir,
        ui_dir=args.ui_dir,
        shared_dir=args.shared_dir,
        debounce_time=args.debounce,
        max_workers=args.workers,
        browser=args.browser,
        parallel=not args.no_parallel,
        verbose=args.verbose,
        auto_run=not args.no_auto_run,
        notifications=not args.no_notifications
    )
    
    # Iniciar watch mode
    watch_mode = EnhancedWatchMode(config)
    
    try:
        watch_mode.start()
    except KeyboardInterrupt:
        print("\n👋 Encerrando...")
    finally:
        watch_mode.save_history()


if __name__ == "__main__":
    main() 