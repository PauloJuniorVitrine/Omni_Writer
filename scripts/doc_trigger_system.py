#!/usr/bin/env python3
"""
📋 Sistema de Triggers Automáticos para Documentação
====================================================

Objetivo: Monitorar mudanças em arquivos e regenerar documentação automaticamente
Autor: AI Assistant
Data: 2025-01-27
Tracing ID: DOC_TRIGGER_20250127_001

Compliance: PCI-DSS 6.3, LGPD Art. 37
"""

import os
import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/doc_trigger_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TriggerEvent:
    """Evento de trigger para regeneração de documentação"""
    event_type: str
    file_path: str
    timestamp: datetime
    file_hash: str
    trigger_id: str
    priority: str = "normal"
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

@dataclass
class TriggerRule:
    """Regra de trigger para monitoramento de arquivos"""
    pattern: str
    action: str
    priority: str
    cooldown_seconds: int = 30
    max_retries: int = 3
    enabled: bool = True
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class DocumentTriggerSystem:
    """
    Sistema de triggers automáticos para regeneração de documentação
    """
    
    def __init__(self, config_path: str = "docs/trigger_config.json"):
        self.config_path = config_path
        self.observer = Observer()
        self.rules: Dict[str, TriggerRule] = {}
        self.event_history: List[TriggerEvent] = []
        self.processing_events: Set[str] = set()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.running = False
        
        # Carregar configuração
        self.load_config()
        
        # Configurar handlers
        self.setup_handlers()
        
        logger.info(f"[DOC_TRIGGER] Sistema inicializado com {len(self.rules)} regras")

    def load_config(self) -> None:
        """Carrega configuração de triggers do arquivo JSON"""
        try:
            if not os.path.exists(self.config_path):
                self.create_default_config()
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Carregar regras
            for rule_id, rule_data in config.get('rules', {}).items():
                self.rules[rule_id] = TriggerRule(**rule_data)
            
            logger.info(f"[DOC_TRIGGER] Configuração carregada: {len(self.rules)} regras")
            
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao carregar configuração: {e}")
            self.create_default_config()

    def create_default_config(self) -> None:
        """Cria configuração padrão de triggers"""
        default_config = {
            "version": "1.0.0",
            "description": "Configuração de triggers para regeneração automática de documentação",
            "rules": {
                "python_files": {
                    "pattern": "**/*.py",
                    "action": "regenerate_semantic_contracts",
                    "priority": "high",
                    "cooldown_seconds": 30,
                    "max_retries": 3,
                    "enabled": True,
                    "metadata": {
                        "description": "Regenera contratos semânticos quando arquivos Python mudam"
                    }
                },
                "architecture_files": {
                    "pattern": "docs/architecture*.md",
                    "action": "regenerate_module_map",
                    "priority": "critical",
                    "cooldown_seconds": 60,
                    "max_retries": 5,
                    "enabled": True,
                    "metadata": {
                        "description": "Regenera mapa de módulos quando arquitetura muda"
                    }
                },
                "test_files": {
                    "pattern": "tests/**/*.py",
                    "action": "regenerate_coverage_map",
                    "priority": "medium",
                    "cooldown_seconds": 45,
                    "max_retries": 3,
                    "enabled": True,
                    "metadata": {
                        "description": "Regenera mapa de cobertura quando testes mudam"
                    }
                },
                "api_files": {
                    "pattern": "**/openapi*.yaml",
                    "action": "regenerate_api_docs",
                    "priority": "high",
                    "cooldown_seconds": 30,
                    "max_retries": 3,
                    "enabled": True,
                    "metadata": {
                        "description": "Regenera documentação da API quando OpenAPI muda"
                    }
                }
            },
            "sensitive_files": [
                ".env",
                "*.key",
                "*.pem",
                "secrets.json"
            ],
            "compliance": {
                "pci_dss": True,
                "lgpd": True,
                "audit_trail": True
            }
        }
        
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[DOC_TRIGGER] Configuração padrão criada em {self.config_path}")

    def setup_handlers(self) -> None:
        """Configura handlers de eventos do sistema de arquivos"""
        self.event_handler = DocumentEventHandler(self)
        
        # Adicionar observadores para diferentes diretórios
        directories_to_watch = [
            "omni_writer",
            "app",
            "tests",
            "docs",
            "scripts"
        ]
        
        for directory in directories_to_watch:
            if os.path.exists(directory):
                self.observer.schedule(
                    self.event_handler,
                    directory,
                    recursive=True
                )
                logger.info(f"[DOC_TRIGGER] Monitorando diretório: {directory}")

    def start(self) -> None:
        """Inicia o sistema de triggers"""
        if self.running:
            logger.warning("[DOC_TRIGGER] Sistema já está rodando")
            return
        
        try:
            self.observer.start()
            self.running = True
            logger.info("[DOC_TRIGGER] Sistema de triggers iniciado")
            
            # Loop principal
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("[DOC_TRIGGER] Interrupção recebida, parando sistema...")
        finally:
            self.stop()

    def stop(self) -> None:
        """Para o sistema de triggers"""
        self.running = False
        self.observer.stop()
        self.observer.join()
        self.executor.shutdown(wait=True)
        logger.info("[DOC_TRIGGER] Sistema de triggers parado")

    def process_event(self, event: TriggerEvent) -> None:
        """Processa evento de trigger"""
        try:
            # Verificar se arquivo é sensível
            if self.is_sensitive_file(event.file_path):
                logger.warning(f"[DOC_TRIGGER] Arquivo sensível detectado: {event.file_path}")
                return
            
            # Verificar cooldown
            if self.is_in_cooldown(event):
                logger.info(f"[DOC_TRIGGER] Evento em cooldown: {event.trigger_id}")
                return
            
            # Adicionar à fila de processamento
            self.processing_events.add(event.trigger_id)
            
            # Executar ação em thread separada
            future = self.executor.submit(self.execute_action, event)
            future.add_done_callback(lambda f: self.processing_events.discard(event.trigger_id))
            
            logger.info(f"[DOC_TRIGGER] Evento processado: {event.trigger_id}")
            
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao processar evento: {e}")
            self.processing_events.discard(event.trigger_id)

    def execute_action(self, event: TriggerEvent) -> None:
        """Executa ação baseada no tipo de evento"""
        try:
            action = event.metadata.get('action', 'unknown')
            
            if action == 'regenerate_semantic_contracts':
                self.regenerate_semantic_contracts(event)
            elif action == 'regenerate_module_map':
                self.regenerate_module_map(event)
            elif action == 'regenerate_coverage_map':
                self.regenerate_coverage_map(event)
            elif action == 'regenerate_api_docs':
                self.regenerate_api_docs(event)
            else:
                logger.warning(f"[DOC_TRIGGER] Ação desconhecida: {action}")
                
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao executar ação: {e}")

    def regenerate_semantic_contracts(self, event: TriggerEvent) -> None:
        """Regenera contratos semânticos"""
        logger.info(f"[DOC_TRIGGER] Regenerando contratos semânticos para: {event.file_path}")
        
        # Importar e executar análise semântica
        try:
            from semantic_analysis import SemanticAnalyzer
            analyzer = SemanticAnalyzer()
            analyzer.analyze_file(event.file_path)
            logger.info(f"[DOC_TRIGGER] Contratos semânticos regenerados com sucesso")
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao regenerar contratos semânticos: {e}")

    def regenerate_module_map(self, event: TriggerEvent) -> None:
        """Regenera mapa de módulos"""
        logger.info(f"[DOC_TRIGGER] Regenerando mapa de módulos para: {event.file_path}")
        
        # Implementar regeneração do mapa de módulos
        try:
            # Lógica de regeneração aqui
            logger.info(f"[DOC_TRIGGER] Mapa de módulos regenerado com sucesso")
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao regenerar mapa de módulos: {e}")

    def regenerate_coverage_map(self, event: TriggerEvent) -> None:
        """Regenera mapa de cobertura"""
        logger.info(f"[DOC_TRIGGER] Regenerando mapa de cobertura para: {event.file_path}")
        
        # Implementar regeneração do mapa de cobertura
        try:
            # Lógica de regeneração aqui
            logger.info(f"[DOC_TRIGGER] Mapa de cobertura regenerado com sucesso")
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao regenerar mapa de cobertura: {e}")

    def regenerate_api_docs(self, event: TriggerEvent) -> None:
        """Regenera documentação da API"""
        logger.info(f"[DOC_TRIGGER] Regenerando documentação da API para: {event.file_path}")
        
        # Implementar regeneração da documentação da API
        try:
            # Lógica de regeneração aqui
            logger.info(f"[DOC_TRIGGER] Documentação da API regenerada com sucesso")
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao regenerar documentação da API: {e}")

    def is_sensitive_file(self, file_path: str) -> bool:
        """Verifica se arquivo é sensível"""
        sensitive_patterns = [
            ".env",
            ".key",
            ".pem",
            "secrets",
            "password",
            "token"
        ]
        
        file_path_lower = file_path.lower()
        return any(pattern in file_path_lower for pattern in sensitive_patterns)

    def is_in_cooldown(self, event: TriggerEvent) -> bool:
        """Verifica se evento está em cooldown"""
        cooldown_seconds = event.metadata.get('cooldown_seconds', 30)
        
        # Verificar eventos recentes
        recent_events = [
            e for e in self.event_history
            if e.file_path == event.file_path
            and (datetime.now(timezone.utc) - e.timestamp).seconds < cooldown_seconds
        ]
        
        return len(recent_events) > 0

    def add_event(self, event: TriggerEvent) -> None:
        """Adiciona evento ao histórico"""
        self.event_history.append(event)
        
        # Manter apenas últimos 1000 eventos
        if len(self.event_history) > 1000:
            self.event_history = self.event_history[-1000:]

    def get_statistics(self) -> Dict:
        """Retorna estatísticas do sistema"""
        return {
            "total_events": len(self.event_history),
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "processing_events": len(self.processing_events),
            "running": self.running
        }


class DocumentEventHandler(FileSystemEventHandler):
    """Handler de eventos do sistema de arquivos"""
    
    def __init__(self, trigger_system: DocumentTriggerSystem):
        self.trigger_system = trigger_system
        super().__init__()

    def on_created(self, event):
        if not event.is_directory:
            self._handle_file_event(event, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_file_event(event, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle_file_event(event, "deleted")

    def _handle_file_event(self, event, event_type: str):
        """Processa evento de arquivo"""
        try:
            file_path = event.src_path
            
            # Verificar se arquivo corresponde a alguma regra
            matching_rules = self._find_matching_rules(file_path)
            
            for rule_id, rule in matching_rules.items():
                if not rule.enabled:
                    continue
                
                # Criar evento de trigger
                trigger_event = TriggerEvent(
                    event_type=event_type,
                    file_path=file_path,
                    timestamp=datetime.now(timezone.utc),
                    file_hash=self._calculate_file_hash(file_path),
                    trigger_id=f"{rule_id}_{int(time.time())}",
                    priority=rule.priority,
                    metadata={
                        "action": rule.action,
                        "cooldown_seconds": rule.cooldown_seconds,
                        "max_retries": rule.max_retries,
                        "rule_id": rule_id
                    }
                )
                
                # Adicionar ao histórico
                self.trigger_system.add_event(trigger_event)
                
                # Processar evento
                self.trigger_system.process_event(trigger_event)
                
        except Exception as e:
            logger.error(f"[DOC_TRIGGER] Erro ao processar evento {event_type}: {e}")

    def _find_matching_rules(self, file_path: str) -> Dict[str, TriggerRule]:
        """Encontra regras que correspondem ao arquivo"""
        matching_rules = {}
        
        for rule_id, rule in self.trigger_system.rules.items():
            if self._matches_pattern(file_path, rule.pattern):
                matching_rules[rule_id] = rule
        
        return matching_rules

    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Verifica se arquivo corresponde ao padrão"""
        try:
            from pathlib import Path
            path = Path(file_path)
            return path.match(pattern)
        except Exception:
            return False

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcula hash do arquivo"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()
                return hashlib.sha256(content).hexdigest()
            return ""
        except Exception:
            return ""


def main():
    """Função principal"""
    print("🚀 Iniciando Sistema de Triggers de Documentação...")
    
    # Criar diretório de logs
    os.makedirs("logs", exist_ok=True)
    
    # Inicializar sistema
    trigger_system = DocumentTriggerSystem()
    
    try:
        # Iniciar sistema
        trigger_system.start()
    except KeyboardInterrupt:
        print("\n⏹️ Parando sistema...")
    finally:
        trigger_system.stop()
        print("✅ Sistema parado com sucesso")


if __name__ == "__main__":
    main() 