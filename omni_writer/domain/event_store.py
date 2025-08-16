"""
Event Store Implementation - IMP-013

Prompt: Event Sourcing - IMP-013
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:30:00Z
Tracing ID: ENTERPRISE_20250127_013

Implementação do Event Store para persistência e recuperação de eventos:
- Armazenamento de eventos em arquivo JSON
- Recuperação de eventos por agregado
- Versionamento e sequenciamento
- Integração com sistema de logging estruturado
- Backup e recuperação de eventos
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Iterator, Tuple
from pathlib import Path
import shutil
import gzip
from contextlib import contextmanager

from .base_event import BaseEvent, EventFactory, EventValidator
from .events.article_events import register_article_events
from shared.logger import get_logger

logger = get_logger(__name__)


class EventStore:
    """
    Event Store para persistência e recuperação de eventos.
    Implementa armazenamento em arquivo JSON com backup automático.
    """
    
    def __init__(self, storage_path: str = "events", max_file_size_mb: int = 100):
        self.storage_path = Path(storage_path)
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self._lock = threading.RLock()
        
        # Cria diretórios necessários
        self.storage_path.mkdir(parents=True, exist_ok=True)
        (self.storage_path / "backups").mkdir(exist_ok=True)
        (self.storage_path / "snapshots").mkdir(exist_ok=True)
        
        # Registra eventos de artigos
        register_article_events()
        
        # Métricas
        self.metrics = {
            'total_events_stored': 0,
            'total_events_retrieved': 0,
            'backups_created': 0,
            'snapshots_created': 0,
            'last_backup_time': None,
            'last_snapshot_time': None
        }
        
        logger.info(
            f"Event Store inicializado: {self.storage_path}",
            extra={
                'event': 'event_store_init',
                'storage_path': str(self.storage_path),
                'max_file_size_mb': max_file_size_mb
            }
        )
    
    def store_event(self, event: BaseEvent) -> bool:
        """
        Armazena um evento no event store.
        
        Args:
            event: Evento a ser armazenado
            
        Returns:
            True se armazenado com sucesso, False caso contrário
        """
        with self._lock:
            try:
                # Valida evento
                if not EventValidator.validate_event(event):
                    logger.error(f"Evento inválido: {event.event_id}")
                    return False
                
                # Determina arquivo de destino
                file_path = self._get_event_file_path(event.aggregate_type, event.aggregate_id)
                
                # Verifica se precisa fazer backup
                if self._should_create_backup(file_path):
                    self._create_backup(file_path)
                
                # Armazena evento
                event_data = event.to_dict()
                event_data['stored_at'] = datetime.now(timezone.utc).isoformat()
                
                # Lê eventos existentes
                events = self._read_events_from_file(file_path)
                
                # Verifica versionamento
                if events and events[-1]['metadata']['version'] >= event.version:
                    logger.warning(
                        f"Versão de evento já existe: {event.aggregate_id}:{event.version}",
                        extra={
                            'event': 'event_store_version_conflict',
                            'aggregate_id': event.aggregate_id,
                            'event_version': event.version,
                            'existing_version': events[-1]['metadata']['version']
                        }
                    )
                    return False
                
                # Adiciona evento
                events.append(event_data)
                
                # Escreve arquivo
                self._write_events_to_file(file_path, events)
                
                # Atualiza métricas
                self.metrics['total_events_stored'] += 1
                
                logger.info(
                    f"Evento armazenado: {event.event_type} para {event.aggregate_type}:{event.aggregate_id}",
                    extra={
                        'event': 'event_store_event_stored',
                        'event_id': event.event_id,
                        'event_type': event.event_type,
                        'aggregate_id': event.aggregate_id,
                        'aggregate_type': event.aggregate_type,
                        'version': event.version,
                        'file_path': str(file_path)
                    }
                )
                
                return True
                
            except Exception as e:
                logger.error(
                    f"Erro ao armazenar evento: {e}",
                    extra={
                        'event': 'event_store_store_error',
                        'event_id': event.event_id,
                        'error': str(e)
                    }
                )
                return False
    
    def get_events(self, aggregate_id: str, aggregate_type: str, from_version: int = 1) -> List[BaseEvent]:
        """
        Recupera eventos de um agregado.
        
        Args:
            aggregate_id: ID do agregado
            aggregate_type: Tipo do agregado
            from_version: Versão inicial (inclusiva)
            
        Returns:
            Lista de eventos ordenados por versão
        """
        with self._lock:
            try:
                file_path = self._get_event_file_path(aggregate_type, aggregate_id)
                
                if not file_path.exists():
                    logger.info(f"Arquivo de eventos não encontrado: {file_path}")
                    return []
                
                # Lê eventos do arquivo
                events_data = self._read_events_from_file(file_path)
                
                # Filtra por versão
                filtered_events = [
                    event_data for event_data in events_data
                    if event_data['metadata']['version'] >= from_version
                ]
                
                # Converte para objetos BaseEvent
                events = []
                for event_data in filtered_events:
                    try:
                        event = EventFactory.create_from_dict(event_data)
                        events.append(event)
                    except Exception as e:
                        logger.error(f"Erro ao reconstruir evento: {e}")
                        continue
                
                # Atualiza métricas
                self.metrics['total_events_retrieved'] += len(events)
                
                logger.info(
                    f"Eventos recuperados: {len(events)} para {aggregate_type}:{aggregate_id}",
                    extra={
                        'event': 'event_store_events_retrieved',
                        'aggregate_id': aggregate_id,
                        'aggregate_type': aggregate_type,
                        'from_version': from_version,
                        'events_count': len(events)
                    }
                )
                
                return events
                
            except Exception as e:
                logger.error(
                    f"Erro ao recuperar eventos: {e}",
                    extra={
                        'event': 'event_store_retrieve_error',
                        'aggregate_id': aggregate_id,
                        'aggregate_type': aggregate_type,
                        'error': str(e)
                    }
                )
                return []
    
    def get_all_events(self, aggregate_type: Optional[str] = None) -> Iterator[BaseEvent]:
        """
        Recupera todos os eventos (ou de um tipo específico).
        
        Args:
            aggregate_type: Tipo do agregado (opcional)
            
        Yields:
            Eventos encontrados
        """
        with self._lock:
            try:
                # Encontra todos os arquivos de eventos
                pattern = f"*_{aggregate_type}_*.json" if aggregate_type else "*.json"
                event_files = list(self.storage_path.glob(pattern))
                
                for file_path in event_files:
                    if file_path.name.startswith('backup_') or file_path.name.startswith('snapshot_'):
                        continue
                    
                    events_data = self._read_events_from_file(file_path)
                    
                    for event_data in events_data:
                        try:
                            event = EventFactory.create_from_dict(event_data)
                            yield event
                        except Exception as e:
                            logger.error(f"Erro ao reconstruir evento: {e}")
                            continue
                
            except Exception as e:
                logger.error(f"Erro ao recuperar todos os eventos: {e}")
    
    def get_event_stream(self, aggregate_id: str, aggregate_type: str) -> Iterator[BaseEvent]:
        """
        Retorna um stream de eventos para um agregado.
        
        Args:
            aggregate_id: ID do agregado
            aggregate_type: Tipo do agregado
            
        Yields:
            Eventos do agregado
        """
        events = self.get_events(aggregate_id, aggregate_type)
        for event in events:
            yield event
    
    def create_snapshot(self, aggregate_id: str, aggregate_type: str, snapshot_data: Dict[str, Any]) -> bool:
        """
        Cria um snapshot do estado atual de um agregado.
        
        Args:
            aggregate_id: ID do agregado
            aggregate_type: Tipo do agregado
            snapshot_data: Dados do snapshot
            
        Returns:
            True se snapshot criado com sucesso
        """
        with self._lock:
            try:
                snapshot_path = self.storage_path / "snapshots" / f"{aggregate_type}_{aggregate_id}_snapshot.json"
                
                snapshot = {
                    'aggregate_id': aggregate_id,
                    'aggregate_type': aggregate_type,
                    'snapshot_data': snapshot_data,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'version': len(self.get_events(aggregate_id, aggregate_type))
                }
                
                with open(snapshot_path, 'w', encoding='utf-8') as f:
                    json.dump(snapshot, f, ensure_ascii=False, indent=2)
                
                self.metrics['snapshots_created'] += 1
                self.metrics['last_snapshot_time'] = datetime.now(timezone.utc)
                
                logger.info(
                    f"Snapshot criado: {aggregate_type}:{aggregate_id}",
                    extra={
                        'event': 'event_store_snapshot_created',
                        'aggregate_id': aggregate_id,
                        'aggregate_type': aggregate_type,
                        'version': snapshot['version'],
                        'snapshot_path': str(snapshot_path)
                    }
                )
                
                return True
                
            except Exception as e:
                logger.error(f"Erro ao criar snapshot: {e}")
                return False
    
    def get_snapshot(self, aggregate_id: str, aggregate_type: str) -> Optional[Dict[str, Any]]:
        """
        Recupera o snapshot mais recente de um agregado.
        
        Args:
            aggregate_id: ID do agregado
            aggregate_type: Tipo do agregado
            
        Returns:
            Dados do snapshot ou None se não encontrado
        """
        try:
            snapshot_path = self.storage_path / "snapshots" / f"{aggregate_type}_{aggregate_id}_snapshot.json"
            
            if not snapshot_path.exists():
                return None
            
            with open(snapshot_path, 'r', encoding='utf-8') as f:
                snapshot = json.load(f)
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Erro ao recuperar snapshot: {e}")
            return None
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas do event store"""
        with self._lock:
            return {
                'storage_path': str(self.storage_path),
                'total_events_stored': self.metrics['total_events_stored'],
                'total_events_retrieved': self.metrics['total_events_retrieved'],
                'backups_created': self.metrics['backups_created'],
                'snapshots_created': self.metrics['snapshots_created'],
                'last_backup_time': self.metrics['last_backup_time'].isoformat() if self.metrics['last_backup_time'] else None,
                'last_snapshot_time': self.metrics['last_snapshot_time'].isoformat() if self.metrics['last_snapshot_time'] else None,
                'registered_events': EventFactory.get_registered_events()
            }
    
    def _get_event_file_path(self, aggregate_type: str, aggregate_id: str) -> Path:
        """Determina o caminho do arquivo de eventos"""
        return self.storage_path / f"{aggregate_type}_{aggregate_id}.json"
    
    def _read_events_from_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Lê eventos de um arquivo"""
        if not file_path.exists():
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Erro ao ler arquivo de eventos {file_path}: {e}")
            return []
    
    def _write_events_to_file(self, file_path: Path, events: List[Dict[str, Any]]):
        """Escreve eventos em um arquivo"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(events, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Erro ao escrever arquivo de eventos {file_path}: {e}")
            raise
    
    def _should_create_backup(self, file_path: Path) -> bool:
        """Verifica se deve criar backup do arquivo"""
        if not file_path.exists():
            return False
        
        # Cria backup se arquivo é muito grande
        if file_path.stat().st_size > self.max_file_size_bytes:
            return True
        
        # Cria backup a cada 1000 eventos
        try:
            events = self._read_events_from_file(file_path)
            return len(events) % 1000 == 0
        except:
            return False
    
    def _create_backup(self, file_path: Path):
        """Cria backup de um arquivo de eventos"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.storage_path / "backups" / f"backup_{file_path.stem}_{timestamp}.json.gz"
            
            # Comprime arquivo original
            with open(file_path, 'rb') as f_in:
                with gzip.open(backup_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            self.metrics['backups_created'] += 1
            self.metrics['last_backup_time'] = datetime.now(timezone.utc)
            
            logger.info(
                f"Backup criado: {backup_path}",
                extra={
                    'event': 'event_store_backup_created',
                    'original_file': str(file_path),
                    'backup_file': str(backup_path)
                }
            )
            
        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
    
    def cleanup_old_backups(self, days_to_keep: int = 30):
        """Remove backups antigos"""
        try:
            backup_dir = self.storage_path / "backups"
            cutoff_time = datetime.now() - timedelta(days=days_to_keep)
            
            for backup_file in backup_dir.glob("backup_*.json.gz"):
                if backup_file.stat().st_mtime < cutoff_time.timestamp():
                    backup_file.unlink()
                    logger.info(f"Backup removido: {backup_file}")
                    
        except Exception as e:
            logger.error(f"Erro ao limpar backups: {e}")


# Instância global do event store
_event_store: Optional[EventStore] = None


def get_event_store() -> EventStore:
    """Retorna instância global do event store"""
    global _event_store
    if _event_store is None:
        _event_store = EventStore()
    return _event_store


@contextmanager
def event_store_context():
    """Context manager para o event store"""
    store = get_event_store()
    try:
        yield store
    finally:
        pass  # Event store não precisa de cleanup específico


class EventPublisher:
    """Publicador de eventos para integração com outros sistemas"""
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.subscribers: List[callable] = []
    
    def subscribe(self, callback: callable):
        """Adiciona um subscriber"""
        self.subscribers.append(callback)
    
    def publish(self, event: BaseEvent):
        """Publica um evento"""
        # Armazena no event store
        success = self.event_store.store_event(event)
        
        if success:
            # Notifica subscribers
            for subscriber in self.subscribers:
                try:
                    subscriber(event)
                except Exception as e:
                    logger.error(f"Erro no subscriber: {e}")
    
    def publish_batch(self, events: List[BaseEvent]):
        """Publica múltiplos eventos"""
        for event in events:
            self.publish(event)


# Instância global do publisher
_event_publisher: Optional[EventPublisher] = None


def get_event_publisher() -> EventPublisher:
    """Retorna instância global do event publisher"""
    global _event_publisher
    if _event_publisher is None:
        store = get_event_store()
        _event_publisher = EventPublisher(store)
    return _event_publisher 