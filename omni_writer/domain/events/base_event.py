"""
Base Event Implementation - IMP-013

Prompt: Event Sourcing - IMP-013
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:30:00Z
Tracing ID: ENTERPRISE_20250127_013

Implementação base para eventos do sistema de Event Sourcing:
- Evento base com metadados obrigatórios
- Serialização e deserialização
- Versionamento de eventos
- Integração com sistema de logging estruturado
"""

import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Type, TypeVar
from enum import Enum

from shared.logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T', bound='BaseEvent')


class EventType(Enum):
    """Tipos de eventos do sistema"""
    # Eventos de geração de artigos
    ARTICLE_GENERATION_STARTED = "article_generation_started"
    ARTICLE_GENERATION_COMPLETED = "article_generation_completed"
    ARTICLE_GENERATION_FAILED = "article_generation_failed"
    
    # Eventos de validação
    PROMPT_VALIDATION_STARTED = "prompt_validation_started"
    PROMPT_VALIDATION_COMPLETED = "prompt_validation_completed"
    PROMPT_VALIDATION_FAILED = "prompt_validation_failed"
    
    # Eventos de cache
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    CACHE_SET = "cache_set"
    CACHE_INVALIDATED = "cache_invalidated"
    
    # Eventos de retry
    RETRY_ATTEMPTED = "retry_attempted"
    RETRY_SUCCEEDED = "retry_succeeded"
    RETRY_FAILED = "retry_failed"
    
    # Eventos de pipeline
    PIPELINE_STARTED = "pipeline_started"
    PIPELINE_COMPLETED = "pipeline_completed"
    PIPELINE_FAILED = "pipeline_failed"
    
    # Eventos de sistema
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIGURATION_CHANGED = "configuration_changed"


@dataclass
class EventMetadata:
    """Metadados obrigatórios para todos os eventos"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = field()
    aggregate_id: str = field()
    aggregate_type: str = field()
    version: int = field(default=1)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: Optional[str] = field(default=None)
    user_id: Optional[str] = field(default=None)
    session_id: Optional[str] = field(default=None)
    source: str = field(default="omni_writer")
    correlation_id: Optional[str] = field(default=None)
    causation_id: Optional[str] = field(default=None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte metadados para dicionário"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'aggregate_id': self.aggregate_id,
            'aggregate_type': self.aggregate_type,
            'version': self.version,
            'timestamp': self.timestamp.isoformat(),
            'trace_id': self.trace_id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'source': self.source,
            'correlation_id': self.correlation_id,
            'causation_id': self.causation_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventMetadata':
        """Cria metadados a partir de dicionário"""
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)


class BaseEvent(ABC):
    """
    Classe base para todos os eventos do sistema.
    Implementa funcionalidades comuns como serialização, versionamento e logging.
    """
    
    def __init__(
        self,
        aggregate_id: str,
        aggregate_type: str,
        event_type: EventType,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        **kwargs
    ):
        self.metadata = EventMetadata(
            event_type=event_type.value,
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id
        )
        
        # Atributos específicos do evento
        for key, value in kwargs.items():
            setattr(self, key, value)
        
        # Log do evento
        self._log_event()
    
    @property
    def event_id(self) -> str:
        """ID único do evento"""
        return self.metadata.event_id
    
    @property
    def event_type(self) -> str:
        """Tipo do evento"""
        return self.metadata.event_type
    
    @property
    def aggregate_id(self) -> str:
        """ID do agregado"""
        return self.metadata.aggregate_id
    
    @property
    def aggregate_type(self) -> str:
        """Tipo do agregado"""
        return self.metadata.aggregate_type
    
    @property
    def timestamp(self) -> datetime:
        """Timestamp do evento"""
        return self.metadata.timestamp
    
    @property
    def version(self) -> int:
        """Versão do evento"""
        return self.metadata.version
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte evento para dicionário"""
        event_dict = {
            'metadata': self.metadata.to_dict(),
            'event_type': self.event_type,
            'aggregate_id': self.aggregate_id,
            'aggregate_type': self.aggregate_type
        }
        
        # Adiciona atributos específicos do evento
        for key, value in self.__dict__.items():
            if key != 'metadata':
                if hasattr(value, 'to_dict'):
                    event_dict[key] = value.to_dict()
                elif isinstance(value, datetime):
                    event_dict[key] = value.isoformat()
                else:
                    event_dict[key] = value
        
        return event_dict
    
    def to_json(self) -> str:
        """Converte evento para JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)
    
    @classmethod
    def from_dict(cls: Type[T], data: Dict[str, Any]) -> T:
        """Cria evento a partir de dicionário"""
        metadata_data = data.pop('metadata', {})
        metadata = EventMetadata.from_dict(metadata_data)
        
        # Reconstrói atributos específicos do evento
        event_data = {}
        for key, value in data.items():
            if key not in ['event_type', 'aggregate_id', 'aggregate_type']:
                event_data[key] = value
        
        # Cria instância do evento
        event = cls.__new__(cls)
        event.metadata = metadata
        
        # Define atributos específicos
        for key, value in event_data.items():
            setattr(event, key, value)
        
        return event
    
    @classmethod
    def from_json(cls: Type[T], json_str: str) -> T:
        """Cria evento a partir de JSON"""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def _log_event(self):
        """Loga o evento usando sistema estruturado"""
        log_data = {
            'event': 'event_sourcing_event_created',
            'event_id': self.event_id,
            'event_type': self.event_type,
            'aggregate_id': self.aggregate_id,
            'aggregate_type': self.aggregate_type,
            'version': self.version,
            'trace_id': self.metadata.trace_id,
            'timestamp': self.timestamp.isoformat()
        }
        
        logger.info(
            f"Evento criado: {self.event_type} para {self.aggregate_type}:{self.aggregate_id}",
            extra=log_data
        )
    
    def __str__(self) -> str:
        """Representação string do evento"""
        return f"{self.__class__.__name__}({self.event_type}, {self.aggregate_id}, v{self.version})"
    
    def __repr__(self) -> str:
        """Representação detalhada do evento"""
        return f"{self.__class__.__name__}(event_id={self.event_id}, event_type={self.event_type}, aggregate_id={self.aggregate_id}, version={self.version})"
    
    def __eq__(self, other: Any) -> bool:
        """Comparação de igualdade baseada no event_id"""
        if not isinstance(other, BaseEvent):
            return False
        return self.event_id == other.event_id
    
    def __hash__(self) -> int:
        """Hash baseado no event_id"""
        return hash(self.event_id)


class EventFactory:
    """Factory para criação de eventos"""
    
    _event_registry: Dict[str, Type[BaseEvent]] = {}
    
    @classmethod
    def register_event(cls, event_type: EventType, event_class: Type[BaseEvent]):
        """Registra uma classe de evento"""
        cls._event_registry[event_type.value] = event_class
        logger.info(f"Evento registrado: {event_type.value} -> {event_class.__name__}")
    
    @classmethod
    def create_event(cls, event_type: EventType, **kwargs) -> BaseEvent:
        """Cria um evento do tipo especificado"""
        if event_type.value not in cls._event_registry:
            raise ValueError(f"Tipo de evento não registrado: {event_type.value}")
        
        event_class = cls._event_registry[event_type.value]
        return event_class(**kwargs)
    
    @classmethod
    def create_from_dict(cls, data: Dict[str, Any]) -> BaseEvent:
        """Cria evento a partir de dicionário"""
        event_type = data.get('event_type')
        if not event_type or event_type not in cls._event_registry:
            raise ValueError(f"Tipo de evento não registrado: {event_type}")
        
        event_class = cls._event_registry[event_type]
        return event_class.from_dict(data)
    
    @classmethod
    def create_from_json(cls, json_str: str) -> BaseEvent:
        """Cria evento a partir de JSON"""
        data = json.loads(json_str)
        return cls.create_from_dict(data)
    
    @classmethod
    def get_registered_events(cls) -> Dict[str, str]:
        """Retorna lista de eventos registrados"""
        return {event_type: event_class.__name__ for event_type, event_class in cls._event_registry.items()}


class EventValidator:
    """Validador de eventos"""
    
    @staticmethod
    def validate_event(event: BaseEvent) -> bool:
        """Valida se um evento está correto"""
        try:
            # Validações básicas
            if not event.event_id:
                logger.error("Evento sem ID")
                return False
            
            if not event.event_type:
                logger.error("Evento sem tipo")
                return False
            
            if not event.aggregate_id:
                logger.error("Evento sem aggregate_id")
                return False
            
            if not event.aggregate_type:
                logger.error("Evento sem aggregate_type")
                return False
            
            if not event.timestamp:
                logger.error("Evento sem timestamp")
                return False
            
            # Validação de versão
            if event.version < 1:
                logger.error("Versão do evento deve ser >= 1")
                return False
            
            # Validação de serialização
            try:
                event_dict = event.to_dict()
                event_json = event.to_json()
                reconstructed = BaseEvent.from_json(event_json)
                
                if event.event_id != reconstructed.event_id:
                    logger.error("Falha na reconstrução do evento")
                    return False
                    
            except Exception as e:
                logger.error(f"Falha na serialização do evento: {e}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação do evento: {e}")
            return False
    
    @staticmethod
    def validate_event_sequence(events: list[BaseEvent]) -> bool:
        """Valida sequência de eventos"""
        if not events:
            return True
        
        # Verifica se todos os eventos são do mesmo agregado
        aggregate_id = events[0].aggregate_id
        aggregate_type = events[0].aggregate_type
        
        for i, event in enumerate(events):
            if event.aggregate_id != aggregate_id:
                logger.error(f"Evento {i} tem aggregate_id diferente: {event.aggregate_id} != {aggregate_id}")
                return False
            
            if event.aggregate_type != aggregate_type:
                logger.error(f"Evento {i} tem aggregate_type diferente: {event.aggregate_type} != {aggregate_type}")
                return False
            
            # Verifica se a versão é sequencial
            expected_version = i + 1
            if event.version != expected_version:
                logger.error(f"Evento {i} tem versão incorreta: {event.version} != {expected_version}")
                return False
        
        return True 