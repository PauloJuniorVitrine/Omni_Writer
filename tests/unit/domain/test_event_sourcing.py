"""
Testes Unitários - Event Sourcing - IMP-013

Prompt: Event Sourcing - IMP-013
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:30:00Z
Tracing ID: ENTERPRISE_20250127_013

Testes baseados APENAS no código real implementado:
- Eventos base e metadados
- Eventos específicos de artigos
- Event store e persistência
- Event factory e validação
- Event publisher e integração
"""

import pytest
import tempfile
import shutil
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from omni_writer.domain.events.base_event import (
    BaseEvent,
    EventType,
    EventMetadata,
    EventFactory,
    EventValidator
)
from omni_writer.domain.events.article_events import (
    ArticleGenerationStartedEvent,
    ArticleGenerationCompletedEvent,
    ArticleGenerationFailedEvent,
    PromptValidationStartedEvent,
    PromptValidationCompletedEvent,
    PromptValidationFailedEvent,
    CacheHitEvent,
    CacheMissEvent,
    CacheSetEvent,
    CacheInvalidatedEvent,
    RetryAttemptedEvent,
    RetrySucceededEvent,
    RetryFailedEvent,
    PipelineStartedEvent,
    PipelineCompletedEvent,
    PipelineFailedEvent
)
from omni_writer.domain.event_store import EventStore, EventPublisher, get_event_store, get_event_publisher
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput


class TestEventMetadata:
    """Testes para metadados de eventos"""
    
    def test_metadata_creation(self):
        """Testa criação de metadados"""
        metadata = EventMetadata(
            event_type="test_event",
            aggregate_id="test_aggregate",
            aggregate_type="test_type"
        )
        
        assert metadata.event_type == "test_event"
        assert metadata.aggregate_id == "test_aggregate"
        assert metadata.aggregate_type == "test_type"
        assert metadata.version == 1
        assert metadata.timestamp is not None
        assert metadata.source == "omni_writer"
    
    def test_metadata_to_dict(self):
        """Testa conversão para dicionário"""
        metadata = EventMetadata(
            event_type="test_event",
            aggregate_id="test_aggregate",
            aggregate_type="test_type",
            trace_id="trace_123",
            user_id="user_456"
        )
        
        data = metadata.to_dict()
        
        assert data['event_type'] == "test_event"
        assert data['aggregate_id'] == "test_aggregate"
        assert data['aggregate_type'] == "test_type"
        assert data['trace_id'] == "trace_123"
        assert data['user_id'] == "user_456"
        assert 'timestamp' in data
    
    def test_metadata_from_dict(self):
        """Testa criação a partir de dicionário"""
        original_metadata = EventMetadata(
            event_type="test_event",
            aggregate_id="test_aggregate",
            aggregate_type="test_type"
        )
        
        data = original_metadata.to_dict()
        reconstructed_metadata = EventMetadata.from_dict(data)
        
        assert reconstructed_metadata.event_type == original_metadata.event_type
        assert reconstructed_metadata.aggregate_id == original_metadata.aggregate_id
        assert reconstructed_metadata.aggregate_type == original_metadata.aggregate_type


class TestBaseEvent:
    """Testes para eventos base"""
    
    def test_base_event_creation(self):
        """Testa criação de evento base"""
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        assert event.event_id is not None
        assert event.event_type == EventType.ARTICLE_GENERATION_STARTED.value
        assert event.aggregate_id == "test_123"
        assert event.aggregate_type == "article_generation"
        assert event.version == 1
        assert event.timestamp is not None
    
    def test_base_event_serialization(self):
        """Testa serialização de evento"""
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        # Testa conversão para dicionário
        event_dict = event.to_dict()
        assert 'metadata' in event_dict
        assert 'event_type' in event_dict
        assert 'aggregate_id' in event_dict
        assert 'aggregate_type' in event_dict
        
        # Testa conversão para JSON
        event_json = event.to_json()
        assert isinstance(event_json, str)
        
        # Testa reconstrução
        reconstructed_event = ArticleGenerationStartedEvent.from_json(event_json)
        assert reconstructed_event.event_id == event.event_id
        assert reconstructed_event.event_type == event.event_type
        assert reconstructed_event.aggregate_id == event.aggregate_id
    
    def test_base_event_equality(self):
        """Testa igualdade de eventos"""
        event1 = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        event2 = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        # Eventos diferentes devem ter IDs diferentes
        assert event1 != event2
        
        # Evento deve ser igual a si mesmo
        assert event1 == event1


class TestArticleEvents:
    """Testes para eventos específicos de artigos"""
    
    @pytest.fixture
    def mock_config(self):
        """Configuração mock para testes"""
        config = Mock(spec=GenerationConfig)
        config.api_key = "test_key"
        config.model_type = "openai"
        config.temperature = 0.7
        config.max_tokens = 4096
        config.language = "pt-BR"
        return config
    
    @pytest.fixture
    def mock_prompt(self):
        """Prompt mock para testes"""
        prompt = Mock(spec=PromptInput)
        prompt.text = "Teste de prompt"
        prompt.index = 0
        return prompt
    
    @pytest.fixture
    def mock_article_output(self):
        """ArticleOutput mock para testes"""
        output = Mock(spec=ArticleOutput)
        output.content = "Conteúdo do artigo"
        output.filename = "artigo_1.txt"
        return output
    
    def test_article_generation_started_event(self, mock_config, mock_prompt):
        """Testa evento de início de geração"""
        event = ArticleGenerationStartedEvent(
            aggregate_id="gen_123",
            config=mock_config,
            prompt=mock_prompt,
            variation=0,
            trace_id="trace_123"
        )
        
        assert event.event_type == EventType.ARTICLE_GENERATION_STARTED.value
        assert event.aggregate_type == "article_generation"
        assert event.config == mock_config
        assert event.prompt == mock_prompt
        assert event.variation == 0
        assert event.started_at is not None
    
    def test_article_generation_completed_event(self, mock_article_output):
        """Testa evento de conclusão de geração"""
        event = ArticleGenerationCompletedEvent(
            aggregate_id="gen_123",
            article_output=mock_article_output,
            generation_time=5.5,
            model_used="gpt-4o",
            tokens_used=1500
        )
        
        assert event.event_type == EventType.ARTICLE_GENERATION_COMPLETED.value
        assert event.article_output == mock_article_output
        assert event.generation_time == 5.5
        assert event.model_used == "gpt-4o"
        assert event.tokens_used == 1500
        assert event.completed_at is not None
    
    def test_article_generation_failed_event(self):
        """Testa evento de falha na geração"""
        event = ArticleGenerationFailedEvent(
            aggregate_id="gen_123",
            error_message="API timeout",
            error_type="TimeoutError",
            generation_time=10.0,
            model_used="gpt-4o"
        )
        
        assert event.event_type == EventType.ARTICLE_GENERATION_FAILED.value
        assert event.error_message == "API timeout"
        assert event.error_type == "TimeoutError"
        assert event.generation_time == 10.0
        assert event.model_used == "gpt-4o"
        assert event.failed_at is not None
    
    def test_prompt_validation_events(self):
        """Testa eventos de validação de prompt"""
        # Evento de início
        started_event = PromptValidationStartedEvent(
            aggregate_id="val_123",
            prompt_text="Teste de prompt",
            validation_rules=["length", "content"]
        )
        
        assert started_event.event_type == EventType.PROMPT_VALIDATION_STARTED.value
        assert started_event.prompt_text == "Teste de prompt"
        assert started_event.validation_rules == ["length", "content"]
        
        # Evento de conclusão
        completed_event = PromptValidationCompletedEvent(
            aggregate_id="val_123",
            is_valid=True,
            validation_results={"length": True, "content": True},
            estimated_tokens=500
        )
        
        assert completed_event.event_type == EventType.PROMPT_VALIDATION_COMPLETED.value
        assert completed_event.is_valid is True
        assert completed_event.estimated_tokens == 500
        
        # Evento de falha
        failed_event = PromptValidationFailedEvent(
            aggregate_id="val_123",
            error_message="Prompt muito longo",
            validation_errors=["length_exceeded"]
        )
        
        assert failed_event.event_type == EventType.PROMPT_VALIDATION_FAILED.value
        assert failed_event.error_message == "Prompt muito longo"
        assert failed_event.validation_errors == ["length_exceeded"]
    
    def test_cache_events(self):
        """Testa eventos de cache"""
        # Cache hit
        hit_event = CacheHitEvent(
            aggregate_id="cache_123",
            cache_key="prompt_hash_123",
            cache_type="memory",
            response_time=0.001
        )
        
        assert hit_event.event_type == EventType.CACHE_HIT.value
        assert hit_event.cache_key == "prompt_hash_123"
        assert hit_event.cache_type == "memory"
        assert hit_event.response_time == 0.001
        
        # Cache miss
        miss_event = CacheMissEvent(
            aggregate_id="cache_123",
            cache_key="prompt_hash_456",
            cache_type="memory",
            reason="not_found"
        )
        
        assert miss_event.event_type == EventType.CACHE_MISS.value
        assert miss_event.reason == "not_found"
        
        # Cache set
        set_event = CacheSetEvent(
            aggregate_id="cache_123",
            cache_key="prompt_hash_789",
            cache_type="memory",
            ttl=3600,
            size_bytes=1024
        )
        
        assert set_event.event_type == EventType.CACHE_SET.value
        assert set_event.ttl == 3600
        assert set_event.size_bytes == 1024
    
    def test_retry_events(self):
        """Testa eventos de retry"""
        # Retry attempted
        attempted_event = RetryAttemptedEvent(
            aggregate_id="retry_123",
            operation="api_call",
            attempt_number=2,
            max_attempts=3,
            delay_seconds=1.0,
            error_message="Connection timeout"
        )
        
        assert attempted_event.event_type == EventType.RETRY_ATTEMPTED.value
        assert attempted_event.operation == "api_call"
        assert attempted_event.attempt_number == 2
        assert attempted_event.max_attempts == 3
        assert attempted_event.delay_seconds == 1.0
        
        # Retry succeeded
        succeeded_event = RetrySucceededEvent(
            aggregate_id="retry_123",
            operation="api_call",
            final_attempt_number=3,
            total_time=5.5
        )
        
        assert succeeded_event.event_type == EventType.RETRY_SUCCEEDED.value
        assert succeeded_event.final_attempt_number == 3
        assert succeeded_event.total_time == 5.5
    
    def test_pipeline_events(self):
        """Testa eventos de pipeline"""
        # Pipeline started
        started_event = PipelineStartedEvent(
            aggregate_id="pipeline_123",
            pipeline_type="single_instance",
            config=Mock(spec=GenerationConfig),
            total_prompts=5
        )
        
        assert started_event.event_type == EventType.PIPELINE_STARTED.value
        assert started_event.pipeline_type == "single_instance"
        assert started_event.total_prompts == 5
        
        # Pipeline completed
        completed_event = PipelineCompletedEvent(
            aggregate_id="pipeline_123",
            pipeline_type="single_instance",
            total_articles=5,
            successful_articles=4,
            failed_articles=1,
            total_time=30.5,
            zip_path="/path/to/zip"
        )
        
        assert completed_event.event_type == EventType.PIPELINE_COMPLETED.value
        assert completed_event.total_articles == 5
        assert completed_event.successful_articles == 4
        assert completed_event.failed_articles == 1
        assert completed_event.total_time == 30.5
        assert completed_event.zip_path == "/path/to/zip"


class TestEventFactory:
    """Testes para factory de eventos"""
    
    def test_event_registration(self):
        """Testa registro de eventos"""
        # Limpa registro para teste
        EventFactory._event_registry.clear()
        
        # Registra evento
        EventFactory.register_event(EventType.ARTICLE_GENERATION_STARTED, ArticleGenerationStartedEvent)
        
        # Verifica registro
        assert EventType.ARTICLE_GENERATION_STARTED.value in EventFactory._event_registry
        assert EventFactory._event_registry[EventType.ARTICLE_GENERATION_STARTED.value] == ArticleGenerationStartedEvent
    
    def test_event_creation(self):
        """Testa criação de eventos via factory"""
        # Registra evento
        EventFactory.register_event(EventType.ARTICLE_GENERATION_STARTED, ArticleGenerationStartedEvent)
        
        # Cria evento
        event = EventFactory.create_event(
            EventType.ARTICLE_GENERATION_STARTED,
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        assert isinstance(event, ArticleGenerationStartedEvent)
        assert event.aggregate_id == "test_123"
    
    def test_event_creation_from_dict(self):
        """Testa criação de evento a partir de dicionário"""
        # Registra evento
        EventFactory.register_event(EventType.ARTICLE_GENERATION_STARTED, ArticleGenerationStartedEvent)
        
        # Cria evento original
        original_event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        # Converte para dicionário e reconstrói
        event_dict = original_event.to_dict()
        reconstructed_event = EventFactory.create_from_dict(event_dict)
        
        assert isinstance(reconstructed_event, ArticleGenerationStartedEvent)
        assert reconstructed_event.event_id == original_event.event_id
        assert reconstructed_event.aggregate_id == original_event.aggregate_id


class TestEventValidator:
    """Testes para validação de eventos"""
    
    def test_event_validation_success(self):
        """Testa validação bem-sucedida de evento"""
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        assert EventValidator.validate_event(event) is True
    
    def test_event_validation_failure(self):
        """Testa falha na validação de evento"""
        # Cria evento inválido (sem aggregate_id)
        event = ArticleGenerationStartedEvent(
            aggregate_id="",  # Inválido
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        assert EventValidator.validate_event(event) is False
    
    def test_event_sequence_validation(self):
        """Testa validação de sequência de eventos"""
        events = [
            ArticleGenerationStartedEvent(
                aggregate_id="test_123",
                config=Mock(spec=GenerationConfig),
                prompt=Mock(spec=PromptInput)
            ),
            ArticleGenerationCompletedEvent(
                aggregate_id="test_123",
                article_output=Mock(spec=ArticleOutput),
                generation_time=5.0,
                model_used="gpt-4o"
            )
        ]
        
        assert EventValidator.validate_event_sequence(events) is True
    
    def test_event_sequence_validation_failure(self):
        """Testa falha na validação de sequência"""
        events = [
            ArticleGenerationStartedEvent(
                aggregate_id="test_123",
                config=Mock(spec=GenerationConfig),
                prompt=Mock(spec=PromptInput)
            ),
            ArticleGenerationCompletedEvent(
                aggregate_id="test_456",  # ID diferente
                article_output=Mock(spec=ArticleOutput),
                generation_time=5.0,
                model_used="gpt-4o"
            )
        ]
        
        assert EventValidator.validate_event_sequence(events) is False


class TestEventStore:
    """Testes para event store"""
    
    @pytest.fixture
    def temp_event_store(self):
        """Event store temporário para testes"""
        temp_dir = tempfile.mkdtemp()
        store = EventStore(storage_path=temp_dir)
        yield store
        shutil.rmtree(temp_dir)
    
    def test_event_store_initialization(self, temp_event_store):
        """Testa inicialização do event store"""
        assert temp_event_store.storage_path.exists()
        assert (temp_event_store.storage_path / "backups").exists()
        assert (temp_event_store.storage_path / "snapshots").exists()
        assert temp_event_store.metrics['total_events_stored'] == 0
    
    def test_store_and_retrieve_event(self, temp_event_store):
        """Testa armazenamento e recuperação de evento"""
        # Cria evento
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        # Armazena evento
        success = temp_event_store.store_event(event)
        assert success is True
        
        # Recupera eventos
        events = temp_event_store.get_events("test_123", "article_generation")
        assert len(events) == 1
        assert events[0].event_id == event.event_id
        assert events[0].event_type == event.event_type
    
    def test_event_versioning(self, temp_event_store):
        """Testa versionamento de eventos"""
        # Cria dois eventos para o mesmo agregado
        event1 = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        event2 = ArticleGenerationCompletedEvent(
            aggregate_id="test_123",
            article_output=Mock(spec=ArticleOutput),
            generation_time=5.0,
            model_used="gpt-4o"
        )
        
        # Armazena eventos
        temp_event_store.store_event(event1)
        temp_event_store.store_event(event2)
        
        # Recupera eventos
        events = temp_event_store.get_events("test_123", "article_generation")
        assert len(events) == 2
        assert events[0].version == 1
        assert events[1].version == 2
    
    def test_event_stream(self, temp_event_store):
        """Testa stream de eventos"""
        # Cria múltiplos eventos
        for i in range(3):
            event = ArticleGenerationStartedEvent(
                aggregate_id="test_123",
                config=Mock(spec=GenerationConfig),
                prompt=Mock(spec=PromptInput)
            )
            temp_event_store.store_event(event)
        
        # Testa stream
        events = list(temp_event_store.get_event_stream("test_123", "article_generation"))
        assert len(events) == 3
    
    def test_snapshot_creation(self, temp_event_store):
        """Testa criação de snapshot"""
        # Cria alguns eventos
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        temp_event_store.store_event(event)
        
        # Cria snapshot
        snapshot_data = {"status": "completed", "articles_count": 1}
        success = temp_event_store.create_snapshot("test_123", "article_generation", snapshot_data)
        assert success is True
        
        # Recupera snapshot
        snapshot = temp_event_store.get_snapshot("test_123", "article_generation")
        assert snapshot is not None
        assert snapshot['snapshot_data'] == snapshot_data
        assert snapshot['version'] == 1
    
    def test_metrics(self, temp_event_store):
        """Testa métricas do event store"""
        # Cria evento
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        # Armazena e recupera evento
        temp_event_store.store_event(event)
        temp_event_store.get_events("test_123", "article_generation")
        
        # Verifica métricas
        metrics = temp_event_store.get_metrics()
        assert metrics['total_events_stored'] == 1
        assert metrics['total_events_retrieved'] == 1
        assert 'registered_events' in metrics


class TestEventPublisher:
    """Testes para event publisher"""
    
    @pytest.fixture
    def temp_event_store(self):
        """Event store temporário para testes"""
        temp_dir = tempfile.mkdtemp()
        store = EventStore(storage_path=temp_dir)
        yield store
        shutil.rmtree(temp_dir)
    
    def test_event_publisher_creation(self, temp_event_store):
        """Testa criação do event publisher"""
        publisher = EventPublisher(temp_event_store)
        assert publisher.event_store == temp_event_store
        assert len(publisher.subscribers) == 0
    
    def test_event_publisher_subscription(self, temp_event_store):
        """Testa subscrição de callbacks"""
        publisher = EventPublisher(temp_event_store)
        
        # Mock callback
        callback = Mock()
        publisher.subscribe(callback)
        
        assert len(publisher.subscribers) == 1
        assert callback in publisher.subscribers
    
    def test_event_publisher_publish(self, temp_event_store):
        """Testa publicação de evento"""
        publisher = EventPublisher(temp_event_store)
        
        # Mock callback
        callback = Mock()
        publisher.subscribe(callback)
        
        # Cria e publica evento
        event = ArticleGenerationStartedEvent(
            aggregate_id="test_123",
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        
        publisher.publish(event)
        
        # Verifica se callback foi chamado
        callback.assert_called_once_with(event)
        
        # Verifica se evento foi armazenado
        events = temp_event_store.get_events("test_123", "article_generation")
        assert len(events) == 1
        assert events[0].event_id == event.event_id
    
    def test_event_publisher_batch_publish(self, temp_event_store):
        """Testa publicação em lote"""
        publisher = EventPublisher(temp_event_store)
        
        # Mock callback
        callback = Mock()
        publisher.subscribe(callback)
        
        # Cria múltiplos eventos
        events = []
        for i in range(3):
            event = ArticleGenerationStartedEvent(
                aggregate_id=f"test_{i}",
                config=Mock(spec=GenerationConfig),
                prompt=Mock(spec=PromptInput)
            )
            events.append(event)
        
        # Publica em lote
        publisher.publish_batch(events)
        
        # Verifica se callback foi chamado para cada evento
        assert callback.call_count == 3


class TestEventSourcingIntegration:
    """Testes de integração do event sourcing"""
    
    @pytest.fixture
    def temp_event_store(self):
        """Event store temporário para testes"""
        temp_dir = tempfile.mkdtemp()
        store = EventStore(storage_path=temp_dir)
        yield store
        shutil.rmtree(temp_dir)
    
    def test_complete_event_flow(self, temp_event_store):
        """Testa fluxo completo de eventos"""
        publisher = EventPublisher(temp_event_store)
        
        # Simula fluxo completo de geração de artigo
        aggregate_id = "gen_123"
        
        # 1. Início da geração
        started_event = ArticleGenerationStartedEvent(
            aggregate_id=aggregate_id,
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        )
        publisher.publish(started_event)
        
        # 2. Conclusão da geração
        completed_event = ArticleGenerationCompletedEvent(
            aggregate_id=aggregate_id,
            article_output=Mock(spec=ArticleOutput),
            generation_time=5.5,
            model_used="gpt-4o"
        )
        publisher.publish(completed_event)
        
        # Recupera eventos
        events = temp_event_store.get_events(aggregate_id, "article_generation")
        assert len(events) == 2
        assert events[0].event_type == EventType.ARTICLE_GENERATION_STARTED.value
        assert events[1].event_type == EventType.ARTICLE_GENERATION_COMPLETED.value
    
    def test_event_replay(self, temp_event_store):
        """Testa replay de eventos"""
        # Cria sequência de eventos
        events = []
        aggregate_id = "replay_123"
        
        # Evento 1: Início
        events.append(ArticleGenerationStartedEvent(
            aggregate_id=aggregate_id,
            config=Mock(spec=GenerationConfig),
            prompt=Mock(spec=PromptInput)
        ))
        
        # Evento 2: Cache miss
        events.append(CacheMissEvent(
            aggregate_id=aggregate_id,
            cache_key="prompt_hash",
            cache_type="memory",
            reason="not_found"
        ))
        
        # Evento 3: Retry
        events.append(RetryAttemptedEvent(
            aggregate_id=aggregate_id,
            operation="api_call",
            attempt_number=1,
            max_attempts=3,
            delay_seconds=1.0,
            error_message="Timeout"
        ))
        
        # Evento 4: Conclusão
        events.append(ArticleGenerationCompletedEvent(
            aggregate_id=aggregate_id,
            article_output=Mock(spec=ArticleOutput),
            generation_time=10.0,
            model_used="gpt-4o"
        ))
        
        # Armazena eventos
        for event in events:
            temp_event_store.store_event(event)
        
        # Replay dos eventos
        replayed_events = temp_event_store.get_events(aggregate_id, "article_generation")
        assert len(replayed_events) == 4
        
        # Verifica sequência
        assert replayed_events[0].event_type == EventType.ARTICLE_GENERATION_STARTED.value
        assert replayed_events[1].event_type == EventType.CACHE_MISS.value
        assert replayed_events[2].event_type == EventType.RETRY_ATTEMPTED.value
        assert replayed_events[3].event_type == EventType.ARTICLE_GENERATION_COMPLETED.value
    
    def test_global_instances(self):
        """Testa instâncias globais"""
        # Testa event store global
        store = get_event_store()
        assert isinstance(store, EventStore)
        
        # Testa event publisher global
        publisher = get_event_publisher()
        assert isinstance(publisher, EventPublisher)
        
        # Verifica se são as mesmas instâncias
        store2 = get_event_store()
        assert store is store2
        
        publisher2 = get_event_publisher()
        assert publisher is publisher2 