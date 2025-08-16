"""
Article Events Implementation - IMP-013

Prompt: Event Sourcing - IMP-013
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T21:30:00Z
Tracing ID: ENTERPRISE_20250127_013

Eventos específicos para geração de artigos baseados no código real:
- Eventos de geração (started, completed, failed)
- Eventos de validação de prompts
- Eventos de cache
- Eventos de retry
- Eventos de pipeline
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .base_event import BaseEvent, EventType, EventFactory
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput


# ============================================================================
# EVENTOS DE GERAÇÃO DE ARTIGOS
# ============================================================================

class ArticleGenerationStartedEvent(BaseEvent):
    """Evento disparado quando a geração de artigo é iniciada"""
    
    def __init__(
        self,
        aggregate_id: str,
        config: GenerationConfig,
        prompt: PromptInput,
        variation: int = 0,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="article_generation",
            event_type=EventType.ARTICLE_GENERATION_STARTED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            config=config,
            prompt=prompt,
            variation=variation,
            started_at=datetime.utcnow()
        )


class ArticleGenerationCompletedEvent(BaseEvent):
    """Evento disparado quando a geração de artigo é concluída com sucesso"""
    
    def __init__(
        self,
        aggregate_id: str,
        article_output: ArticleOutput,
        generation_time: float,
        model_used: str,
        tokens_used: Optional[int] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="article_generation",
            event_type=EventType.ARTICLE_GENERATION_COMPLETED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            article_output=article_output,
            generation_time=generation_time,
            model_used=model_used,
            tokens_used=tokens_used,
            completed_at=datetime.utcnow()
        )


class ArticleGenerationFailedEvent(BaseEvent):
    """Evento disparado quando a geração de artigo falha"""
    
    def __init__(
        self,
        aggregate_id: str,
        error_message: str,
        error_type: str,
        generation_time: Optional[float] = None,
        model_used: Optional[str] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="article_generation",
            event_type=EventType.ARTICLE_GENERATION_FAILED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            error_message=error_message,
            error_type=error_type,
            generation_time=generation_time,
            model_used=model_used,
            failed_at=datetime.utcnow()
        )


# ============================================================================
# EVENTOS DE VALIDAÇÃO DE PROMPTS
# ============================================================================

class PromptValidationStartedEvent(BaseEvent):
    """Evento disparado quando a validação de prompt é iniciada"""
    
    def __init__(
        self,
        aggregate_id: str,
        prompt_text: str,
        validation_rules: List[str],
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="prompt_validation",
            event_type=EventType.PROMPT_VALIDATION_STARTED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            prompt_text=prompt_text,
            validation_rules=validation_rules,
            started_at=datetime.utcnow()
        )


class PromptValidationCompletedEvent(BaseEvent):
    """Evento disparado quando a validação de prompt é concluída com sucesso"""
    
    def __init__(
        self,
        aggregate_id: str,
        is_valid: bool,
        validation_results: Dict[str, bool],
        estimated_tokens: Optional[int] = None,
        suggestions: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="prompt_validation",
            event_type=EventType.PROMPT_VALIDATION_COMPLETED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            is_valid=is_valid,
            validation_results=validation_results,
            estimated_tokens=estimated_tokens,
            suggestions=suggestions,
            completed_at=datetime.utcnow()
        )


class PromptValidationFailedEvent(BaseEvent):
    """Evento disparado quando a validação de prompt falha"""
    
    def __init__(
        self,
        aggregate_id: str,
        error_message: str,
        validation_errors: List[str],
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="prompt_validation",
            event_type=EventType.PROMPT_VALIDATION_FAILED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            error_message=error_message,
            validation_errors=validation_errors,
            failed_at=datetime.utcnow()
        )


# ============================================================================
# EVENTOS DE CACHE
# ============================================================================

class CacheHitEvent(BaseEvent):
    """Evento disparado quando há hit no cache"""
    
    def __init__(
        self,
        aggregate_id: str,
        cache_key: str,
        cache_type: str,
        response_time: float,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="cache",
            event_type=EventType.CACHE_HIT,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            cache_key=cache_key,
            cache_type=cache_type,
            response_time=response_time,
            occurred_at=datetime.utcnow()
        )


class CacheMissEvent(BaseEvent):
    """Evento disparado quando há miss no cache"""
    
    def __init__(
        self,
        aggregate_id: str,
        cache_key: str,
        cache_type: str,
        reason: str,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="cache",
            event_type=EventType.CACHE_MISS,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            cache_key=cache_key,
            cache_type=cache_type,
            reason=reason,
            occurred_at=datetime.utcnow()
        )


class CacheSetEvent(BaseEvent):
    """Evento disparado quando um item é armazenado no cache"""
    
    def __init__(
        self,
        aggregate_id: str,
        cache_key: str,
        cache_type: str,
        ttl: Optional[int] = None,
        size_bytes: Optional[int] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="cache",
            event_type=EventType.CACHE_SET,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            cache_key=cache_key,
            cache_type=cache_type,
            ttl=ttl,
            size_bytes=size_bytes,
            occurred_at=datetime.utcnow()
        )


class CacheInvalidatedEvent(BaseEvent):
    """Evento disparado quando um item é invalidado no cache"""
    
    def __init__(
        self,
        aggregate_id: str,
        cache_key: str,
        cache_type: str,
        invalidation_reason: str,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="cache",
            event_type=EventType.CACHE_INVALIDATED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            cache_key=cache_key,
            cache_type=cache_type,
            invalidation_reason=invalidation_reason,
            occurred_at=datetime.utcnow()
        )


# ============================================================================
# EVENTOS DE RETRY
# ============================================================================

class RetryAttemptedEvent(BaseEvent):
    """Evento disparado quando uma tentativa de retry é feita"""
    
    def __init__(
        self,
        aggregate_id: str,
        operation: str,
        attempt_number: int,
        max_attempts: int,
        delay_seconds: float,
        error_message: str,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="retry",
            event_type=EventType.RETRY_ATTEMPTED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            operation=operation,
            attempt_number=attempt_number,
            max_attempts=max_attempts,
            delay_seconds=delay_seconds,
            error_message=error_message,
            occurred_at=datetime.utcnow()
        )


class RetrySucceededEvent(BaseEvent):
    """Evento disparado quando um retry é bem-sucedido"""
    
    def __init__(
        self,
        aggregate_id: str,
        operation: str,
        final_attempt_number: int,
        total_time: float,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="retry",
            event_type=EventType.RETRY_SUCCEEDED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            operation=operation,
            final_attempt_number=final_attempt_number,
            total_time=total_time,
            occurred_at=datetime.utcnow()
        )


class RetryFailedEvent(BaseEvent):
    """Evento disparado quando um retry falha após todas as tentativas"""
    
    def __init__(
        self,
        aggregate_id: str,
        operation: str,
        total_attempts: int,
        total_time: float,
        final_error_message: str,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="retry",
            event_type=EventType.RETRY_FAILED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            operation=operation,
            total_attempts=total_attempts,
            total_time=total_time,
            final_error_message=final_error_message,
            occurred_at=datetime.utcnow()
        )


# ============================================================================
# EVENTOS DE PIPELINE
# ============================================================================

class PipelineStartedEvent(BaseEvent):
    """Evento disparado quando um pipeline é iniciado"""
    
    def __init__(
        self,
        aggregate_id: str,
        pipeline_type: str,
        config: GenerationConfig,
        total_prompts: int,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="pipeline",
            event_type=EventType.PIPELINE_STARTED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            pipeline_type=pipeline_type,
            config=config,
            total_prompts=total_prompts,
            started_at=datetime.utcnow()
        )


class PipelineCompletedEvent(BaseEvent):
    """Evento disparado quando um pipeline é concluído com sucesso"""
    
    def __init__(
        self,
        aggregate_id: str,
        pipeline_type: str,
        total_articles: int,
        successful_articles: int,
        failed_articles: int,
        total_time: float,
        zip_path: Optional[str] = None,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="pipeline",
            event_type=EventType.PIPELINE_COMPLETED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            pipeline_type=pipeline_type,
            total_articles=total_articles,
            successful_articles=successful_articles,
            failed_articles=failed_articles,
            total_time=total_time,
            zip_path=zip_path,
            completed_at=datetime.utcnow()
        )


class PipelineFailedEvent(BaseEvent):
    """Evento disparado quando um pipeline falha"""
    
    def __init__(
        self,
        aggregate_id: str,
        pipeline_type: str,
        error_message: str,
        error_type: str,
        completed_articles: int,
        total_time: float,
        trace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None
    ):
        super().__init__(
            aggregate_id=aggregate_id,
            aggregate_type="pipeline",
            event_type=EventType.PIPELINE_FAILED,
            trace_id=trace_id,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            pipeline_type=pipeline_type,
            error_message=error_message,
            error_type=error_type,
            completed_articles=completed_articles,
            total_time=total_time,
            failed_at=datetime.utcnow()
        )


# ============================================================================
# REGISTRO DE EVENTOS
# ============================================================================

def register_article_events():
    """Registra todos os eventos de artigos no factory"""
    events = [
        # Eventos de geração
        (EventType.ARTICLE_GENERATION_STARTED, ArticleGenerationStartedEvent),
        (EventType.ARTICLE_GENERATION_COMPLETED, ArticleGenerationCompletedEvent),
        (EventType.ARTICLE_GENERATION_FAILED, ArticleGenerationFailedEvent),
        
        # Eventos de validação
        (EventType.PROMPT_VALIDATION_STARTED, PromptValidationStartedEvent),
        (EventType.PROMPT_VALIDATION_COMPLETED, PromptValidationCompletedEvent),
        (EventType.PROMPT_VALIDATION_FAILED, PromptValidationFailedEvent),
        
        # Eventos de cache
        (EventType.CACHE_HIT, CacheHitEvent),
        (EventType.CACHE_MISS, CacheMissEvent),
        (EventType.CACHE_SET, CacheSetEvent),
        (EventType.CACHE_INVALIDATED, CacheInvalidatedEvent),
        
        # Eventos de retry
        (EventType.RETRY_ATTEMPTED, RetryAttemptedEvent),
        (EventType.RETRY_SUCCEEDED, RetrySucceededEvent),
        (EventType.RETRY_FAILED, RetryFailedEvent),
        
        # Eventos de pipeline
        (EventType.PIPELINE_STARTED, PipelineStartedEvent),
        (EventType.PIPELINE_COMPLETED, PipelineCompletedEvent),
        (EventType.PIPELINE_FAILED, PipelineFailedEvent),
    ]
    
    for event_type, event_class in events:
        EventFactory.register_event(event_type, event_class)


# Registra eventos automaticamente quando o módulo é importado
register_article_events() 