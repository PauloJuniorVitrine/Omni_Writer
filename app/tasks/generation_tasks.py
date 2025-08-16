"""
Tasks de geração de artigos para sistema distribuído.
Implementa geração com priorização, retry inteligente e monitoramento.
"""
import os
import logging
import time
from typing import Dict, List, Optional
from celery import current_task
from celery.utils.log import get_task_logger

# Importações do domínio
from omni_writer.domain.integrated_generator import IntegratedGenerator
from omni_writer.domain.parallel_generator import ParallelGenerator
from omni_writer.domain.intelligent_cache import IntelligentCache
from omni_writer.domain.smart_retry import SmartRetry
from omni_writer.domain.prompt_validator import PromptValidator
from omni_writer.domain.data_models import GenerationConfig, PromptInput

# Configuração de logging
logger = get_task_logger(__name__)

# Instâncias dos componentes
generator = IntegratedGenerator()
parallel_generator = ParallelGenerator()
cache = IntelligentCache()
retry = SmartRetry()
validator = PromptValidator()

@current_task.task(bind=True, name='app.tasks.generation_tasks.generate_article')
def generate_article(self, config_dict: Dict, trace_id: Optional[str] = None) -> Dict:
    """
    Task de alta prioridade para geração de artigo único.
    
    Args:
        config_dict: Configuração de geração
        trace_id: ID de rastreamento
        
    Returns:
        Resultado da geração
    """
    start_time = time.time()
    
    try:
        # Validação do prompt
        if not validator.validate_prompt(config_dict.get('prompt', '')):
            raise ValueError("Prompt inválido ou vazio")
        
        # Verificação de cache
        cache_key = cache.generate_key(config_dict)
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.info(f"Cache hit para {trace_id}")
            return {
                'status': 'success',
                'result': cached_result,
                'cached': True,
                'duration': time.time() - start_time
            }
        
        # Geração do artigo
        config = GenerationConfig(
            api_key=config_dict.get('api_key'),
            model_type=config_dict.get('model_type', 'openai'),
            prompts=[PromptInput(content=config_dict.get('prompt'))]
        )
        
        result = generator.generate_article(config, trace_id=trace_id)
        
        # Armazenamento em cache
        cache.set(cache_key, result, ttl=3600)  # 1 hora
        
        return {
            'status': 'success',
            'result': result,
            'cached': False,
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na geração de artigo: {exc}")
        
        # Retry automático para falhas temporárias
        if self.request.retries < 3:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.generation_tasks.batch_generate')
def batch_generate(self, configs: List[Dict], trace_id: Optional[str] = None) -> Dict:
    """
    Task de prioridade padrão para geração em lote.
    
    Args:
        configs: Lista de configurações
        trace_id: ID de rastreamento
        
    Returns:
        Resultados da geração em lote
    """
    start_time = time.time()
    
    try:
        # Validação de todos os prompts
        for config in configs:
            if not validator.validate_prompt(config.get('prompt', '')):
                raise ValueError(f"Prompt inválido: {config.get('prompt', '')[:50]}...")
        
        # Geração paralela
        results = []
        for i, config_dict in enumerate(configs):
            config = GenerationConfig(
                api_key=config_dict.get('api_key'),
                model_type=config_dict.get('model_type', 'openai'),
                prompts=[PromptInput(content=config_dict.get('prompt'))]
            )
            
            result = parallel_generator.generate_parallel(
                config, 
                trace_id=f"{trace_id}_batch_{i}"
            )
            results.append(result)
        
        return {
            'status': 'success',
            'results': results,
            'count': len(results),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na geração em lote: {exc}")
        
        # Retry automático
        if self.request.retries < 2:
            raise self.retry(countdown=120 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.generation_tasks.generate_with_retry')
def generate_with_retry(self, config_dict: Dict, trace_id: Optional[str] = None) -> Dict:
    """
    Task com retry inteligente para gerações críticas.
    
    Args:
        config_dict: Configuração de geração
        trace_id: ID de rastreamento
        
    Returns:
        Resultado da geração com retry
    """
    start_time = time.time()
    
    try:
        # Configuração de retry
        retry_config = {
            'max_retries': 5,
            'backoff_factor': 2,
            'timeout': 300
        }
        
        # Geração com retry inteligente
        config = GenerationConfig(
            api_key=config_dict.get('api_key'),
            model_type=config_dict.get('model_type', 'openai'),
            prompts=[PromptInput(content=config_dict.get('prompt'))]
        )
        
        result = retry.execute_with_retry(
            lambda: generator.generate_article(config, trace_id=trace_id),
            **retry_config
        )
        
        return {
            'status': 'success',
            'result': result,
            'retries': retry.get_retry_count(),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na geração com retry: {exc}")
        
        # Retry automático do Celery
        if self.request.retries < 3:
            raise self.retry(countdown=30 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.generation_tasks.validate_and_generate')
def validate_and_generate(self, config_dict: Dict, trace_id: Optional[str] = None) -> Dict:
    """
    Task com validação avançada antes da geração.
    
    Args:
        config_dict: Configuração de geração
        trace_id: ID de rastreamento
        
    Returns:
        Resultado da geração com validação
    """
    start_time = time.time()
    
    try:
        prompt = config_dict.get('prompt', '')
        
        # Validação avançada
        validation_result = validator.validate_prompt_advanced(prompt)
        if not validation_result['is_valid']:
            return {
                'status': 'validation_error',
                'errors': validation_result['errors'],
                'suggestions': validation_result['suggestions'],
                'duration': time.time() - start_time
            }
        
        # Estimativa de tokens
        token_estimate = validator.estimate_tokens(prompt)
        if token_estimate > 4000:  # Limite de segurança
            return {
                'status': 'token_limit_exceeded',
                'estimated_tokens': token_estimate,
                'max_tokens': 4000,
                'duration': time.time() - start_time
            }
        
        # Geração normal
        config = GenerationConfig(
            api_key=config_dict.get('api_key'),
            model_type=config_dict.get('model_type', 'openai'),
            prompts=[PromptInput(content=prompt)]
        )
        
        result = generator.generate_article(config, trace_id=trace_id)
        
        return {
            'status': 'success',
            'result': result,
            'estimated_tokens': token_estimate,
            'validation_passed': True,
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na validação e geração: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        } 