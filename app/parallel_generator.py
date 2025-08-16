"""
Integração de paralelismo controlado com pipeline principal.

Prompt: Otimização de Performance - IMP-006
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:00:00Z
Tracing ID: ENTERPRISE_20250127_006
"""

import asyncio
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os
import uuid

from omni_writer.domain.models import GenerationConfig, PromptInput, ArticleOutput
from omni_writer.domain.parallel_generator import ParallelArticleGenerator, RateLimiter
from app.controller import generate_article
from infraestructure.storage import save_article
from shared.logging_config import get_structured_logger, log_performance_event
from shared.status_repository import update_status

logger = get_structured_logger("app.parallel_generator")


@dataclass
class PipelineTask:
    """Representa uma tarefa de geração no pipeline"""
    task_id: str
    config: GenerationConfig
    prompt: PromptInput
    variation: int = 0
    priority: int = 1
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class PipelineParallelGenerator:
    """
    Gerador paralelo otimizado para pipeline principal.
    Integra com o sistema de paralelismo existente.
    """
    
    def __init__(self, max_workers: int = 5, max_concurrent_per_provider: int = 3):
        self.max_workers = max_workers
        self.max_concurrent_per_provider = max_concurrent_per_provider
        self.rate_limiter = RateLimiter()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks = {}
        self.completed_tasks = []
        self.failed_tasks = []
        self.metrics = {
            'total_generated': 0,
            'total_failed': 0,
            'avg_generation_time': 0.0,
            'concurrent_peak': 0,
            'rate_limit_hits': defaultdict(int),
            'provider_usage': defaultdict(int)
        }
        self.lock = threading.Lock()
        
        logger.info(f"PipelineParallelGenerator inicializado com {max_workers} workers")
        
    def generate_articles_parallel(
        self,
        config: GenerationConfig,
        trace_id: str = None,
        progress_callback: Callable = None
    ) -> List[ArticleOutput]:
        """
        Gera artigos em paralelo usando o pipeline otimizado.
        
        Args:
            config: Configuração de geração
            trace_id: ID de rastreamento
            progress_callback: Callback para atualizar progresso
            
        Returns:
            Lista de artigos gerados
        """
        if not trace_id:
            trace_id = str(uuid.uuid4())
            
        start_time = time.time()
        total_prompts = len(config.prompts)
        
        logger.info(f"Iniciando geração paralela | prompts={total_prompts} | trace_id={trace_id}")
        
        # Cria tarefas para cada prompt
        tasks = []
        for idx, prompt in enumerate(config.prompts):
            task = PipelineTask(
                task_id=f"{trace_id}_{idx}",
                config=config,
                prompt=prompt,
                variation=idx,
                priority=1
            )
            tasks.append(task)
            
        # Executa geração paralela
        results = self._execute_parallel_generation(tasks, trace_id, progress_callback)
        
        # Calcula métricas
        end_time = time.time()
        total_time = end_time - start_time
        avg_time = total_time / len(results) if results else 0
        
        with self.lock:
            self.metrics['total_generated'] += len(results)
            self.metrics['avg_generation_time'] = avg_time
            self.metrics['provider_usage'][config.model_type] += len(results)
            
        # Log de performance
        log_performance_event(
            logger=logger,
            operation="parallel_article_generation",
            duration_ms=total_time * 1000,
            trace_id=trace_id,
            concurrent_workers=self.max_workers,
            total_articles=len(results),
            provider=config.model_type
        )
        
        logger.info(f"Geração paralela concluída | artigos={len(results)} | tempo={total_time:.2f}s | trace_id={trace_id}")
        
        return results
        
    def _execute_parallel_generation(
        self,
        tasks: List[PipelineTask],
        trace_id: str,
        progress_callback: Callable = None
    ) -> List[ArticleOutput]:
        """
        Executa geração paralela com controle de concorrência.
        """
        results = []
        completed_count = 0
        total_tasks = len(tasks)
        
        # Submete tarefas ao executor
        future_to_task = {}
        for task in tasks:
            future = self.executor.submit(self._generate_single_article, task, trace_id)
            future_to_task[future] = task
            
        # Processa resultados conforme completam
        try:
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        completed_count += 1
                        
                        # Atualiza progresso
                        if progress_callback:
                            progress_callback(completed_count, total_tasks)
                            
                        # Log de progresso
                        logger.info(f"Artigo gerado | {completed_count}/{total_tasks} | trace_id={trace_id}")
                        
                except Exception as e:
                    logger.error(f"Erro na geração | task_id={task.task_id} | error={str(e)} | trace_id={trace_id}")
                    with self.lock:
                        self.metrics['total_failed'] += 1
                        self.failed_tasks.append(task)
                        
        except Exception as e:
            logger.error(f"Erro na execução paralela | error={str(e)} | trace_id={trace_id}")
            
        return results
        
    def _generate_single_article(self, task: PipelineTask, trace_id: str) -> Optional[ArticleOutput]:
        """
        Gera um único artigo com controle de rate limiting.
        """
        start_time = time.time()
        provider_name = task.config.model_type
        
        try:
            # Controle de rate limiting
            if not self.rate_limiter.can_proceed(provider_name):
                wait_time = self.rate_limiter.get_wait_time(provider_name)
                if wait_time > 0:
                    logger.info(f"Rate limit atingido | provider={provider_name} | wait={wait_time}s | trace_id={trace_id}")
                    time.sleep(wait_time)
                    
            # Registra início da requisição
            self.rate_limiter.record_request(provider_name)
            
            try:
                # Gera artigo
                article = generate_article(
                    config=task.config,
                    prompt=task.prompt,
                    trace_id=trace_id,
                    variation=task.variation
                )
                
                # Calcula tempo de geração
                generation_time = time.time() - start_time
                
                # Log de performance individual
                log_performance_event(
                    logger=logger,
                    operation="single_article_generation",
                    duration_ms=generation_time * 1000,
                    trace_id=trace_id,
                    provider=provider_name,
                    prompt_length=len(task.prompt.text)
                )
                
                return article
                
            finally:
                # Libera requisição
                self.rate_limiter.release_request(provider_name)
                
        except Exception as e:
            generation_time = time.time() - start_time
            logger.error(f"Erro na geração | task_id={task.task_id} | time={generation_time:.2f}s | error={str(e)} | trace_id={trace_id}")
            
            with self.lock:
                self.metrics['rate_limit_hits'][provider_name] += 1
                
            raise
            
    def get_metrics(self) -> Dict:
        """
        Retorna métricas de performance.
        """
        with self.lock:
            return {
                'total_generated': self.metrics['total_generated'],
                'total_failed': self.metrics['total_failed'],
                'avg_generation_time': self.metrics['avg_generation_time'],
                'concurrent_peak': self.metrics['concurrent_peak'],
                'rate_limit_hits': dict(self.metrics['rate_limit_hits']),
                'provider_usage': dict(self.metrics['provider_usage']),
                'active_workers': len(self.active_tasks),
                'max_workers': self.max_workers
            }
            
    def shutdown(self):
        """
        Desliga o gerador paralelo.
        """
        logger.info("Desligando PipelineParallelGenerator")
        self.executor.shutdown(wait=True)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()


class PerformanceOptimizer:
    """
    Otimizador de performance para pipeline.
    """
    
    def __init__(self):
        self.parallel_generator = None
        self.performance_config = {
            'max_workers': 5,
            'max_concurrent_per_provider': 3,
            'enable_parallel': True,
            'fallback_to_sequential': True
        }
        
    def optimize_pipeline_generation(
        self,
        config: GenerationConfig,
        trace_id: str = None,
        progress_callback: Callable = None
    ) -> List[ArticleOutput]:
        """
        Otimiza geração do pipeline usando paralelismo.
        """
        if not self.performance_config['enable_parallel']:
            return self._sequential_generation(config, trace_id, progress_callback)
            
        try:
            # Inicializa gerador paralelo
            if not self.parallel_generator:
                self.parallel_generator = PipelineParallelGenerator(
                    max_workers=self.performance_config['max_workers'],
                    max_concurrent_per_provider=self.performance_config['max_concurrent_per_provider']
                )
                
            # Executa geração paralela
            return self.parallel_generator.generate_articles_parallel(
                config=config,
                trace_id=trace_id,
                progress_callback=progress_callback
            )
            
        except Exception as e:
            logger.error(f"Erro na geração paralela | fallback para sequencial | error={str(e)} | trace_id={trace_id}")
            
            if self.performance_config['fallback_to_sequential']:
                return self._sequential_generation(config, trace_id, progress_callback)
            else:
                raise
                
    def _sequential_generation(
        self,
        config: GenerationConfig,
        trace_id: str = None,
        progress_callback: Callable = None
    ) -> List[ArticleOutput]:
        """
        Geração sequencial como fallback.
        """
        logger.info(f"Iniciando geração sequencial | trace_id={trace_id}")
        
        results = []
        total_prompts = len(config.prompts)
        
        for idx, prompt in enumerate(config.prompts):
            try:
                article = generate_article(
                    config=config,
                    prompt=prompt,
                    trace_id=trace_id,
                    variation=idx
                )
                results.append(article)
                
                # Atualiza progresso
                if progress_callback:
                    progress_callback(idx + 1, total_prompts)
                    
            except Exception as e:
                logger.error(f"Erro na geração sequencial | prompt={idx} | error={str(e)} | trace_id={trace_id}")
                raise
                
        return results
        
    def get_performance_metrics(self) -> Dict:
        """
        Retorna métricas de performance.
        """
        metrics = {
            'optimizer_config': self.performance_config,
            'parallel_enabled': self.performance_config['enable_parallel']
        }
        
        if self.parallel_generator:
            metrics['parallel_metrics'] = self.parallel_generator.get_metrics()
            
        return metrics
        
    def update_config(self, new_config: Dict):
        """
        Atualiza configuração de performance.
        """
        self.performance_config.update(new_config)
        logger.info(f"Configuração de performance atualizada | config={new_config}")
        
    def shutdown(self):
        """
        Desliga o otimizador.
        """
        if self.parallel_generator:
            self.parallel_generator.shutdown()
            self.parallel_generator = None 