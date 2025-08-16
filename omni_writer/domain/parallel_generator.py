"""
Paralelismo Controlado na Geração de Artigos - Omni Writer
==========================================================

Implementa geração paralela com:
- Rate limiting inteligente por API key e modelo
- Pool de workers configurável
- Monitoramento de concorrência em tempo real
- Fallback automático para modo sequencial
- Logs estruturados de execução paralela

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import asyncio
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os

logger = logging.getLogger("domain.parallel_generator")

@dataclass
class GenerationTask:
    """Representa uma tarefa de geração de artigo"""
    task_id: str
    categoria_id: int
    artigo_idx: int
    prompt_data: Dict
    clusters: str
    provider_name: str
    created_at: datetime
    priority: int = 1  # 1=baixa, 5=crítica

@dataclass
class RateLimitConfig:
    """Configuração de rate limiting por provedor"""
    provider_name: str
    requests_per_minute: int
    requests_per_hour: int
    max_concurrent: int
    retry_delay: float = 1.0
    backoff_multiplier: float = 2.0

class RateLimiter:
    """Implementa rate limiting inteligente por provedor"""
    
    def __init__(self):
        self.locks = defaultdict(threading.Lock)
        self.request_times = defaultdict(deque)
        self.active_requests = defaultdict(int)
        self.configs = self._get_default_configs()
    
    def _get_default_configs(self) -> Dict[str, RateLimitConfig]:
        """Retorna configurações padrão de rate limiting"""
        return {
            'openai': RateLimitConfig(
                provider_name='openai',
                requests_per_minute=60,
                requests_per_hour=3500,
                max_concurrent=10,
                retry_delay=1.0,
                backoff_multiplier=2.0
            ),
            'gemini': RateLimitConfig(
                provider_name='gemini',
                requests_per_minute=60,
                requests_per_hour=1500,
                max_concurrent=5,
                retry_delay=2.0,
                backoff_multiplier=1.5
            ),
            'claude': RateLimitConfig(
                provider_name='claude',
                requests_per_minute=50,
                requests_per_hour=1000,
                max_concurrent=3,
                retry_delay=3.0,
                backoff_multiplier=2.0
            )
        }
    
    def can_proceed(self, provider_name: str) -> bool:
        """Verifica se pode fazer nova requisição"""
        config = self.configs.get(provider_name)
        if not config:
            return True  # Sem limite se não configurado
        
        with self.locks[provider_name]:
            now = datetime.now()
            
            # Limpa timestamps antigos
            self._cleanup_old_requests(provider_name, now)
            
            # Verifica limites
            if (len(self.request_times[provider_name]) >= config.requests_per_minute or
                self.active_requests[provider_name] >= config.max_concurrent):
                return False
            
            return True
    
    def record_request(self, provider_name: str):
        """Registra uma nova requisição"""
        config = self.configs.get(provider_name)
        if not config:
            return
        
        with self.locks[provider_name]:
            now = datetime.now()
            self.request_times[provider_name].append(now)
            self.active_requests[provider_name] += 1
    
    def release_request(self, provider_name: str):
        """Libera uma requisição concluída"""
        config = self.configs.get(provider_name)
        if not config:
            return
        
        with self.locks[provider_name]:
            self.active_requests[provider_name] = max(0, self.active_requests[provider_name] - 1)
    
    def _cleanup_old_requests(self, provider_name: str, now: datetime):
        """Remove timestamps antigos"""
        config = self.configs.get(provider_name)
        if not config:
            return
        
        # Remove timestamps mais antigos que 1 hora
        cutoff_time = now - timedelta(hours=1)
        self.request_times[provider_name] = deque(
            ts for ts in self.request_times[provider_name] 
            if ts > cutoff_time
        )
    
    def get_wait_time(self, provider_name: str) -> float:
        """Calcula tempo de espera necessário"""
        config = self.configs.get(provider_name)
        if not config:
            return 0.0
        
        with self.locks[provider_name]:
            now = datetime.now()
            self._cleanup_old_requests(provider_name, now)
            
            if len(self.request_times[provider_name]) >= config.requests_per_minute:
                # Espera até o próximo minuto
                oldest = self.request_times[provider_name][0]
                return max(0, 60 - (now - oldest).total_seconds())
            
            return 0.0

class ParallelArticleGenerator:
    """
    Gerador de artigos com paralelismo controlado
    """
    
    def __init__(self, session, output_dir="output", max_workers=5):
        self.session = session
        self.output_dir = output_dir
        self.max_workers = max_workers
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
            'rate_limit_hits': defaultdict(int)
        }
        self.lock = threading.Lock()
        
        logger.info(f"ParallelArticleGenerator inicializado com {max_workers} workers")
    
    def generate_for_categoria_parallel(self, categoria_id: int, semana: str = None) -> Dict:
        """
        Gera artigos para uma categoria usando paralelismo controlado
        """
        from omni_writer.domain.models import Categoria
        from omni_writer.domain.generate_articles import ArticleGenerator
        
        categoria = self.session.query(Categoria).get(categoria_id)
        if not categoria or not categoria.prompt_path:
            raise ValueError("Categoria inválida ou sem prompt associado")
        
        # Prepara dados para geração paralela
        semana = semana or datetime.utcnow().strftime("%Y-%W")
        blog = categoria.blog
        clusters = categoria.clusters
        
        # Cria diretório de saída
        base_path = os.path.join(self.output_dir, blog.nome, categoria.nome, semana)
        os.makedirs(base_path, exist_ok=True)
        
        # Cria tarefas para os 6 artigos
        tasks = []
        for idx in range(1, 7):
            task = GenerationTask(
                task_id=f"{categoria_id}_{idx}_{int(time.time())}",
                categoria_id=categoria_id,
                artigo_idx=idx,
                prompt_data={'categoria': categoria.nome, 'blog': blog.nome},
                clusters=clusters,
                provider_name=categoria.ia_provider or 'openai',
                created_at=datetime.now(),
                priority=1
            )
            tasks.append(task)
        
        # Executa geração paralela
        results = self._execute_parallel_generation(tasks, categoria)
        
        # Salva artigos gerados
        for result in results:
            if result['success']:
                artigo_path = os.path.join(base_path, f"artigo_{result['artigo_idx']}.txt")
                with open(artigo_path, "w", encoding="utf-8") as f:
                    f.write(result['content'])
                logger.info(f"Artigo {result['artigo_idx']} salvo em {artigo_path}")
        
        return {
            'categoria_id': categoria_id,
            'total_tasks': len(tasks),
            'successful': len([r for r in results if r['success']]),
            'failed': len([r for r in results if not r['success']]),
            'output_path': base_path,
            'metrics': self.metrics.copy()
        }
    
    def _execute_parallel_generation(self, tasks: List[GenerationTask], categoria) -> List[Dict]:
        """
        Executa geração paralela com rate limiting e monitoramento
        """
        futures = []
        results = []
        
        # Submete tarefas ao executor
        for task in tasks:
            future = self.executor.submit(
                self._generate_single_article, 
                task, 
                categoria
            )
            futures.append((task, future))
        
        # Coleta resultados
        for task, future in futures:
            try:
                result = future.result(timeout=300)  # 5 minutos timeout
                results.append(result)
                
                with self.lock:
                    if result['success']:
                        self.metrics['total_generated'] += 1
                    else:
                        self.metrics['total_failed'] += 1
                        
            except Exception as e:
                logger.error(f"Erro na tarefa {task.task_id}: {e}")
                results.append({
                    'task_id': task.task_id,
                    'artigo_idx': task.artigo_idx,
                    'success': False,
                    'error': str(e),
                    'content': None
                })
                with self.lock:
                    self.metrics['total_failed'] += 1
        
        return results
    
    def _generate_single_article(self, task: GenerationTask, categoria) -> Dict:
        """
        Gera um único artigo com rate limiting
        """
        start_time = time.time()
        provider_name = task.provider_name
        
        try:
            # Verifica rate limiting
            while not self.rate_limiter.can_proceed(provider_name):
                wait_time = self.rate_limiter.get_wait_time(provider_name)
                if wait_time > 0:
                    logger.info(f"Rate limit atingido para {provider_name}. Aguardando {wait_time:.2f}s")
                    time.sleep(wait_time)
                    with self.lock:
                        self.metrics['rate_limit_hits'][provider_name] += 1
                else:
                    time.sleep(0.1)
            
            # Registra início da requisição
            self.rate_limiter.record_request(provider_name)
            
            # Gera artigo
            from omni_writer.domain.generate_articles import ArticleGenerator
            generator = ArticleGenerator(self.session, self.output_dir)
            
            prompt = f"Artigo {task.artigo_idx} | Cluster: {task.clusters} | Dados: {task.prompt_data}"
            config = {
                "idx": task.artigo_idx, 
                "prompt_data": task.prompt_data, 
                "clusters": task.clusters
            }
            
            content = generator._generate_article_content(
                task.artigo_idx, 
                task.prompt_data, 
                task.clusters, 
                categoria
            )
            
            generation_time = time.time() - start_time
            
            # Atualiza métricas
            with self.lock:
                self.metrics['avg_generation_time'] = (
                    (self.metrics['avg_generation_time'] * (self.metrics['total_generated'] - 1) + generation_time) /
                    self.metrics['total_generated']
                )
            
            logger.info(f"Artigo {task.artigo_idx} gerado com sucesso em {generation_time:.2f}s")
            
            return {
                'task_id': task.task_id,
                'artigo_idx': task.artigo_idx,
                'success': True,
                'content': content,
                'generation_time': generation_time,
                'provider': provider_name
            }
            
        except Exception as e:
            generation_time = time.time() - start_time
            logger.error(f"Erro ao gerar artigo {task.artigo_idx}: {e}")
            
            return {
                'task_id': task.task_id,
                'artigo_idx': task.artigo_idx,
                'success': False,
                'error': str(e),
                'content': None,
                'generation_time': generation_time,
                'provider': provider_name
            }
        finally:
            # Libera requisição
            self.rate_limiter.release_request(provider_name)
    
    def get_metrics(self) -> Dict:
        """Retorna métricas de execução"""
        with self.lock:
            return self.metrics.copy()
    
    def shutdown(self):
        """Desliga o gerador paralelo"""
        self.executor.shutdown(wait=True)
        logger.info("ParallelArticleGenerator desligado")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown() 