"""
Gerador Integrado - Omni Writer
===============================

Combina todos os sistemas críticos:
- Paralelismo controlado na geração
- Cache inteligente avançado
- Sistema de retry inteligente
- Validação de prompts avançada

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
import os

from .parallel_generator import ParallelArticleGenerator
from .intelligent_cache import IntelligentCache
from .smart_retry import SmartRetry
from .prompt_validator import PromptValidator, ValidationResult

logger = logging.getLogger("domain.integrated_generator")

class IntegratedArticleGenerator:
    """
    Gerador integrado que combina todos os sistemas críticos
    """
    
    def __init__(self, session, output_dir="output", max_workers=5, cache_size_mb=100):
        self.session = session
        self.output_dir = output_dir
        
        # Inicializa componentes
        self.parallel_generator = ParallelArticleGenerator(session, output_dir, max_workers)
        self.cache = IntelligentCache(cache_size_mb, "cache")
        self.retry_system = SmartRetry()
        self.validator = PromptValidator()
        
        # Métricas integradas
        self.integrated_metrics = {
            'total_generations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'validation_passed': 0,
            'validation_failed': 0,
            'retry_attempts': 0,
            'parallel_executions': 0,
            'total_time_saved': 0.0,
            'cost_saved': 0.0
        }
        
        logger.info("IntegratedArticleGenerator inicializado com todos os sistemas críticos")
    
    def generate_for_categoria_integrated(self, categoria_id: int, semana: str = None, 
                                        validate_prompts: bool = True) -> Dict[str, Any]:
        """
        Gera artigos para uma categoria usando todos os sistemas integrados
        """
        start_time = time.time()
        
        try:
            from omni_writer.domain.models import Categoria
            
            # Busca categoria
            categoria = self.session.query(Categoria).get(categoria_id)
            if not categoria or not categoria.prompt_path:
                raise ValueError("Categoria inválida ou sem prompt associado")
            
            # Valida prompt se solicitado
            if validate_prompts:
                validation_result = self._validate_categoria_prompt(categoria)
                if not validation_result.is_valid:
                    logger.warning(f"Validação de prompt falhou para categoria {categoria_id}")
                    self.integrated_metrics['validation_failed'] += 1
                else:
                    self.integrated_metrics['validation_passed'] += 1
            
            # Tenta buscar do cache primeiro
            cache_key = self._generate_cache_key_for_categoria(categoria, semana)
            provider = categoria.ia_provider or 'openai'
            cached_result = self.cache.get(cache_key, provider, 'gpt-4o')
            
            if cached_result:
                logger.info(f"Resultado encontrado no cache para categoria {categoria_id}")
                self.integrated_metrics['cache_hits'] += 1
                self.integrated_metrics['total_time_saved'] += 30.0  # Estimativa de tempo economizado
                return {
                    'categoria_id': categoria_id,
                    'source': 'cache',
                    'content': cached_result,
                    'metrics': self.get_integrated_metrics()
                }
            
            self.integrated_metrics['cache_misses'] += 1
            
            # Executa geração paralela com retry
            logger.info(f"Iniciando geração paralela para categoria {categoria_id}")
            self.integrated_metrics['parallel_executions'] += 1
            
            # Define operação de geração com retry
            def generation_operation():
                return self.parallel_generator.generate_for_categoria_parallel(categoria_id, semana)
            
            # Executa com retry inteligente
            provider = categoria.ia_provider or 'openai'
            result = self.retry_system.execute_with_retry(
                generation_operation, 
                provider
            )
            
            # Armazena no cache
            if result and 'output_path' in result:
                self.cache.set(
                    cache_key,
                    str(result),
                    provider,
                    'gpt-4o'
                )
            
            # Atualiza métricas
            self.integrated_metrics['total_generations'] += 1
            execution_time = time.time() - start_time
            
            return {
                'categoria_id': categoria_id,
                'source': 'generation',
                'result': result,
                'execution_time': execution_time,
                'metrics': self.get_integrated_metrics()
            }
            
        except Exception as e:
            logger.error(f"Erro na geração integrada para categoria {categoria_id}: {e}")
            raise
    
    def generate_for_all_integrated(self, semana: str = None, validate_prompts: bool = True) -> Dict[str, Any]:
        """
        Gera artigos para todas as categorias usando sistema integrado
        """
        start_time = time.time()
        
        from omni_writer.domain.models import Blog, Categoria
        
        blogs = self.session.query(Blog).all()
        results = []
        total_categorias = 0
        successful_categorias = 0
        
        for blog in blogs:
            for categoria in blog.categorias:
                total_categorias += 1
                try:
                    result = self.generate_for_categoria_integrated(
                        categoria.id, 
                        semana=semana, 
                        validate_prompts=validate_prompts
                    )
                    results.append(result)
                    successful_categorias += 1
                    
                except Exception as e:
                    logger.error(f"Erro ao gerar artigos para categoria {categoria.id}: {e}")
                    results.append({
                        'categoria_id': categoria.id,
                        'error': str(e),
                        'success': False
                    })
        
        total_time = time.time() - start_time
        
        return {
            'total_categorias': total_categorias,
            'successful_categorias': successful_categorias,
            'failed_categorias': total_categorias - successful_categorias,
            'total_time': total_time,
            'results': results,
            'metrics': self.get_integrated_metrics()
        }
    
    def _validate_categoria_prompt(self, categoria) -> ValidationResult:
        """
        Valida prompt de uma categoria
        """
        try:
            from shared.prompts.parser_prompt_base_artigos import PromptBaseArtigosParser
            
            parser = PromptBaseArtigosParser(categoria.prompt_path)
            prompt_data = parser.parse()
            
            # Converte para string para validação
            prompt_text = str(prompt_data)
            
            return self.validator.validate_prompt(prompt_text, 'gpt-4o')
            
        except Exception as e:
            logger.error(f"Erro ao validar prompt da categoria {categoria.id}: {e}")
            # Retorna resultado inválido em caso de erro
            from .prompt_validator import ValidationIssue, ValidationLevel
            return ValidationResult(
                is_valid=False,
                issues=[ValidationIssue(
                    level=ValidationLevel.ERROR,
                    field="prompt",
                    message=f"Erro ao validar prompt: {e}",
                    code="VALIDATION_ERROR"
                )]
            )
    
    def _generate_cache_key_for_categoria(self, categoria, semana: str = None) -> str:
        """
        Gera chave de cache para categoria
        """
        import hashlib
        
        semana = semana or datetime.utcnow().strftime("%Y-%W")
        key_data = f"{categoria.id}:{categoria.prompt_path}:{semana}:{categoria.ia_provider}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get_integrated_metrics(self) -> Dict[str, Any]:
        """
        Retorna métricas integradas de todos os sistemas
        """
        return {
            'integrated': self.integrated_metrics.copy(),
            'parallel': self.parallel_generator.get_metrics(),
            'cache': self.cache.get_metrics(),
            'retry': self.retry_system.get_metrics()
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Retorna resumo de performance do sistema integrado
        """
        cache_metrics = self.cache.get_metrics()
        retry_metrics = self.retry_system.get_metrics()
        
        total_requests = cache_metrics.get('total_requests', 0)
        cache_hits = cache_metrics.get('cache_hits', 0)
        cache_miss_ratio = 1 - (cache_hits / max(1, total_requests))
        
        # Calcula economia de tempo
        avg_generation_time = self.parallel_generator.metrics.get('avg_generation_time', 30.0)
        time_saved = cache_hits * avg_generation_time
        
        # Calcula economia de custo
        cost_saved = cache_hits * 0.05  # Estimativa de $0.05 por geração
        
        return {
            'cache_performance': {
                'hit_ratio': cache_metrics.get('hit_ratio', 0.0),
                'miss_ratio': cache_miss_ratio,
                'total_requests': total_requests,
                'cache_hits': cache_hits
            },
            'retry_performance': {
                'total_attempts': retry_metrics.get('total_attempts', 0),
                'success_rate': self._calculate_success_rate(retry_metrics)
            },
            'parallel_performance': {
                'total_generated': self.parallel_generator.metrics.get('total_generated', 0),
                'avg_generation_time': avg_generation_time,
                'concurrent_peak': self.parallel_generator.metrics.get('concurrent_peak', 0)
            },
            'efficiency_metrics': {
                'time_saved_seconds': time_saved,
                'time_saved_hours': time_saved / 3600,
                'cost_saved_usd': cost_saved,
                'efficiency_improvement': self._calculate_efficiency_improvement()
            }
        }
    
    def _calculate_success_rate(self, retry_metrics: Dict) -> float:
        """
        Calcula taxa de sucesso do sistema de retry
        """
        total_attempts = retry_metrics.get('total_attempts', 0)
        if total_attempts == 0:
            return 1.0
        
        successful_attempts = 0
        for provider_metrics in retry_metrics.get('providers', {}).values():
            successful_attempts += provider_metrics.get('successful_attempts', 0)
        
        return successful_attempts / total_attempts
    
    def _calculate_efficiency_improvement(self) -> float:
        """
        Calcula melhoria de eficiência geral
        """
        cache_metrics = self.cache.get_metrics()
        total_requests = cache_metrics.get('total_requests', 0)
        cache_hits = cache_metrics.get('cache_hits', 0)
        
        if total_requests == 0:
            return 0.0
        
        # Eficiência baseada em cache hits e tempo economizado
        cache_efficiency = cache_hits / total_requests
        time_efficiency = min(1.0, self.integrated_metrics['total_time_saved'] / (total_requests * 30))
        
        return (cache_efficiency + time_efficiency) / 2
    
    def warm_cache(self, categoria_ids: List[int]):
        """
        Aquece cache com categorias específicas
        """
        logger.info(f"Aquecendo cache com {len(categoria_ids)} categorias")
        
        for categoria_id in categoria_ids:
            try:
                # Gera conteúdo para aquecer cache
                self.generate_for_categoria_integrated(categoria_id, validate_prompts=False)
                logger.debug(f"Cache aquecido para categoria {categoria_id}")
            except Exception as e:
                logger.error(f"Erro ao aquecer cache para categoria {categoria_id}: {e}")
    
    def clear_all_caches(self):
        """
        Limpa todos os caches
        """
        self.cache.clear()
        self.retry_system.clear_history()
        logger.info("Todos os caches foram limpos")
    
    def reset_all_systems(self):
        """
        Reseta todos os sistemas
        """
        # Reseta circuit breakers
        for provider in ['openai', 'deepseek', 'gemini', 'claude']:
            self.retry_system.reset_circuit_breaker(provider)
        
        # Limpa caches
        self.clear_all_caches()
        
        # Reseta métricas
        self.integrated_metrics = {
            'total_generations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'validation_passed': 0,
            'validation_failed': 0,
            'retry_attempts': 0,
            'parallel_executions': 0,
            'total_time_saved': 0.0,
            'cost_saved': 0.0
        }
        
        logger.info("Todos os sistemas foram resetados")
    
    def shutdown(self):
        """
        Desliga o gerador integrado
        """
        self.parallel_generator.shutdown()
        self.cache.__exit__(None, None, None)
        logger.info("IntegratedArticleGenerator desligado")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown() 