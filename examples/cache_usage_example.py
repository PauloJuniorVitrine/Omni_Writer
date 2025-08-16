#!/usr/bin/env python3
"""
Exemplo de Uso do Sistema de Cache Inteligente - Omni Writer

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import time
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Importa componentes do cache
from shared.cache_manager import get_cache_manager, CacheType, cache_get, cache_set
from shared.cache_config import CacheConfig, CacheStrategy
from shared.intelligent_cache import cached

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ArticleGenerationService:
    """
    Serviço de geração de artigos que demonstra o uso do cache.
    """
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
        self.generation_count = 0
    
    def generate_article(self, topic: str, language: str = 'pt-BR') -> Dict:
        """
        Gera um artigo sobre um tópico específico.
        Usa cache para evitar regeneração desnecessária.
        """
        # Chave única para o cache
        cache_key = f"{topic}_{language}"
        
        # Tenta obter do cache primeiro
        cached_article = self.cache_manager.get(
            CacheType.ARTICLE_CONTENT, 
            cache_key
        )
        
        if cached_article:
            logger.info(f"Artigo encontrado no cache: {topic}")
            return cached_article
        
        # Simula geração cara do artigo
        logger.info(f"Gerando novo artigo: {topic}")
        time.sleep(2)  # Simula processamento
        
        article = {
            'id': f"art_{self.generation_count}",
            'topic': topic,
            'language': language,
            'content': f"Artigo sobre {topic} em {language}",
            'generated_at': datetime.now().isoformat(),
            'word_count': len(topic.split()) * 100
        }
        
        self.generation_count += 1
        
        # Armazena no cache
        self.cache_manager.set(
            CacheType.ARTICLE_CONTENT,
            cache_key,
            article,
            ttl=14400  # 4 horas
        )
        
        return article
    
    def get_generation_status(self, trace_id: str) -> Optional[Dict]:
        """
        Obtém status de uma geração em andamento.
        """
        return self.cache_manager.get(CacheType.GENERATION_STATUS, trace_id)
    
    def update_generation_status(self, trace_id: str, status: Dict):
        """
        Atualiza status de uma geração.
        """
        self.cache_manager.set(CacheType.GENERATION_STATUS, trace_id, status)
    
    def export_articles(self, article_ids: List[str]) -> Dict:
        """
        Exporta artigos para arquivo.
        Usa cache para evitar re-exportação.
        """
        # Chave baseada nos IDs dos artigos
        cache_key = f"export_{'_'.join(sorted(article_ids))}"
        
        # Verifica cache de exportação
        cached_export = self.cache_manager.get(CacheType.EXPORT_CACHE, cache_key)
        if cached_export:
            logger.info("Exportação encontrada no cache")
            return cached_export
        
        # Simula exportação cara
        logger.info("Realizando nova exportação")
        time.sleep(3)  # Simula processamento
        
        export_data = {
            'export_id': f"exp_{int(time.time())}",
            'article_ids': article_ids,
            'file_path': f"/exports/export_{int(time.time())}.zip",
            'created_at': datetime.now().isoformat(),
            'file_size_mb': len(article_ids) * 2.5
        }
        
        # Armazena no cache
        self.cache_manager.set(CacheType.EXPORT_CACHE, cache_key, export_data)
        
        return export_data


class UserPreferencesService:
    """
    Serviço de preferências do usuário com cache criptografado.
    """
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
    
    def get_user_preferences(self, user_id: str) -> Dict:
        """
        Obtém preferências do usuário.
        """
        preferences = self.cache_manager.get(CacheType.USER_PREFERENCES, user_id)
        
        if preferences:
            return preferences
        
        # Preferências padrão
        default_preferences = {
            'theme': 'light',
            'language': 'pt-BR',
            'notifications_enabled': True,
            'auto_save': True
        }
        
        # Armazena preferências padrão
        self.cache_manager.set(CacheType.USER_PREFERENCES, user_id, default_preferences)
        
        return default_preferences
    
    def update_user_preferences(self, user_id: str, preferences: Dict):
        """
        Atualiza preferências do usuário.
        """
        self.cache_manager.set(CacheType.USER_PREFERENCES, user_id, preferences)


class APICacheService:
    """
    Serviço que demonstra cache de respostas de API.
    """
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
    
    @cached('api_responses', ttl=1800)  # 30 minutos
    def fetch_external_data(self, endpoint: str, params: Dict = None) -> Dict:
        """
        Busca dados de API externa com cache automático.
        """
        # Simula chamada de API cara
        logger.info(f"Chamando API externa: {endpoint}")
        time.sleep(1)  # Simula latência de rede
        
        return {
            'endpoint': endpoint,
            'params': params or {},
            'data': f"Dados de {endpoint}",
            'timestamp': datetime.now().isoformat()
        }
    
    def get_cached_data(self, key: str) -> Optional[Dict]:
        """
        Obtém dados do cache de API.
        """
        return self.cache_manager.get(CacheType.API_RESPONSES, key)


class MetricsService:
    """
    Serviço de métricas com cache de curta duração.
    """
    
    def __init__(self):
        self.cache_manager = get_cache_manager()
    
    def get_system_metrics(self) -> Dict:
        """
        Obtém métricas do sistema.
        """
        cache_key = "system_metrics"
        
        metrics = self.cache_manager.get(CacheType.METRICS, cache_key)
        if metrics:
            return metrics
        
        # Simula coleta de métricas cara
        logger.info("Coletando métricas do sistema")
        time.sleep(0.5)
        
        system_metrics = {
            'cpu_usage': 45.2,
            'memory_usage': 67.8,
            'disk_usage': 23.1,
            'active_connections': 125,
            'timestamp': datetime.now().isoformat()
        }
        
        # Cache de curta duração (5 minutos)
        self.cache_manager.set(CacheType.METRICS, cache_key, system_metrics, ttl=300)
        
        return system_metrics


def demonstrate_cache_workflow():
    """
    Demonstra workflow completo do sistema de cache.
    """
    logger.info("=== Demonstração do Sistema de Cache Inteligente ===")
    
    # Inicializa serviços
    article_service = ArticleGenerationService()
    user_service = UserPreferencesService()
    api_service = APICacheService()
    metrics_service = MetricsService()
    
    # 1. Demonstração de geração de artigos
    logger.info("\n1. Geração de Artigos:")
    
    # Primeira geração (cache miss)
    article1 = article_service.generate_article("Inteligência Artificial")
    logger.info(f"Artigo gerado: {article1['id']}")
    
    # Segunda geração do mesmo tópico (cache hit)
    article1_cached = article_service.generate_article("Inteligência Artificial")
    logger.info(f"Artigo do cache: {article1_cached['id']}")
    
    # Novo tópico (cache miss)
    article2 = article_service.generate_article("Machine Learning")
    logger.info(f"Novo artigo: {article2['id']}")
    
    # 2. Demonstração de status de geração
    logger.info("\n2. Status de Geração:")
    
    trace_id = "trace_12345"
    status = {
        'status': 'processing',
        'progress': 50,
        'started_at': datetime.now().isoformat()
    }
    
    article_service.update_generation_status(trace_id, status)
    retrieved_status = article_service.get_generation_status(trace_id)
    logger.info(f"Status recuperado: {retrieved_status}")
    
    # 3. Demonstração de exportação
    logger.info("\n3. Exportação de Artigos:")
    
    article_ids = [article1['id'], article2['id']]
    
    # Primeira exportação (cache miss)
    export1 = article_service.export_articles(article_ids)
    logger.info(f"Exportação criada: {export1['export_id']}")
    
    # Segunda exportação dos mesmos artigos (cache hit)
    export2 = article_service.export_articles(article_ids)
    logger.info(f"Exportação do cache: {export2['export_id']}")
    
    # 4. Demonstração de preferências do usuário
    logger.info("\n4. Preferências do Usuário:")
    
    user_id = "user_123"
    
    # Primeira vez (cache miss)
    prefs1 = user_service.get_user_preferences(user_id)
    logger.info(f"Preferências padrão: {prefs1['theme']}")
    
    # Segunda vez (cache hit)
    prefs2 = user_service.get_user_preferences(user_id)
    logger.info(f"Preferências do cache: {prefs2['theme']}")
    
    # Atualiza preferências
    new_prefs = {'theme': 'dark', 'language': 'en-US'}
    user_service.update_user_preferences(user_id, new_prefs)
    logger.info("Preferências atualizadas")
    
    # 5. Demonstração de cache de API
    logger.info("\n5. Cache de API:")
    
    # Primeira chamada (cache miss)
    data1 = api_service.fetch_external_data("/users", {'limit': 10})
    logger.info(f"Dados da API: {data1['endpoint']}")
    
    # Segunda chamada (cache hit)
    data2 = api_service.fetch_external_data("/users", {'limit': 10})
    logger.info(f"Dados do cache: {data2['endpoint']}")
    
    # 6. Demonstração de métricas
    logger.info("\n6. Métricas do Sistema:")
    
    # Primeira coleta (cache miss)
    metrics1 = metrics_service.get_system_metrics()
    logger.info(f"CPU: {metrics1['cpu_usage']}%")
    
    # Segunda coleta (cache hit)
    metrics2 = metrics_service.get_system_metrics()
    logger.info(f"CPU do cache: {metrics2['cpu_usage']}%")
    
    # 7. Demonstração de métricas do cache
    logger.info("\n7. Métricas do Cache:")
    
    cache_metrics = get_cache_manager().get_metrics()
    
    logger.info("=== Métricas do Cache Inteligente ===")
    intelligent_metrics = cache_metrics['intelligent_cache']
    logger.info(f"Hits: {intelligent_metrics['hits']}")
    logger.info(f"Misses: {intelligent_metrics['misses']}")
    logger.info(f"Hit Ratio: {intelligent_metrics['hit_ratio']}%")
    
    logger.info("\n=== Métricas das Estratégias ===")
    for cache_type, stats in cache_metrics['strategies'].items():
        logger.info(f"{cache_type}: {stats['total_entries']} entries, "
                   f"{stats['utilization_percent']:.1f}% utilization")
    
    logger.info("\n=== Métricas de Operações ===")
    operation_metrics = cache_metrics['operations']
    logger.info(f"Total Operations: {operation_metrics['total_operations']}")
    logger.info(f"Success Rate: {operation_metrics['success_rate']}%")
    logger.info(f"Average Duration: {operation_metrics['avg_duration_ms']:.2f}ms")


def demonstrate_cache_warming():
    """
    Demonstra cache warming.
    """
    logger.info("\n=== Demonstração de Cache Warming ===")
    
    cache_manager = get_cache_manager()
    
    # Dados frequentes para aquecimento
    warm_data = {
        'user_001': {'theme': 'dark', 'language': 'pt-BR'},
        'user_002': {'theme': 'light', 'language': 'en-US'},
        'user_003': {'theme': 'dark', 'language': 'es-ES'},
        'article_ai': {'topic': 'Inteligência Artificial', 'content': 'Conteúdo pré-gerado...'},
        'article_ml': {'topic': 'Machine Learning', 'content': 'Conteúdo pré-gerado...'}
    }
    
    # Aquecimento do cache de preferências
    cache_manager.warm_cache(CacheType.USER_PREFERENCES, {
        k: v for k, v in warm_data.items() if k.startswith('user_')
    })
    
    # Aquecimento do cache de artigos
    cache_manager.warm_cache(CacheType.ARTICLE_CONTENT, {
        k: v for k, v in warm_data.items() if k.startswith('article_')
    })
    
    logger.info("Cache aquecido com dados frequentes")


def demonstrate_cache_cleanup():
    """
    Demonstra limpeza de cache.
    """
    logger.info("\n=== Demonstração de Limpeza de Cache ===")
    
    cache_manager = get_cache_manager()
    
    # Adiciona alguns dados
    cache_manager.set(CacheType.GENERATION_STATUS, 'old_trace_1', {'status': 'old'})
    cache_manager.set(CacheType.GENERATION_STATUS, 'old_trace_2', {'status': 'old'})
    cache_manager.set(CacheType.EXPORT_CACHE, 'old_export_1', {'file': 'old.zip'})
    
    # Limpa cache de geração
    removed_count = cache_manager.clear(CacheType.GENERATION_STATUS)
    logger.info(f"Removidas {removed_count} entradas do cache de geração")
    
    # Limpeza de entradas expiradas
    cleanup_results = cache_manager.cleanup_expired()
    logger.info(f"Limpeza de expirados: {cleanup_results}")


def demonstrate_error_handling():
    """
    Demonstra tratamento de erros.
    """
    logger.info("\n=== Demonstração de Tratamento de Erros ===")
    
    cache_manager = get_cache_manager()
    
    # Simula operações que podem falhar
    try:
        # Operação normal
        success = cache_manager.set(CacheType.GENERATION_STATUS, 'test_key', {'data': 'value'})
        logger.info(f"Operação normal: {'Sucesso' if success else 'Falha'}")
        
        # Tenta obter dados inexistentes
        result = cache_manager.get(CacheType.GENERATION_STATUS, 'non_existent_key')
        logger.info(f"Dados inexistentes: {result}")
        
        # Remove dados inexistentes
        success = cache_manager.delete(CacheType.GENERATION_STATUS, 'non_existent_key')
        logger.info(f"Remoção de dados inexistentes: {'Sucesso' if success else 'Falha'}")
        
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")


if __name__ == "__main__":
    """
    Executa demonstração completa do sistema de cache.
    """
    try:
        # Demonstração principal
        demonstrate_cache_workflow()
        
        # Demonstrações adicionais
        demonstrate_cache_warming()
        demonstrate_cache_cleanup()
        demonstrate_error_handling()
        
        logger.info("\n=== Demonstração Concluída ===")
        logger.info("O sistema de cache está funcionando corretamente!")
        
    except Exception as e:
        logger.error(f"Erro durante demonstração: {e}")
        raise 