"""
Módulo de queries CQRS para o domínio Omni Writer.

Este módulo contém todas as queries que consultam o estado do sistema.
Queries são responsáveis por operações de leitura (Read).

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

from .base_query import BaseQuery
from .blog_queries import GetBlogQuery, GetBlogsQuery, GetBlogWithCategoriasQuery
from .categoria_queries import GetCategoriaQuery, GetCategoriasQuery, GetCategoriaWithClustersQuery
from .prompt_queries import GetPromptQuery, GetPromptsQuery, GetPromptsByCategoriaQuery
from .cluster_queries import GetClusterQuery, GetClustersQuery, GetClustersByCategoriaQuery
from .article_queries import GetArticleStatsQuery, GetGenerationConfigQuery, GetArticleContentQuery

__all__ = [
    'BaseQuery',
    'GetBlogQuery',
    'GetBlogsQuery',
    'GetBlogWithCategoriasQuery',
    'GetCategoriaQuery',
    'GetCategoriasQuery',
    'GetCategoriaWithClustersQuery',
    'GetPromptQuery',
    'GetPromptsQuery',
    'GetPromptsByCategoriaQuery',
    'GetClusterQuery',
    'GetClustersQuery',
    'GetClustersByCategoriaQuery',
    'GetArticleStatsQuery',
    'GetGenerationConfigQuery',
    'GetArticleContentQuery'
] 