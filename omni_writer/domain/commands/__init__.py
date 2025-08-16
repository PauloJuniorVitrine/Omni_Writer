"""
Módulo de comandos CQRS para o domínio Omni Writer.

Este módulo contém todos os comandos que modificam o estado do sistema.
Comandos são responsáveis por operações de escrita (Create, Update, Delete).

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

from .base_command import BaseCommand
from .blog_commands import CreateBlogCommand, UpdateBlogCommand, DeleteBlogCommand
from .categoria_commands import CreateCategoriaCommand, UpdateCategoriaCommand, DeleteCategoriaCommand
from .prompt_commands import CreatePromptCommand, UpdatePromptCommand, DeletePromptCommand
from .cluster_commands import CreateClusterCommand, UpdateClusterCommand, DeleteClusterCommand
from .article_commands import GenerateArticleCommand, GenerateArticlesForCategoriaCommand, GenerateZipEntregaCommand

__all__ = [
    'BaseCommand',
    'CreateBlogCommand',
    'UpdateBlogCommand', 
    'DeleteBlogCommand',
    'CreateCategoriaCommand',
    'UpdateCategoriaCommand',
    'DeleteCategoriaCommand',
    'CreatePromptCommand',
    'UpdatePromptCommand',
    'DeletePromptCommand',
    'CreateClusterCommand',
    'UpdateClusterCommand',
    'DeleteClusterCommand',
    'GenerateArticleCommand',
    'GenerateArticlesForCategoriaCommand',
    'GenerateZipEntregaCommand'
] 