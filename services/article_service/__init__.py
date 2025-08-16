"""
Article Service - Microserviço de Geração e Gestão de Artigos

Responsabilidades:
- Geração de artigos via IA (OpenAI, DeepSeek)
- Armazenamento e consulta de artigos
- Gestão de prompts e configurações
- Exportação e download de artigos
- Pipeline de geração em lote

Prompt: IMP-015: Microserviços
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:00:00Z
Tracing ID: ENTERPRISE_20250127_015
"""

__version__ = "1.0.0"
__service_name__ = "article-service"
__description__ = "Microserviço para geração e gestão de artigos"

from .app import create_app
from .models import Article, Prompt, GenerationConfig
from .services import ArticleGenerationService, ArticleStorageService
from .controllers import ArticleController

__all__ = [
    'create_app',
    'Article',
    'Prompt', 
    'GenerationConfig',
    'ArticleGenerationService',
    'ArticleStorageService',
    'ArticleController'
] 