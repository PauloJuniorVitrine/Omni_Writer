"""
Barrel module para modelos de domínio e ORM.
Reexporta símbolos de data_models.py e orm_models.py para padronizar imports em todo o projeto.
"""
from .data_models import (
    PromptInput,
    ArticleOutput,
    GenerationConfig,
)
from .orm_models import (
    Base,
    Blog,
    Prompt,
    Categoria,
    Cluster,
)

__all__ = [
    "PromptInput",
    "ArticleOutput",
    "GenerationConfig",
    "Base",
    "Blog",
    "Prompt",
    "Categoria",
    "Cluster",
] 