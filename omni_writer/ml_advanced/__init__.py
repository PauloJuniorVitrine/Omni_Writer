#!/usr/bin/env python3
"""
Módulo de ML Avançado para Omni Writer.
Sistema de otimização e geração inteligente de conteúdo.
"""

from .content_optimizer import (
    ContentOptimizer,
    ContentAnalysis,
    ContentMetrics,
    LearningData
)

from .intelligent_generator import (
    IntelligentGenerator,
    GenerationRequest,
    GenerationResult,
    StyleTemplate
)

from .ml_integration import (
    MLIntegration,
    MLArticleRequest,
    MLArticleResponse
)

__version__ = "1.0.0"
__author__ = "Omni Writer Team"
__description__ = "Sistema de ML avançado para otimização e geração de conteúdo"

__all__ = [
    # Content Optimizer
    "ContentOptimizer",
    "ContentAnalysis", 
    "ContentMetrics",
    "LearningData",
    
    # Intelligent Generator
    "IntelligentGenerator",
    "GenerationRequest",
    "GenerationResult",
    "StyleTemplate",
    
    # ML Integration
    "MLIntegration",
    "MLArticleRequest",
    "MLArticleResponse"
]

def get_ml_system():
    """
    Retorna instância configurada do sistema ML completo.
    
    Returns:
        MLIntegration: Sistema ML configurado
    """
    return MLIntegration()

def quick_optimize(content: str, target_metrics: dict = None) -> tuple[str, dict]:
    """
    Função rápida para otimizar conteúdo.
    
    Args:
        content: Conteúdo a ser otimizado
        target_metrics: Métricas alvo (opcional)
    
    Returns:
        tuple: (conteúdo_otimizado, métricas)
    """
    optimizer = ContentOptimizer()
    optimized_content, analysis = optimizer.optimize_content(content, target_metrics)
    
    metrics = {
        "uniqueness": analysis.metrics.uniqueness_score,
        "humanization": analysis.metrics.humanization_score,
        "readability": analysis.metrics.readability_score,
        "coherence": analysis.metrics.coherence_score,
        "creativity": analysis.metrics.creativity_score,
        "overall": analysis.metrics.overall_score
    }
    
    return optimized_content, metrics

def quick_generate(topic: str, length: int = 500, style: str = "casual") -> str:
    """
    Função rápida para gerar conteúdo.
    
    Args:
        topic: Tópico do conteúdo
        length: Tamanho em palavras
        style: Estilo do conteúdo
    
    Returns:
        str: Conteúdo gerado
    """
    generator = IntelligentGenerator()
    
    request = GenerationRequest(
        topic=topic,
        content_type="article",
        target_length=length,
        style=style,
        language="en"
    )
    
    result = generator.generate_content(request)
    return result.content if result else f"Erro na geração de conteúdo sobre {topic}." 