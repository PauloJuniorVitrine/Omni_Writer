#!/usr/bin/env python3
"""
Módulo de Integração do ML Avançado com o Sistema Omni Writer.
Conecta os módulos de ML com a geração de artigos existente.
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
import traceback

# Importa módulos ML
from .content_optimizer import ContentOptimizer, ContentAnalysis, LearningData
from .intelligent_generator import IntelligentGenerator, GenerationRequest, GenerationResult

# Importa módulos existentes
try:
    from ..domain.generate_articles import ArticleGenerator
    from ..domain.data_models import ArticleRequest, ArticleResponse
    from ..shared.logger import get_logger
    EXISTING_AVAILABLE = True
except ImportError:
    EXISTING_AVAILABLE = False
    logging.warning("Módulos existentes não disponíveis")

# Configuração de logging
logger = logging.getLogger('ml_integration')

@dataclass
class MLArticleRequest:
    """Requisição de artigo com ML avançado."""
    topic: str
    target_length: int
    style: str
    language: str
    keywords: List[str] = None
    tone: str = "neutral"
    complexity: str = "intermediate"
    enable_optimization: bool = True
    enable_learning: bool = True
    unique_requirements: List[str] = None

@dataclass
class MLArticleResponse:
    """Resposta de artigo com ML avançado."""
    content: str
    original_content: str
    analysis: ContentAnalysis
    generation_result: GenerationResult
    optimization_applied: bool
    learning_applied: bool
    quality_metrics: Dict[str, float]
    suggestions: List[str]
    generation_time: float

class MLIntegration:
    """
    Integração do ML avançado com o sistema existente.
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.optimizer = None
        self.generator = None
        self.article_generator = None
        
        # Configurações
        self.config = self._load_config()
        
        # Inicializa componentes
        self._initialize_components()
        
        # Histórico de integração
        self.integration_history = []
        
        logger.info("MLIntegration inicializado")
    
    def _load_config(self) -> Dict[str, Any]:
        """Carrega configuração."""
        default_config = {
            "ml_enabled": True,
            "optimization_enabled": True,
            "learning_enabled": True,
            "min_quality_score": 0.8,
            "max_iterations": 5,
            "similarity_threshold": 0.85,
            "style_mapping": {
                "formal": "academic",
                "casual": "conversational",
                "technical": "technical",
                "storytelling": "narrative"
            }
        }
        
        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                logger.error(f"Erro ao carregar configuração: {e}")
        
        return default_config
    
    def _initialize_components(self):
        """Inicializa componentes ML e existentes."""
        try:
            # Inicializa otimizador
            if self.config["ml_enabled"]:
                self.optimizer = ContentOptimizer()
                logger.info("ContentOptimizer inicializado")
            
            # Inicializa gerador
            if self.optimizer:
                self.generator = IntelligentGenerator(self.optimizer)
                logger.info("IntelligentGenerator inicializado")
            
            # Inicializa gerador existente
            if EXISTING_AVAILABLE:
                self.article_generator = ArticleGenerator()
                logger.info("ArticleGenerator existente inicializado")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar componentes: {e}")
    
    def generate_article_with_ml(self, request: MLArticleRequest) -> MLArticleResponse:
        """
        Gera artigo usando ML avançado integrado com sistema existente.
        
        Args:
            request: Requisição de artigo com ML
        
        Returns:
            Resposta com artigo otimizado
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Gerando artigo com ML: {request.topic}")
            
            # 1. Gera conteúdo inicial (sistema existente ou ML)
            original_content = self._generate_initial_content(request)
            
            # 2. Aplica otimização ML se habilitada
            optimized_content = original_content
            optimization_applied = False
            analysis = None
            generation_result = None
            
            if self.config["optimization_enabled"] and self.optimizer:
                optimized_content, analysis = self.optimizer.optimize_content(original_content)
                optimization_applied = True
                logger.info("Otimização ML aplicada")
            
            # 3. Gera conteúdo com ML se qualidade insuficiente
            if (not analysis or analysis.metrics.overall_score < self.config["min_quality_score"]) and self.generator:
                logger.info("Qualidade insuficiente, gerando com ML")
                
                # Converte requisição para formato ML
                ml_request = GenerationRequest(
                    topic=request.topic,
                    content_type="article",
                    target_length=request.target_length,
                    style=request.style,
                    language=request.language,
                    keywords=request.keywords,
                    tone=request.tone,
                    complexity=request.complexity,
                    unique_requirements=request.unique_requirements
                )
                
                # Gera com ML
                generation_result = self.generator.generate_content(ml_request)
                if generation_result:
                    optimized_content = generation_result.content
                    analysis = generation_result.analysis
                    optimization_applied = True
                    logger.info(f"Conteúdo gerado com ML: Score {analysis.metrics.overall_score:.2f}")
            
            # 4. Aplica aprendizado se habilitado
            learning_applied = False
            if self.config["learning_enabled"] and request.enable_learning and analysis:
                self._apply_learning(request, analysis, generation_result)
                learning_applied = True
                logger.info("Aprendizado aplicado")
            
            # 5. Gera métricas de qualidade
            quality_metrics = self._extract_quality_metrics(analysis)
            
            # 6. Gera sugestões
            suggestions = []
            if self.optimizer:
                suggestions = self.optimizer.get_optimization_suggestions(optimized_content)
            
            # 7. Calcula tempo total
            generation_time = (datetime.now() - start_time).total_seconds()
            
            # 8. Cria resposta
            response = MLArticleResponse(
                content=optimized_content,
                original_content=original_content,
                analysis=analysis,
                generation_result=generation_result,
                optimization_applied=optimization_applied,
                learning_applied=learning_applied,
                quality_metrics=quality_metrics,
                suggestions=suggestions,
                generation_time=generation_time
            )
            
            # 9. Salva no histórico
            self.integration_history.append(response)
            
            logger.info(f"Artigo gerado com sucesso: Score {quality_metrics.get('overall_score', 0):.2f}")
            
            return response
            
        except Exception as e:
            logger.error(f"Erro na geração com ML: {e}")
            logger.error(traceback.format_exc())
            return None
    
    def _generate_initial_content(self, request: MLArticleRequest) -> str:
        """Gera conteúdo inicial usando sistema existente ou ML."""
        try:
            # Tenta usar sistema existente primeiro
            if self.article_generator and EXISTING_AVAILABLE:
                try:
                    # Converte para formato existente
                    existing_request = ArticleRequest(
                        topic=request.topic,
                        length=request.target_length,
                        style=self.config["style_mapping"].get(request.style, "general"),
                        language=request.language
                    )
                    
                    # Gera com sistema existente
                    existing_response = self.article_generator.generate_article(existing_request)
                    if existing_response and existing_response.content:
                        logger.info("Conteúdo gerado com sistema existente")
                        return existing_response.content
                
                except Exception as e:
                    logger.warning(f"Sistema existente falhou: {e}")
            
            # Fallback para ML
            if self.generator:
                logger.info("Usando ML como fallback")
                ml_request = GenerationRequest(
                    topic=request.topic,
                    content_type="article",
                    target_length=request.target_length,
                    style=request.style,
                    language=request.language,
                    keywords=request.keywords
                )
                
                result = self.generator.generate_content(ml_request)
                if result:
                    return result.content
            
            # Fallback final
            return f"Artigo sobre {request.topic}. Este é um conteúdo gerado automaticamente."
            
        except Exception as e:
            logger.error(f"Erro na geração inicial: {e}")
            return f"Erro na geração de conteúdo sobre {request.topic}."
    
    def _apply_learning(self, request: MLArticleRequest, analysis: ContentAnalysis, generation_result: GenerationResult):
        """Aplica aprendizado baseado no resultado."""
        try:
            if not self.optimizer or not request.enable_learning:
                return
            
            # Cria dados de aprendizado
            learning_data = LearningData(
                content_hash=analysis.content_hash,
                user_feedback=analysis.metrics.overall_score,
                engagement_metrics={
                    "uniqueness": analysis.metrics.uniqueness_score,
                    "humanization": analysis.metrics.humanization_score,
                    "readability": analysis.metrics.readability_score,
                    "coherence": analysis.metrics.coherence_score,
                    "creativity": analysis.metrics.creativity_score
                },
                improvement_suggestions=[],
                successful_patterns=[],
                failed_patterns=[]
            )
            
            # Extrai padrões se resultado de geração disponível
            if generation_result:
                learning_data.improvement_suggestions = generation_result.suggestions
                
                # Extrai padrões do conteúdo
                content = generation_result.content
                if analysis.metrics.overall_score > 0.8:
                    learning_data.successful_patterns = self._extract_patterns(content, "successful")
                else:
                    learning_data.failed_patterns = self._extract_patterns(content, "failed")
            
            # Aplica aprendizado
            self.optimizer.learn_from_feedback(analysis.content_hash, learning_data)
            
        except Exception as e:
            logger.error(f"Erro ao aplicar aprendizado: {e}")
    
    def _extract_patterns(self, content: str, pattern_type: str) -> List[str]:
        """Extrai padrões do conteúdo."""
        patterns = []
        
        try:
            if pattern_type == "successful":
                # Padrões bem-sucedidos
                if any(pronoun in content.lower() for pronoun in ['you', 'we', 'our']):
                    patterns.append("personal_pronouns")
                
                if any(phrase in content.lower() for phrase in ['you know', 'well', 'actually']):
                    patterns.append("conversational_phrases")
                
                if '?' in content:
                    patterns.append("questions")
                
                if any(word in content.lower() for word in ['imagine', 'picture', 'consider']):
                    patterns.append("engaging_hooks")
            
            elif pattern_type == "failed":
                # Padrões que falharam
                if content.count('.') < 5:
                    patterns.append("short_content")
                
                if len(set(content.lower().split())) / len(content.split()) < 0.6:
                    patterns.append("repetitive_vocabulary")
                
                if content.count('the') > content.count('you') * 2:
                    patterns.append("overly_formal")
        
        except Exception as e:
            logger.error(f"Erro ao extrair padrões: {e}")
        
        return patterns
    
    def _extract_quality_metrics(self, analysis: ContentAnalysis) -> Dict[str, float]:
        """Extrai métricas de qualidade."""
        if not analysis:
            return {}
        
        return {
            "overall_score": analysis.metrics.overall_score,
            "uniqueness_score": analysis.metrics.uniqueness_score,
            "humanization_score": analysis.metrics.humanization_score,
            "readability_score": analysis.metrics.readability_score,
            "coherence_score": analysis.metrics.coherence_score,
            "creativity_score": analysis.metrics.creativity_score,
            "learning_potential": analysis.metrics.learning_potential
        }
    
    def get_integration_stats(self, days: int = 30) -> Dict[str, Any]:
        """Obtém estatísticas de integração."""
        try:
            recent_history = [
                response for response in self.integration_history
                if (datetime.now() - response.analysis.timestamp).days <= days
            ]
            
            if not recent_history:
                return {"message": "Nenhum dado disponível"}
            
            stats = {
                "total_articles": len(recent_history),
                "avg_generation_time": sum(r.generation_time for r in recent_history) / len(recent_history),
                "optimization_rate": sum(1 for r in recent_history if r.optimization_applied) / len(recent_history),
                "learning_rate": sum(1 for r in recent_history if r.learning_applied) / len(recent_history),
                "avg_quality_score": sum(r.quality_metrics.get('overall_score', 0) for r in recent_history) / len(recent_history),
                "top_topics": self._get_top_topics(recent_history),
                "style_performance": self._get_style_performance(recent_history),
                "ml_usage_rate": sum(1 for r in recent_history if r.generation_result) / len(recent_history)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            return {"error": str(e)}
    
    def _get_top_topics(self, history: List[MLArticleResponse]) -> List[Dict[str, Any]]:
        """Obtém tópicos mais gerados."""
        topic_counts = {}
        topic_scores = {}
        
        for response in history:
            topic = response.analysis.topics[0] if response.analysis.topics else "unknown"
            topic_counts[topic] = topic_counts.get(topic, 0) + 1
            
            if topic not in topic_scores:
                topic_scores[topic] = []
            topic_scores[topic].append(response.quality_metrics.get('overall_score', 0))
        
        top_topics = []
        for topic, count in sorted(topic_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            avg_score = sum(topic_scores[topic]) / len(topic_scores[topic])
            top_topics.append({
                "topic": topic,
                "count": count,
                "avg_score": avg_score
            })
        
        return top_topics
    
    def _get_style_performance(self, history: List[MLArticleResponse]) -> Dict[str, float]:
        """Obtém performance por estilo."""
        style_scores = {}
        
        for response in history:
            # Determina estilo baseado nas características
            humanization = response.quality_metrics.get('humanization_score', 0)
            readability = response.quality_metrics.get('readability_score', 0)
            
            if humanization > 0.8:
                style = "casual"
            elif readability > 0.8:
                style = "formal"
            else:
                style = "technical"
            
            if style not in style_scores:
                style_scores[style] = []
            style_scores[style].append(response.quality_metrics.get('overall_score', 0))
        
        performance = {}
        for style, scores in style_scores.items():
            performance[style] = sum(scores) / len(scores)
        
        return performance
    
    def generate_batch_with_ml(self, requests: List[MLArticleRequest]) -> List[MLArticleResponse]:
        """Gera múltiplos artigos em lote com ML."""
        responses = []
        
        for request in requests:
            try:
                response = self.generate_article_with_ml(request)
                if response:
                    responses.append(response)
            except Exception as e:
                logger.error(f"Erro na geração em lote: {e}")
        
        return responses
    
    def export_integration_data(self, filepath: str):
        """Exporta dados de integração."""
        try:
            data = {
                "integration_history": [
                    {
                        "content": response.content,
                        "original_content": response.original_content,
                        "analysis": asdict(response.analysis),
                        "quality_metrics": response.quality_metrics,
                        "optimization_applied": response.optimization_applied,
                        "learning_applied": response.learning_applied,
                        "generation_time": response.generation_time
                    }
                    for response in self.integration_history
                ],
                "config": self.config,
                "stats": self.get_integration_stats()
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Dados de integração exportados para: {filepath}")
            
        except Exception as e:
            logger.error(f"Erro ao exportar dados: {e}")
    
    def update_config(self, new_config: Dict[str, Any]):
        """Atualiza configuração."""
        try:
            self.config.update(new_config)
            
            # Salva configuração
            if self.config_path:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=2)
            
            logger.info("Configuração atualizada")
            
        except Exception as e:
            logger.error(f"Erro ao atualizar configuração: {e}")


def main():
    """Função principal para testes."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Integração ML com Omni Writer")
    parser.add_argument("--topic", required=True, help="Tópico para gerar artigo")
    parser.add_argument("--style", default="casual", help="Estilo do artigo")
    parser.add_argument("--length", type=int, default=500, help="Tamanho em palavras")
    parser.add_argument("--language", default="en", help="Idioma")
    parser.add_argument("--no-optimization", action="store_true", help="Desabilitar otimização")
    parser.add_argument("--no-learning", action="store_true", help="Desabilitar aprendizado")
    parser.add_argument("--stats", action="store_true", help="Mostrar estatísticas")
    
    args = parser.parse_args()
    
    integration = MLIntegration()
    
    if args.stats:
        stats = integration.get_integration_stats()
        print("📊 Estatísticas de Integração:")
        print(json.dumps(stats, indent=2))
        return
    
    # Cria requisição
    request = MLArticleRequest(
        topic=args.topic,
        target_length=args.length,
        style=args.style,
        language=args.language,
        enable_optimization=not args.no_optimization,
        enable_learning=not args.no_learning
    )
    
    # Gera artigo
    print(f"🚀 Gerando artigo com ML: {args.topic}")
    response = integration.generate_article_with_ml(request)
    
    if response:
        print(f"\n✅ Artigo gerado com sucesso!")
        print(f"📊 Score: {response.quality_metrics.get('overall_score', 0):.2f}")
        print(f"🔒 Unicidade: {response.quality_metrics.get('uniqueness_score', 0):.2f}")
        print(f"👤 Humanização: {response.quality_metrics.get('humanization_score', 0):.2f}")
        print(f"⏱️ Tempo: {response.generation_time:.2f}s")
        print(f"🔄 Otimização: {'Sim' if response.optimization_applied else 'Não'}")
        print(f"🧠 Aprendizado: {'Sim' if response.learning_applied else 'Não'}")
        
        print(f"\n📝 Artigo Otimizado:\n{response.content}")
        
        if response.suggestions:
            print(f"\n💡 Sugestões de melhoria:")
            for suggestion in response.suggestions:
                print(f"  - {suggestion}")
    else:
        print("❌ Erro na geração de artigo")


if __name__ == "__main__":
    main() 