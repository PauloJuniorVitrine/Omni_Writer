#!/usr/bin/env python3
"""
Módulo de Geração Inteligente de Conteúdo com Aprendizado Contínuo.
Integra com ContentOptimizer para criar conteúdo único e humanizado.
"""

import os
import sys
import json
import random
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import sqlite3
import numpy as np
from collections import defaultdict

# Importa o otimizador de conteúdo
from .content_optimizer import ContentOptimizer, ContentAnalysis, LearningData

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('intelligent_generator')

@dataclass
class GenerationRequest:
    """Requisição de geração de conteúdo."""
    topic: str
    content_type: str  # article, blog, social, etc.
    target_length: int  # palavras
    style: str  # formal, casual, technical, etc.
    language: str
    keywords: List[str] = None
    tone: str = "neutral"  # positive, negative, neutral
    complexity: str = "intermediate"  # basic, intermediate, advanced
    unique_requirements: List[str] = None

@dataclass
class GenerationResult:
    """Resultado da geração de conteúdo."""
    content: str
    analysis: ContentAnalysis
    generation_time: float
    iterations: int
    optimization_applied: bool
    uniqueness_score: float
    humanization_score: float
    suggestions: List[str]

@dataclass
class StyleTemplate:
    """Template de estilo para geração."""
    name: str
    description: str
    characteristics: Dict[str, Any]
    examples: List[str]
    success_rate: float

class IntelligentGenerator:
    """
    Gerador inteligente de conteúdo com aprendizado contínuo.
    """
    
    def __init__(self, optimizer: ContentOptimizer = None):
        self.optimizer = optimizer or ContentOptimizer()
        self.style_templates = self._load_style_templates()
        self.generation_history = []
        self.success_patterns = {}
        self.failed_patterns = {}
        
        # Configurações
        self.max_iterations = 5
        self.min_quality_score = 0.8
        self.learning_enabled = True
        
        logger.info("IntelligentGenerator inicializado")
    
    def _load_style_templates(self) -> Dict[str, StyleTemplate]:
        """Carrega templates de estilo."""
        templates = {
            "formal": StyleTemplate(
                name="Formal",
                description="Estilo acadêmico e profissional",
                characteristics={
                    "sentence_structure": "complex",
                    "vocabulary": "advanced",
                    "personal_pronouns": "minimal",
                    "contractions": "none",
                    "tone": "objective"
                },
                examples=[
                    "The research indicates that...",
                    "Furthermore, it is evident that...",
                    "In conclusion, the findings demonstrate..."
                ],
                success_rate=0.85
            ),
            "casual": StyleTemplate(
                name="Casual",
                description="Estilo conversacional e amigável",
                characteristics={
                    "sentence_structure": "simple",
                    "vocabulary": "everyday",
                    "personal_pronouns": "frequent",
                    "contractions": "common",
                    "tone": "friendly"
                },
                examples=[
                    "You know what's really cool?",
                    "I think you'll find this interesting...",
                    "Let me tell you about..."
                ],
                success_rate=0.90
            ),
            "technical": StyleTemplate(
                name="Technical",
                description="Estilo técnico e detalhado",
                characteristics={
                    "sentence_structure": "precise",
                    "vocabulary": "technical",
                    "personal_pronouns": "minimal",
                    "contractions": "none",
                    "tone": "precise"
                },
                examples=[
                    "The implementation requires...",
                    "The algorithm processes...",
                    "The configuration parameters include..."
                ],
                success_rate=0.80
            ),
            "storytelling": StyleTemplate(
                name="Storytelling",
                description="Estilo narrativo e envolvente",
                characteristics={
                    "sentence_structure": "varied",
                    "vocabulary": "descriptive",
                    "personal_pronouns": "moderate",
                    "contractions": "some",
                    "tone": "engaging"
                },
                examples=[
                    "Imagine a world where...",
                    "Picture this scenario...",
                    "Let me share a story with you..."
                ],
                success_rate=0.88
            )
        }
        
        return templates
    
    def generate_content(self, request: GenerationRequest) -> GenerationResult:
        """
        Gera conteúdo inteligente baseado na requisição.
        
        Args:
            request: Requisição de geração
        
        Returns:
            Resultado da geração
        """
        start_time = datetime.now()
        iterations = 0
        
        try:
            logger.info(f"Gerando conteúdo: {request.topic}")
            
            # Gera conteúdo inicial
            content = self._generate_initial_content(request)
            iterations += 1
            
            # Analisa e otimiza
            analysis = self.optimizer.analyze_content(
                content, 
                request.content_type, 
                request.language
            )
            
            # Itera até atingir qualidade mínima
            while (analysis.metrics.overall_score < self.min_quality_score and 
                   iterations < self.max_iterations):
                
                logger.info(f"Iteração {iterations}: Score {analysis.metrics.overall_score:.2f}")
                
                # Otimiza conteúdo
                optimized_content, analysis = self.optimizer.optimize_content(content)
                content = optimized_content
                iterations += 1
            
            # Gera sugestões de melhoria
            suggestions = self.optimizer.get_optimization_suggestions(content)
            
            # Calcula tempo de geração
            generation_time = (datetime.now() - start_time).total_seconds()
            
            # Cria resultado
            result = GenerationResult(
                content=content,
                analysis=analysis,
                generation_time=generation_time,
                iterations=iterations,
                optimization_applied=iterations > 1,
                uniqueness_score=analysis.metrics.uniqueness_score,
                humanization_score=analysis.metrics.humanization_score,
                suggestions=suggestions
            )
            
            # Salva no histórico
            self.generation_history.append(result)
            
            # Aprende com o resultado
            if self.learning_enabled:
                self._learn_from_generation(request, result)
            
            logger.info(f"Conteúdo gerado com sucesso: Score {analysis.metrics.overall_score:.2f}")
            
            return result
            
        except Exception as e:
            logger.error(f"Erro na geração: {e}")
            return None
    
    def _generate_initial_content(self, request: GenerationRequest) -> str:
        """Gera conteúdo inicial baseado na requisição."""
        try:
            # Seleciona template de estilo
            style_template = self.style_templates.get(request.style, self.style_templates["casual"])
            
            # Gera estrutura base
            structure = self._generate_structure(request, style_template)
            
            # Preenche com conteúdo
            content = self._fill_structure(structure, request, style_template)
            
            # Aplica padrões de sucesso
            content = self._apply_success_patterns(content, request)
            
            return content
            
        except Exception as e:
            logger.error(f"Erro na geração inicial: {e}")
            return f"Erro na geração de conteúdo sobre {request.topic}."
    
    def _generate_structure(self, request: GenerationRequest, style_template: StyleTemplate) -> Dict[str, Any]:
        """Gera estrutura do conteúdo."""
        structure = {
            "introduction": {
                "length": request.target_length * 0.15,
                "elements": ["hook", "context", "thesis"]
            },
            "body": {
                "sections": [],
                "total_length": request.target_length * 0.70
            },
            "conclusion": {
                "length": request.target_length * 0.15,
                "elements": ["summary", "insight", "call_to_action"]
            }
        }
        
        # Determina número de seções baseado no tamanho
        num_sections = max(2, request.target_length // 200)
        section_length = structure["body"]["total_length"] / num_sections
        
        for i in range(num_sections):
            structure["body"]["sections"].append({
                "id": i + 1,
                "length": section_length,
                "elements": ["topic_sentence", "explanation", "example", "transition"]
            })
        
        return structure
    
    def _fill_structure(self, structure: Dict[str, Any], request: GenerationRequest, style_template: StyleTemplate) -> str:
        """Preenche estrutura com conteúdo."""
        content_parts = []
        
        # Introdução
        intro = self._generate_introduction(request, style_template, structure["introduction"]["length"])
        content_parts.append(intro)
        
        # Corpo
        for section in structure["body"]["sections"]:
            section_content = self._generate_section(request, style_template, section)
            content_parts.append(section_content)
        
        # Conclusão
        conclusion = self._generate_conclusion(request, style_template, structure["conclusion"]["length"])
        content_parts.append(conclusion)
        
        return "\n\n".join(content_parts)
    
    def _generate_introduction(self, request: GenerationRequest, style_template: StyleTemplate, target_length: int) -> str:
        """Gera introdução."""
        hooks = {
            "formal": [
                f"Recent developments in {request.topic} have sparked significant interest...",
                f"The field of {request.topic} presents unique challenges and opportunities...",
                f"Understanding {request.topic} is crucial for modern applications..."
            ],
            "casual": [
                f"Have you ever wondered about {request.topic}?",
                f"You know what's really fascinating about {request.topic}?",
                f"Let me tell you something cool about {request.topic}..."
            ],
            "technical": [
                f"The implementation of {request.topic} requires careful consideration...",
                f"Technical aspects of {request.topic} involve several key components...",
                f"Optimizing {request.topic} involves understanding core principles..."
            ],
            "storytelling": [
                f"Imagine a world where {request.topic} changes everything...",
                f"Picture this: you're exploring {request.topic} for the first time...",
                f"Let me share a story about how {request.topic} transformed..."
            ]
        }
        
        hook = random.choice(hooks.get(request.style, hooks["casual"]))
        
        # Contexto
        context_templates = [
            f"This topic is becoming increasingly important in today's digital landscape.",
            f"Many people are discovering the value of understanding this subject.",
            f"The implications of this knowledge extend far beyond initial expectations."
        ]
        context = random.choice(context_templates)
        
        # Tese
        thesis = f"In this article, we'll explore the key aspects of {request.topic} and its practical applications."
        
        introduction = f"{hook} {context} {thesis}"
        
        # Ajusta para o tamanho alvo
        while len(introduction.split()) < target_length * 0.8:
            introduction += f" We'll also examine how {request.topic} relates to current trends and future developments."
        
        return introduction
    
    def _generate_section(self, request: GenerationRequest, style_template: StyleTemplate, section: Dict[str, Any]) -> str:
        """Gera seção do corpo."""
        section_content = []
        
        # Tópico da seção
        topics = [
            f"Key aspects of {request.topic}",
            f"Important considerations for {request.topic}",
            f"Practical applications of {request.topic}",
            f"Benefits and advantages of {request.topic}",
            f"Challenges and solutions in {request.topic}"
        ]
        
        topic = topics[section["id"] % len(topics)]
        topic_sentence = f"One of the most important aspects to consider is {topic.lower()}."
        section_content.append(topic_sentence)
        
        # Explicação
        explanation_templates = [
            f"This involves understanding the fundamental principles and how they apply in real-world scenarios.",
            f"By examining this aspect, we can better appreciate the complexity and value of the subject.",
            f"This consideration helps us make informed decisions and optimize our approach."
        ]
        explanation = random.choice(explanation_templates)
        section_content.append(explanation)
        
        # Exemplo
        example_templates = [
            f"For example, when implementing {request.topic}, professionals often encounter situations where...",
            f"A practical example would be how companies use {request.topic} to improve their processes...",
            f"Consider how {request.topic} has been successfully applied in various industries..."
        ]
        example = random.choice(example_templates)
        section_content.append(example)
        
        # Transição
        transition_templates = [
            f"Moving forward, let's explore another important aspect.",
            f"Now, let's consider how this relates to other factors.",
            f"Building on this understanding, we can examine..."
        ]
        transition = random.choice(transition_templates)
        section_content.append(transition)
        
        return " ".join(section_content)
    
    def _generate_conclusion(self, request: GenerationRequest, style_template: StyleTemplate, target_length: int) -> str:
        """Gera conclusão."""
        summary_templates = [
            f"In summary, {request.topic} represents a significant opportunity for improvement and innovation.",
            f"To conclude, understanding {request.topic} is essential for success in today's environment.",
            f"Ultimately, the value of {request.topic} cannot be overstated in modern applications."
        ]
        summary = random.choice(summary_templates)
        
        insight_templates = [
            f"The key insight is that proper implementation leads to measurable improvements.",
            f"What's most important is recognizing the long-term benefits of this approach.",
            f"The real value lies in the systematic application of these principles."
        ]
        insight = random.choice(insight_templates)
        
        call_to_action_templates = [
            f"Consider how you can apply these concepts in your own projects.",
            f"Take the time to explore these ideas further and discover their potential.",
            f"Start implementing these strategies today to see immediate benefits."
        ]
        call_to_action = random.choice(call_to_action_templates)
        
        conclusion = f"{summary} {insight} {call_to_action}"
        
        return conclusion
    
    def _apply_success_patterns(self, content: str, request: GenerationRequest) -> str:
        """Aplica padrões de sucesso aprendidos."""
        try:
            # Busca padrões de sucesso para o tópico
            topic_patterns = self._get_topic_patterns(request.topic)
            
            if not topic_patterns:
                return content
            
            # Aplica padrões com maior taxa de sucesso
            for pattern in sorted(topic_patterns, key=lambda x: x['success_rate'], reverse=True)[:3]:
                if pattern['success_rate'] > 0.8:
                    content = self._apply_pattern(content, pattern)
            
            return content
            
        except Exception as e:
            logger.error(f"Erro ao aplicar padrões: {e}")
            return content
    
    def _get_topic_patterns(self, topic: str) -> List[Dict[str, Any]]:
        """Obtém padrões de sucesso para o tópico."""
        try:
            conn = sqlite3.connect(self.optimizer.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT pattern_data, success_rate, usage_count 
                FROM success_patterns 
                WHERE pattern_type = 'successful' AND success_rate > 0.7
                ORDER BY success_rate DESC
            ''')
            
            patterns = []
            for row in cursor.fetchall():
                pattern_data, success_rate, usage_count = row
                if topic.lower() in pattern_data.lower():
                    patterns.append({
                        'pattern_data': pattern_data,
                        'success_rate': success_rate,
                        'usage_count': usage_count
                    })
            
            conn.close()
            return patterns
            
        except Exception as e:
            logger.error(f"Erro ao buscar padrões: {e}")
            return []
    
    def _apply_pattern(self, content: str, pattern: Dict[str, Any]) -> str:
        """Aplica um padrão específico ao conteúdo."""
        try:
            pattern_data = pattern['pattern_data']
            
            # Padrões simples de substituição
            if "personal_pronouns" in pattern_data:
                content = content.replace("The research", "Our research")
                content = content.replace("This approach", "This approach we've developed")
            
            if "conversational_phrases" in pattern_data:
                content = content.replace("Furthermore", "You know what's interesting")
                content = content.replace("In conclusion", "So, to wrap this up")
            
            if "questions" in pattern_data:
                sentences = content.split('. ')
                if len(sentences) > 2:
                    mid_sentence = sentences[len(sentences)//2]
                    question = f"But what does this really mean for you? "
                    sentences.insert(len(sentences)//2, question)
                    content = '. '.join(sentences)
            
            return content
            
        except Exception as e:
            logger.error(f"Erro ao aplicar padrão: {e}")
            return content
    
    def _learn_from_generation(self, request: GenerationRequest, result: GenerationResult):
        """Aprende com o resultado da geração."""
        try:
            # Cria dados de aprendizado
            learning_data = LearningData(
                content_hash=result.analysis.content_hash,
                user_feedback=result.analysis.metrics.overall_score,
                engagement_metrics={
                    "uniqueness": result.uniqueness_score,
                    "humanization": result.humanization_score,
                    "readability": result.analysis.metrics.readability_score
                },
                improvement_suggestions=result.suggestions,
                successful_patterns=self._extract_successful_patterns(result.content),
                failed_patterns=self._extract_failed_patterns(result.content)
            )
            
            # Salva aprendizado
            self.optimizer.learn_from_feedback(result.analysis.content_hash, learning_data)
            
            # Atualiza padrões locais
            self._update_local_patterns(request, result)
            
        except Exception as e:
            logger.error(f"Erro no aprendizado: {e}")
    
    def _extract_successful_patterns(self, content: str) -> List[str]:
        """Extrai padrões bem-sucedidos do conteúdo."""
        patterns = []
        
        # Padrões de humanização
        if any(pronoun in content.lower() for pronoun in ['you', 'we', 'our']):
            patterns.append("personal_pronouns")
        
        if any(phrase in content.lower() for phrase in ['you know', 'well', 'actually']):
            patterns.append("conversational_phrases")
        
        if '?' in content:
            patterns.append("questions")
        
        if any(word in content.lower() for word in ['imagine', 'picture', 'consider']):
            patterns.append("engaging_hooks")
        
        return patterns
    
    def _extract_failed_patterns(self, content: str) -> List[str]:
        """Extrai padrões que falharam."""
        patterns = []
        
        # Padrões que indicam problemas
        if content.count('.') < 5:  # Poucas sentenças
            patterns.append("short_content")
        
        if len(set(content.lower().split())) / len(content.split()) < 0.6:  # Repetição
            patterns.append("repetitive_vocabulary")
        
        if content.count('the') > content.count('you') * 2:  # Muito formal
            patterns.append("overly_formal")
        
        return patterns
    
    def _update_local_patterns(self, request: GenerationRequest, result: GenerationResult):
        """Atualiza padrões locais baseado no resultado."""
        try:
            topic_key = request.topic.lower()
            
            if result.analysis.metrics.overall_score > 0.8:
                # Padrão de sucesso
                if topic_key not in self.success_patterns:
                    self.success_patterns[topic_key] = []
                
                self.success_patterns[topic_key].append({
                    'style': request.style,
                    'length': request.target_length,
                    'score': result.analysis.metrics.overall_score,
                    'timestamp': datetime.now()
                })
            else:
                # Padrão que falhou
                if topic_key not in self.failed_patterns:
                    self.failed_patterns[topic_key] = []
                
                self.failed_patterns[topic_key].append({
                    'style': request.style,
                    'length': request.target_length,
                    'score': result.analysis.metrics.overall_score,
                    'timestamp': datetime.now()
                })
            
        except Exception as e:
            logger.error(f"Erro ao atualizar padrões locais: {e}")
    
    def get_generation_stats(self, days: int = 30) -> Dict[str, Any]:
        """Obtém estatísticas de geração."""
        try:
            recent_history = [
                result for result in self.generation_history
                if (datetime.now() - result.analysis.timestamp).days <= days
            ]
            
            if not recent_history:
                return {"message": "Nenhum dado disponível"}
            
            stats = {
                "total_generations": len(recent_history),
                "avg_generation_time": np.mean([r.generation_time for r in recent_history]),
                "avg_iterations": np.mean([r.iterations for r in recent_history]),
                "avg_uniqueness": np.mean([r.uniqueness_score for r in recent_history]),
                "avg_humanization": np.mean([r.humanization_score for r in recent_history]),
                "optimization_rate": sum(1 for r in recent_history if r.optimization_applied) / len(recent_history),
                "top_topics": self._get_top_topics(recent_history),
                "style_performance": self._get_style_performance(recent_history)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            return {"error": str(e)}
    
    def _get_top_topics(self, history: List[GenerationResult]) -> List[Dict[str, Any]]:
        """Obtém tópicos mais gerados."""
        topic_counts = defaultdict(int)
        topic_scores = defaultdict(list)
        
        for result in history:
            topics = result.analysis.topics or []
            for topic in topics:
                topic_counts[topic] += 1
                topic_scores[topic].append(result.analysis.metrics.overall_score)
        
        top_topics = []
        for topic, count in sorted(topic_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            avg_score = np.mean(topic_scores[topic])
            top_topics.append({
                "topic": topic,
                "count": count,
                "avg_score": avg_score
            })
        
        return top_topics
    
    def _get_style_performance(self, history: List[GenerationResult]) -> Dict[str, float]:
        """Obtém performance por estilo."""
        style_scores = defaultdict(list)
        
        for result in history:
            # Associa resultado ao estilo baseado nas características
            if result.analysis.metrics.humanization_score > 0.8:
                style_scores["casual"].append(result.analysis.metrics.overall_score)
            elif result.analysis.metrics.readability_score > 0.8:
                style_scores["formal"].append(result.analysis.metrics.overall_score)
            else:
                style_scores["technical"].append(result.analysis.metrics.overall_score)
        
        performance = {}
        for style, scores in style_scores.items():
            performance[style] = np.mean(scores)
        
        return performance
    
    def generate_batch(self, requests: List[GenerationRequest]) -> List[GenerationResult]:
        """Gera múltiplos conteúdos em lote."""
        results = []
        
        for request in requests:
            try:
                result = self.generate_content(request)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Erro na geração em lote: {e}")
        
        return results
    
    def export_learning_data(self, filepath: str):
        """Exporta dados de aprendizado."""
        try:
            data = {
                "generation_history": [
                    {
                        "content": result.content,
                        "analysis": asdict(result.analysis),
                        "generation_time": result.generation_time,
                        "iterations": result.iterations
                    }
                    for result in self.generation_history
                ],
                "success_patterns": self.success_patterns,
                "failed_patterns": self.failed_patterns,
                "style_templates": {
                    name: asdict(template) for name, template in self.style_templates.items()
                }
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Dados exportados para: {filepath}")
            
        except Exception as e:
            logger.error(f"Erro ao exportar dados: {e}")


def main():
    """Função principal para testes."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Gerador Inteligente de Conteúdo")
    parser.add_argument("--topic", required=True, help="Tópico para gerar conteúdo")
    parser.add_argument("--style", default="casual", help="Estilo do conteúdo")
    parser.add_argument("--length", type=int, default=500, help="Tamanho em palavras")
    parser.add_argument("--language", default="en", help="Idioma")
    parser.add_argument("--stats", action="store_true", help="Mostrar estatísticas")
    
    args = parser.parse_args()
    
    generator = IntelligentGenerator()
    
    if args.stats:
        stats = generator.get_generation_stats()
        print("📊 Estatísticas de Geração:")
        print(json.dumps(stats, indent=2))
        return
    
    # Cria requisição
    request = GenerationRequest(
        topic=args.topic,
        content_type="article",
        target_length=args.length,
        style=args.style,
        language=args.language
    )
    
    # Gera conteúdo
    print(f"🚀 Gerando conteúdo sobre: {args.topic}")
    result = generator.generate_content(request)
    
    if result:
        print(f"\n✅ Conteúdo gerado com sucesso!")
        print(f"📊 Score: {result.analysis.metrics.overall_score:.2f}")
        print(f"🔒 Unicidade: {result.uniqueness_score:.2f}")
        print(f"👤 Humanização: {result.humanization_score:.2f}")
        print(f"⏱️ Tempo: {result.generation_time:.2f}s")
        print(f"🔄 Iterações: {result.iterations}")
        
        print(f"\n📝 Conteúdo:\n{result.content}")
        
        if result.suggestions:
            print(f"\n💡 Sugestões de melhoria:")
            for suggestion in result.suggestions:
                print(f"  - {suggestion}")
    else:
        print("❌ Erro na geração de conteúdo")


if __name__ == "__main__":
    main() 