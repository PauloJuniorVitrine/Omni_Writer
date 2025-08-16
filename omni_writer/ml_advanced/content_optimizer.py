#!/usr/bin/env python3
"""
Módulo de ML Avançado para Otimização de Conteúdo Humanizado.
Resolve: 1) Não repetição, 2) Humanização, 3) Aprendizado contínuo.
"""

import os
import sys
import json
import hashlib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import pickle
import sqlite3
from collections import defaultdict
import re
import random

# ML Libraries
try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    import nltk
    from nltk.tokenize import sent_tokenize, word_tokenize
    from nltk.corpus import stopwords
    from nltk.stem import WordNetLemmatizer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("ML libraries não disponíveis. Instale: pip install sentence-transformers scikit-learn nltk")

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('content_optimizer')

@dataclass
class ContentMetrics:
    """Métricas de qualidade do conteúdo."""
    uniqueness_score: float
    humanization_score: float
    readability_score: float
    coherence_score: float
    creativity_score: float
    overall_score: float
    similarity_with_existing: float
    learning_potential: float

@dataclass
class ContentAnalysis:
    """Análise completa do conteúdo."""
    content_hash: str
    timestamp: datetime
    content_type: str
    language: str
    word_count: int
    sentence_count: int
    paragraph_count: int
    metrics: ContentMetrics
    embeddings: Optional[np.ndarray] = None
    keywords: List[str] = None
    topics: List[str] = None
    sentiment: str = None
    complexity_level: str = None

@dataclass
class LearningData:
    """Dados para aprendizado contínuo."""
    content_hash: str
    user_feedback: float
    engagement_metrics: Dict[str, float]
    improvement_suggestions: List[str]
    successful_patterns: List[str]
    failed_patterns: List[str]

class ContentOptimizer:
    """
    Otimizador de conteúdo com ML avançado.
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", db_path: str = "content_ml.db"):
        self.model_name = model_name
        self.db_path = db_path
        self.model = None
        self.vectorizer = None
        self.lemmatizer = None
        self.stop_words = set()
        
        # Inicializa componentes ML
        self._initialize_ml_components()
        
        # Inicializa banco de dados
        self._initialize_database()
        
        # Cache de embeddings
        self.embeddings_cache = {}
        self.content_history = []
        
        # Configurações
        self.similarity_threshold = 0.85
        self.min_uniqueness_score = 0.7
        self.min_humanization_score = 0.8
        
        logger.info("ContentOptimizer inicializado com sucesso")
    
    def _initialize_ml_components(self):
        """Inicializa componentes de ML."""
        if not ML_AVAILABLE:
            logger.error("ML libraries não disponíveis")
            return
        
        try:
            # Modelo de embeddings
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Modelo de embeddings carregado: {self.model_name}")
            
            # Vectorizer TF-IDF
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )
            
            # NLTK components
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('wordnet', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            
            self.lemmatizer = WordNetLemmatizer()
            self.stop_words = set(stopwords.words('english'))
            
            logger.info("Componentes ML inicializados")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar ML: {e}")
    
    def _initialize_database(self):
        """Inicializa banco de dados SQLite."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de conteúdo
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS content_analysis (
                    content_hash TEXT PRIMARY KEY,
                    timestamp TEXT,
                    content_type TEXT,
                    language TEXT,
                    word_count INTEGER,
                    sentence_count INTEGER,
                    paragraph_count INTEGER,
                    metrics TEXT,
                    embeddings BLOB,
                    keywords TEXT,
                    topics TEXT,
                    sentiment TEXT,
                    complexity_level TEXT
                )
            ''')
            
            # Tabela de aprendizado
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS learning_data (
                    content_hash TEXT PRIMARY KEY,
                    user_feedback REAL,
                    engagement_metrics TEXT,
                    improvement_suggestions TEXT,
                    successful_patterns TEXT,
                    failed_patterns TEXT,
                    timestamp TEXT
                )
            ''')
            
            # Tabela de padrões de sucesso
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS success_patterns (
                    pattern_hash TEXT PRIMARY KEY,
                    pattern_type TEXT,
                    success_rate REAL,
                    usage_count INTEGER,
                    last_used TEXT,
                    pattern_data TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Banco de dados inicializado")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar banco: {e}")
    
    def generate_content_hash(self, content: str) -> str:
        """Gera hash único para o conteúdo."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def extract_text_features(self, content: str) -> Dict[str, Any]:
        """Extrai características do texto."""
        features = {
            'word_count': len(content.split()),
            'sentence_count': len(sent_tokenize(content)),
            'paragraph_count': len([p for p in content.split('\n\n') if p.strip()]),
            'avg_sentence_length': 0,
            'avg_word_length': 0,
            'unique_words_ratio': 0,
            'stop_words_ratio': 0
        }
        
        if features['sentence_count'] > 0:
            features['avg_sentence_length'] = features['word_count'] / features['sentence_count']
        
        words = word_tokenize(content.lower())
        if words:
            features['avg_word_length'] = sum(len(word) for word in words) / len(words)
            features['unique_words_ratio'] = len(set(words)) / len(words)
            features['stop_words_ratio'] = sum(1 for word in words if word in self.stop_words) / len(words)
        
        return features
    
    def calculate_readability_score(self, content: str) -> float:
        """Calcula score de legibilidade (Flesch Reading Ease)."""
        try:
            sentences = sent_tokenize(content)
            words = word_tokenize(content.lower())
            syllables = sum(self._count_syllables(word) for word in words)
            
            if sentences and words:
                # Flesch Reading Ease
                score = 206.835 - (1.015 * (len(words) / len(sentences))) - (84.6 * (syllables / len(words)))
                return max(0, min(100, score)) / 100  # Normaliza para 0-1
            return 0.5
            
        except Exception as e:
            logger.error(f"Erro ao calcular legibilidade: {e}")
            return 0.5
    
    def _count_syllables(self, word: str) -> int:
        """Conta sílabas em uma palavra."""
        word = word.lower()
        count = 0
        vowels = "aeiouy"
        on_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not on_vowel:
                count += 1
            on_vowel = is_vowel
        
        if word.endswith('e'):
            count -= 1
        if count == 0:
            count = 1
        return count
    
    def calculate_coherence_score(self, content: str) -> float:
        """Calcula score de coerência."""
        try:
            sentences = sent_tokenize(content)
            if len(sentences) < 2:
                return 1.0
            
            # Calcula similaridade entre sentenças consecutivas
            similarities = []
            for i in range(len(sentences) - 1):
                sim = self._calculate_sentence_similarity(sentences[i], sentences[i + 1])
                similarities.append(sim)
            
            return np.mean(similarities) if similarities else 0.5
            
        except Exception as e:
            logger.error(f"Erro ao calcular coerência: {e}")
            return 0.5
    
    def _calculate_sentence_similarity(self, sent1: str, sent2: str) -> float:
        """Calcula similaridade entre duas sentenças."""
        try:
            if not self.model:
                return 0.5
            
            embeddings = self.model.encode([sent1, sent2])
            similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
            return float(similarity)
            
        except Exception as e:
            logger.error(f"Erro ao calcular similaridade: {e}")
            return 0.5
    
    def calculate_creativity_score(self, content: str) -> float:
        """Calcula score de criatividade."""
        try:
            # Análise de diversidade lexical
            words = word_tokenize(content.lower())
            unique_words = set(words)
            
            # Diversidade de tipos de palavras
            pos_tags = nltk.pos_tag(words)
            pos_diversity = len(set(tag for word, tag in pos_tags)) / len(pos_tags) if pos_tags else 0
            
            # Complexidade sintática
            sentences = sent_tokenize(content)
            avg_sentence_length = np.mean([len(word_tokenize(sent)) for sent in sentences]) if sentences else 0
            
            # Score composto
            lexical_diversity = len(unique_words) / len(words) if words else 0
            complexity_score = min(1.0, avg_sentence_length / 20)  # Normaliza
            
            creativity_score = (lexical_diversity * 0.4 + pos_diversity * 0.3 + complexity_score * 0.3)
            return creativity_score
            
        except Exception as e:
            logger.error(f"Erro ao calcular criatividade: {e}")
            return 0.5
    
    def check_uniqueness(self, content: str) -> Tuple[float, List[str]]:
        """Verifica unicidade do conteúdo."""
        try:
            if not self.model:
                return 0.5, []
            
            # Gera embedding do novo conteúdo
            new_embedding = self.model.encode([content])[0]
            
            # Busca conteúdo similar no histórico
            similar_contents = []
            max_similarity = 0.0
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT content_hash, embeddings FROM content_analysis')
            
            for row in cursor.fetchall():
                content_hash, embeddings_blob = row
                if embeddings_blob:
                    stored_embedding = pickle.loads(embeddings_blob)
                    similarity = cosine_similarity([new_embedding], [stored_embedding])[0][0]
                    
                    if similarity > self.similarity_threshold:
                        similar_contents.append(content_hash)
                        max_similarity = max(max_similarity, similarity)
            
            conn.close()
            
            # Score de unicidade (inverso da similaridade máxima)
            uniqueness_score = 1.0 - max_similarity
            
            return uniqueness_score, similar_contents
            
        except Exception as e:
            logger.error(f"Erro ao verificar unicidade: {e}")
            return 0.5, []
    
    def calculate_humanization_score(self, content: str) -> float:
        """Calcula score de humanização."""
        try:
            # Fatores de humanização
            factors = {
                'personal_pronouns': 0.0,
                'contractions': 0.0,
                'questions': 0.0,
                'exclamations': 0.0,
                'conversational_phrases': 0.0,
                'varied_sentence_structure': 0.0
            }
            
            # Pronomes pessoais
            personal_pronouns = ['i', 'you', 'he', 'she', 'we', 'they', 'me', 'him', 'her', 'us', 'them']
            words = word_tokenize(content.lower())
            pronoun_count = sum(1 for word in words if word in personal_pronouns)
            factors['personal_pronouns'] = min(1.0, pronoun_count / len(words) * 10) if words else 0
            
            # Contrações
            contractions = ["'t", "'s", "'re", "'ve", "'ll", "'d"]
            contraction_count = sum(1 for word in words if any(cont in word for cont in contractions))
            factors['contractions'] = min(1.0, contraction_count / len(words) * 5) if words else 0
            
            # Perguntas e exclamações
            question_count = content.count('?')
            exclamation_count = content.count('!')
            factors['questions'] = min(1.0, question_count / 10)
            factors['exclamations'] = min(1.0, exclamation_count / 10)
            
            # Frases conversacionais
            conversational_phrases = [
                'you know', 'i mean', 'well', 'actually', 'basically',
                'obviously', 'clearly', 'frankly', 'honestly'
            ]
            content_lower = content.lower()
            phrase_count = sum(content_lower.count(phrase) for phrase in conversational_phrases)
            factors['conversational_phrases'] = min(1.0, phrase_count / 5)
            
            # Estrutura variada de sentenças
            sentences = sent_tokenize(content)
            if len(sentences) > 1:
                sentence_lengths = [len(word_tokenize(sent)) for sent in sentences]
                length_variance = np.var(sentence_lengths)
                factors['varied_sentence_structure'] = min(1.0, length_variance / 100)
            
            # Score composto
            humanization_score = (
                factors['personal_pronouns'] * 0.25 +
                factors['contractions'] * 0.20 +
                factors['questions'] * 0.15 +
                factors['exclamations'] * 0.10 +
                factors['conversational_phrases'] * 0.20 +
                factors['varied_sentence_structure'] * 0.10
            )
            
            return humanization_score
            
        except Exception as e:
            logger.error(f"Erro ao calcular humanização: {e}")
            return 0.5
    
    def analyze_content(self, content: str, content_type: str = "article", language: str = "en") -> ContentAnalysis:
        """Analisa conteúdo completo."""
        try:
            content_hash = self.generate_content_hash(content)
            
            # Extrai características básicas
            features = self.extract_text_features(content)
            
            # Calcula métricas
            readability_score = self.calculate_readability_score(content)
            coherence_score = self.calculate_coherence_score(content)
            creativity_score = self.calculate_creativity_score(content)
            humanization_score = self.calculate_humanization_score(content)
            
            # Verifica unicidade
            uniqueness_score, similar_contents = self.check_uniqueness(content)
            
            # Gera embedding
            embedding = None
            if self.model:
                embedding = self.model.encode([content])[0]
            
            # Calcula score geral
            overall_score = (
                uniqueness_score * 0.25 +
                humanization_score * 0.25 +
                readability_score * 0.20 +
                coherence_score * 0.15 +
                creativity_score * 0.15
            )
            
            # Calcula potencial de aprendizado
            learning_potential = self._calculate_learning_potential(content, features)
            
            # Cria métricas
            metrics = ContentMetrics(
                uniqueness_score=uniqueness_score,
                humanization_score=humanization_score,
                readability_score=readability_score,
                coherence_score=coherence_score,
                creativity_score=creativity_score,
                overall_score=overall_score,
                similarity_with_existing=1.0 - uniqueness_score,
                learning_potential=learning_potential
            )
            
            # Análise de sentimento
            sentiment = self._analyze_sentiment(content)
            
            # Nível de complexidade
            complexity_level = self._determine_complexity_level(features)
            
            # Extrai keywords e tópicos
            keywords = self._extract_keywords(content)
            topics = self._extract_topics(content)
            
            analysis = ContentAnalysis(
                content_hash=content_hash,
                timestamp=datetime.now(),
                content_type=content_type,
                language=language,
                word_count=features['word_count'],
                sentence_count=features['sentence_count'],
                paragraph_count=features['paragraph_count'],
                metrics=metrics,
                embeddings=embedding,
                keywords=keywords,
                topics=topics,
                sentiment=sentiment,
                complexity_level=complexity_level
            )
            
            # Salva no banco
            self._save_analysis(analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erro ao analisar conteúdo: {e}")
            return None
    
    def _calculate_learning_potential(self, content: str, features: Dict[str, Any]) -> float:
        """Calcula potencial de aprendizado do conteúdo."""
        try:
            # Fatores que indicam potencial de aprendizado
            factors = {
                'length': min(1.0, features['word_count'] / 1000),  # Conteúdo longo
                'complexity': min(1.0, features['avg_sentence_length'] / 20),  # Sentenças complexas
                'diversity': features['unique_words_ratio'],  # Vocabulário diverso
                'structure': min(1.0, features['paragraph_count'] / 10)  # Boa estrutura
            }
            
            # Score composto
            learning_potential = (
                factors['length'] * 0.3 +
                factors['complexity'] * 0.3 +
                factors['diversity'] * 0.2 +
                factors['structure'] * 0.2
            )
            
            return learning_potential
            
        except Exception as e:
            logger.error(f"Erro ao calcular potencial de aprendizado: {e}")
            return 0.5
    
    def _analyze_sentiment(self, content: str) -> str:
        """Análise básica de sentimento."""
        try:
            positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic']
            negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disappointing']
            
            words = word_tokenize(content.lower())
            positive_count = sum(1 for word in words if word in positive_words)
            negative_count = sum(1 for word in words if word in negative_words)
            
            if positive_count > negative_count:
                return 'positive'
            elif negative_count > positive_count:
                return 'negative'
            else:
                return 'neutral'
                
        except Exception as e:
            logger.error(f"Erro ao analisar sentimento: {e}")
            return 'neutral'
    
    def _determine_complexity_level(self, features: Dict[str, Any]) -> str:
        """Determina nível de complexidade."""
        try:
            avg_sentence_length = features['avg_sentence_length']
            avg_word_length = features['avg_word_length']
            
            if avg_sentence_length > 25 or avg_word_length > 6:
                return 'advanced'
            elif avg_sentence_length > 15 or avg_word_length > 5:
                return 'intermediate'
            else:
                return 'basic'
                
        except Exception as e:
            logger.error(f"Erro ao determinar complexidade: {e}")
            return 'intermediate'
    
    def _extract_keywords(self, content: str) -> List[str]:
        """Extrai keywords do conteúdo."""
        try:
            if not self.vectorizer:
                return []
            
            # Usa TF-IDF para extrair keywords
            tfidf_matrix = self.vectorizer.fit_transform([content])
            feature_names = self.vectorizer.get_feature_names_out()
            
            # Pega as top keywords
            scores = tfidf_matrix.toarray()[0]
            keyword_indices = np.argsort(scores)[-10:]  # Top 10
            keywords = [feature_names[i] for i in keyword_indices if scores[i] > 0]
            
            return keywords[:5]  # Retorna top 5
            
        except Exception as e:
            logger.error(f"Erro ao extrair keywords: {e}")
            return []
    
    def _extract_topics(self, content: str) -> List[str]:
        """Extrai tópicos do conteúdo."""
        try:
            # Análise básica de tópicos baseada em palavras-chave
            topics = []
            
            # Categorias de tópicos
            topic_keywords = {
                'technology': ['tech', 'software', 'digital', 'computer', 'internet'],
                'business': ['business', 'company', 'market', 'industry', 'profit'],
                'health': ['health', 'medical', 'fitness', 'wellness', 'disease'],
                'education': ['education', 'learning', 'school', 'study', 'knowledge'],
                'lifestyle': ['lifestyle', 'life', 'personal', 'daily', 'routine']
            }
            
            content_lower = content.lower()
            for topic, keywords in topic_keywords.items():
                if any(keyword in content_lower for keyword in keywords):
                    topics.append(topic)
            
            return topics[:3]  # Retorna top 3
            
        except Exception as e:
            logger.error(f"Erro ao extrair tópicos: {e}")
            return []
    
    def _save_analysis(self, analysis: ContentAnalysis):
        """Salva análise no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO content_analysis 
                (content_hash, timestamp, content_type, language, word_count, 
                 sentence_count, paragraph_count, metrics, embeddings, keywords, 
                 topics, sentiment, complexity_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis.content_hash,
                analysis.timestamp.isoformat(),
                analysis.content_type,
                analysis.language,
                analysis.word_count,
                analysis.sentence_count,
                analysis.paragraph_count,
                json.dumps(asdict(analysis.metrics)),
                pickle.dumps(analysis.embeddings) if analysis.embeddings is not None else None,
                json.dumps(analysis.keywords) if analysis.keywords else None,
                json.dumps(analysis.topics) if analysis.topics else None,
                analysis.sentiment,
                analysis.complexity_level
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Erro ao salvar análise: {e}")
    
    def optimize_content(self, content: str, target_metrics: Dict[str, float] = None) -> Tuple[str, ContentAnalysis]:
        """Otimiza conteúdo para melhor qualidade."""
        try:
            # Análise inicial
            analysis = self.analyze_content(content)
            if not analysis:
                return content, None
            
            # Define métricas alvo se não fornecidas
            if not target_metrics:
                target_metrics = {
                    'uniqueness_score': 0.8,
                    'humanization_score': 0.9,
                    'readability_score': 0.8,
                    'coherence_score': 0.9,
                    'creativity_score': 0.7
                }
            
            # Otimizações baseadas em métricas
            optimized_content = content
            
            # 1. Melhora humanização
            if analysis.metrics.humanization_score < target_metrics['humanization_score']:
                optimized_content = self._improve_humanization(optimized_content)
            
            # 2. Melhora legibilidade
            if analysis.metrics.readability_score < target_metrics['readability_score']:
                optimized_content = self._improve_readability(optimized_content)
            
            # 3. Melhora coerência
            if analysis.metrics.coherence_score < target_metrics['coherence_score']:
                optimized_content = self._improve_coherence(optimized_content)
            
            # 4. Melhora criatividade
            if analysis.metrics.creativity_score < target_metrics['creativity_score']:
                optimized_content = self._improve_creativity(optimized_content)
            
            # Análise final
            final_analysis = self.analyze_content(optimized_content)
            
            return optimized_content, final_analysis
            
        except Exception as e:
            logger.error(f"Erro ao otimizar conteúdo: {e}")
            return content, analysis
    
    def _improve_humanization(self, content: str) -> str:
        """Melhora humanização do conteúdo."""
        try:
            sentences = sent_tokenize(content)
            improved_sentences = []
            
            for i, sentence in enumerate(sentences):
                improved = sentence
                
                # Adiciona pronomes pessoais ocasionalmente
                if random.random() < 0.3 and i > 0:
                    if not any(pronoun in sentence.lower() for pronoun in ['i', 'you', 'we']):
                        improved = f"You'll find that {sentence.lower()}"
                
                # Adiciona frases conversacionais
                if random.random() < 0.2:
                    conversational_phrases = ['Actually, ', 'Well, ', 'You know, ', 'Basically, ']
                    improved = random.choice(conversational_phrases) + improved
                
                # Adiciona perguntas retóricas
                if random.random() < 0.1 and len(sentences) > 3:
                    improved += f" But what does this really mean for you?"
                
                improved_sentences.append(improved)
            
            return ' '.join(improved_sentences)
            
        except Exception as e:
            logger.error(f"Erro ao melhorar humanização: {e}")
            return content
    
    def _improve_readability(self, content: str) -> str:
        """Melhora legibilidade do conteúdo."""
        try:
            sentences = sent_tokenize(content)
            improved_sentences = []
            
            for sentence in sentences:
                words = word_tokenize(sentence)
                
                # Quebra sentenças muito longas
                if len(words) > 25:
                    # Divide em sentenças menores
                    mid_point = len(words) // 2
                    first_half = ' '.join(words[:mid_point])
                    second_half = ' '.join(words[mid_point:])
                    improved_sentences.extend([first_half + '.', second_half])
                else:
                    improved_sentences.append(sentence)
            
            return ' '.join(improved_sentences)
            
        except Exception as e:
            logger.error(f"Erro ao melhorar legibilidade: {e}")
            return content
    
    def _improve_coherence(self, content: str) -> str:
        """Melhora coerência do conteúdo."""
        try:
            sentences = sent_tokenize(content)
            improved_sentences = []
            
            # Adiciona conectores entre sentenças
            connectors = ['Furthermore, ', 'Moreover, ', 'Additionally, ', 'In addition, ', 'Also, ']
            
            for i, sentence in enumerate(sentences):
                if i > 0 and random.random() < 0.3:
                    connector = random.choice(connectors)
                    improved_sentences.append(connector + sentence)
                else:
                    improved_sentences.append(sentence)
            
            return ' '.join(improved_sentences)
            
        except Exception as e:
            logger.error(f"Erro ao melhorar coerência: {e}")
            return content
    
    def _improve_creativity(self, content: str) -> str:
        """Melhora criatividade do conteúdo."""
        try:
            # Adiciona elementos criativos
            creative_elements = [
                "Imagine this scenario: ",
                "Here's an interesting perspective: ",
                "Let's explore this further: ",
                "Consider this approach: ",
                "Think about it this way: "
            ]
            
            if random.random() < 0.3:
                element = random.choice(creative_elements)
                content = element + content
            
            return content
            
        except Exception as e:
            logger.error(f"Erro ao melhorar criatividade: {e}")
            return content
    
    def learn_from_feedback(self, content_hash: str, feedback: LearningData):
        """Aprende com feedback do usuário."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO learning_data 
                (content_hash, user_feedback, engagement_metrics, improvement_suggestions,
                 successful_patterns, failed_patterns, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                content_hash,
                feedback.user_feedback,
                json.dumps(feedback.engagement_metrics),
                json.dumps(feedback.improvement_suggestions),
                json.dumps(feedback.successful_patterns),
                json.dumps(feedback.failed_patterns),
                datetime.now().isoformat()
            ))
            
            # Atualiza padrões de sucesso
            self._update_success_patterns(feedback)
            
            conn.commit()
            conn.close()
            
            logger.info(f"Aprendizado salvo para {content_hash}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar aprendizado: {e}")
    
    def _update_success_patterns(self, feedback: LearningData):
        """Atualiza padrões de sucesso."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Atualiza padrões bem-sucedidos
            for pattern in feedback.successful_patterns:
                pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO success_patterns 
                    (pattern_hash, pattern_type, success_rate, usage_count, last_used, pattern_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    pattern_hash,
                    'successful',
                    0.9,  # Alta taxa de sucesso
                    1,
                    datetime.now().isoformat(),
                    pattern
                ))
            
            # Atualiza padrões que falharam
            for pattern in feedback.failed_patterns:
                pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO success_patterns 
                    (pattern_hash, pattern_type, success_rate, usage_count, last_used, pattern_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    pattern_hash,
                    'failed',
                    0.1,  # Baixa taxa de sucesso
                    1,
                    datetime.now().isoformat(),
                    pattern
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Erro ao atualizar padrões: {e}")
    
    def get_optimization_suggestions(self, content: str) -> List[str]:
        """Gera sugestões de otimização."""
        try:
            analysis = self.analyze_content(content)
            if not analysis:
                return []
            
            suggestions = []
            
            # Sugestões baseadas em métricas
            if analysis.metrics.uniqueness_score < 0.7:
                suggestions.append("Conteúdo muito similar ao existente. Considere abordar o tema de forma mais única.")
            
            if analysis.metrics.humanization_score < 0.8:
                suggestions.append("Adicione mais elementos conversacionais e pronomes pessoais.")
            
            if analysis.metrics.readability_score < 0.7:
                suggestions.append("Use sentenças mais curtas e vocabulário mais simples.")
            
            if analysis.metrics.coherence_score < 0.8:
                suggestions.append("Melhore a conexão entre parágrafos e sentenças.")
            
            if analysis.metrics.creativity_score < 0.6:
                suggestions.append("Adicione mais elementos criativos e perspectivas únicas.")
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Erro ao gerar sugestões: {e}")
            return []
    
    def generate_report(self, days: int = 30) -> str:
        """Gera relatório de análise."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Estatísticas gerais
            df_analysis = pd.read_sql_query('''
                SELECT * FROM content_analysis 
                WHERE timestamp >= datetime('now', '-{} days')
            '''.format(days), conn)
            
            df_learning = pd.read_sql_query('''
                SELECT * FROM learning_data 
                WHERE timestamp >= datetime('now', '-{} days')
            '''.format(days), conn)
            
            conn.close()
            
            if df_analysis.empty:
                return "Nenhum dado disponível para o período."
            
            # Calcula estatísticas
            avg_metrics = df_analysis['metrics'].apply(lambda x: json.loads(x)).apply(pd.Series).mean()
            
            report = f"""
# Relatório de Análise de Conteúdo - Últimos {days} dias

## 📊 Estatísticas Gerais
- **Total de conteúdos analisados**: {len(df_analysis)}
- **Conteúdos com feedback**: {len(df_learning)}

## 📈 Métricas Médias
- **Unicidade**: {avg_metrics.get('uniqueness_score', 0):.2f}
- **Humanização**: {avg_metrics.get('humanization_score', 0):.2f}
- **Legibilidade**: {avg_metrics.get('readability_score', 0):.2f}
- **Coerência**: {avg_metrics.get('coherence_score', 0):.2f}
- **Criatividade**: {avg_metrics.get('creativity_score', 0):.2f}
- **Score Geral**: {avg_metrics.get('overall_score', 0):.2f}

## 🎯 Tendências
- **Melhorando**: {'Sim' if avg_metrics.get('overall_score', 0) > 0.7 else 'Não'}
- **Área de melhoria**: {'Humanização' if avg_metrics.get('humanization_score', 0) < 0.8 else 'Legibilidade'}

## 📋 Recomendações
- Continue monitorando métricas de humanização
- Foque em melhorar coerência entre sentenças
- Mantenha diversidade de vocabulário

---
*Relatório gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
            
            return report
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return f"Erro ao gerar relatório: {e}"


def main():
    """Função principal para testes."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Optimizer com ML")
    parser.add_argument("--content", help="Conteúdo para analisar")
    parser.add_argument("--optimize", action="store_true", help="Otimizar conteúdo")
    parser.add_argument("--report", type=int, help="Gerar relatório dos últimos N dias")
    
    args = parser.parse_args()
    
    optimizer = ContentOptimizer()
    
    if args.content:
        print("🔍 Analisando conteúdo...")
        analysis = optimizer.analyze_content(args.content)
        
        if analysis:
            print(f"📊 Score Geral: {analysis.metrics.overall_score:.2f}")
            print(f"🔒 Unicidade: {analysis.metrics.uniqueness_score:.2f}")
            print(f"👤 Humanização: {analysis.metrics.humanization_score:.2f}")
            print(f"📖 Legibilidade: {analysis.metrics.readability_score:.2f}")
            
            if args.optimize:
                print("\n🚀 Otimizando conteúdo...")
                optimized, final_analysis = optimizer.optimize_content(args.content)
                print(f"✅ Score após otimização: {final_analysis.metrics.overall_score:.2f}")
                print(f"📝 Conteúdo otimizado:\n{optimized}")
    
    if args.report:
        print("📊 Gerando relatório...")
        report = optimizer.generate_report(args.report)
        print(report)


if __name__ == "__main__":
    main() 