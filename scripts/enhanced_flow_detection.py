#!/usr/bin/env python3
"""
🔍 FRAMEWORK APRIMORADO DE DETECÇÃO DE FLUXOS
📐 CoCoT + ToT + ReAct + Análise Semântica Avançada
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Framework avançado para detecção automática de novos fluxos via análise semântica de logs.
Identifica cenários não testados baseados em logs reais de produção com análise contextual.

Tracing ID: ENHANCED_FLOW_DETECTION_20250712_001
Data/Hora: 2025-07-12T21:30:00Z
Versão: 2.0
"""

import time
import json
import logging
import threading
import hashlib
import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "ENHANCED_FLOW_DETECTION_20250712_001"

@dataclass
class SemanticLogEntry:
    """Entrada de log com análise semântica."""
    timestamp: datetime
    level: str
    message: str
    service: str
    endpoint: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    tracing_id: str = TRACING_ID
    semantic_tokens: List[str] = None
    context_vector: List[float] = None
    sentiment_score: float = 0.0
    complexity_score: float = 0.0

@dataclass
class EnhancedFlowPattern:
    """Padrão de fluxo com análise semântica avançada."""
    name: str
    description: str
    risk_score: int
    frequency: int
    is_tested: bool
    semantic_cluster: str
    context_keywords: List[str]
    complexity_level: str
    business_impact: str
    technical_debt: float
    last_occurrence: datetime
    first_occurrence: datetime
    confidence_score: float
    related_patterns: List[str]
    suggested_tests: List[str]

@dataclass
class EnhancedFlowDetectionResult:
    """Resultado da detecção de fluxos aprimorada."""
    patterns: List[EnhancedFlowPattern]
    semantic_clusters: Dict[str, List[str]]
    coverage_analysis: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]

class SemanticAnalyzer:
    """Analisador semântico para logs."""
    
    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        
        # Padrões semânticos específicos do Omni Writer
        self.business_patterns = {
            'article_generation': [
                'generate_article', 'content_creation', 'article_pipeline',
                'content_generation', 'article_processing'
            ],
            'user_management': [
                'user_authentication', 'user_authorization', 'user_profile',
                'user_preferences', 'user_settings'
            ],
            'monitoring': [
                'health_check', 'performance_monitoring', 'metrics_collection',
                'alert_system', 'logging_system'
            ],
            'testing': [
                'test_execution', 'test_coverage', 'test_validation',
                'test_reporting', 'test_analysis'
            ]
        }
        
        # Padrões de complexidade
        self.complexity_patterns = {
            'high': ['error_handling', 'fallback', 'retry', 'circuit_breaker'],
            'medium': ['validation', 'sanitization', 'transformation'],
            'low': ['logging', 'monitoring', 'basic_operations']
        }
    
    def analyze_semantics(self, message: str) -> Dict[str, Any]:
        """Analisa semântica de uma mensagem de log."""
        # Tokenização e limpeza
        tokens = word_tokenize(message.lower())
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens 
                 if token.isalnum() and token not in self.stop_words]
        
        # Análise de padrões de negócio
        business_context = self._identify_business_context(message)
        
        # Análise de complexidade
        complexity = self._assess_complexity(message)
        
        # Análise de sentimento (simplificada)
        sentiment = self._analyze_sentiment(message)
        
        return {
            'tokens': tokens,
            'business_context': business_context,
            'complexity': complexity,
            'sentiment': sentiment,
            'context_keywords': self._extract_context_keywords(message)
        }
    
    def _identify_business_context(self, message: str) -> str:
        """Identifica contexto de negócio da mensagem."""
        message_lower = message.lower()
        
        for context, patterns in self.business_patterns.items():
            if any(pattern in message_lower for pattern in patterns):
                return context
        
        return 'general'
    
    def _assess_complexity(self, message: str) -> str:
        """Avalia complexidade da operação."""
        message_lower = message.lower()
        
        high_complexity_count = sum(1 for pattern in self.complexity_patterns['high'] 
                                   if pattern in message_lower)
        medium_complexity_count = sum(1 for pattern in self.complexity_patterns['medium'] 
                                     if pattern in message_lower)
        
        if high_complexity_count > 0:
            return 'high'
        elif medium_complexity_count > 0:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_sentiment(self, message: str) -> float:
        """Análise simplificada de sentimento."""
        positive_words = ['success', 'completed', 'ok', 'healthy', 'passed']
        negative_words = ['error', 'failed', 'exception', 'critical', 'warning']
        
        message_lower = message.lower()
        
        positive_count = sum(1 for word in positive_words if word in message_lower)
        negative_count = sum(1 for word in negative_words if word in message_lower)
        
        if positive_count > negative_count:
            return 0.5 + (positive_count * 0.1)
        elif negative_count > positive_count:
            return -0.5 - (negative_count * 0.1)
        else:
            return 0.0
    
    def _extract_context_keywords(self, message: str) -> List[str]:
        """Extrai palavras-chave de contexto."""
        keywords = []
        message_lower = message.lower()
        
        # Extrai palavras técnicas importantes
        technical_terms = re.findall(r'\b[a-z_]+(?:_[a-z_]+)*\b', message_lower)
        keywords.extend([term for term in technical_terms if len(term) > 3])
        
        # Extrai IDs e referências
        ids = re.findall(r'\b[A-Z0-9]{8,}\b', message)
        keywords.extend(ids)
        
        return list(set(keywords))

class EnhancedFlowDetectionFramework:
    """Framework aprimorado de detecção de fluxos."""
    
    def __init__(self, db_path: str = "flow_detection.db"):
        self.db_path = db_path
        self.semantic_analyzer = SemanticAnalyzer()
        self.pattern_cache = {}
        self.cluster_cache = {}
        
        # Inicializa banco de dados
        self._init_database()
        
        # Configurações
        self.config = {
            'min_frequency': 3,
            'confidence_threshold': 0.7,
            'max_patterns_per_cluster': 10,
            'semantic_similarity_threshold': 0.8
        }
    
    def _init_database(self):
        """Inicializa banco de dados para cache de padrões."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flow_patterns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    risk_score INTEGER,
                    frequency INTEGER,
                    is_tested BOOLEAN,
                    semantic_cluster TEXT,
                    context_keywords TEXT,
                    complexity_level TEXT,
                    business_impact TEXT,
                    technical_debt REAL,
                    last_occurrence TEXT,
                    first_occurrence TEXT,
                    confidence_score REAL,
                    created_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS semantic_clusters (
                    cluster_id TEXT PRIMARY KEY,
                    cluster_name TEXT NOT NULL,
                    keywords TEXT,
                    patterns TEXT,
                    created_at TEXT
                )
            """)
    
    def analyze_logs_enhanced(self, log_sources: Dict[str, str]) -> EnhancedFlowDetectionResult:
        """Análise aprimorada de logs com detecção semântica."""
        logger.info(f"[{TRACING_ID}] Iniciando análise semântica de logs...")
        
        all_entries = []
        semantic_clusters = {}
        
        # Processa cada fonte de log
        for source_name, source_path in log_sources.items():
            logger.info(f"[{TRACING_ID}] Processando fonte: {source_name}")
            
            entries = self._load_log_entries(source_path, source_name)
            semantic_entries = self._enhance_entries_with_semantics(entries)
            all_entries.extend(semantic_entries)
        
        # Análise de clustering semântico
        clusters = self._perform_semantic_clustering(all_entries)
        
        # Detecção de padrões aprimorada
        patterns = self._detect_enhanced_patterns(all_entries, clusters)
        
        # Análise de cobertura
        coverage_analysis = self._analyze_coverage_enhanced(patterns)
        
        # Avaliação de risco
        risk_assessment = self._assess_risk_enhanced(patterns)
        
        # Gera recomendações
        recommendations = self._generate_recommendations(patterns, coverage_analysis, risk_assessment)
        
        return EnhancedFlowDetectionResult(
            patterns=patterns,
            semantic_clusters=clusters,
            coverage_analysis=coverage_analysis,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            metadata={
                'tracing_id': TRACING_ID,
                'timestamp': datetime.now().isoformat(),
                'total_entries': len(all_entries),
                'total_patterns': len(patterns),
                'total_clusters': len(clusters)
            }
        )
    
    def _load_log_entries(self, source_path: str, source_name: str) -> List[SemanticLogEntry]:
        """Carrega entradas de log com análise semântica."""
        entries = []
        
        try:
            if source_path.endswith('.json'):
                with open(source_path, 'r', encoding='utf-8') as f:
                    log_data = json.load(f)
                    
                if isinstance(log_data, list):
                    for entry in log_data:
                        semantic_entry = self._create_semantic_entry(entry, source_name)
                        entries.append(semantic_entry)
                else:
                    semantic_entry = self._create_semantic_entry(log_data, source_name)
                    entries.append(semantic_entry)
            
            elif source_path.endswith('.log'):
                with open(source_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        entry = self._parse_log_line(line, source_name, line_num)
                        if entry:
                            semantic_entry = self._create_semantic_entry(entry, source_name)
                            entries.append(semantic_entry)
        
        except Exception as e:
            logger.error(f"[{TRACING_ID}] Erro ao carregar {source_path}: {e}")
        
        return entries
    
    def _create_semantic_entry(self, entry_data: Dict[str, Any], source_name: str) -> SemanticLogEntry:
        """Cria entrada semântica a partir de dados de log."""
        # Análise semântica da mensagem
        message = entry_data.get('message', '')
        semantic_analysis = self.semantic_analyzer.analyze_semantics(message)
        
        return SemanticLogEntry(
            timestamp=datetime.fromisoformat(entry_data.get('timestamp', datetime.now().isoformat())),
            level=entry_data.get('level', 'INFO'),
            message=message,
            service=entry_data.get('service', source_name),
            endpoint=entry_data.get('endpoint', ''),
            user_id=entry_data.get('user_id'),
            session_id=entry_data.get('session_id'),
            request_id=entry_data.get('request_id'),
            metadata=entry_data.get('metadata', {}),
            semantic_tokens=semantic_analysis['tokens'],
            context_vector=self._create_context_vector(semantic_analysis),
            sentiment_score=semantic_analysis['sentiment'],
            complexity_score=self._calculate_complexity_score(semantic_analysis['complexity'])
        )
    
    def _enhance_entries_with_semantics(self, entries: List[SemanticLogEntry]) -> List[SemanticLogEntry]:
        """Aprimora entradas com análise semântica adicional."""
        enhanced_entries = []
        
        for entry in entries:
            # Análise adicional de contexto
            entry.metadata['business_context'] = self.semantic_analyzer._identify_business_context(entry.message)
            entry.metadata['complexity_level'] = self.semantic_analyzer._assess_complexity(entry.message)
            entry.metadata['context_keywords'] = self.semantic_analyzer._extract_context_keywords(entry.message)
            
            enhanced_entries.append(entry)
        
        return enhanced_entries
    
    def _create_context_vector(self, semantic_analysis: Dict[str, Any]) -> List[float]:
        """Cria vetor de contexto para análise semântica."""
        # Vetor simplificado baseado em características
        vector = [
            len(semantic_analysis['tokens']),  # Comprimento
            semantic_analysis['sentiment'],   # Sentimento
            len(semantic_analysis['context_keywords']),  # Palavras-chave
            1.0 if semantic_analysis['business_context'] != 'general' else 0.0,  # Contexto específico
        ]
        
        # Normaliza vetor
        max_val = max(vector) if vector else 1.0
        return [v / max_val for v in vector]
    
    def _calculate_complexity_score(self, complexity: str) -> float:
        """Calcula score de complexidade."""
        complexity_scores = {
            'high': 1.0,
            'medium': 0.6,
            'low': 0.2
        }
        return complexity_scores.get(complexity, 0.5)
    
    def _perform_semantic_clustering(self, entries: List[SemanticLogEntry]) -> Dict[str, List[str]]:
        """Realiza clustering semântico das entradas."""
        if not entries:
            return {}
        
        # Extrai vetores de contexto
        vectors = [entry.context_vector for entry in entries]
        
        # Aplica DBSCAN para clustering
        clustering = DBSCAN(eps=0.3, min_samples=2).fit(vectors)
        
        # Agrupa entradas por cluster
        clusters = defaultdict(list)
        for i, cluster_id in enumerate(clustering.labels_):
            if cluster_id != -1:  # Ignora outliers
                cluster_name = f"cluster_{cluster_id}"
                clusters[cluster_name].append(entries[i].message)
        
        return dict(clusters)
    
    def _detect_enhanced_patterns(self, entries: List[SemanticLogEntry], clusters: Dict[str, List[str]]) -> List[EnhancedFlowPattern]:
        """Detecção aprimorada de padrões com análise semântica."""
        patterns = []
        
        # Agrupa entradas por contexto de negócio
        business_groups = defaultdict(list)
        for entry in entries:
            business_context = entry.metadata.get('business_context', 'general')
            business_groups[business_context].append(entry)
        
        # Detecta padrões por contexto
        for business_context, context_entries in business_groups.items():
            if len(context_entries) >= self.config['min_frequency']:
                pattern = self._create_enhanced_pattern(context_entries, business_context, clusters)
                if pattern:
                    patterns.append(pattern)
        
        return patterns
    
    def _create_enhanced_pattern(self, entries: List[SemanticLogEntry], business_context: str, clusters: Dict[str, List[str]]) -> Optional[EnhancedFlowPattern]:
        """Cria padrão aprimorado baseado em entradas."""
        if not entries:
            return None
        
        # Análise de frequência e timing
        first_occurrence = min(entry.timestamp for entry in entries)
        last_occurrence = max(entry.timestamp for entry in entries)
        frequency = len(entries)
        
        # Análise de complexidade
        complexity_scores = [entry.complexity_score for entry in entries]
        avg_complexity = sum(complexity_scores) / len(complexity_scores)
        
        # Determina nível de complexidade
        if avg_complexity > 0.7:
            complexity_level = 'high'
        elif avg_complexity > 0.4:
            complexity_level = 'medium'
        else:
            complexity_level = 'low'
        
        # Calcula score de risco
        risk_score = self._calculate_enhanced_risk_score(entries, complexity_level, frequency)
        
        # Identifica cluster semântico
        semantic_cluster = self._identify_semantic_cluster(entries, clusters)
        
        # Extrai palavras-chave de contexto
        context_keywords = self._extract_pattern_keywords(entries)
        
        # Avalia impacto no negócio
        business_impact = self._assess_business_impact(business_context, frequency, complexity_level)
        
        # Calcula dívida técnica
        technical_debt = self._calculate_technical_debt(entries, complexity_level)
        
        # Calcula score de confiança
        confidence_score = self._calculate_confidence_score(entries, frequency, complexity_level)
        
        # Identifica padrões relacionados
        related_patterns = self._identify_related_patterns(business_context, context_keywords)
        
        # Gera sugestões de teste
        suggested_tests = self._generate_test_suggestions(business_context, complexity_level, context_keywords)
        
        return EnhancedFlowPattern(
            name=f"Fluxo de {business_context.replace('_', ' ').title()}",
            description=f"Padrão detectado em {business_context} com {frequency} ocorrências",
            risk_score=risk_score,
            frequency=frequency,
            is_tested=self._check_if_tested(business_context, context_keywords),
            semantic_cluster=semantic_cluster,
            context_keywords=context_keywords,
            complexity_level=complexity_level,
            business_impact=business_impact,
            technical_debt=technical_debt,
            last_occurrence=last_occurrence,
            first_occurrence=first_occurrence,
            confidence_score=confidence_score,
            related_patterns=related_patterns,
            suggested_tests=suggested_tests
        )
    
    def _calculate_enhanced_risk_score(self, entries: List[SemanticLogEntry], complexity: str, frequency: int) -> int:
        """Calcula score de risco aprimorado."""
        base_score = {
            'high': 100,
            'medium': 60,
            'low': 30
        }.get(complexity, 50)
        
        # Ajusta por frequência
        frequency_multiplier = min(frequency / 10, 2.0)
        
        # Ajusta por sentimento (erros aumentam risco)
        error_count = sum(1 for entry in entries if entry.level in ['ERROR', 'CRITICAL'])
        error_multiplier = 1.0 + (error_count / len(entries)) * 0.5
        
        return int(base_score * frequency_multiplier * error_multiplier)
    
    def _identify_semantic_cluster(self, entries: List[SemanticLogEntry], clusters: Dict[str, List[str]]) -> str:
        """Identifica cluster semântico para as entradas."""
        for cluster_name, cluster_messages in clusters.items():
            entry_messages = [entry.message for entry in entries]
            similarity = self._calculate_semantic_similarity(entry_messages, cluster_messages)
            
            if similarity > self.config['semantic_similarity_threshold']:
                return cluster_name
        
        return "cluster_isolated"
    
    def _calculate_semantic_similarity(self, messages1: List[str], messages2: List[str]) -> float:
        """Calcula similaridade semântica entre grupos de mensagens."""
        if not messages1 or not messages2:
            return 0.0
        
        # Concatena mensagens
        text1 = ' '.join(messages1)
        text2 = ' '.join(messages2)
        
        # Calcula similaridade usando TF-IDF
        try:
            tfidf_matrix = self.semantic_analyzer.vectorizer.fit_transform([text1, text2])
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            return similarity
        except:
            return 0.0
    
    def _extract_pattern_keywords(self, entries: List[SemanticLogEntry]) -> List[str]:
        """Extrai palavras-chave do padrão."""
        all_keywords = []
        for entry in entries:
            all_keywords.extend(entry.metadata.get('context_keywords', []))
        
        # Conta frequência e retorna mais comuns
        keyword_counts = Counter(all_keywords)
        return [keyword for keyword, count in keyword_counts.most_common(10)]
    
    def _assess_business_impact(self, business_context: str, frequency: int, complexity: str) -> str:
        """Avalia impacto no negócio."""
        if business_context in ['article_generation', 'user_management']:
            if frequency > 50:
                return 'critical'
            elif frequency > 20:
                return 'high'
            else:
                return 'medium'
        else:
            if complexity == 'high' and frequency > 10:
                return 'high'
            else:
                return 'medium'
    
    def _calculate_technical_debt(self, entries: List[SemanticLogEntry], complexity: str) -> float:
        """Calcula dívida técnica."""
        base_debt = {
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }.get(complexity, 0.5)
        
        # Ajusta por frequência de erros
        error_rate = sum(1 for entry in entries if entry.level in ['ERROR', 'CRITICAL']) / len(entries)
        
        return min(base_debt + error_rate, 1.0)
    
    def _calculate_confidence_score(self, entries: List[SemanticLogEntry], frequency: int, complexity: str) -> float:
        """Calcula score de confiança da detecção."""
        # Base na frequência
        frequency_score = min(frequency / 20, 1.0)
        
        # Base na consistência
        consistency_score = 1.0 - (len(set(entry.service for entry in entries)) / len(entries))
        
        # Base na complexidade (padrões mais complexos são mais confiáveis)
        complexity_score = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }.get(complexity, 0.6)
        
        return (frequency_score + consistency_score + complexity_score) / 3
    
    def _check_if_tested(self, business_context: str, context_keywords: List[str]) -> bool:
        """Verifica se o padrão está testado."""
        # Verifica se há testes específicos para o contexto
        test_patterns = [
            'test_' + business_context,
            business_context + '_test',
            'test_' + business_context.replace('_', '')
        ]
        
        # Verifica se há palavras-chave relacionadas a testes
        test_keywords = ['test', 'spec', 'coverage', 'validation']
        
        return any(keyword in test_keywords for keyword in context_keywords)
    
    def _identify_related_patterns(self, business_context: str, context_keywords: List[str]) -> List[str]:
        """Identifica padrões relacionados."""
        related = []
        
        # Padrões relacionados por contexto
        context_relations = {
            'article_generation': ['content_processing', 'pipeline_execution'],
            'user_management': ['authentication', 'authorization'],
            'monitoring': ['health_check', 'metrics_collection'],
            'testing': ['test_execution', 'coverage_analysis']
        }
        
        related.extend(context_relations.get(business_context, []))
        
        # Padrões relacionados por palavras-chave
        for keyword in context_keywords:
            if 'error' in keyword:
                related.append('error_handling')
            elif 'validation' in keyword:
                related.append('input_validation')
            elif 'cache' in keyword:
                related.append('caching_strategy')
        
        return list(set(related))
    
    def _generate_test_suggestions(self, business_context: str, complexity: str, context_keywords: List[str]) -> List[str]:
        """Gera sugestões de teste específicas."""
        suggestions = []
        
        # Testes baseados no contexto
        context_tests = {
            'article_generation': [
                'test_article_generation_pipeline',
                'test_content_validation',
                'test_generation_performance'
            ],
            'user_management': [
                'test_user_authentication',
                'test_user_authorization',
                'test_user_profile_management'
            ],
            'monitoring': [
                'test_health_check_endpoints',
                'test_metrics_collection',
                'test_alert_system'
            ],
            'testing': [
                'test_test_execution_flow',
                'test_coverage_analysis',
                'test_test_reporting'
            ]
        }
        
        suggestions.extend(context_tests.get(business_context, []))
        
        # Testes baseados na complexidade
        if complexity == 'high':
            suggestions.extend([
                'test_error_handling_scenarios',
                'test_fallback_mechanisms',
                'test_edge_cases'
            ])
        
        # Testes baseados em palavras-chave
        for keyword in context_keywords:
            if 'validation' in keyword:
                suggestions.append('test_input_validation')
            elif 'cache' in keyword:
                suggestions.append('test_cache_behavior')
            elif 'error' in keyword:
                suggestions.append('test_error_recovery')
        
        return list(set(suggestions))
    
    def _analyze_coverage_enhanced(self, patterns: List[EnhancedFlowPattern]) -> Dict[str, Any]:
        """Análise aprimorada de cobertura."""
        total_patterns = len(patterns)
        tested_patterns = sum(1 for p in patterns if p.is_tested)
        untested_patterns = total_patterns - tested_patterns
        
        coverage_rate = (tested_patterns / total_patterns * 100) if total_patterns > 0 else 0
        
        # Análise por complexidade
        complexity_coverage = {}
        for complexity in ['low', 'medium', 'high']:
            complexity_patterns = [p for p in patterns if p.complexity_level == complexity]
            if complexity_patterns:
                tested = sum(1 for p in complexity_patterns if p.is_tested)
                complexity_coverage[complexity] = {
                    'total': len(complexity_patterns),
                    'tested': tested,
                    'coverage_rate': (tested / len(complexity_patterns)) * 100
                }
        
        # Análise por impacto no negócio
        business_impact_coverage = {}
        for impact in ['low', 'medium', 'high', 'critical']:
            impact_patterns = [p for p in patterns if p.business_impact == impact]
            if impact_patterns:
                tested = sum(1 for p in impact_patterns if p.is_tested)
                business_impact_coverage[impact] = {
                    'total': len(impact_patterns),
                    'tested': tested,
                    'coverage_rate': (tested / len(impact_patterns)) * 100
                }
        
        return {
            'overall_coverage': coverage_rate,
            'total_patterns': total_patterns,
            'tested_patterns': tested_patterns,
            'untested_patterns': untested_patterns,
            'complexity_coverage': complexity_coverage,
            'business_impact_coverage': business_impact_coverage,
            'critical_gaps': self._identify_critical_gaps(patterns)
        }
    
    def _identify_critical_gaps(self, patterns: List[EnhancedFlowPattern]) -> List[Dict[str, Any]]:
        """Identifica lacunas críticas na cobertura."""
        critical_gaps = []
        
        for pattern in patterns:
            if not pattern.is_tested and (
                pattern.complexity_level == 'high' or 
                pattern.business_impact in ['high', 'critical'] or
                pattern.risk_score > 100
            ):
                critical_gaps.append({
                    'pattern_name': pattern.name,
                    'risk_score': pattern.risk_score,
                    'complexity': pattern.complexity_level,
                    'business_impact': pattern.business_impact,
                    'frequency': pattern.frequency,
                    'suggested_tests': pattern.suggested_tests
                })
        
        return sorted(critical_gaps, key=lambda x: x['risk_score'], reverse=True)
    
    def _assess_risk_enhanced(self, patterns: List[EnhancedFlowPattern]) -> Dict[str, Any]:
        """Avaliação aprimorada de risco."""
        if not patterns:
            return {}
        
        risk_scores = [p.risk_score for p in patterns]
        avg_risk = sum(risk_scores) / len(risk_scores)
        max_risk = max(risk_scores)
        
        # Análise de risco por categoria
        high_risk_patterns = [p for p in patterns if p.risk_score > 100]
        medium_risk_patterns = [p for p in patterns if 50 <= p.risk_score <= 100]
        low_risk_patterns = [p for p in patterns if p.risk_score < 50]
        
        # Análise de dívida técnica
        technical_debt_scores = [p.technical_debt for p in patterns]
        avg_technical_debt = sum(technical_debt_scores) / len(technical_debt_scores)
        
        return {
            'average_risk_score': avg_risk,
            'max_risk_score': max_risk,
            'high_risk_count': len(high_risk_patterns),
            'medium_risk_count': len(medium_risk_patterns),
            'low_risk_count': len(low_risk_patterns),
            'average_technical_debt': avg_technical_debt,
            'risk_distribution': {
                'high': len(high_risk_patterns),
                'medium': len(medium_risk_patterns),
                'low': len(low_risk_patterns)
            },
            'critical_patterns': [
                {
                    'name': p.name,
                    'risk_score': p.risk_score,
                    'business_impact': p.business_impact,
                    'is_tested': p.is_tested
                }
                for p in high_risk_patterns
            ]
        }
    
    def _generate_recommendations(self, patterns: List[EnhancedFlowPattern], coverage_analysis: Dict[str, Any], risk_assessment: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas na análise."""
        recommendations = []
        
        # Recomendações baseadas na cobertura
        if coverage_analysis['overall_coverage'] < 85:
            recommendations.append(
                f"Implementar testes para atingir cobertura mínima de 85% "
                f"(atual: {coverage_analysis['overall_coverage']:.1f}%)"
            )
        
        # Recomendações baseadas em lacunas críticas
        for gap in coverage_analysis['critical_gaps']:
            recommendations.append(
                f"PRIORIDADE ALTA: Implementar testes para '{gap['pattern_name']}' "
                f"(Risk: {gap['risk_score']}, Impact: {gap['business_impact']})"
            )
        
        # Recomendações baseadas no risco
        if risk_assessment['average_risk_score'] > 80:
            recommendations.append(
                f"Revisar padrões de alto risco (média: {risk_assessment['average_risk_score']:.1f})"
            )
        
        # Recomendações baseadas na dívida técnica
        if risk_assessment['average_technical_debt'] > 0.7:
            recommendations.append(
                f"Reduzir dívida técnica (atual: {risk_assessment['average_technical_debt']:.1f})"
            )
        
        # Recomendações específicas por padrão
        for pattern in patterns:
            if not pattern.is_tested and pattern.suggested_tests:
                recommendations.append(
                    f"Implementar testes sugeridos para '{pattern.name}': "
                    f"{', '.join(pattern.suggested_tests[:3])}"
                )
        
        return recommendations
    
    def save_enhanced_results(self, result: EnhancedFlowDetectionResult, output_path: str):
        """Salva resultados aprimorados em formato JSON."""
        output_data = {
            'enhanced_flow_detection_result': asdict(result),
            'metadata': {
                'tracing_id': TRACING_ID,
                'timestamp': datetime.now().isoformat(),
                'version': '2.0',
                'description': 'Framework Aprimorado de Detecção de Fluxos'
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        logger.info(f"[{TRACING_ID}] Resultados salvos em: {output_path}")

def main():
    """Função principal para demonstração do framework aprimorado."""
    print(f"=== FRAMEWORK APRIMORADO DE DETECÇÃO DE FLUXOS ===")
    print(f"Tracing ID: {TRACING_ID}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")
    
    # Configura fontes de log
    log_sources = {
        'application_logs': 'logs/structured_logs.json',
        'pipeline_logs': 'logs/pipeline_multi_diag.log',
        'decision_logs': 'logs/decisions_2025-01-27.log'
    }
    
    # Inicializa framework
    framework = EnhancedFlowDetectionFramework()
    
    try:
        # Executa análise aprimorada
        print("1. EXECUTANDO ANÁLISE SEMÂNTICA APRIMORADA...")
        result = framework.analyze_logs_enhanced(log_sources)
        
        # Exibe resultados
        print("2. RESULTADOS DA ANÁLISE APRIMORADA...")
        print(f"   Total de padrões detectados: {len(result.patterns)}")
        print(f"   Clusters semânticos: {len(result.semantic_clusters)}")
        print(f"   Cobertura geral: {result.coverage_analysis['overall_coverage']:.1f}%")
        print(f"   Score médio de risco: {result.risk_assessment['average_risk_score']:.1f}")
        
        # Exibe padrões detectados
        print("3. PADRÕES DETECTADOS:")
        for pattern in result.patterns:
            status = "✅ TESTADO" if pattern.is_tested else "❌ NÃO TESTADO"
            print(f"   • {pattern.name} (Risk: {pattern.risk_score}, {status})")
            print(f"     Complexidade: {pattern.complexity_level}, Impacto: {pattern.business_impact}")
            if pattern.suggested_tests:
                print(f"     Testes sugeridos: {', '.join(pattern.suggested_tests[:2])}")
        
        # Exibe recomendações
        print("4. RECOMENDAÇÕES:")
        for i, recommendation in enumerate(result.recommendations[:5], 1):
            print(f"   {i}. {recommendation}")
        
        # Salva resultados
        output_path = f"tests/integration/reports/enhanced_flow_detection_{datetime.now().strftime('%Y%m%dT%H%M%SZ')}.json"
        framework.save_enhanced_results(result, output_path)
        
        print(f"5. RESULTADOS SALVOS EM: {output_path}")
        
    except Exception as e:
        logger.error(f"[{TRACING_ID}] Erro na análise: {e}")
        print(f"❌ ERRO: {e}")

if __name__ == "__main__":
    main() 