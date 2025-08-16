"""
Sensitivity Classification System
================================

Tracing ID: SENS_CLASS_20250127_001
Prompt: Item 14 - Sensitivity Classification
Ruleset: checklist_integracao_externa.md
Created: 2025-01-27T23:00:00Z

Sistema de classificação automática de dados por nível de sensibilidade,
baseado em NIST Cybersecurity Framework e ISO/IEC 27001.
"""

import json
import re
import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
import logging
from collections import defaultdict
import threading
import time

# Configuração de logging
logger = logging.getLogger(__name__)

class SensitivityLevel(Enum):
    """Níveis de sensibilidade baseados em NIST Cybersecurity Framework"""
    PUBLIC = "public"
    INTERNAL = "internal" 
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    CRITICAL = "critical"

@dataclass
class ClassificationResult:
    """Resultado da classificação de sensibilidade"""
    field_name: str
    field_value: str
    sensitivity_level: SensitivityLevel
    confidence_score: float
    classification_method: str
    context: Dict[str, Any]
    timestamp: datetime
    tracing_id: str
    false_positive_risk: float
    recommendations: List[str]

@dataclass
class SensitivityRule:
    """Regra de classificação de sensibilidade"""
    name: str
    patterns: List[str]
    sensitivity_level: SensitivityLevel
    weight: float
    context_required: bool
    false_positive_patterns: List[str]
    description: str

class SensitivityClassifier:
    """
    Classificador de sensibilidade com ML simples e validação de falsos positivos
    
    Baseado em:
    - NIST Cybersecurity Framework
    - ISO/IEC 27001
    - OWASP ASVS 1.2
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Inicializa o classificador de sensibilidade"""
        self.tracing_id = f"SENS_CLASS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger = logging.getLogger(f"{__name__}.{self.tracing_id}")
        
        # Cache de classificação
        self.classification_cache: Dict[str, ClassificationResult] = {}
        self.cache_ttl = timedelta(hours=1)
        self.cache_lock = threading.Lock()
        
        # Métricas de performance
        self.metrics = {
            'classifications_total': 0,
            'cache_hits': 0,
            'false_positives_detected': 0,
            'ml_classifications': 0,
            'rule_classifications': 0
        }
        self.metrics_lock = threading.Lock()
        
        # Carregar configuração
        self.config = self._load_config(config_path)
        
        # Inicializar regras
        self.rules = self._initialize_rules()
        
        # Inicializar ML simples
        self.ml_model = self._initialize_ml_model()
        
        # Thread de limpeza de cache
        self._start_cache_cleanup()
        
        self.logger.info(f"Sensitivity Classifier inicializado - Tracing ID: {self.tracing_id}")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Carrega configuração do classificador"""
        default_config = {
            'cache_enabled': True,
            'cache_ttl_hours': 1,
            'ml_enabled': True,
            'confidence_threshold': 0.7,
            'false_positive_threshold': 0.3,
            'max_field_length': 1000,
            'sensitive_services': [
                'payment', 'auth', 'user', 'admin', 'financial',
                'health', 'legal', 'compliance', 'security'
            ],
            'public_patterns': [
                r'public', r'published', r'announcement', r'news',
                r'blog', r'article', r'help', r'faq', r'about'
            ]
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    default_config.update(file_config)
            except Exception as e:
                self.logger.warning(f"Erro ao carregar config: {e}. Usando padrão.")
        
        return default_config
    
    def _initialize_rules(self) -> List[SensitivityRule]:
        """Inicializa regras de classificação baseadas em padrões"""
        rules = [
            # Regras CRÍTICAS
            SensitivityRule(
                name="API Keys",
                patterns=[r'api[_-]?key', r'secret[_-]?key', r'private[_-]?key'],
                sensitivity_level=SensitivityLevel.CRITICAL,
                weight=1.0,
                context_required=False,
                false_positive_patterns=[r'test', r'example', r'dummy'],
                description="Chaves de API são sempre críticas"
            ),
            SensitivityRule(
                name="Passwords",
                patterns=[r'password', r'senha', r'passwd', r'pwd'],
                sensitivity_level=SensitivityLevel.CRITICAL,
                weight=1.0,
                context_required=False,
                false_positive_patterns=[r'test', r'example', r'default'],
                description="Senhas são sempre críticas"
            ),
            SensitivityRule(
                name="Tokens",
                patterns=[r'token', r'jwt', r'bearer', r'access[_-]?token'],
                sensitivity_level=SensitivityLevel.CRITICAL,
                weight=0.9,
                context_required=True,
                false_positive_patterns=[r'test', r'example', r'placeholder'],
                description="Tokens de acesso são críticos"
            ),
            
            # Regras RESTRITAS
            SensitivityRule(
                name="Personal Data",
                patterns=[r'cpf', r'cnpj', r'ssn', r'credit[_-]?card', r'card[_-]?number'],
                sensitivity_level=SensitivityLevel.RESTRICTED,
                weight=0.9,
                context_required=True,
                false_positive_patterns=[r'test', r'example', r'1234'],
                description="Dados pessoais são restritos"
            ),
            SensitivityRule(
                name="Financial Data",
                patterns=[r'account[_-]?number', r'bank[_-]?account', r'balance', r'amount'],
                sensitivity_level=SensitivityLevel.RESTRICTED,
                weight=0.8,
                context_required=True,
                false_positive_patterns=[r'test', r'example', r'demo'],
                description="Dados financeiros são restritos"
            ),
            
            # Regras CONFIDENCIAIS
            SensitivityRule(
                name="Internal IDs",
                patterns=[r'user[_-]?id', r'customer[_-]?id', r'client[_-]?id'],
                sensitivity_level=SensitivityLevel.CONFIDENTIAL,
                weight=0.7,
                context_required=True,
                false_positive_patterns=[r'public', r'published'],
                description="IDs internos são confidenciais"
            ),
            SensitivityRule(
                name="Business Data",
                patterns=[r'revenue', r'profit', r'cost', r'budget', r'strategy'],
                sensitivity_level=SensitivityLevel.CONFIDENTIAL,
                weight=0.6,
                context_required=True,
                false_positive_patterns=[r'public', r'announcement'],
                description="Dados de negócio são confidenciais"
            ),
            
            # Regras INTERNAS
            SensitivityRule(
                name="Internal Config",
                patterns=[r'config', r'setting', r'parameter', r'option'],
                sensitivity_level=SensitivityLevel.INTERNAL,
                weight=0.5,
                context_required=True,
                false_positive_patterns=[r'public', r'published'],
                description="Configurações internas"
            ),
            
            # Regras PÚBLICAS
            SensitivityRule(
                name="Public Content",
                patterns=[r'title', r'description', r'content', r'text'],
                sensitivity_level=SensitivityLevel.PUBLIC,
                weight=0.3,
                context_required=True,
                false_positive_patterns=[r'private', r'secret', r'confidential'],
                description="Conteúdo público"
            )
        ]
        
        return rules
    
    def _initialize_ml_model(self) -> Dict[str, Any]:
        """Inicializa modelo ML simples baseado em frequência de palavras"""
        # Modelo simples baseado em TF-IDF conceitual
        model = {
            'sensitive_words': {
                'critical': ['secret', 'key', 'password', 'token', 'private', 'secure'],
                'restricted': ['personal', 'financial', 'credit', 'account', 'identity'],
                'confidential': ['internal', 'business', 'strategy', 'revenue', 'customer'],
                'internal': ['config', 'setting', 'parameter', 'option', 'admin'],
                'public': ['public', 'published', 'announcement', 'news', 'blog']
            },
            'word_weights': {},
            'context_weights': {
                'service_name': 0.8,
                'field_name': 0.6,
                'field_value': 0.4,
                'surrounding_context': 0.3
            }
        }
        
        # Calcular pesos das palavras
        for level, words in model['sensitive_words'].items():
            for word in words:
                model['word_weights'][word] = {
                    'critical': 1.0,
                    'restricted': 0.8,
                    'confidential': 0.6,
                    'internal': 0.4,
                    'public': 0.2
                }.get(level, 0.5)
        
        return model
    
    def classify_field(self, 
                      field_name: str, 
                      field_value: str, 
                      context: Optional[Dict[str, Any]] = None,
                      service_name: Optional[str] = None) -> ClassificationResult:
        """
        Classifica um campo por nível de sensibilidade
        
        Args:
            field_name: Nome do campo
            field_value: Valor do campo
            context: Contexto adicional (opcional)
            service_name: Nome do serviço (opcional)
        
        Returns:
            ClassificationResult com nível de sensibilidade e confiança
        """
        if context is None:
            context = {}
        
        # Verificar cache
        cache_key = self._generate_cache_key(field_name, field_value, context, service_name)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result
        
        # Classificação por regras
        rule_result = self._classify_by_rules(field_name, field_value, context, service_name)
        
        # Classificação por ML
        ml_result = self._classify_by_ml(field_name, field_value, context, service_name)
        
        # Combinar resultados
        final_result = self._combine_classifications(rule_result, ml_result, context)
        
        # Validar falsos positivos
        final_result = self._validate_false_positive(final_result, context, service_name)
        
        # Gerar recomendações
        final_result.recommendations = self._generate_recommendations(final_result, context)
        
        # Salvar no cache
        self._save_to_cache(cache_key, final_result)
        
        # Atualizar métricas
        self._update_metrics(final_result)
        
        return final_result
    
    def _classify_by_rules(self, 
                          field_name: str, 
                          field_value: str, 
                          context: Dict[str, Any],
                          service_name: Optional[str]) -> ClassificationResult:
        """Classifica usando regras baseadas em padrões"""
        best_match = None
        best_score = 0.0
        
        for rule in self.rules:
            # Verificar padrões no nome do campo
            field_match = any(re.search(pattern, field_name, re.IGNORECASE) 
                            for pattern in rule.patterns)
            
            # Verificar padrões no valor do campo
            value_match = any(re.search(pattern, field_value, re.IGNORECASE) 
                            for pattern in rule.patterns)
            
            # Verificar falsos positivos
            false_positive = any(re.search(pattern, field_name + " " + field_value, re.IGNORECASE)
                               for pattern in rule.false_positive_patterns)
            
            if false_positive:
                continue
            
            # Calcular score
            score = 0.0
            if field_match:
                score += rule.weight * 0.7
            if value_match:
                score += rule.weight * 0.3
            
            # Ajustar por contexto se necessário
            if rule.context_required and context:
                context_score = self._calculate_context_score(context, service_name)
                score *= context_score
            
            if score > best_score:
                best_score = score
                best_match = rule
        
        if best_match and best_score > 0.5:
            return ClassificationResult(
                field_name=field_name,
                field_value=field_value[:100] + "..." if len(field_value) > 100 else field_value,
                sensitivity_level=best_match.sensitivity_level,
                confidence_score=min(best_score, 1.0),
                classification_method="rules",
                context=context,
                timestamp=datetime.now(),
                tracing_id=self.tracing_id,
                false_positive_risk=self._calculate_false_positive_risk(best_match, context),
                recommendations=[]
            )
        
        # Fallback para interno
        return ClassificationResult(
            field_name=field_name,
            field_value=field_value[:100] + "..." if len(field_value) > 100 else field_value,
            sensitivity_level=SensitivityLevel.INTERNAL,
            confidence_score=0.3,
            classification_method="rules_fallback",
            context=context,
            timestamp=datetime.now(),
            tracing_id=self.tracing_id,
            false_positive_risk=0.1,
            recommendations=[]
        )
    
    def _classify_by_ml(self, 
                       field_name: str, 
                       field_value: str, 
                       context: Dict[str, Any],
                       service_name: Optional[str]) -> ClassificationResult:
        """Classifica usando modelo ML simples"""
        if not self.config['ml_enabled']:
            return None
        
        # Extrair features
        features = self._extract_features(field_name, field_value, context, service_name)
        
        # Calcular scores para cada nível
        scores = {}
        for level in SensitivityLevel:
            scores[level] = self._calculate_ml_score(features, level)
        
        # Encontrar melhor nível
        best_level = max(scores, key=scores.get)
        best_score = scores[best_level]
        
        if best_score > self.config['confidence_threshold']:
            return ClassificationResult(
                field_name=field_name,
                field_value=field_value[:100] + "..." if len(field_value) > 100 else field_value,
                sensitivity_level=best_level,
                confidence_score=best_score,
                classification_method="ml",
                context=context,
                timestamp=datetime.now(),
                tracing_id=self.tracing_id,
                false_positive_risk=self._calculate_ml_false_positive_risk(features),
                recommendations=[]
            )
        
        return None
    
    def _extract_features(self, 
                         field_name: str, 
                         field_value: str, 
                         context: Dict[str, Any],
                         service_name: Optional[str]) -> Dict[str, float]:
        """Extrai features para o modelo ML"""
        features = {}
        
        # Features do nome do campo
        field_lower = field_name.lower()
        for level, words in self.ml_model['sensitive_words'].items():
            for word in words:
                if word in field_lower:
                    features[f"field_{word}"] = 1.0
        
        # Features do valor do campo
        value_lower = field_value.lower()
        for level, words in self.ml_model['sensitive_words'].items():
            for word in words:
                if word in value_lower:
                    features[f"value_{word}"] = 1.0
        
        # Features de contexto
        if service_name:
            service_lower = service_name.lower()
            for level, words in self.ml_model['sensitive_words'].items():
                for word in words:
                    if word in service_lower:
                        features[f"service_{word}"] = 1.0
        
        # Features de comprimento e formato
        features['field_length'] = len(field_value) / 1000.0  # Normalizado
        features['has_special_chars'] = 1.0 if re.search(r'[!@#$%^&*()]', field_value) else 0.0
        features['has_numbers'] = 1.0 if re.search(r'\d', field_value) else 0.0
        features['has_uppercase'] = 1.0 if re.search(r'[A-Z]', field_value) else 0.0
        
        return features
    
    def _calculate_ml_score(self, features: Dict[str, float], level: SensitivityLevel) -> float:
        """Calcula score ML para um nível específico"""
        score = 0.0
        level_words = self.ml_model['sensitive_words'].get(level.value, [])
        
        for word in level_words:
            field_feature = features.get(f"field_{word}", 0.0)
            value_feature = features.get(f"value_{word}", 0.0)
            service_feature = features.get(f"service_{word}", 0.0)
            
            score += (field_feature * 0.4 + 
                     value_feature * 0.3 + 
                     service_feature * 0.3) * self.ml_model['word_weights'].get(word, 0.5)
        
        # Ajustar por features gerais
        if features.get('has_special_chars', 0.0) > 0:
            score *= 1.2
        if features.get('has_numbers', 0.0) > 0:
            score *= 1.1
        
        return min(score, 1.0)
    
    def _combine_classifications(self, 
                               rule_result: ClassificationResult,
                               ml_result: Optional[ClassificationResult],
                               context: Dict[str, Any]) -> ClassificationResult:
        """Combina resultados de regras e ML"""
        if not ml_result:
            return rule_result
        
        # Peso maior para regras (mais confiáveis)
        rule_weight = 0.7
        ml_weight = 0.3
        
        # Combinar confidence scores
        combined_confidence = (rule_result.confidence_score * rule_weight + 
                             ml_result.confidence_score * ml_weight)
        
        # Escolher nível baseado em confiança
        if rule_result.confidence_score > ml_result.confidence_score:
            final_level = rule_result.sensitivity_level
            final_method = "rules_ml_combined"
        else:
            final_level = ml_result.sensitivity_level
            final_method = "ml_rules_combined"
        
        return ClassificationResult(
            field_name=rule_result.field_name,
            field_value=rule_result.field_value,
            sensitivity_level=final_level,
            confidence_score=combined_confidence,
            classification_method=final_method,
            context=context,
            timestamp=datetime.now(),
            tracing_id=self.tracing_id,
            false_positive_risk=(rule_result.false_positive_risk * rule_weight + 
                               ml_result.false_positive_risk * ml_weight),
            recommendations=[]
        )
    
    def _validate_false_positive(self, 
                                result: ClassificationResult,
                                context: Dict[str, Any],
                                service_name: Optional[str]) -> ClassificationResult:
        """Valida se a classificação é um falso positivo"""
        false_positive_risk = result.false_positive_risk
        
        # Verificar contexto de desenvolvimento
        if context.get('environment') in ['dev', 'test', 'staging']:
            false_positive_risk *= 1.5
        
        # Verificar padrões de teste
        if any(word in result.field_value.lower() for word in ['test', 'example', 'dummy', 'mock']):
            false_positive_risk *= 2.0
        
        # Verificar se é conteúdo público
        if any(re.search(pattern, result.field_name + " " + result.field_value, re.IGNORECASE)
               for pattern in self.config['public_patterns']):
            false_positive_risk *= 1.8
        
        # Ajustar nível se risco de falso positivo for alto
        if false_positive_risk > self.config['false_positive_threshold']:
            # Reduzir um nível
            level_mapping = {
                SensitivityLevel.CRITICAL: SensitivityLevel.RESTRICTED,
                SensitivityLevel.RESTRICTED: SensitivityLevel.CONFIDENTIAL,
                SensitivityLevel.CONFIDENTIAL: SensitivityLevel.INTERNAL,
                SensitivityLevel.INTERNAL: SensitivityLevel.PUBLIC,
                SensitivityLevel.PUBLIC: SensitivityLevel.PUBLIC
            }
            
            result.sensitivity_level = level_mapping.get(result.sensitivity_level, SensitivityLevel.INTERNAL)
            result.confidence_score *= 0.8
            result.false_positive_risk = false_positive_risk
            
            self.logger.info(f"Falso positivo detectado - {result.field_name} reclassificado para {result.sensitivity_level.value}")
        
        return result
    
    def _generate_recommendations(self, 
                                result: ClassificationResult,
                                context: Dict[str, Any]) -> List[str]:
        """Gera recomendações baseadas na classificação"""
        recommendations = []
        
        if result.sensitivity_level == SensitivityLevel.CRITICAL:
            recommendations.extend([
                "Aplicar criptografia em repouso e em trânsito",
                "Implementar controle de acesso rigoroso",
                "Auditoria completa de acesso",
                "Rotação automática de credenciais"
            ])
        elif result.sensitivity_level == SensitivityLevel.RESTRICTED:
            recommendations.extend([
                "Aplicar criptografia em trânsito",
                "Implementar controle de acesso baseado em roles",
                "Logging de acesso detalhado",
                "Validação de entrada rigorosa"
            ])
        elif result.sensitivity_level == SensitivityLevel.CONFIDENTIAL:
            recommendations.extend([
                "Implementar controle de acesso",
                "Logging de acesso",
                "Validação de entrada"
            ])
        elif result.sensitivity_level == SensitivityLevel.INTERNAL:
            recommendations.extend([
                "Validação de entrada básica",
                "Logging de acesso básico"
            ])
        
        # Recomendações específicas por contexto
        if context.get('service_name') in ['payment', 'financial']:
            recommendations.append("Implementar compliance PCI-DSS")
        
        if context.get('service_name') in ['auth', 'user']:
            recommendations.append("Implementar autenticação multi-fator")
        
        return recommendations
    
    def _calculate_context_score(self, context: Dict[str, Any], service_name: Optional[str]) -> float:
        """Calcula score baseado no contexto"""
        score = 1.0
        
        # Ajustar por serviço
        if service_name:
            service_lower = service_name.lower()
            if any(sensitive in service_lower for sensitive in self.config['sensitive_services']):
                score *= 1.3
        
        # Ajustar por ambiente
        environment = context.get('environment', 'production')
        if environment in ['dev', 'test']:
            score *= 0.7
        
        return score
    
    def _calculate_false_positive_risk(self, rule: SensitivityRule, context: Dict[str, Any]) -> float:
        """Calcula risco de falso positivo para uma regra"""
        risk = 0.1  # Base
        
        # Ajustar por contexto de desenvolvimento
        if context.get('environment') in ['dev', 'test']:
            risk += 0.3
        
        # Ajustar por padrões de teste
        if any(word in rule.name.lower() for word in ['test', 'example']):
            risk += 0.2
        
        return min(risk, 1.0)
    
    def _calculate_ml_false_positive_risk(self, features: Dict[str, float]) -> float:
        """Calcula risco de falso positivo para classificação ML"""
        risk = 0.1  # Base
        
        # Ajustar por features que indicam teste
        if features.get('field_test', 0.0) > 0:
            risk += 0.4
        if features.get('value_test', 0.0) > 0:
            risk += 0.3
        
        return min(risk, 1.0)
    
    def _generate_cache_key(self, 
                           field_name: str, 
                           field_value: str, 
                           context: Dict[str, Any],
                           service_name: Optional[str]) -> str:
        """Gera chave única para cache"""
        content = f"{field_name}:{field_value[:50]}:{service_name}:{json.dumps(context, sort_keys=True)}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_from_cache(self, cache_key: str) -> Optional[ClassificationResult]:
        """Obtém resultado do cache"""
        if not self.config['cache_enabled']:
            return None
        
        with self.cache_lock:
            if cache_key in self.classification_cache:
                result = self.classification_cache[cache_key]
                if datetime.now() - result.timestamp < self.cache_ttl:
                    self.metrics['cache_hits'] += 1
                    return result
                else:
                    del self.classification_cache[cache_key]
        
        return None
    
    def _save_to_cache(self, cache_key: str, result: ClassificationResult):
        """Salva resultado no cache"""
        if not self.config['cache_enabled']:
            return
        
        with self.cache_lock:
            self.classification_cache[cache_key] = result
    
    def _update_metrics(self, result: ClassificationResult):
        """Atualiza métricas de performance"""
        with self.metrics_lock:
            self.metrics['classifications_total'] += 1
            
            if 'ml' in result.classification_method:
                self.metrics['ml_classifications'] += 1
            else:
                self.metrics['rule_classifications'] += 1
            
            if result.false_positive_risk > self.config['false_positive_threshold']:
                self.metrics['false_positives_detected'] += 1
    
    def _start_cache_cleanup(self):
        """Inicia thread de limpeza de cache"""
        def cleanup():
            while True:
                time.sleep(300)  # 5 minutos
                self._cleanup_cache()
        
        cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_cache(self):
        """Remove entradas expiradas do cache"""
        with self.cache_lock:
            current_time = datetime.now()
            expired_keys = [
                key for key, result in self.classification_cache.items()
                if current_time - result.timestamp > self.cache_ttl
            ]
            
            for key in expired_keys:
                del self.classification_cache[key]
            
            if expired_keys:
                self.logger.info(f"Cache limpo: {len(expired_keys)} entradas removidas")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas de performance"""
        with self.metrics_lock:
            return self.metrics.copy()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do cache"""
        with self.cache_lock:
            return {
                'cache_size': len(self.classification_cache),
                'cache_ttl_hours': self.cache_ttl.total_seconds() / 3600,
                'cache_enabled': self.config['cache_enabled']
            }
    
    def export_classifications(self, 
                             format: str = 'json',
                             include_hashes: bool = True) -> str:
        """Exporta classificações em diferentes formatos"""
        classifications = []
        
        with self.cache_lock:
            for result in self.classification_cache.values():
                data = asdict(result)
                data['timestamp'] = data['timestamp'].isoformat()
                data['sensitivity_level'] = data['sensitivity_level'].value
                
                if not include_hashes:
                    data.pop('field_value', None)
                
                classifications.append(data)
        
        if format.lower() == 'json':
            return json.dumps(classifications, indent=2, ensure_ascii=False)
        elif format.lower() == 'csv':
            if not classifications:
                return ""
            
            headers = list(classifications[0].keys())
            csv_lines = [','.join(headers)]
            
            for item in classifications:
                row = [str(item.get(header, '')) for header in headers]
                csv_lines.append(','.join(row))
            
            return '\n'.join(csv_lines)
        else:
            raise ValueError(f"Formato não suportado: {format}")
    
    def search_classifications(self, 
                             service_name: Optional[str] = None,
                             sensitivity_level: Optional[SensitivityLevel] = None,
                             field_name: Optional[str] = None,
                             tracing_id: Optional[str] = None) -> List[ClassificationResult]:
        """Busca classificações por critérios"""
        results = []
        
        with self.cache_lock:
            for result in self.classification_cache.values():
                if service_name and service_name not in str(result.context.get('service_name', '')):
                    continue
                
                if sensitivity_level and result.sensitivity_level != sensitivity_level:
                    continue
                
                if field_name and field_name.lower() not in result.field_name.lower():
                    continue
                
                if tracing_id and result.tracing_id != tracing_id:
                    continue
                
                results.append(result)
        
        return results
    
    def get_sensitivity_summary(self) -> Dict[str, Any]:
        """Retorna resumo de classificações por nível de sensibilidade"""
        summary = defaultdict(int)
        
        with self.cache_lock:
            for result in self.classification_cache.values():
                summary[result.sensitivity_level.value] += 1
        
        return dict(summary)
    
    def validate_classification(self, 
                              field_name: str, 
                              field_value: str,
                              expected_level: SensitivityLevel,
                              context: Optional[Dict[str, Any]] = None) -> bool:
        """Valida se a classificação está correta"""
        result = self.classify_field(field_name, field_value, context or {})
        return result.sensitivity_level == expected_level
    
    def __str__(self) -> str:
        """Representação string do classificador"""
        metrics = self.get_metrics()
        cache_stats = self.get_cache_stats()
        summary = self.get_sensitivity_summary()
        
        return f"""SensitivityClassifier(
    tracing_id={self.tracing_id},
    metrics={metrics},
    cache_stats={cache_stats},
    sensitivity_summary={summary}
)"""


# Função de conveniência para uso rápido
def classify_data_sensitivity(field_name: str, 
                            field_value: str,
                            context: Optional[Dict[str, Any]] = None,
                            service_name: Optional[str] = None) -> ClassificationResult:
    """
    Função de conveniência para classificação rápida de dados
    
    Args:
        field_name: Nome do campo
        field_value: Valor do campo
        context: Contexto adicional (opcional)
        service_name: Nome do serviço (opcional)
    
    Returns:
        ClassificationResult com nível de sensibilidade
    """
    classifier = SensitivityClassifier()
    return classifier.classify_field(field_name, field_value, context, service_name)


if __name__ == "__main__":
    # Exemplo de uso
    classifier = SensitivityClassifier()
    
    # Teste de classificação
    test_cases = [
        ("api_key", "sk_test_1234567890abcdef", {"environment": "test"}, "payment"),
        ("user_password", "mypassword123", {"environment": "production"}, "auth"),
        ("customer_name", "João Silva", {"environment": "production"}, "user"),
        ("blog_title", "Como usar APIs", {"environment": "production"}, "content"),
        ("config_database_url", "postgresql://user:pass@localhost/db", {"environment": "dev"}, "config")
    ]
    
    print("=== Teste de Classificação de Sensibilidade ===\n")
    
    for field_name, field_value, context, service_name in test_cases:
        result = classifier.classify_field(field_name, field_value, context, service_name)
        
        print(f"Campo: {field_name}")
        print(f"Valor: {field_value[:30]}...")
        print(f"Nível: {result.sensitivity_level.value}")
        print(f"Confiança: {result.confidence_score:.2f}")
        print(f"Método: {result.classification_method}")
        print(f"Risco Falso Positivo: {result.false_positive_risk:.2f}")
        print(f"Recomendações: {len(result.recommendations)}")
        print("-" * 50)
    
    print(f"\nMétricas: {classifier.get_metrics()}")
    print(f"Cache Stats: {classifier.get_cache_stats()}")
    print(f"Resumo: {classifier.get_sensitivity_summary()}") 