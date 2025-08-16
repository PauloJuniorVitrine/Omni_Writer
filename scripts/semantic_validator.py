#!/usr/bin/env python3
"""
🧠 SEMANTIC VALIDATOR - Sistema de Validação Semântica com Embeddings
Tracing ID: SEMANTIC_VALIDATOR_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Implementar validação semântica usando embeddings para detectar
divergências de significado em campos, além da validação sintática tradicional.
"""

import json
import re
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import pickle

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s',
    handlers=[
        logging.FileHandler('logs/semantic_validator.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('semantic_validator')

@dataclass
class SemanticField:
    """Estrutura para campo com análise semântica."""
    field_name: str
    field_type: str
    description: str
    semantic_vector: Optional[np.ndarray] = None
    semantic_hash: Optional[str] = None
    synonyms: List[str] = None
    related_fields: List[str] = None
    
    def __post_init__(self):
        """Inicializa listas se None."""
        if self.synonyms is None:
            self.synonyms = []
        if self.related_fields is None:
            self.related_fields = []

@dataclass
class SemanticValidationResult:
    """Resultado de validação semântica."""
    field_name: str
    is_semantically_valid: bool
    confidence_score: float
    detected_issues: List[str]
    suggestions: List[str]
    semantic_similarity: Optional[float] = None
    compared_with: Optional[str] = None

@dataclass
class SemanticDriftReport:
    """Relatório de divergência semântica."""
    schema_name: str
    drift_detected: bool
    drift_score: float
    affected_fields: List[str]
    drift_details: List[Dict[str, Any]]
    timestamp: datetime
    recommendations: List[str]

class SemanticValidator:
    """
    Validador semântico usando embeddings para análise de campos.
    
    Funcionalidades:
    - Gera embeddings para campos e descrições
    - Detecta divergências semânticas
    - Identifica campos relacionados
    - Sugere melhorias baseadas em semântica
    """
    
    def __init__(self, 
                 similarity_threshold: float = 0.7,
                 cache_embeddings: bool = True,
                 model_path: str = "models/semantic_validator.pkl"):
        """
        Inicializa o validador semântico.
        
        Args:
            similarity_threshold: Threshold para similaridade semântica
            cache_embeddings: Se deve cachear embeddings
            model_path: Caminho para salvar/carregar modelo
        """
        self.similarity_threshold = similarity_threshold
        self.cache_embeddings = cache_embeddings
        self.model_path = Path(model_path)
        
        # Inicializa vetorizador TF-IDF
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2),
            min_df=1
        )
        
        # Cache de embeddings
        self.embedding_cache: Dict[str, np.ndarray] = {}
        self.field_cache: Dict[str, SemanticField] = {}
        
        # Padrões semânticos conhecidos
        self.semantic_patterns = self._load_semantic_patterns()
        self.field_synonyms = self._load_field_synonyms()
        
        # Carrega modelo se existir
        self._load_model()
        
        logger.info(f"SemanticValidator inicializado - Threshold: {similarity_threshold}")
    
    def _load_semantic_patterns(self) -> Dict[str, List[str]]:
        """Carrega padrões semânticos conhecidos."""
        return {
            'identification': [
                'id', 'identifier', 'uuid', 'guid', 'key', 'primary_key',
                'identificador', 'chave', 'código'
            ],
            'user_data': [
                'user', 'usuario', 'person', 'pessoa', 'account', 'conta',
                'profile', 'perfil', 'customer', 'cliente'
            ],
            'contact': [
                'email', 'phone', 'telephone', 'contact', 'address',
                'endereço', 'telefone', 'contato'
            ],
            'temporal': [
                'date', 'time', 'timestamp', 'created', 'updated', 'modified',
                'data', 'hora', 'criado', 'atualizado'
            ],
            'content': [
                'title', 'content', 'body', 'text', 'description', 'message',
                'título', 'conteúdo', 'corpo', 'descrição'
            ],
            'status': [
                'status', 'state', 'condition', 'active', 'enabled', 'valid',
                'estado', 'condição', 'ativo', 'válido'
            ],
            'quantity': [
                'count', 'number', 'amount', 'quantity', 'size', 'length',
                'contagem', 'número', 'quantidade', 'tamanho'
            ],
            'file': [
                'file', 'document', 'attachment', 'upload', 'download',
                'arquivo', 'documento', 'anexo'
            ],
            'location': [
                'location', 'place', 'address', 'city', 'country', 'region',
                'localização', 'lugar', 'cidade', 'país'
            ],
            'category': [
                'category', 'type', 'class', 'group', 'tag', 'label',
                'categoria', 'tipo', 'classe', 'grupo'
            ]
        }
    
    def _load_field_synonyms(self) -> Dict[str, List[str]]:
        """Carrega sinônimos conhecidos para campos."""
        return {
            'user_id': ['user_identifier', 'user_key', 'account_id', 'person_id'],
            'email': ['email_address', 'mail', 'e_mail', 'correio'],
            'created_at': ['created_date', 'creation_time', 'created_timestamp'],
            'updated_at': ['modified_at', 'last_updated', 'updated_timestamp'],
            'title': ['name', 'heading', 'subject', 'título'],
            'content': ['body', 'text', 'message', 'conteúdo'],
            'status': ['state', 'condition', 'estado'],
            'count': ['number', 'quantity', 'amount', 'quantidade'],
            'file': ['document', 'attachment', 'arquivo'],
            'category': ['type', 'class', 'group', 'categoria']
        }
    
    def _load_model(self) -> None:
        """Carrega modelo salvo se existir."""
        try:
            if self.model_path.exists():
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.vectorizer = model_data.get('vectorizer', self.vectorizer)
                    self.embedding_cache = model_data.get('embedding_cache', {})
                    self.field_cache = model_data.get('field_cache', {})
                logger.info(f"Modelo carregado de {self.model_path}")
        except Exception as e:
            logger.warning(f"Erro ao carregar modelo: {e}")
    
    def _save_model(self) -> None:
        """Salva modelo atual."""
        try:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            model_data = {
                'vectorizer': self.vectorizer,
                'embedding_cache': self.embedding_cache,
                'field_cache': self.field_cache
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Modelo salvo em {self.model_path}")
        except Exception as e:
            logger.error(f"Erro ao salvar modelo: {e}")
    
    def _generate_semantic_hash(self, text: str) -> str:
        """Gera hash semântico para cache."""
        return hashlib.md5(text.lower().encode()).hexdigest()
    
    def _get_embedding(self, text: str) -> np.ndarray:
        """
        Gera embedding para texto.
        
        Args:
            text: Texto para gerar embedding
            
        Returns:
            Vetor de embedding
        """
        # Verifica cache
        text_hash = self._generate_semantic_hash(text)
        if text_hash in self.embedding_cache:
            return self.embedding_cache[text_hash]
        
        # Gera embedding
        try:
            # Usa TF-IDF para gerar vetor
            vector = self.vectorizer.fit_transform([text]).toarray()[0]
            
            # Cache se habilitado
            if self.cache_embeddings:
                self.embedding_cache[text_hash] = vector
            
            return vector
        except Exception as e:
            logger.error(f"Erro ao gerar embedding para '{text}': {e}")
            return np.zeros(1000)  # Vetor zero como fallback
    
    def _calculate_semantic_similarity(self, text1: str, text2: str) -> float:
        """
        Calcula similaridade semântica entre dois textos.
        
        Args:
            text1: Primeiro texto
            text2: Segundo texto
            
        Returns:
            Score de similaridade (0-1)
        """
        try:
            # Gera embeddings
            embedding1 = self._get_embedding(text1)
            embedding2 = self._get_embedding(text2)
            
            # Calcula similaridade cosseno
            similarity = cosine_similarity([embedding1], [embedding2])[0][0]
            
            return float(similarity)
        except Exception as e:
            logger.error(f"Erro ao calcular similaridade: {e}")
            return 0.0
    
    def _detect_semantic_category(self, field_name: str, description: str) -> str:
        """
        Detecta categoria semântica de um campo.
        
        Args:
            field_name: Nome do campo
            description: Descrição do campo
            
        Returns:
            Categoria semântica detectada
        """
        combined_text = f"{field_name} {description}".lower()
        
        best_category = "unknown"
        best_score = 0.0
        
        for category, patterns in self.semantic_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern in combined_text:
                    score += 1
            
            if score > best_score:
                best_score = score
                best_category = category
        
        return best_category
    
    def _find_synonyms(self, field_name: str) -> List[str]:
        """
        Encontra sinônimos para um campo.
        
        Args:
            field_name: Nome do campo
            
        Returns:
            Lista de sinônimos
        """
        return self.field_synonyms.get(field_name, [])
    
    def _find_related_fields(self, field_name: str, all_fields: List[SemanticField]) -> List[str]:
        """
        Encontra campos relacionados semanticamente.
        
        Args:
            field_name: Nome do campo
            all_fields: Lista de todos os campos
            
        Returns:
            Lista de campos relacionados
        """
        related = []
        field_semantic = next((f for f in all_fields if f.field_name == field_name), None)
        
        if field_semantic and field_semantic.semantic_vector is not None:
            for other_field in all_fields:
                if other_field.field_name != field_name and other_field.semantic_vector is not None:
                    similarity = cosine_similarity(
                        [field_semantic.semantic_vector], 
                        [other_field.semantic_vector]
                    )[0][0]
                    
                    if similarity > self.similarity_threshold:
                        related.append(other_field.field_name)
        
        return related
    
    def analyze_field_semantics(self, 
                               field_name: str, 
                               field_type: str, 
                               description: str) -> SemanticField:
        """
        Analisa semântica de um campo.
        
        Args:
            field_name: Nome do campo
            field_type: Tipo do campo
            description: Descrição do campo
            
        Returns:
            Campo com análise semântica
        """
        # Gera embedding
        combined_text = f"{field_name} {field_type} {description}"
        semantic_vector = self._get_embedding(combined_text)
        semantic_hash = self._generate_semantic_hash(combined_text)
        
        # Detecta categoria
        category = self._detect_semantic_category(field_name, description)
        
        # Encontra sinônimos
        synonyms = self._find_synonyms(field_name)
        
        semantic_field = SemanticField(
            field_name=field_name,
            field_type=field_type,
            description=description,
            semantic_vector=semantic_vector,
            semantic_hash=semantic_hash,
            synonyms=synonyms,
            related_fields=[]
        )
        
        # Cache se habilitado
        if self.cache_embeddings:
            self.field_cache[field_name] = semantic_field
        
        return semantic_field
    
    def validate_field_semantics(self, 
                                field: SemanticField, 
                                reference_fields: List[SemanticField]) -> SemanticValidationResult:
        """
        Valida semântica de um campo contra campos de referência.
        
        Args:
            field: Campo a ser validado
            reference_fields: Campos de referência
            
        Returns:
            Resultado da validação semântica
        """
        issues = []
        suggestions = []
        best_similarity = 0.0
        best_match = None
        
        # Compara com campos de referência
        for ref_field in reference_fields:
            if ref_field.field_name != field.field_name:
                similarity = self._calculate_semantic_similarity(
                    f"{field.field_name} {field.description}",
                    f"{ref_field.field_name} {ref_field.description}"
                )
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = ref_field.field_name
        
        # Detecta problemas semânticos
        if best_similarity > 0.9:
            issues.append(f"Campo muito similar a '{best_match}' (similaridade: {best_similarity:.2f})")
            suggestions.append(f"Considere unificar com '{best_match}' ou diferenciar melhor")
        
        elif best_similarity > 0.7:
            suggestions.append(f"Campo similar a '{best_match}' - verifique se são realmente diferentes")
        
        # Verifica se descrição é adequada
        if len(field.description) < 20:
            issues.append("Descrição muito curta para análise semântica adequada")
            suggestions.append("Expanda a descrição para melhor compreensão semântica")
        
        # Verifica se tipo é apropriado
        if field.field_type == 'string' and any(word in field.field_name.lower() for word in ['count', 'number', 'amount']):
            issues.append("Campo numérico definido como string")
            suggestions.append("Considere usar tipo 'integer' ou 'number'")
        
        # Determina se é semanticamente válido
        is_valid = len(issues) == 0
        confidence_score = 1.0 - (len(issues) * 0.2)  # Reduz confiança baseado no número de issues
        
        return SemanticValidationResult(
            field_name=field.field_name,
            is_semantically_valid=is_valid,
            confidence_score=max(0.0, confidence_score),
            detected_issues=issues,
            suggestions=suggestions,
            semantic_similarity=best_similarity,
            compared_with=best_match
        )
    
    def detect_semantic_drift(self, 
                             current_schema: List[SemanticField], 
                             reference_schema: List[SemanticField],
                             schema_name: str) -> SemanticDriftReport:
        """
        Detecta divergência semântica entre schemas.
        
        Args:
            current_schema: Schema atual
            reference_schema: Schema de referência
            schema_name: Nome do schema
            
        Returns:
            Relatório de divergência semântica
        """
        drift_details = []
        affected_fields = []
        total_drift_score = 0.0
        
        # Analisa cada campo atual
        for current_field in current_schema:
            # Encontra campo correspondente na referência
            ref_field = next(
                (f for f in reference_schema if f.field_name == current_field.field_name), 
                None
            )
            
            if ref_field:
                # Calcula divergência
                similarity = self._calculate_semantic_similarity(
                    f"{current_field.field_name} {current_field.description}",
                    f"{ref_field.field_name} {ref_field.description}"
                )
                
                drift_score = 1.0 - similarity
                
                if drift_score > 0.3:  # Threshold para drift significativo
                    drift_details.append({
                        'field_name': current_field.field_name,
                        'drift_score': drift_score,
                        'similarity': similarity,
                        'current_description': current_field.description,
                        'reference_description': ref_field.description
                    })
                    affected_fields.append(current_field.field_name)
                    total_drift_score += drift_score
            else:
                # Campo novo - drift potencial
                drift_details.append({
                    'field_name': current_field.field_name,
                    'drift_score': 0.5,  # Score médio para campos novos
                    'similarity': 0.0,
                    'current_description': current_field.description,
                    'reference_description': 'N/A (campo novo)'
                })
                affected_fields.append(current_field.field_name)
                total_drift_score += 0.5
        
        # Calcula score médio de drift
        avg_drift_score = total_drift_score / len(current_schema) if current_schema else 0.0
        drift_detected = avg_drift_score > 0.2  # Threshold para drift geral
        
        # Gera recomendações
        recommendations = []
        if drift_detected:
            recommendations.append(f"Drift semântico detectado (score: {avg_drift_score:.2f})")
            recommendations.append(f"Campos afetados: {', '.join(affected_fields[:5])}")
            
            if len(affected_fields) > 5:
                recommendations.append(f"... e mais {len(affected_fields) - 5} campos")
        
        return SemanticDriftReport(
            schema_name=schema_name,
            drift_detected=drift_detected,
            drift_score=avg_drift_score,
            affected_fields=affected_fields,
            drift_details=drift_details,
            timestamp=datetime.now(),
            recommendations=recommendations
        )
    
    def analyze_schema_semantics(self, schema_data: Dict[str, Any], schema_name: str) -> List[SemanticField]:
        """
        Analisa semântica de um schema completo.
        
        Args:
            schema_data: Dados do schema
            schema_name: Nome do schema
            
        Returns:
            Lista de campos com análise semântica
        """
        semantic_fields = []
        properties = schema_data.get('properties', {})
        
        for field_name, field_data in properties.items():
            field_type = field_data.get('type', 'string')
            description = field_data.get('description', '')
            
            semantic_field = self.analyze_field_semantics(field_name, field_type, description)
            semantic_fields.append(semantic_field)
        
        # Encontra campos relacionados
        for field in semantic_fields:
            field.related_fields = self._find_related_fields(field.field_name, semantic_fields)
        
        return semantic_fields
    
    def generate_semantic_report(self, 
                                schemas_path: str = "shared/schemas/") -> Dict[str, Any]:
        """
        Gera relatório semântico para todos os schemas.
        
        Args:
            schemas_path: Caminho para schemas
            
        Returns:
            Relatório estruturado
        """
        schemas_dir = Path(schemas_path)
        schema_files = list(schemas_dir.glob('*.json')) + list(schemas_dir.glob('*.yaml')) + list(schemas_dir.glob('*.yml'))
        
        all_semantic_fields = []
        validation_results = []
        
        for schema_file in schema_files:
            try:
                with open(schema_file, 'r', encoding='utf-8') as f:
                    if schema_file.suffix == '.json':
                        schema_data = json.load(f)
                    else:
                        import yaml
                        schema_data = yaml.safe_load(f)
                
                schema_name = schema_file.stem
                semantic_fields = self.analyze_schema_semantics(schema_data, schema_name)
                
                # Valida campos
                for field in semantic_fields:
                    validation_result = self.validate_field_semantics(field, semantic_fields)
                    validation_results.append(validation_result)
                
                all_semantic_fields.extend(semantic_fields)
                
            except Exception as e:
                logger.error(f"Erro ao processar schema {schema_file}: {e}")
        
        # Calcula métricas
        total_fields = len(all_semantic_fields)
        valid_fields = len([r for r in validation_results if r.is_semantically_valid])
        avg_confidence = sum(r.confidence_score for r in validation_results) / len(validation_results) if validation_results else 0.0
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_schemas': len(schema_files),
                'total_fields': total_fields,
                'valid_fields': valid_fields,
                'invalid_fields': total_fields - valid_fields,
                'validation_rate': (valid_fields / total_fields * 100) if total_fields > 0 else 0,
                'avg_confidence': avg_confidence
            },
            'validation_results': [asdict(result) for result in validation_results],
            'semantic_fields': [asdict(field) for field in all_semantic_fields],
            'recommendations': self._generate_semantic_recommendations(validation_results)
        }
        
        # Salva modelo se cache está habilitado
        if self.cache_embeddings:
            self._save_model()
        
        return report
    
    def _generate_semantic_recommendations(self, validation_results: List[SemanticValidationResult]) -> List[str]:
        """Gera recomendações baseadas na análise semântica."""
        recommendations = []
        
        # Conta tipos de problemas
        issue_types = defaultdict(int)
        for result in validation_results:
            for issue in result.detected_issues:
                issue_types[issue] += 1
        
        # Gera recomendações baseadas nos problemas mais comuns
        if issue_types.get("Campo muito similar", 0) > 0:
            recommendations.append(f"Unificar {issue_types['Campo muito similar']} campos muito similares")
        
        if issue_types.get("Descrição muito curta", 0) > 0:
            recommendations.append(f"Expandir descrições de {issue_types['Descrição muito curta']} campos")
        
        if issue_types.get("Campo numérico definido como string", 0) > 0:
            recommendations.append(f"Corrigir tipos de {issue_types['Campo numérico definido como string']} campos numéricos")
        
        # Recomendações baseadas em similaridade
        high_similarity_results = [r for r in validation_results if r.semantic_similarity and r.semantic_similarity > 0.8]
        if high_similarity_results:
            recommendations.append(f"Revisar {len(high_similarity_results)} campos com alta similaridade semântica")
        
        if not recommendations:
            recommendations.append("Análise semântica não detectou problemas significativos")
        
        return recommendations

# Instância global
semantic_validator = SemanticValidator()

def get_semantic_validator() -> SemanticValidator:
    """Retorna instância global do validador semântico."""
    return semantic_validator

if __name__ == "__main__":
    # Teste do sistema
    validator = SemanticValidator()
    
    # Testa análise semântica de campos
    test_fields = [
        ("user_id", "integer", "Identificador único do usuário"),
        ("email", "string", "Endereço de email válido"),
        ("created_at", "datetime", "Data e hora de criação"),
        ("title", "string", "Título do conteúdo"),
    ]
    
    print("🧠 Testando análise semântica:")
    semantic_fields = []
    for field_name, field_type, description in test_fields:
        field = validator.analyze_field_semantics(field_name, field_type, description)
        semantic_fields.append(field)
        print(f"  {field_name}: {len(field.synonyms)} sinônimos, {len(field.related_fields)} relacionados")
    
    # Testa validação semântica
    print("\n🔍 Testando validação semântica:")
    for field in semantic_fields:
        result = validator.validate_field_semantics(field, semantic_fields)
        status = "✅" if result.is_semantically_valid else "⚠️"
        print(f"  {status} {field.field_name}: {result.confidence_score:.2f} confiança")
    
    # Testa detecção de drift
    print("\n📊 Testando detecção de drift:")
    reference_fields = [
        validator.analyze_field_semantics("user_id", "integer", "ID do usuário"),
        validator.analyze_field_semantics("email", "string", "Email do usuário"),
    ]
    
    drift_report = validator.detect_semantic_drift(semantic_fields, reference_fields, "test_schema")
    print(f"  Drift detectado: {drift_report.drift_detected}")
    print(f"  Score de drift: {drift_report.drift_score:.2f}")
    
    print("✅ SemanticValidator testado com sucesso!") 