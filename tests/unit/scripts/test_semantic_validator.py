#!/usr/bin/env python3
"""
🧪 TESTES UNITÁRIOS - SEMANTIC VALIDATOR
Tracing ID: TEST_SEMANTIC_VALIDATOR_20250128_001
Data/Hora: 2025-01-28T10:45:00Z
Versão: 1.0

Objetivo: Testar funcionalidades do sistema de validação semântica
baseado no código real implementado em scripts/semantic_validator.py
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from pathlib import Path
import sys
import os

# Adiciona o diretório scripts ao path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts'))

from semantic_validator import (
    SemanticValidator, 
    SemanticField, 
    SemanticValidationResult, 
    SemanticDriftReport
)

class TestSemanticField:
    """Testes para a classe SemanticField."""
    
    def test_semantic_field_initialization(self):
        """Testa inicialização correta de SemanticField."""
        field = SemanticField(
            field_name="user_id",
            field_type="integer",
            description="Identificador único do usuário"
        )
        
        assert field.field_name == "user_id"
        assert field.field_type == "integer"
        assert field.description == "Identificador único do usuário"
        assert field.semantic_vector is None
        assert field.semantic_hash is None
        assert field.synonyms == []
        assert field.related_fields == []
    
    def test_semantic_field_with_optional_params(self):
        """Testa SemanticField com parâmetros opcionais."""
        field = SemanticField(
            field_name="email",
            field_type="string",
            description="Email do usuário",
            synonyms=["email_address", "mail"],
            related_fields=["user_id", "username"]
        )
        
        assert field.synonyms == ["email_address", "mail"]
        assert field.related_fields == ["user_id", "username"]
    
    def test_semantic_field_post_init(self):
        """Testa inicialização automática de listas vazias."""
        field = SemanticField(
            field_name="title",
            field_type="string",
            description="Título do conteúdo",
            synonyms=None,
            related_fields=None
        )
        
        assert field.synonyms == []
        assert field.related_fields == []

class TestSemanticValidationResult:
    """Testes para a classe SemanticValidationResult."""
    
    def test_validation_result_initialization(self):
        """Testa inicialização de SemanticValidationResult."""
        result = SemanticValidationResult(
            field_name="user_id",
            is_semantically_valid=True,
            confidence_score=0.95,
            detected_issues=[],
            suggestions=["Campo bem definido"],
            semantic_similarity=0.8,
            compared_with="user_identifier"
        )
        
        assert result.field_name == "user_id"
        assert result.is_semantically_valid is True
        assert result.confidence_score == 0.95
        assert result.detected_issues == []
        assert result.suggestions == ["Campo bem definido"]
        assert result.semantic_similarity == 0.8
        assert result.compared_with == "user_identifier"

class TestSemanticDriftReport:
    """Testes para a classe SemanticDriftReport."""
    
    def test_drift_report_initialization(self):
        """Testa inicialização de SemanticDriftReport."""
        report = SemanticDriftReport(
            schema_name="user_schema",
            drift_detected=True,
            drift_score=0.75,
            affected_fields=["user_id", "email"],
            drift_details=[{"field": "user_id", "score": 0.8}],
            timestamp=datetime.now(),
            recommendations=["Revisar campo user_id"]
        )
        
        assert report.schema_name == "user_schema"
        assert report.drift_detected is True
        assert report.drift_score == 0.75
        assert report.affected_fields == ["user_id", "email"]
        assert len(report.drift_details) == 1
        assert len(report.recommendations) == 1

class TestSemanticValidator:
    """Testes para a classe SemanticValidator."""
    
    @pytest.fixture
    def validator(self):
        """Fixture para criar instância de SemanticValidator."""
        return SemanticValidator(similarity_threshold=0.7)
    
    def test_validator_initialization(self, validator):
        """Testa inicialização correta do SemanticValidator."""
        assert validator.similarity_threshold == 0.7
        assert validator.cache_embeddings is True
        assert isinstance(validator.embedding_cache, dict)
        assert isinstance(validator.field_cache, dict)
        assert len(validator.semantic_patterns) > 0
        assert len(validator.field_synonyms) > 0
    
    def test_load_semantic_patterns(self, validator):
        """Testa carregamento de padrões semânticos."""
        patterns = validator._load_semantic_patterns()
        
        # Verifica se padrões essenciais estão presentes
        assert 'identification' in patterns
        assert 'user_data' in patterns
        assert 'contact' in patterns
        assert 'temporal' in patterns
        assert 'content' in patterns
        
        # Verifica se padrões têm elementos
        assert len(patterns['identification']) > 0
        assert len(patterns['user_data']) > 0
    
    def test_load_field_synonyms(self, validator):
        """Testa carregamento de sinônimos de campos."""
        synonyms = validator._load_field_synonyms()
        
        # Verifica sinônimos conhecidos
        assert 'user_id' in synonyms
        assert 'email' in synonyms
        assert 'created_at' in synonyms
        
        # Verifica se sinônimos são listas
        assert isinstance(synonyms['user_id'], list)
        assert len(synonyms['user_id']) > 0
    
    def test_generate_semantic_hash(self, validator):
        """Testa geração de hash semântico."""
        text1 = "user_id integer Identificador do usuário"
        text2 = "user_id integer Identificador do usuário"
        text3 = "email string Email do usuário"
        
        hash1 = validator._generate_semantic_hash(text1)
        hash2 = validator._generate_semantic_hash(text2)
        hash3 = validator._generate_semantic_hash(text3)
        
        # Hashs idênticos para textos idênticos
        assert hash1 == hash2
        
        # Hashs diferentes para textos diferentes
        assert hash1 != hash3
        
        # Hashs são strings hexadecimais
        assert len(hash1) == 32  # MD5 hash length
        assert all(c in '0123456789abcdef' for c in hash1)
    
    @patch('semantic_validator.TfidfVectorizer')
    def test_get_embedding(self, mock_vectorizer, validator):
        """Testa geração de embeddings."""
        # Mock do vetorizador
        mock_vectorizer_instance = Mock()
        mock_vectorizer_instance.fit_transform.return_value.toarray.return_value = [np.array([0.1, 0.2, 0.3])]
        mock_vectorizer.return_value = mock_vectorizer_instance
        
        # Testa geração de embedding
        text = "user_id integer Identificador do usuário"
        embedding = validator._get_embedding(text)
        
        # Verifica se embedding foi gerado
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) > 0
        
        # Verifica se foi cacheado
        text_hash = validator._generate_semantic_hash(text)
        assert text_hash in validator.embedding_cache
    
    def test_calculate_semantic_similarity(self, validator):
        """Testa cálculo de similaridade semântica."""
        text1 = "user_id integer Identificador do usuário"
        text2 = "user_id integer Identificador do usuário"
        text3 = "email string Email do usuário"
        
        # Similaridade entre textos idênticos
        similarity1 = validator._calculate_semantic_similarity(text1, text2)
        assert similarity1 > 0.9  # Deve ser muito alta
        
        # Similaridade entre textos diferentes
        similarity2 = validator._calculate_semantic_similarity(text1, text3)
        assert similarity2 < similarity1  # Deve ser menor
    
    def test_detect_semantic_category(self, validator):
        """Testa detecção de categoria semântica."""
        # Testa categoria de identificação
        category1 = validator._detect_semantic_category("user_id", "Identificador único do usuário")
        assert category1 in ['identification', 'user_data']
        
        # Testa categoria de contato
        category2 = validator._detect_semantic_category("email", "Endereço de email")
        assert category2 in ['contact']
        
        # Testa categoria temporal
        category3 = validator._detect_semantic_category("created_at", "Data de criação")
        assert category3 in ['temporal']
    
    def test_find_synonyms(self, validator):
        """Testa busca de sinônimos."""
        # Testa sinônimos conhecidos
        synonyms = validator._find_synonyms("user_id")
        assert isinstance(synonyms, list)
        assert len(synonyms) > 0
        
        # Testa campo sem sinônimos
        synonyms_unknown = validator._find_synonyms("unknown_field")
        assert synonyms_unknown == []
    
    def test_analyze_field_semantics(self, validator):
        """Testa análise semântica de campo."""
        field = validator.analyze_field_semantics(
            field_name="user_id",
            field_type="integer",
            description="Identificador único do usuário"
        )
        
        assert isinstance(field, SemanticField)
        assert field.field_name == "user_id"
        assert field.field_type == "integer"
        assert field.description == "Identificador único do usuário"
        assert field.semantic_vector is not None
        assert field.semantic_hash is not None
        assert isinstance(field.synonyms, list)
        assert isinstance(field.related_fields, list)
    
    def test_validate_field_semantics(self, validator):
        """Testa validação semântica de campo."""
        # Cria campos de teste
        field = SemanticField(
            field_name="user_id",
            field_type="integer",
            description="Identificador único do usuário"
        )
        
        reference_fields = [
            SemanticField("user_id", "integer", "ID do usuário"),
            SemanticField("email", "string", "Email do usuário")
        ]
        
        # Valida campo
        result = validator.validate_field_semantics(field, reference_fields)
        
        assert isinstance(result, SemanticValidationResult)
        assert result.field_name == "user_id"
        assert isinstance(result.is_semantically_valid, bool)
        assert 0.0 <= result.confidence_score <= 1.0
        assert isinstance(result.detected_issues, list)
        assert isinstance(result.suggestions, list)
    
    def test_detect_semantic_drift(self, validator):
        """Testa detecção de drift semântico."""
        # Schemas de teste
        current_schema = [
            SemanticField("user_id", "integer", "Identificador único do usuário"),
            SemanticField("email", "string", "Email do usuário")
        ]
        
        reference_schema = [
            SemanticField("user_id", "integer", "ID do usuário"),
            SemanticField("email", "string", "Endereço de email")
        ]
        
        # Detecta drift
        drift_report = validator.detect_semantic_drift(
            current_schema, reference_schema, "test_schema"
        )
        
        assert isinstance(drift_report, SemanticDriftReport)
        assert drift_report.schema_name == "test_schema"
        assert isinstance(drift_report.drift_detected, bool)
        assert 0.0 <= drift_report.drift_score <= 1.0
        assert isinstance(drift_report.affected_fields, list)
        assert isinstance(drift_report.drift_details, list)
        assert isinstance(drift_report.recommendations, list)
        assert isinstance(drift_report.timestamp, datetime)
    
    def test_analyze_schema_semantics(self, validator):
        """Testa análise semântica de schema."""
        schema_data = {
            "properties": {
                "user_id": {
                    "type": "integer",
                    "description": "Identificador único do usuário"
                },
                "email": {
                    "type": "string",
                    "description": "Email do usuário"
                }
            }
        }
        
        semantic_fields = validator.analyze_schema_semantics(schema_data, "test_schema")
        
        assert isinstance(semantic_fields, list)
        assert len(semantic_fields) == 2
        
        for field in semantic_fields:
            assert isinstance(field, SemanticField)
            assert field.field_name in ["user_id", "email"]
            assert field.semantic_vector is not None
            assert field.semantic_hash is not None
    
    @patch('pathlib.Path.glob')
    def test_generate_semantic_report(self, mock_glob, validator):
        """Testa geração de relatório semântico."""
        # Mock de arquivos de schema
        mock_schema_file = Mock()
        mock_schema_file.suffix = '.json'
        mock_schema_file.stem = 'test_schema'
        mock_glob.return_value = [mock_schema_file]
        
        # Mock de leitura de arquivo
        with patch('builtins.open', mock_open(read_data='{"properties": {"user_id": {"type": "integer", "description": "ID"}}}')):
            with patch('json.load', return_value={"properties": {"user_id": {"type": "integer", "description": "ID"}}}):
                report = validator.generate_semantic_report()
        
        assert isinstance(report, dict)
        assert 'generated_at' in report
        assert 'summary' in report
        assert 'validation_results' in report
        assert 'semantic_fields' in report
        assert 'recommendations' in report
    
    def test_generate_semantic_recommendations(self, validator):
        """Testa geração de recomendações semânticas."""
        # Resultados de validação de teste
        validation_results = [
            SemanticValidationResult(
                field_name="user_id",
                is_semantically_valid=True,
                confidence_score=0.9,
                detected_issues=[],
                suggestions=[]
            ),
            SemanticValidationResult(
                field_name="email",
                is_semantically_valid=False,
                confidence_score=0.6,
                detected_issues=["Descrição muito curta"],
                suggestions=["Expandir descrição"]
            )
        ]
        
        recommendations = validator._generate_semantic_recommendations(validation_results)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

class TestSemanticValidatorIntegration:
    """Testes de integração para SemanticValidator."""
    
    @pytest.fixture
    def validator(self):
        """Fixture para validator com cache desabilitado."""
        return SemanticValidator(cache_embeddings=False)
    
    def test_end_to_end_validation_workflow(self, validator):
        """Testa workflow completo de validação semântica."""
        # 1. Analisa campos
        field1 = validator.analyze_field_semantics("user_id", "integer", "Identificador único do usuário")
        field2 = validator.analyze_field_semantics("email", "string", "Email do usuário")
        
        # 2. Valida campos
        result1 = validator.validate_field_semantics([field1, field2], [field1, field2])
        result2 = validator.validate_field_semantics([field1, field2], [field1, field2])
        
        # 3. Verifica resultados
        assert isinstance(result1, SemanticValidationResult)
        assert isinstance(result2, SemanticValidationResult)
        assert result1.field_name == "user_id"
        assert result2.field_name == "email"
    
    def test_semantic_drift_detection_workflow(self, validator):
        """Testa workflow de detecção de drift semântico."""
        # Schema atual
        current_schema = [
            validator.analyze_field_semantics("user_id", "integer", "Identificador único do usuário"),
            validator.analyze_field_semantics("email", "string", "Email do usuário")
        ]
        
        # Schema de referência (versão anterior)
        reference_schema = [
            validator.analyze_field_semantics("user_id", "integer", "ID do usuário"),
            validator.analyze_field_semantics("email", "string", "Endereço de email")
        ]
        
        # Detecta drift
        drift_report = validator.detect_semantic_drift(
            current_schema, reference_schema, "user_schema"
        )
        
        # Verifica relatório
        assert isinstance(drift_report, SemanticDriftReport)
        assert drift_report.schema_name == "user_schema"
        assert isinstance(drift_report.drift_detected, bool)
        assert isinstance(drift_report.drift_score, float)
        assert 0.0 <= drift_report.drift_score <= 1.0

class TestSemanticValidatorEdgeCases:
    """Testes para casos extremos do SemanticValidator."""
    
    @pytest.fixture
    def validator(self):
        """Fixture para validator."""
        return SemanticValidator()
    
    def test_empty_text_embedding(self, validator):
        """Testa geração de embedding para texto vazio."""
        embedding = validator._get_embedding("")
        assert isinstance(embedding, np.ndarray)
    
    def test_special_characters_embedding(self, validator):
        """Testa geração de embedding com caracteres especiais."""
        text = "user_id!@#$%^&*()_+{}|:<>?[]\\;'\",./"
        embedding = validator._get_embedding(text)
        assert isinstance(embedding, np.ndarray)
    
    def test_very_long_text_embedding(self, validator):
        """Testa geração de embedding para texto muito longo."""
        long_text = "user_id " * 1000  # Texto muito longo
        embedding = validator._get_embedding(long_text)
        assert isinstance(embedding, np.ndarray)
    
    def test_unicode_text_embedding(self, validator):
        """Testa geração de embedding com caracteres Unicode."""
        unicode_text = "user_id 用户标识符 пользователь_id"
        embedding = validator._get_embedding(unicode_text)
        assert isinstance(embedding, np.ndarray)
    
    def test_similarity_with_identical_texts(self, validator):
        """Testa similaridade entre textos idênticos."""
        text = "user_id integer Identificador do usuário"
        similarity = validator._calculate_semantic_similarity(text, text)
        assert similarity > 0.9  # Deve ser muito alta
    
    def test_similarity_with_completely_different_texts(self, validator):
        """Testa similaridade entre textos completamente diferentes."""
        text1 = "user_id integer Identificador do usuário"
        text2 = "completely different text with no relation"
        similarity = validator._calculate_semantic_similarity(text1, text2)
        assert similarity < 0.5  # Deve ser baixa

# Mock para open() em testes
def mock_open(mock_file):
    """Mock para função open() em testes."""
    return Mock(return_value=Mock(__enter__=Mock(return_value=mock_file), __exit__=Mock(return_value=None)))

if __name__ == "__main__":
    # Executa testes se chamado diretamente
    pytest.main([__file__, "-v"]) 