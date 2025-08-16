#!/usr/bin/env python3
"""
Testes unitários para ContentOptimizer.
Valida funcionalidades de otimização e análise de conteúdo.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from omni_writer.ml_advanced.content_optimizer import (
    ContentOptimizer,
    ContentAnalysis,
    ContentMetrics,
    LearningData
)

class TestContentOptimizer:
    """Testes para ContentOptimizer."""
    
    @pytest.fixture
    def optimizer(self):
        """Fixture para ContentOptimizer."""
        with patch('omni_writer.ml_advanced.content_optimizer.ML_AVAILABLE', True):
            with patch('omni_writer.ml_advanced.content_optimizer.SentenceTransformer'):
                with patch('omni_writer.ml_advanced.content_optimizer.sqlite3'):
                    optimizer = ContentOptimizer()
                    optimizer.model = Mock()
                    optimizer.vectorizer = Mock()
                    optimizer.lemmatizer = Mock()
                    optimizer.stop_words = set(['the', 'a', 'an'])
                    return optimizer
    
    @pytest.fixture
    def sample_content(self):
        """Conteúdo de teste."""
        return """
        Artificial intelligence is transforming the way we work and live. 
        Machine learning algorithms are becoming more sophisticated every day. 
        Companies are implementing AI solutions to improve efficiency and productivity.
        """
    
    def test_initialization(self, optimizer):
        """Testa inicialização do otimizador."""
        assert optimizer is not None
        assert optimizer.model is not None
        assert optimizer.vectorizer is not None
        assert optimizer.similarity_threshold == 0.85
        assert optimizer.min_uniqueness_score == 0.7
        assert optimizer.min_humanization_score == 0.8
    
    def test_generate_content_hash(self, optimizer):
        """Testa geração de hash de conteúdo."""
        content = "Test content"
        hash1 = optimizer.generate_content_hash(content)
        hash2 = optimizer.generate_content_hash(content)
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hash length
        assert isinstance(hash1, str)
    
    def test_extract_text_features(self, optimizer):
        """Testa extração de características do texto."""
        content = "This is a test sentence. This is another sentence."
        features = optimizer.extract_text_features(content)
        
        assert features['word_count'] == 10
        assert features['sentence_count'] == 2
        assert features['paragraph_count'] == 1
        assert features['avg_sentence_length'] == 5.0
        assert features['unique_words_ratio'] > 0
        assert features['stop_words_ratio'] > 0
    
    def test_calculate_readability_score(self, optimizer):
        """Testa cálculo de score de legibilidade."""
        content = "This is a simple sentence. It has basic words."
        score = optimizer.calculate_readability_score(content)
        
        assert 0 <= score <= 1
        assert isinstance(score, float)
    
    def test_calculate_humanization_score(self, optimizer):
        """Testa cálculo de score de humanização."""
        content = "You know what's really cool? I think you'll find this interesting."
        score = optimizer.calculate_humanization_score(content)
        
        assert 0 <= score <= 1
        assert isinstance(score, float)
        
        # Conteúdo com pronomes pessoais deve ter score mais alto
        assert score > 0.5
    
    def test_calculate_coherence_score(self, optimizer):
        """Testa cálculo de score de coerência."""
        content = "First sentence. Second sentence. Third sentence."
        
        with patch.object(optimizer, '_calculate_sentence_similarity', return_value=0.8):
            score = optimizer.calculate_coherence_score(content)
            
            assert 0 <= score <= 1
            assert isinstance(score, float)
    
    def test_calculate_creativity_score(self, optimizer):
        """Testa cálculo de score de criatividade."""
        content = "Innovative technology transforms traditional approaches."
        score = optimizer.calculate_creativity_score(content)
        
        assert 0 <= score <= 1
        assert isinstance(score, float)
    
    def test_check_uniqueness(self, optimizer):
        """Testa verificação de unicidade."""
        content = "Unique content that should not be similar to anything."
        
        with patch.object(optimizer, 'model') as mock_model:
            mock_model.encode.return_value = [[0.1, 0.2, 0.3]]
            
            with patch('omni_writer.ml_advanced.content_optimizer.sqlite3') as mock_sqlite:
                mock_conn = Mock()
                mock_cursor = Mock()
                mock_cursor.fetchall.return_value = []
                mock_conn.cursor.return_value = mock_cursor
                mock_sqlite.connect.return_value = mock_conn
                
                uniqueness_score, similar_contents = optimizer.check_uniqueness(content)
                
                assert 0 <= uniqueness_score <= 1
                assert isinstance(similar_contents, list)
    
    def test_analyze_content(self, optimizer, sample_content):
        """Testa análise completa de conteúdo."""
        with patch.object(optimizer, 'model') as mock_model:
            mock_model.encode.return_value = [[0.1, 0.2, 0.3]]
            
            with patch.object(optimizer, '_save_analysis'):
                analysis = optimizer.analyze_content(sample_content)
                
                assert analysis is not None
                assert isinstance(analysis, ContentAnalysis)
                assert analysis.content_hash is not None
                assert analysis.metrics is not None
                assert analysis.word_count > 0
                assert analysis.sentence_count > 0
                assert 0 <= analysis.metrics.overall_score <= 1
    
    def test_optimize_content(self, optimizer, sample_content):
        """Testa otimização de conteúdo."""
        with patch.object(optimizer, 'analyze_content') as mock_analyze:
            mock_analysis = Mock()
            mock_analysis.metrics.overall_score = 0.6
            mock_analyze.return_value = mock_analysis
            
            with patch.object(optimizer, '_improve_humanization') as mock_improve:
                mock_improve.return_value = "Improved content"
                
                optimized_content, analysis = optimizer.optimize_content(sample_content)
                
                assert optimized_content is not None
                assert analysis is not None
                assert mock_improve.called
    
    def test_get_optimization_suggestions(self, optimizer):
        """Testa geração de sugestões de otimização."""
        content = "Basic content that needs improvement."
        
        with patch.object(optimizer, 'analyze_content') as mock_analyze:
            mock_analysis = Mock()
            mock_analysis.metrics.uniqueness_score = 0.5
            mock_analysis.metrics.humanization_score = 0.4
            mock_analyze.return_value = mock_analysis
            
            suggestions = optimizer.get_optimization_suggestions(content)
            
            assert isinstance(suggestions, list)
            assert len(suggestions) > 0
    
    def test_learn_from_feedback(self, optimizer):
        """Testa aprendizado com feedback."""
        content_hash = "test_hash"
        feedback = LearningData(
            content_hash=content_hash,
            user_feedback=0.8,
            engagement_metrics={"uniqueness": 0.7, "humanization": 0.8},
            improvement_suggestions=["Add more personal pronouns"],
            successful_patterns=["personal_pronouns"],
            failed_patterns=["overly_formal"]
        )
        
        with patch.object(optimizer, '_update_success_patterns'):
            optimizer.learn_from_feedback(content_hash, feedback)
            # Verifica se o método foi chamado
            optimizer._update_success_patterns.assert_called_once_with(feedback)
    
    def test_generate_report(self, optimizer):
        """Testa geração de relatório."""
        with patch('omni_writer.ml_advanced.content_optimizer.pd') as mock_pd:
            mock_df = Mock()
            mock_df.empty = False
            mock_df.__getitem__.return_value.apply.return_value.apply.return_value.mean.return_value = {
                'uniqueness_score': 0.8,
                'humanization_score': 0.7,
                'readability_score': 0.8,
                'coherence_score': 0.7,
                'creativity_score': 0.6,
                'overall_score': 0.72
            }
            mock_pd.read_sql_query.return_value = mock_df
            
            with patch('omni_writer.ml_advanced.content_optimizer.sqlite3'):
                report = optimizer.generate_report(days=30)
                
                assert isinstance(report, str)
                assert "Relatório de Análise" in report
                assert "Score Geral" in report
    
    def test_error_handling_ml_not_available(self):
        """Testa comportamento quando ML não está disponível."""
        with patch('omni_writer.ml_advanced.content_optimizer.ML_AVAILABLE', False):
            optimizer = ContentOptimizer()
            
            # Deve funcionar mesmo sem ML
            assert optimizer is not None
            assert optimizer.model is None
    
    def test_error_handling_analysis_failure(self, optimizer):
        """Testa tratamento de erro na análise."""
        with patch.object(optimizer, 'model') as mock_model:
            mock_model.encode.side_effect = Exception("Model error")
            
            analysis = optimizer.analyze_content("test content")
            
            # Deve retornar None em caso de erro
            assert analysis is None
    
    def test_performance_metrics(self, optimizer, sample_content):
        """Testa métricas de performance."""
        import time
        
        start_time = time.time()
        
        with patch.object(optimizer, 'model') as mock_model:
            mock_model.encode.return_value = [[0.1, 0.2, 0.3]]
            
            with patch.object(optimizer, '_save_analysis'):
                analysis = optimizer.analyze_content(sample_content)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        assert analysis is not None
        assert processing_time < 5.0  # Deve processar em menos de 5 segundos
    
    def test_content_validation(self, optimizer):
        """Testa validação de conteúdo."""
        # Conteúdo vazio
        analysis = optimizer.analyze_content("")
        assert analysis is not None
        
        # Conteúdo muito longo
        long_content = "word " * 10000
        analysis = optimizer.analyze_content(long_content)
        assert analysis is not None
        assert analysis.word_count == 10000
    
    def test_metrics_consistency(self, optimizer, sample_content):
        """Testa consistência das métricas."""
        with patch.object(optimizer, 'model') as mock_model:
            mock_model.encode.return_value = [[0.1, 0.2, 0.3]]
            
            with patch.object(optimizer, '_save_analysis'):
                analysis = optimizer.analyze_content(sample_content)
                
                metrics = analysis.metrics
                
                # Todas as métricas devem estar entre 0 e 1
                assert 0 <= metrics.uniqueness_score <= 1
                assert 0 <= metrics.humanization_score <= 1
                assert 0 <= metrics.readability_score <= 1
                assert 0 <= metrics.coherence_score <= 1
                assert 0 <= metrics.creativity_score <= 1
                assert 0 <= metrics.overall_score <= 1
                
                # Score geral deve ser uma combinação das outras métricas
                expected_score = (
                    metrics.uniqueness_score * 0.25 +
                    metrics.humanization_score * 0.25 +
                    metrics.readability_score * 0.20 +
                    metrics.coherence_score * 0.15 +
                    metrics.creativity_score * 0.15
                )
                
                assert abs(metrics.overall_score - expected_score) < 0.01


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 