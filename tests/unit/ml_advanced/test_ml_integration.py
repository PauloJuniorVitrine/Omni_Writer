#!/usr/bin/env python3
"""
Testes unitários para MLIntegration.
Valida integração do sistema ML com o sistema existente.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from omni_writer.ml_advanced.ml_integration import (
    MLIntegration,
    MLArticleRequest,
    MLArticleResponse
)

class TestMLIntegration:
    """Testes para MLIntegration."""
    
    @pytest.fixture
    def integration(self):
        """Fixture para MLIntegration."""
        with patch('omni_writer.ml_advanced.ml_integration.ContentOptimizer'):
            with patch('omni_writer.ml_advanced.ml_integration.IntelligentGenerator'):
                with patch('omni_writer.ml_advanced.ml_integration.EXISTING_AVAILABLE', True):
                    with patch('omni_writer.ml_advanced.ml_integration.ArticleGenerator'):
                        integration = MLIntegration()
                        integration.optimizer = Mock()
                        integration.generator = Mock()
                        integration.article_generator = Mock()
                        integration.config = {
                            "ml_enabled": True,
                            "optimization_enabled": True,
                            "learning_enabled": True,
                            "min_quality_score": 0.8,
                            "max_iterations": 5,
                            "similarity_threshold": 0.85
                        }
                        return integration
    
    @pytest.fixture
    def sample_request(self):
        """Requisição de teste."""
        return MLArticleRequest(
            topic="artificial intelligence in healthcare",
            target_length=800,
            style="casual",
            language="en",
            keywords=["AI", "healthcare", "machine learning"],
            tone="positive",
            complexity="intermediate",
            enable_optimization=True,
            enable_learning=True,
            unique_requirements=["include real examples"]
        )
    
    def test_initialization(self, integration):
        """Testa inicialização da integração."""
        assert integration is not None
        assert integration.optimizer is not None
        assert integration.generator is not None
        assert integration.article_generator is not None
        assert integration.config is not None
        assert integration.integration_history is not None
        assert len(integration.integration_history) == 0
    
    def test_load_config(self, integration):
        """Testa carregamento de configuração."""
        config = integration._load_config()
        
        assert isinstance(config, dict)
        assert "ml_enabled" in config
        assert "optimization_enabled" in config
        assert "learning_enabled" in config
        assert "min_quality_score" in config
        assert "max_iterations" in config
        assert "similarity_threshold" in config
        assert "style_mapping" in config
    
    def test_initialize_components_success(self, integration):
        """Testa inicialização bem-sucedida dos componentes."""
        with patch('omni_writer.ml_advanced.ml_integration.ContentOptimizer') as mock_optimizer:
            with patch('omni_writer.ml_advanced.ml_integration.IntelligentGenerator') as mock_generator:
                with patch('omni_writer.ml_advanced.ml_integration.ArticleGenerator') as mock_article:
                    integration._initialize_components()
                    
                    assert integration.optimizer is not None
                    assert integration.generator is not None
                    assert integration.article_generator is not None
    
    def test_initialize_components_ml_disabled(self, integration):
        """Testa inicialização com ML desabilitado."""
        integration.config["ml_enabled"] = False
        
        with patch('omni_writer.ml_advanced.ml_integration.ContentOptimizer'):
            with patch('omni_writer.ml_advanced.ml_integration.IntelligentGenerator'):
                with patch('omni_writer.ml_advanced.ml_integration.ArticleGenerator'):
                    integration._initialize_components()
                    
                    # ML components não devem ser inicializados
                    assert integration.optimizer is None
                    assert integration.generator is None
    
    def test_generate_initial_content_existing_system(self, integration, sample_request):
        """Testa geração de conteúdo inicial com sistema existente."""
        with patch('omni_writer.ml_advanced.ml_integration.ArticleRequest') as mock_article_request:
            with patch('omni_writer.ml_advanced.ml_integration.ArticleResponse') as mock_article_response:
                mock_response = Mock()
                mock_response.content = "Generated content from existing system."
                integration.article_generator.generate_article.return_value = mock_response
                
                content = integration._generate_initial_content(sample_request)
                
                assert content == "Generated content from existing system."
                assert integration.article_generator.generate_article.called
    
    def test_generate_initial_content_ml_fallback(self, integration, sample_request):
        """Testa fallback para ML quando sistema existente falha."""
        # Simula falha do sistema existente
        integration.article_generator.generate_article.side_effect = Exception("System error")
        
        with patch.object(integration.generator, 'generate_content') as mock_generate:
            mock_result = Mock()
            mock_result.content = "Generated content from ML."
            mock_generate.return_value = mock_result
            
            content = integration._generate_initial_content(sample_request)
            
            assert content == "Generated content from ML."
            assert mock_generate.called
    
    def test_generate_initial_content_final_fallback(self, integration, sample_request):
        """Testa fallback final quando todos os sistemas falham."""
        # Simula falha de todos os sistemas
        integration.article_generator.generate_article.side_effect = Exception("System error")
        integration.generator.generate_content.side_effect = Exception("ML error")
        
        content = integration._generate_initial_content(sample_request)
        
        assert "artificial intelligence in healthcare" in content
        assert "erro na geração" in content.lower()
    
    def test_apply_learning(self, integration, sample_request):
        """Testa aplicação de aprendizado."""
        mock_analysis = Mock()
        mock_analysis.content_hash = "test_hash"
        mock_analysis.metrics.overall_score = 0.8
        
        mock_generation_result = Mock()
        mock_generation_result.suggestions = ["Add more examples"]
        
        with patch.object(integration.optimizer, 'learn_from_feedback') as mock_learn:
            integration._apply_learning(sample_request, mock_analysis, mock_generation_result)
            
            assert mock_learn.called
    
    def test_extract_patterns(self, integration):
        """Testa extração de padrões."""
        content = "You know what's really cool? I think you'll find this interesting."
        
        # Testa padrões bem-sucedidos
        successful_patterns = integration._extract_patterns(content, "successful")
        assert "personal_pronouns" in successful_patterns
        assert "conversational_phrases" in successful_patterns
        
        # Testa padrões que falharam
        failed_content = "The research. The data. The analysis."
        failed_patterns = integration._extract_patterns(failed_content, "failed")
        assert len(failed_patterns) > 0
    
    def test_extract_quality_metrics(self, integration):
        """Testa extração de métricas de qualidade."""
        mock_analysis = Mock()
        mock_analysis.metrics.overall_score = 0.85
        mock_analysis.metrics.uniqueness_score = 0.8
        mock_analysis.metrics.humanization_score = 0.7
        mock_analysis.metrics.readability_score = 0.9
        mock_analysis.metrics.coherence_score = 0.8
        mock_analysis.metrics.creativity_score = 0.6
        mock_analysis.metrics.learning_potential = 0.75
        
        metrics = integration._extract_quality_metrics(mock_analysis)
        
        assert isinstance(metrics, dict)
        assert metrics["overall_score"] == 0.85
        assert metrics["uniqueness_score"] == 0.8
        assert metrics["humanization_score"] == 0.7
        assert metrics["readability_score"] == 0.9
        assert metrics["coherence_score"] == 0.8
        assert metrics["creativity_score"] == 0.6
        assert metrics["learning_potential"] == 0.75
    
    def test_generate_article_with_ml_success(self, integration, sample_request):
        """Testa geração bem-sucedida de artigo com ML."""
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Original content about AI in healthcare."
            
            with patch.object(integration.optimizer, 'optimize_content') as mock_optimize:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.9
                mock_optimize.return_value = ("Optimized content.", mock_analysis)
                
                with patch.object(integration, '_apply_learning'):
                    with patch.object(integration.optimizer, 'get_optimization_suggestions') as mock_suggestions:
                        mock_suggestions.return_value = ["Add more personal examples"]
                        
                        response = integration.generate_article_with_ml(sample_request)
                        
                        assert response is not None
                        assert isinstance(response, MLArticleResponse)
                        assert response.content == "Optimized content."
                        assert response.original_content == "Original content about AI in healthcare."
                        assert response.optimization_applied is True
                        assert response.learning_applied is True
                        assert response.quality_metrics is not None
                        assert len(response.suggestions) > 0
                        assert response.generation_time > 0
    
    def test_generate_article_with_ml_quality_insufficient(self, integration, sample_request):
        """Testa geração quando qualidade é insuficiente."""
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Low quality content."
            
            with patch.object(integration.optimizer, 'optimize_content') as mock_optimize:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.5  # Score baixo
                mock_optimize.return_value = ("Still low quality.", mock_analysis)
                
                with patch.object(integration.generator, 'generate_content') as mock_ml_generate:
                    mock_result = Mock()
                    mock_result.content = "High quality ML content."
                    mock_result.analysis = Mock()
                    mock_result.analysis.metrics.overall_score = 0.9
                    mock_ml_generate.return_value = mock_result
                    
                    with patch.object(integration, '_apply_learning'):
                        response = integration.generate_article_with_ml(sample_request)
                        
                        assert response is not None
                        assert response.content == "High quality ML content."
                        assert mock_ml_generate.called
    
    def test_generate_article_with_ml_error_handling(self, integration, sample_request):
        """Testa tratamento de erro na geração."""
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.side_effect = Exception("Generation error")
            
            response = integration.generate_article_with_ml(sample_request)
            
            # Deve retornar None em caso de erro
            assert response is None
    
    def test_get_integration_stats(self, integration):
        """Testa obtenção de estatísticas de integração."""
        # Adiciona alguns resultados ao histórico
        mock_response1 = Mock()
        mock_response1.analysis.timestamp.days = 10
        mock_response1.quality_metrics = {
            "overall_score": 0.8,
            "uniqueness_score": 0.7,
            "humanization_score": 0.8
        }
        mock_response1.optimization_applied = True
        mock_response1.learning_applied = True
        mock_response1.generation_time = 2.5
        
        mock_response2 = Mock()
        mock_response2.analysis.timestamp.days = 5
        mock_response2.quality_metrics = {
            "overall_score": 0.9,
            "uniqueness_score": 0.8,
            "humanization_score": 0.9
        }
        mock_response2.optimization_applied = False
        mock_response2.learning_applied = True
        mock_response2.generation_time = 1.8
        
        integration.integration_history = [mock_response1, mock_response2]
        
        stats = integration.get_integration_stats(days=30)
        
        assert isinstance(stats, dict)
        assert "total_articles" in stats
        assert "avg_generation_time" in stats
        assert "optimization_rate" in stats
        assert "learning_rate" in stats
        assert "avg_quality_score" in stats
        assert "ml_usage_rate" in stats
    
    def test_get_top_topics(self, integration):
        """Testa obtenção de tópicos mais gerados."""
        # Mock de respostas com tópicos
        mock_response1 = Mock()
        mock_response1.analysis.topics = ["technology", "ai"]
        
        mock_response2 = Mock()
        mock_response2.analysis.topics = ["healthcare", "ai"]
        
        mock_response3 = Mock()
        mock_response3.analysis.topics = ["technology", "innovation"]
        
        history = [mock_response1, mock_response2, mock_response3]
        
        top_topics = integration._get_top_topics(history)
        
        assert isinstance(top_topics, list)
        assert len(top_topics) > 0
        assert all(isinstance(topic, dict) for topic in top_topics)
        assert all("topic" in topic for topic in top_topics)
        assert all("count" in topic for topic in top_topics)
        assert all("avg_score" in topic for topic in top_topics)
    
    def test_get_style_performance(self, integration):
        """Testa obtenção de performance por estilo."""
        # Mock de respostas com diferentes métricas
        mock_response1 = Mock()
        mock_response1.quality_metrics = {"humanization_score": 0.9}  # Casual
        
        mock_response2 = Mock()
        mock_response2.quality_metrics = {"readability_score": 0.9}  # Formal
        
        mock_response3 = Mock()
        mock_response3.quality_metrics = {"humanization_score": 0.8}  # Casual
        
        history = [mock_response1, mock_response2, mock_response3]
        
        performance = integration._get_style_performance(history)
        
        assert isinstance(performance, dict)
        assert "casual" in performance
        assert "formal" in performance
        assert all(isinstance(score, float) for score in performance.values())
        assert all(0 <= score <= 1 for score in performance.values())
    
    def test_generate_batch_with_ml(self, integration):
        """Testa geração em lote com ML."""
        requests = [
            MLArticleRequest(topic="AI", target_length=300, style="casual", language="en"),
            MLArticleRequest(topic="ML", target_length=400, style="formal", language="en")
        ]
        
        with patch.object(integration, 'generate_article_with_ml') as mock_generate:
            mock_generate.side_effect = [
                Mock(content="AI content"),
                Mock(content="ML content")
            ]
            
            results = integration.generate_batch_with_ml(requests)
            
            assert len(results) == 2
            assert mock_generate.call_count == 2
    
    def test_export_integration_data(self, integration, tmp_path):
        """Testa exportação de dados de integração."""
        # Adiciona dados ao histórico
        mock_response = Mock()
        mock_response.content = "Test content"
        mock_response.original_content = "Original content"
        mock_response.analysis = Mock()
        mock_response.quality_metrics = {"overall_score": 0.8}
        mock_response.optimization_applied = True
        mock_response.learning_applied = True
        mock_response.generation_time = 2.0
        
        integration.integration_history = [mock_response]
        
        export_path = tmp_path / "integration_data.json"
        
        integration.export_integration_data(str(export_path))
        
        assert export_path.exists()
        assert export_path.stat().st_size > 0
    
    def test_update_config(self, integration, tmp_path):
        """Testa atualização de configuração."""
        new_config = {
            "min_quality_score": 0.9,
            "max_iterations": 10
        }
        
        config_path = tmp_path / "test_config.json"
        integration.config_path = str(config_path)
        
        integration.update_config(new_config)
        
        # Verifica se a configuração foi atualizada
        assert integration.config["min_quality_score"] == 0.9
        assert integration.config["max_iterations"] == 10
        
        # Verifica se o arquivo foi salvo
        assert config_path.exists()
    
    def test_error_handling_optimization_disabled(self, integration, sample_request):
        """Testa comportamento quando otimização está desabilitada."""
        integration.config["optimization_enabled"] = False
        
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Original content."
            
            with patch.object(integration, '_apply_learning'):
                response = integration.generate_article_with_ml(sample_request)
                
                assert response is not None
                assert response.optimization_applied is False
                assert response.content == "Original content."
    
    def test_error_handling_learning_disabled(self, integration, sample_request):
        """Testa comportamento quando aprendizado está desabilitado."""
        sample_request.enable_learning = False
        
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Original content."
            
            with patch.object(integration.optimizer, 'optimize_content') as mock_optimize:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.9
                mock_optimize.return_value = ("Optimized content.", mock_analysis)
                
                response = integration.generate_article_with_ml(sample_request)
                
                assert response is not None
                assert response.learning_applied is False
    
    def test_performance_metrics(self, integration, sample_request):
        """Testa métricas de performance."""
        import time
        
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Original content."
            
            with patch.object(integration.optimizer, 'optimize_content') as mock_optimize:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.9
                mock_optimize.return_value = ("Optimized content.", mock_analysis)
                
                with patch.object(integration, '_apply_learning'):
                    with patch.object(integration.optimizer, 'get_optimization_suggestions'):
                        start_time = time.time()
                        response = integration.generate_article_with_ml(sample_request)
                        end_time = time.time()
                        
                        processing_time = end_time - start_time
                        
                        assert response is not None
                        assert processing_time < 10.0  # Deve processar em menos de 10 segundos
    
    def test_content_quality_validation(self, integration, sample_request):
        """Testa validação de qualidade do conteúdo."""
        with patch.object(integration, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "High quality content about AI in healthcare."
            
            with patch.object(integration.optimizer, 'optimize_content') as mock_optimize:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.95
                mock_analysis.metrics.uniqueness_score = 0.9
                mock_analysis.metrics.humanization_score = 0.8
                mock_optimize.return_value = ("Optimized content.", mock_analysis)
                
                with patch.object(integration, '_apply_learning'):
                    with patch.object(integration.optimizer, 'get_optimization_suggestions'):
                        response = integration.generate_article_with_ml(sample_request)
                        
                        assert response is not None
                        assert response.quality_metrics["overall_score"] >= 0.9
                        assert response.quality_metrics["uniqueness_score"] >= 0.9
                        assert response.quality_metrics["humanization_score"] >= 0.8


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 