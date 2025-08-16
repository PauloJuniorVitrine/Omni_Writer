#!/usr/bin/env python3
"""
Testes unitários para IntelligentGenerator.
Valida funcionalidades de geração inteligente de conteúdo.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Adiciona o diretório raiz ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from omni_writer.ml_advanced.intelligent_generator import (
    IntelligentGenerator,
    GenerationRequest,
    GenerationResult,
    StyleTemplate
)

class TestIntelligentGenerator:
    """Testes para IntelligentGenerator."""
    
    @pytest.fixture
    def generator(self):
        """Fixture para IntelligentGenerator."""
        with patch('omni_writer.ml_advanced.intelligent_generator.ContentOptimizer'):
            generator = IntelligentGenerator()
            generator.optimizer = Mock()
            generator.style_templates = {
                "casual": StyleTemplate(
                    name="Casual",
                    description="Estilo conversacional",
                    characteristics={"tone": "friendly"},
                    examples=["You know what's cool?"],
                    success_rate=0.9
                ),
                "formal": StyleTemplate(
                    name="Formal",
                    description="Estilo acadêmico",
                    characteristics={"tone": "objective"},
                    examples=["The research indicates"],
                    success_rate=0.85
                )
            }
            return generator
    
    @pytest.fixture
    def sample_request(self):
        """Requisição de teste."""
        return GenerationRequest(
            topic="artificial intelligence",
            content_type="article",
            target_length=300,
            style="casual",
            language="en",
            keywords=["AI", "machine learning"],
            tone="positive",
            complexity="intermediate"
        )
    
    def test_initialization(self, generator):
        """Testa inicialização do gerador."""
        assert generator is not None
        assert generator.optimizer is not None
        assert generator.style_templates is not None
        assert len(generator.style_templates) > 0
        assert generator.max_iterations == 5
        assert generator.min_quality_score == 0.8
        assert generator.learning_enabled is True
    
    def test_load_style_templates(self, generator):
        """Testa carregamento de templates de estilo."""
        templates = generator._load_style_templates()
        
        assert isinstance(templates, dict)
        assert "formal" in templates
        assert "casual" in templates
        assert "technical" in templates
        assert "storytelling" in templates
        
        # Verifica estrutura dos templates
        for style, template in templates.items():
            assert isinstance(template, StyleTemplate)
            assert template.name is not None
            assert template.description is not None
            assert template.characteristics is not None
            assert template.examples is not None
            assert 0 <= template.success_rate <= 1
    
    def test_generate_structure(self, generator, sample_request):
        """Testa geração de estrutura de conteúdo."""
        style_template = generator.style_templates["casual"]
        structure = generator._generate_structure(sample_request, style_template)
        
        assert isinstance(structure, dict)
        assert "introduction" in structure
        assert "body" in structure
        assert "conclusion" in structure
        
        # Verifica seções do corpo
        assert len(structure["body"]["sections"]) > 0
        assert structure["body"]["total_length"] > 0
        
        # Verifica proporções
        total_length = sample_request.target_length
        intro_length = structure["introduction"]["length"]
        body_length = structure["body"]["total_length"]
        conclusion_length = structure["conclusion"]["length"]
        
        assert abs(intro_length + body_length + conclusion_length - total_length) < 50
    
    def test_generate_introduction(self, generator, sample_request):
        """Testa geração de introdução."""
        style_template = generator.style_templates["casual"]
        target_length = 100
        
        introduction = generator._generate_introduction(sample_request, style_template, target_length)
        
        assert isinstance(introduction, str)
        assert len(introduction) > 0
        assert sample_request.topic.lower() in introduction.lower()
        
        # Verifica se contém elementos de introdução
        assert any(word in introduction.lower() for word in ["artificial", "intelligence", "ai"])
    
    def test_generate_section(self, generator, sample_request):
        """Testa geração de seção."""
        style_template = generator.style_templates["casual"]
        section = {
            "id": 1,
            "length": 150,
            "elements": ["topic_sentence", "explanation", "example", "transition"]
        }
        
        section_content = generator._generate_section(sample_request, style_template, section)
        
        assert isinstance(section_content, str)
        assert len(section_content) > 0
        
        # Verifica se contém elementos da seção
        assert "." in section_content  # Deve ter sentenças
    
    def test_generate_conclusion(self, generator, sample_request):
        """Testa geração de conclusão."""
        style_template = generator.style_templates["casual"]
        target_length = 100
        
        conclusion = generator._generate_conclusion(sample_request, style_template, target_length)
        
        assert isinstance(conclusion, str)
        assert len(conclusion) > 0
        
        # Verifica se contém elementos de conclusão
        conclusion_lower = conclusion.lower()
        assert any(word in conclusion_lower for word in ["summary", "conclude", "ultimately", "finally"])
    
    def test_apply_success_patterns(self, generator, sample_request):
        """Testa aplicação de padrões de sucesso."""
        content = "This is a test content about artificial intelligence."
        
        with patch.object(generator, '_get_topic_patterns') as mock_get_patterns:
            mock_get_patterns.return_value = [
                {
                    'pattern_data': 'personal_pronouns',
                    'success_rate': 0.9,
                    'usage_count': 10
                }
            ]
            
            with patch.object(generator, '_apply_pattern') as mock_apply:
                mock_apply.return_value = "You'll find this test content about artificial intelligence."
                
                result = generator._apply_success_patterns(content, sample_request)
                
                assert result is not None
                assert mock_apply.called
    
    def test_get_topic_patterns(self, generator):
        """Testa obtenção de padrões por tópico."""
        topic = "artificial intelligence"
        
        with patch('omni_writer.ml_advanced.intelligent_generator.sqlite3') as mock_sqlite:
            mock_conn = Mock()
            mock_cursor = Mock()
            mock_cursor.fetchall.return_value = [
                ("hash1", "personal_pronouns", 0.9, 5),
                ("hash2", "conversational_phrases", 0.8, 3)
            ]
            mock_conn.cursor.return_value = mock_cursor
            mock_sqlite.connect.return_value = mock_conn
            
            patterns = generator._get_topic_patterns(topic)
            
            assert isinstance(patterns, list)
            assert len(patterns) > 0
            assert all(isinstance(p, dict) for p in patterns)
            assert all('success_rate' in p for p in patterns)
    
    def test_apply_pattern(self, generator):
        """Testa aplicação de padrão específico."""
        content = "The research shows that AI is important."
        pattern = {
            'pattern_data': 'personal_pronouns',
            'success_rate': 0.9,
            'usage_count': 10
        }
        
        result = generator._apply_pattern(content, pattern)
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_extract_successful_patterns(self, generator):
        """Testa extração de padrões bem-sucedidos."""
        content = "You know what's really cool? I think you'll find this interesting."
        
        patterns = generator._extract_successful_patterns(content)
        
        assert isinstance(patterns, list)
        assert "personal_pronouns" in patterns
        assert "conversational_phrases" in patterns
    
    def test_extract_failed_patterns(self, generator):
        """Testa extração de padrões que falharam."""
        content = "The research. The data. The analysis. The conclusion."
        
        patterns = generator._extract_failed_patterns(content)
        
        assert isinstance(patterns, list)
        # Conteúdo muito formal deve gerar padrões de falha
        assert len(patterns) > 0
    
    def test_learn_from_generation(self, generator, sample_request):
        """Testa aprendizado com geração."""
        # Mock do resultado de geração
        mock_result = Mock()
        mock_result.content = "Test content"
        mock_result.analysis = Mock()
        mock_result.analysis.content_hash = "test_hash"
        mock_result.analysis.metrics.overall_score = 0.8
        mock_result.suggestions = ["Add more examples"]
        
        with patch.object(generator.optimizer, 'learn_from_feedback'):
            generator._learn_from_generation(sample_request, mock_result)
            
            # Verifica se o aprendizado foi chamado
            generator.optimizer.learn_from_feedback.assert_called_once()
    
    def test_get_generation_stats(self, generator):
        """Testa obtenção de estatísticas de geração."""
        # Adiciona alguns resultados ao histórico
        mock_result1 = Mock()
        mock_result1.analysis.timestamp = Mock()
        mock_result1.analysis.timestamp.days = 10
        mock_result1.uniqueness_score = 0.8
        mock_result1.humanization_score = 0.7
        mock_result1.iterations = 3
        mock_result1.generation_time = 2.5
        
        mock_result2 = Mock()
        mock_result2.analysis.timestamp = Mock()
        mock_result2.analysis.timestamp.days = 5
        mock_result2.uniqueness_score = 0.9
        mock_result2.humanization_score = 0.8
        mock_result2.iterations = 2
        mock_result2.generation_time = 1.8
        
        generator.generation_history = [mock_result1, mock_result2]
        
        stats = generator.get_generation_stats(days=30)
        
        assert isinstance(stats, dict)
        assert "total_generations" in stats
        assert "avg_generation_time" in stats
        assert "avg_iterations" in stats
        assert "avg_uniqueness" in stats
        assert "avg_humanization" in stats
    
    def test_generate_content_success(self, generator, sample_request):
        """Testa geração de conteúdo bem-sucedida."""
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Generated content about AI."
            
            with patch.object(generator.optimizer, 'analyze_content') as mock_analyze:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.9
                mock_analyze.return_value = mock_analysis
                
                with patch.object(generator, '_learn_from_generation'):
                    result = generator.generate_content(sample_request)
                    
                    assert result is not None
                    assert isinstance(result, GenerationResult)
                    assert result.content is not None
                    assert result.analysis is not None
                    assert result.iterations >= 1
    
    def test_generate_content_with_optimization(self, generator, sample_request):
        """Testa geração com otimização."""
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Initial content."
            
            with patch.object(generator.optimizer, 'analyze_content') as mock_analyze:
                # Primeira análise com score baixo
                mock_analysis1 = Mock()
                mock_analysis1.metrics.overall_score = 0.5
                mock_analyze.return_value = mock_analysis1
                
                with patch.object(generator.optimizer, 'optimize_content') as mock_optimize:
                    mock_optimize.return_value = ("Optimized content.", mock_analysis1)
                    
                    with patch.object(generator, '_learn_from_generation'):
                        result = generator.generate_content(sample_request)
                        
                        assert result is not None
                        assert result.optimization_applied is True
                        assert mock_optimize.called
    
    def test_generate_batch(self, generator):
        """Testa geração em lote."""
        requests = [
            GenerationRequest(topic="AI", target_length=200, style="casual", language="en"),
            GenerationRequest(topic="ML", target_length=300, style="formal", language="en")
        ]
        
        with patch.object(generator, 'generate_content') as mock_generate:
            mock_generate.side_effect = [
                Mock(content="AI content"),
                Mock(content="ML content")
            ]
            
            results = generator.generate_batch(requests)
            
            assert len(results) == 2
            assert mock_generate.call_count == 2
    
    def test_export_learning_data(self, generator, tmp_path):
        """Testa exportação de dados de aprendizado."""
        # Adiciona dados ao histórico
        mock_result = Mock()
        mock_result.content = "Test content"
        mock_result.analysis = Mock()
        mock_result.generation_time = 2.0
        mock_result.iterations = 3
        
        generator.generation_history = [mock_result]
        generator.success_patterns = {"ai": [{"pattern": "test"}]}
        generator.failed_patterns = {"ml": [{"pattern": "failed"}]}
        
        export_path = tmp_path / "learning_data.json"
        
        generator.export_learning_data(str(export_path))
        
        assert export_path.exists()
        assert export_path.stat().st_size > 0
    
    def test_error_handling_generation_failure(self, generator, sample_request):
        """Testa tratamento de erro na geração."""
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.side_effect = Exception("Generation error")
            
            result = generator.generate_content(sample_request)
            
            # Deve retornar None em caso de erro
            assert result is None
    
    def test_error_handling_optimization_failure(self, generator, sample_request):
        """Testa tratamento de erro na otimização."""
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Test content"
            
            with patch.object(generator.optimizer, 'analyze_content') as mock_analyze:
                mock_analyze.side_effect = Exception("Analysis error")
                
                result = generator.generate_content(sample_request)
                
                # Deve retornar None em caso de erro
                assert result is None
    
    def test_performance_metrics(self, generator, sample_request):
        """Testa métricas de performance."""
        import time
        
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "Generated content."
            
            with patch.object(generator.optimizer, 'analyze_content') as mock_analyze:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.9
                mock_analyze.return_value = mock_analysis
                
                with patch.object(generator, '_learn_from_generation'):
                    start_time = time.time()
                    result = generator.generate_content(sample_request)
                    end_time = time.time()
                    
                    processing_time = end_time - start_time
                    
                    assert result is not None
                    assert processing_time < 10.0  # Deve processar em menos de 10 segundos
    
    def test_content_quality_validation(self, generator, sample_request):
        """Testa validação de qualidade do conteúdo."""
        with patch.object(generator, '_generate_initial_content') as mock_generate:
            mock_generate.return_value = "High quality content about artificial intelligence."
            
            with patch.object(generator.optimizer, 'analyze_content') as mock_analyze:
                mock_analysis = Mock()
                mock_analysis.metrics.overall_score = 0.95
                mock_analysis.metrics.uniqueness_score = 0.9
                mock_analysis.metrics.humanization_score = 0.8
                mock_analyze.return_value = mock_analysis
                
                with patch.object(generator, '_learn_from_generation'):
                    result = generator.generate_content(sample_request)
                    
                    assert result is not None
                    assert result.uniqueness_score >= 0.9
                    assert result.humanization_score >= 0.8
    
    def test_style_template_validation(self, generator):
        """Testa validação de templates de estilo."""
        templates = generator.style_templates
        
        for style_name, template in templates.items():
            assert isinstance(template, StyleTemplate)
            assert template.name is not None
            assert template.description is not None
            assert template.characteristics is not None
            assert template.examples is not None
            assert 0 <= template.success_rate <= 1
            
            # Verifica características específicas
            if style_name == "casual":
                assert template.characteristics.get("tone") == "friendly"
            elif style_name == "formal":
                assert template.characteristics.get("tone") == "objective"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 