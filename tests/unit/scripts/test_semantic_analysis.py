"""
Testes unitários para o sistema de análise semântica.

Prompt: Documentação Enterprise - IMP-004
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:20:00Z
Tracing ID: DOC_ENTERPRISE_20250127_004
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts'))

from semantic_analysis import SemanticAnalyzer, SemanticAnalysisResult


class TestSemanticAnalyzer:
    """Testes para a classe SemanticAnalyzer"""
    
    def setup_method(self):
        """Configuração para cada teste"""
        self.analyzer = SemanticAnalyzer()
    
    def test_initialization(self):
        """Testa inicialização do analisador"""
        assert self.analyzer.model_name == 'all-MiniLM-L6-v2'
        assert self.analyzer.similarity_threshold == 0.85
        assert self.analyzer.analysis_results == []
    
    def test_fallback_embedding(self):
        """Testa geração de embedding fallback"""
        text = "test text"
        embedding = self.analyzer._fallback_embedding(text)
        
        assert embedding is not None
        assert embedding.shape == (384,)
        assert embedding.dtype.name == 'float32'
    
    def test_calculate_similarity(self):
        """Testa cálculo de similaridade"""
        # Criar embeddings de teste
        embedding1 = self.analyzer._fallback_embedding("test text 1")
        embedding2 = self.analyzer._fallback_embedding("test text 2")
        
        similarity = self.analyzer.calculate_similarity(embedding1, embedding2)
        
        assert 0.0 <= similarity <= 1.0
    
    def test_calculate_completeness(self):
        """Testa cálculo de completude"""
        # Teste com documentação completa
        complete_docs = """
        Calcula a soma de dois números.
        
        Args:
            a: Primeiro número
            b: Segundo número
            
        Returns:
            Soma dos números
            
        Raises:
            ValueError: Se os números forem inválidos
            
        Example:
            >>> calculate_sum(1, 2)
            3
        """
        
        score = self.analyzer._calculate_completeness(complete_docs)
        assert score > 0.7
        
        # Teste com documentação vazia
        empty_docs = ""
        score = self.analyzer._calculate_completeness(empty_docs)
        assert score == 0.0
    
    def test_calculate_coherence(self):
        """Testa cálculo de coerência"""
        # Teste com documentação coerente
        coherent_docs = """
        Esta função calcula a soma de dois números.
        
        A função recebe dois parâmetros numéricos e retorna
        a soma deles. Se os parâmetros forem inválidos,
        uma exceção será lançada.
        """
        
        score = self.analyzer._calculate_coherence(coherent_docs)
        assert score > 0.6
        
        # Teste com documentação incoerente
        incoherent_docs = "texto sem estrutura"
        score = self.analyzer._calculate_coherence(incoherent_docs)
        assert score < 0.6
    
    def test_generate_recommendations(self):
        """Testa geração de recomendações"""
        # Teste com scores baixos
        recommendations = self.analyzer._generate_recommendations(0.5, 0.4, 0.3)
        assert len(recommendations) > 0
        assert any("Similaridade baixa" in rec for rec in recommendations)
        
        # Teste com scores altos
        recommendations = self.analyzer._generate_recommendations(0.9, 0.8, 0.85)
        assert any("alta qualidade" in rec.lower() for rec in recommendations)
    
    def test_analyze_function_semantics(self):
        """Testa análise semântica de função"""
        function_path = "test.py::calculate_sum"
        function_code = """
def calculate_sum(a: int, b: int) -> int:
    return a + b
        """
        function_docs = "Calcula a soma de dois números inteiros."
        
        result = self.analyzer.analyze_function_semantics(
            function_path, function_code, function_docs
        )
        
        assert isinstance(result, SemanticAnalysisResult)
        assert result.function_path == function_path
        assert 0.0 <= result.overall_score <= 1.0
        assert len(result.recommendations) >= 0
    
    def test_extract_functions(self):
        """Testa extração de funções de código Python"""
        code = """
def function1():
    \"\"\"Docstring da função 1\"\"\"
    pass

def function2():
    \"\"\"Docstring da função 2\"\"\"
    return True
        """
        
        functions = self.analyzer._extract_functions(code)
        
        assert len(functions) == 2
        assert functions[0][0] == "function1"
        assert "Docstring da função 1" in functions[0][2]
        assert functions[1][0] == "function2"
    
    def test_save_results(self):
        """Testa salvamento de resultados"""
        # Adicionar resultado de teste
        result = SemanticAnalysisResult(
            function_path="test.py::test_func",
            function_code="def test_func(): pass",
            function_docs="Test function",
            similarity_score=0.8,
            completeness_score=0.7,
            coherence_score=0.6,
            overall_score=0.7,
            analysis_timestamp="2025-01-27T16:20:00Z",
            embedding_hash="test_hash",
            recommendations=["Test recommendation"]
        )
        
        self.analyzer.analysis_results.append(result)
        
        # Salvar em arquivo temporário
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_file = f.name
        
        try:
            self.analyzer.save_results(temp_file)
            
            # Verificar se arquivo foi criado
            assert os.path.exists(temp_file)
            
            # Verificar conteúdo
            with open(temp_file, 'r') as f:
                data = f.read()
                assert "test.py::test_func" in data
                assert "0.7" in data
                
        finally:
            os.unlink(temp_file)
    
    def test_get_summary_stats(self):
        """Testa obtenção de estatísticas resumidas"""
        # Adicionar resultados de teste
        for i in range(3):
            result = SemanticAnalysisResult(
                function_path=f"test.py::func_{i}",
                function_code=f"def func_{i}(): pass",
                function_docs=f"Function {i}",
                similarity_score=0.8 + (i * 0.05),
                completeness_score=0.7 + (i * 0.05),
                coherence_score=0.6 + (i * 0.05),
                overall_score=0.7 + (i * 0.05),
                analysis_timestamp="2025-01-27T16:20:00Z",
                embedding_hash=f"hash_{i}",
                recommendations=[]
            )
            self.analyzer.analysis_results.append(result)
        
        stats = self.analyzer.get_summary_stats()
        
        assert stats['total_functions'] == 3
        assert 'average_score' in stats
        assert 'median_score' in stats
        assert 'min_score' in stats
        assert 'max_score' in stats


class TestSemanticAnalysisResult:
    """Testes para a classe SemanticAnalysisResult"""
    
    def test_to_dict(self):
        """Testa conversão para dicionário"""
        result = SemanticAnalysisResult(
            function_path="test.py::test_func",
            function_code="def test_func(): pass",
            function_docs="Test function",
            similarity_score=0.8,
            completeness_score=0.7,
            coherence_score=0.6,
            overall_score=0.7,
            analysis_timestamp="2025-01-27T16:20:00Z",
            embedding_hash="test_hash",
            recommendations=["Test recommendation"]
        )
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict['function_path'] == "test.py::test_func"
        assert result_dict['similarity_score'] == 0.8
        assert result_dict['recommendations'] == ["Test recommendation"]


@pytest.mark.integration
class TestSemanticAnalyzerIntegration:
    """Testes de integração para SemanticAnalyzer"""
    
    def test_full_analysis_workflow(self):
        """Testa workflow completo de análise"""
        analyzer = SemanticAnalyzer()
        
        # Criar arquivo de teste
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            test_file = f.name
            f.write("""
def calculate_sum(a: int, b: int) -> int:
    \"\"\"
    Calcula a soma de dois números inteiros.
    
    Args:
        a: Primeiro número
        b: Segundo número
        
    Returns:
        Soma dos dois números
    \"\"\"
    return a + b

def multiply_numbers(x: float, y: float) -> float:
    \"\"\"
    Multiplica dois números.
    \"\"\"
    return x * y
            """)
        
        try:
            # Analisar funções do arquivo
            results = analyzer._analyze_file_functions(test_file)
            
            assert len(results) == 2
            assert any("calculate_sum" in r.function_path for r in results)
            assert any("multiply_numbers" in r.function_path for r in results)
            
            # Verificar scores
            for result in results:
                assert 0.0 <= result.overall_score <= 1.0
                assert len(result.recommendations) >= 0
                
        finally:
            os.unlink(test_file)


if __name__ == "__main__":
    pytest.main([__file__]) 