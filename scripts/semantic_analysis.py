"""
Sistema de Análise Semântica para Documentação Enterprise
Implementa embeddings semânticos e cálculo de similaridade para validação de documentação.

Prompt: Documentação Enterprise - IMP-001
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T16:05:00Z
Tracing ID: DOC_ENTERPRISE_20250127_001
"""

import os
import json
import logging
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

# Configuração de logging estruturado
logger = logging.getLogger("semantic_analysis")
logger.setLevel(logging.INFO)

@dataclass
class SemanticAnalysisResult:
    """Resultado da análise semântica"""
    function_path: str
    function_code: str
    function_docs: str
    similarity_score: float
    completeness_score: float
    coherence_score: float
    overall_score: float
    analysis_timestamp: str
    embedding_hash: str
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class SemanticAnalyzer:
    """
    Analisador semântico para validação de documentação.
    Implementa embeddings e cálculo de similaridade para garantir qualidade da documentação.
    """
    
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2', similarity_threshold: float = 0.85):
        """
        Inicializa o analisador semântico.
        
        Args:
            model_name: Nome do modelo de embeddings
            similarity_threshold: Limite mínimo de similaridade
        """
        self.model_name = model_name
        self.similarity_threshold = similarity_threshold
        self.model = None
        self.analysis_results: List[SemanticAnalysisResult] = []
        
        # Inicializar modelo de embeddings
        self._initialize_model()
        
        logger.info(f"SemanticAnalyzer inicializado com modelo: {model_name}")
    
    def _initialize_model(self):
        """Inicializa o modelo de embeddings"""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Modelo {self.model_name} carregado com sucesso")
        except ImportError:
            logger.warning("sentence-transformers não disponível, usando fallback")
            self.model = None
        except Exception as e:
            logger.error(f"Erro ao carregar modelo: {e}")
            self.model = None
    
    def generate_embedding(self, text: str) -> Optional[np.ndarray]:
        """
        Gera embedding para um texto.
        
        Args:
            text: Texto para gerar embedding
            
        Returns:
            Embedding como numpy array ou None se falhar
        """
        if not text or not text.strip():
            return None
        
        try:
            if self.model:
                return self.model.encode(text)
            else:
                # Fallback: embedding simples baseado em hash
                return self._fallback_embedding(text)
        except Exception as e:
            logger.error(f"Erro ao gerar embedding: {e}")
            return None
    
    def _fallback_embedding(self, text: str) -> np.ndarray:
        """
        Fallback para geração de embedding quando modelo não está disponível.
        
        Args:
            text: Texto para gerar embedding
            
        Returns:
            Embedding simulado como numpy array
        """
        # Hash do texto para simular embedding
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        # Converter hash para array de números
        numbers = [int(text_hash[i:i+2], 16) for i in range(0, len(text_hash), 2)]
        
        # Normalizar para 384 dimensões (tamanho do all-MiniLM-L6-v2)
        while len(numbers) < 384:
            numbers.extend(numbers[:384 - len(numbers)])
        
        return np.array(numbers[:384], dtype=np.float32)
    
    def calculate_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Calcula similaridade entre dois embeddings usando cosine similarity.
        
        Args:
            embedding1: Primeiro embedding
            embedding2: Segundo embedding
            
        Returns:
            Score de similaridade entre 0 e 1
        """
        try:
            # Normalizar embeddings
            norm1 = np.linalg.norm(embedding1)
            norm2 = np.linalg.norm(embedding2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
            
            # Calcular cosine similarity
            similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
            
            # Garantir que está entre 0 e 1
            return max(0.0, min(1.0, similarity))
            
        except Exception as e:
            logger.error(f"Erro ao calcular similaridade: {e}")
            return 0.0
    
    def analyze_function_semantics(self, function_path: str, function_code: str, 
                                 function_docs: str) -> SemanticAnalysisResult:
        """
        Analisa semântica de uma função comparando código e documentação.
        
        Args:
            function_path: Caminho da função
            function_code: Código da função
            function_docs: Documentação da função
            
        Returns:
            Resultado da análise semântica
        """
        # Gerar embeddings
        code_embedding = self.generate_embedding(function_code)
        docs_embedding = self.generate_embedding(function_docs)
        
        # Calcular similaridade
        similarity_score = 0.0
        if code_embedding is not None and docs_embedding is not None:
            similarity_score = self.calculate_similarity(code_embedding, docs_embedding)
        
        # Calcular scores de qualidade
        completeness_score = self._calculate_completeness(function_docs)
        coherence_score = self._calculate_coherence(function_docs)
        
        # Score geral
        overall_score = ((completeness_score * 4) + (coherence_score * 3) + (similarity_score * 3)) / 10
        
        # Gerar recomendações
        recommendations = self._generate_recommendations(similarity_score, completeness_score, coherence_score)
        
        # Criar hash do embedding para rastreabilidade
        embedding_hash = hashlib.sha256(str(code_embedding).encode()).hexdigest()[:16]
        
        result = SemanticAnalysisResult(
            function_path=function_path,
            function_code=function_code,
            function_docs=function_docs,
            similarity_score=similarity_score,
            completeness_score=completeness_score,
            coherence_score=coherence_score,
            overall_score=overall_score,
            analysis_timestamp=datetime.utcnow().isoformat(),
            embedding_hash=embedding_hash,
            recommendations=recommendations
        )
        
        self.analysis_results.append(result)
        
        logger.info(f"Análise semântica concluída para {function_path}: score={overall_score:.3f}")
        
        return result
    
    def _calculate_completeness(self, docs: str) -> float:
        """
        Calcula score de completude da documentação.
        
        Args:
            docs: Documentação da função
            
        Returns:
            Score de completude entre 0 e 1
        """
        if not docs or not docs.strip():
            return 0.0
        
        # Critérios de completude
        criteria = {
            'has_description': len(docs.strip()) > 10,
            'has_params': 'param' in docs.lower() or 'args' in docs.lower(),
            'has_returns': 'return' in docs.lower() or 'retorna' in docs.lower(),
            'has_examples': 'exemplo' in docs.lower() or 'example' in docs.lower(),
            'has_raises': 'raise' in docs.lower() or 'exception' in docs.lower()
        }
        
        # Calcular score baseado nos critérios
        score = sum(criteria.values()) / len(criteria)
        
        return score
    
    def _calculate_coherence(self, docs: str) -> float:
        """
        Calcula score de coerência da documentação.
        
        Args:
            docs: Documentação da função
            
        Returns:
            Score de coerência entre 0 e 1
        """
        if not docs or not docs.strip():
            return 0.0
        
        # Critérios de coerência
        criteria = {
            'has_structure': docs.count('\n') > 2,  # Estrutura com parágrafos
            'has_consistent_format': docs.count('*') == 0 or docs.count('*') % 2 == 0,  # Markdown válido
            'has_clear_language': len(docs.split()) > 5,  # Texto substancial
            'has_logical_flow': docs.count('.') > 0,  # Frases completas
            'has_no_duplicates': len(set(docs.split())) / len(docs.split()) > 0.7  # Baixa repetição
        }
        
        # Calcular score baseado nos critérios
        score = sum(criteria.values()) / len(criteria)
        
        return score
    
    def _generate_recommendations(self, similarity: float, completeness: float, 
                                coherence: float) -> List[str]:
        """
        Gera recomendações baseadas nos scores.
        
        Args:
            similarity: Score de similaridade
            completeness: Score de completude
            coherence: Score de coerência
            
        Returns:
            Lista de recomendações
        """
        recommendations = []
        
        if similarity < self.similarity_threshold:
            recommendations.append(f"Similaridade baixa ({similarity:.3f} < {self.similarity_threshold}). "
                                 "Revisar documentação para alinhar com implementação.")
        
        if completeness < 0.7:
            recommendations.append(f"Completude baixa ({completeness:.3f} < 0.7). "
                                 "Adicionar descrição, parâmetros, retornos e exemplos.")
        
        if coherence < 0.6:
            recommendations.append(f"Coerência baixa ({coherence:.3f} < 0.6). "
                                 "Melhorar estrutura e clareza da documentação.")
        
        if similarity >= self.similarity_threshold and completeness >= 0.8 and coherence >= 0.7:
            recommendations.append("Documentação de alta qualidade. Manter padrão.")
        
        return recommendations
    
    def analyze_project_functions(self, project_path: str) -> List[SemanticAnalysisResult]:
        """
        Analisa todas as funções públicas de um projeto.
        
        Args:
            project_path: Caminho do projeto
            
        Returns:
            Lista de resultados de análise
        """
        results = []
        
        # Encontrar arquivos Python
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    results.extend(self._analyze_file_functions(file_path))
        
        return results
    
    def _analyze_file_functions(self, file_path: str) -> List[SemanticAnalysisResult]:
        """
        Analisa funções de um arquivo Python.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Lista de resultados de análise
        """
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extrair funções e suas documentações
            functions = self._extract_functions(content)
            
            for func_name, func_code, func_docs in functions:
                function_path = f"{file_path}::{func_name}"
                result = self.analyze_function_semantics(function_path, func_code, func_docs)
                results.append(result)
                
        except Exception as e:
            logger.error(f"Erro ao analisar arquivo {file_path}: {e}")
        
        return results
    
    def _extract_functions(self, content: str) -> List[Tuple[str, str, str]]:
        """
        Extrai funções e suas documentações de um arquivo Python.
        
        Args:
            content: Conteúdo do arquivo
            
        Returns:
            Lista de tuplas (nome, código, documentação)
        """
        import ast
        
        functions = []
        
        try:
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_name = node.name
                    
                    # Extrair documentação
                    func_docs = ast.get_docstring(node) or ""
                    
                    # Extrair código da função
                    func_code = ast.unparse(node)
                    
                    functions.append((func_name, func_code, func_docs))
                    
        except Exception as e:
            logger.error(f"Erro ao extrair funções: {e}")
        
        return functions
    
    def save_results(self, output_path: str):
        """
        Salva resultados da análise em arquivo JSON.
        
        Args:
            output_path: Caminho do arquivo de saída
        """
        try:
            results_data = {
                'analysis_metadata': {
                    'model_name': self.model_name,
                    'similarity_threshold': self.similarity_threshold,
                    'total_functions': len(self.analysis_results),
                    'analysis_timestamp': datetime.utcnow().isoformat(),
                    'tracing_id': 'DOC_ENTERPRISE_20250127_001'
                },
                'results': [result.to_dict() for result in self.analysis_results]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Resultados salvos em: {output_path}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {e}")
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas resumidas da análise.
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.analysis_results:
            return {}
        
        scores = [result.overall_score for result in self.analysis_results]
        
        return {
            'total_functions': len(self.analysis_results),
            'average_score': np.mean(scores),
            'median_score': np.median(scores),
            'min_score': np.min(scores),
            'max_score': np.max(scores),
            'std_score': np.std(scores),
            'functions_below_threshold': len([s for s in scores if s < self.similarity_threshold]),
            'high_quality_functions': len([s for s in scores if s >= 0.8])
        }


def main():
    """Função principal para demonstração"""
    analyzer = SemanticAnalyzer()
    
    # Exemplo de análise
    test_code = """
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
    """
    
    result = analyzer.analyze_function_semantics(
        "test.py::calculate_sum",
        test_code,
        "Calcula a soma de dois números inteiros."
    )
    
    print(f"Score geral: {result.overall_score:.3f}")
    print(f"Recomendações: {result.recommendations}")


if __name__ == "__main__":
    main() 