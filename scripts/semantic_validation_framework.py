#!/usr/bin/env python3
"""
🧠 FRAMEWORK DE VALIDAÇÃO SEMÂNTICA COM EMBEDDINGS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Framework para validação semântica de testes usando embeddings.
Garante que testes validem funcionalidade real, não apenas sintaxe.

Tracing ID: SEMANTIC_VALIDATION_FRAMEWORK_20250127_001
Data/Hora: 2025-01-27T18:00:00Z
Versão: 1.0
"""

import time
import json
import logging
import threading
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import uuid
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import ast
import inspect

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "SEMANTIC_VALIDATION_FRAMEWORK_20250127_001"

@dataclass
class SemanticValidationResult:
    """Resultado de uma validação semântica."""
    test_id: str
    test_name: str
    file_path: str
    timestamp: datetime
    semantic_score: float
    code_similarity: float
    context_similarity: float
    is_generic: bool
    is_synthetic: bool
    validation_passed: bool
    issues_found: List[str]
    suggestions: List[str]
    tracing_id: str = TRACING_ID

@dataclass
class CodeContext:
    """Contexto do código para análise semântica."""
    function_name: str
    class_name: str
    module_name: str
    docstring: str
    source_code: str
    imports: List[str]
    dependencies: List[str]
    risk_score: int
    tracing_id: str = TRACING_ID

@dataclass
class TestContext:
    """Contexto do teste para análise semântica."""
    test_name: str
    test_description: str
    test_code: str
    assertions: List[str]
    mocks: List[str]
    test_data: Dict[str, Any]
    risk_score: int
    tracing_id: str = TRACING_ID

class SemanticValidationFramework:
    """
    Framework de validação semântica com embeddings.
    
    Valida se testes são baseados em código real e representativos
    da funcionalidade que testam.
    """
    
    def __init__(self, db_path: str = "tests/integration/semantic_validation.db"):
        self.tracing_id = TRACING_ID
        self.db_path = db_path
        self.active_validations: Dict[str, SemanticValidationResult] = {}
        self.results: List[SemanticValidationResult] = []
        self.lock = threading.Lock()
        
        # Configuração de análise semântica
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # Padrões para detectar testes genéricos/sintéticos
        self.generic_patterns = self._load_generic_patterns()
        
        # Inicializa banco de dados
        self._init_database()
        
        logger.info(f"[{self.tracing_id}] SemanticValidationFramework inicializado")
    
    def _load_generic_patterns(self) -> Dict[str, List[str]]:
        """
        Carrega padrões para detectar testes genéricos/sintéticos.
        
        Padrões baseados em análise de testes reais do Omni Writer:
        - Nomes genéricos (test_something, test_function)
        - Dados sintéticos (foo, bar, lorem, ipsum)
        - Assertions genéricas (assert True, assert not None)
        """
        return {
            "generic_names": [
                r"test_something",
                r"test_function",
                r"test_method",
                r"test_.*_works",
                r"test_.*_function",
                r"test_.*_method"
            ],
            "synthetic_data": [
                r"foo",
                r"bar",
                r"baz",
                r"lorem",
                r"ipsum",
                r"dolor",
                r"test_data",
                r"sample_data",
                r"dummy_data",
                r"mock_data"
            ],
            "generic_assertions": [
                r"assert\s+True",
                r"assert\s+not\s+None",
                r"assert\s+is\s+not\s+None",
                r"assert\s+.*\s+is\s+not\s+None",
                r"assert\s+.*\s+is\s+not\s+False",
                r"assert\s+.*\s+is\s+not\s+empty",
                r"assert\s+.*\s+exists",
                r"assert\s+.*\s+is\s+defined"
            ],
            "generic_mocks": [
                r"Mock\(",
                r"MagicMock\(",
                r"patch\(",
                r"side_effect\s*=\s*lambda",
                r"return_value\s*=\s*\{\}",
                r"return_value\s*=\s*\[\]"
            ]
        }
    
    def _init_database(self):
        """Inicializa banco de dados SQLite para validação semântica."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de resultados de validação semântica
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS semantic_validation_results (
                    test_id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    semantic_score REAL NOT NULL,
                    code_similarity REAL NOT NULL,
                    context_similarity REAL NOT NULL,
                    is_generic BOOLEAN NOT NULL,
                    is_synthetic BOOLEAN NOT NULL,
                    validation_passed BOOLEAN NOT NULL,
                    issues_found TEXT,
                    suggestions TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de contextos de código
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS code_contexts (
                    context_id TEXT PRIMARY KEY,
                    function_name TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    docstring TEXT,
                    source_code TEXT NOT NULL,
                    imports TEXT,
                    dependencies TEXT,
                    risk_score INTEGER NOT NULL,
                    semantic_vector TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de contextos de teste
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_contexts (
                    context_id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    test_description TEXT,
                    test_code TEXT NOT NULL,
                    assertions TEXT,
                    mocks TEXT,
                    test_data TEXT,
                    risk_score INTEGER NOT NULL,
                    semantic_vector TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info(f"[{self.tracing_id}] Banco de dados inicializado: {self.db_path}")
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao inicializar banco: {e}")
    
    def _extract_code_context(self, file_path: str, function_name: str) -> CodeContext:
        """
        Extrai contexto do código real para análise semântica.
        
        Args:
            file_path: Caminho do arquivo
            function_name: Nome da função
            
        Returns:
            Contexto do código
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse do código Python
            tree = ast.parse(source_code)
            
            # Encontra a função
            function_node = None
            class_name = "Unknown"
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == function_name:
                    function_node = node
                    break
                elif isinstance(node, ast.ClassDef):
                    for child in ast.walk(node):
                        if isinstance(child, ast.FunctionDef) and child.name == function_name:
                            function_node = child
                            class_name = node.name
                            break
            
            if not function_node:
                raise ValueError(f"Função {function_name} não encontrada em {file_path}")
            
            # Extrai informações
            docstring = ast.get_docstring(function_node) or ""
            function_source = ast.unparse(function_node)
            
            # Extrai imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
            
            # Calcula RISK_SCORE (baseado na implementação anterior)
            risk_score = self._calculate_risk_score(function_source, imports)
            
            return CodeContext(
                function_name=function_name,
                class_name=class_name,
                module_name=Path(file_path).stem,
                docstring=docstring,
                source_code=function_source,
                imports=imports,
                dependencies=imports,  # Simplificado
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao extrair contexto: {e}")
            return CodeContext(
                function_name=function_name,
                class_name="Unknown",
                module_name="Unknown",
                docstring="",
                source_code="",
                imports=[],
                dependencies=[],
                risk_score=50
            )
    
    def _calculate_risk_score(self, source_code: str, imports: List[str]) -> int:
        """
        Calcula RISK_SCORE baseado no código fonte.
        
        Args:
            source_code: Código fonte da função
            imports: Lista de imports
            
        Returns:
            RISK_SCORE calculado
        """
        # Camadas tocadas
        layers = 0
        if any(layer in source_code.lower() for layer in ["controller", "service", "repository", "gateway"]):
            layers += 1
        
        # Serviços externos
        services = 0
        service_keywords = ["openai", "postgresql", "redis", "stripe", "deepseek"]
        for service in service_keywords:
            if service in source_code.lower() or any(service in imp.lower() for imp in imports):
                services += 1
        
        # Frequência de uso (estimada)
        frequency = 3  # Média por padrão
        
        # Calcula RISK_SCORE
        risk_score = (layers * 10) + (services * 15) + (frequency * 5)
        
        return risk_score
    
    def _extract_test_context(self, test_file_path: str, test_name: str) -> TestContext:
        """
        Extrai contexto do teste para análise semântica.
        
        Args:
            test_file_path: Caminho do arquivo de teste
            test_name: Nome do teste
            
        Returns:
            Contexto do teste
        """
        try:
            with open(test_file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse do código Python
            tree = ast.parse(source_code)
            
            # Encontra o teste
            test_node = None
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == test_name:
                    test_node = node
                    break
            
            if not test_node:
                raise ValueError(f"Teste {test_name} não encontrado em {test_file_path}")
            
            # Extrai informações
            docstring = ast.get_docstring(test_node) or ""
            test_source = ast.unparse(test_node)
            
            # Extrai assertions
            assertions = []
            for node in ast.walk(test_node):
                if isinstance(node, ast.Assert):
                    assertions.append(ast.unparse(node))
            
            # Extrai mocks
            mocks = []
            for node in ast.walk(test_node):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and "mock" in node.func.id.lower():
                        mocks.append(ast.unparse(node))
                    elif isinstance(node.func, ast.Attribute) and "patch" in node.func.attr.lower():
                        mocks.append(ast.unparse(node))
            
            # Extrai dados de teste
            test_data = {}
            for node in ast.walk(test_node):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            test_data[target.id] = ast.unparse(node.value)
            
            # Calcula RISK_SCORE
            risk_score = self._calculate_risk_score(test_source, [])
            
            return TestContext(
                test_name=test_name,
                test_description=docstring,
                test_code=test_source,
                assertions=assertions,
                mocks=mocks,
                test_data=test_data,
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao extrair contexto do teste: {e}")
            return TestContext(
                test_name=test_name,
                test_description="",
                test_code="",
                assertions=[],
                mocks=[],
                test_data={},
                risk_score=50
            )
    
    def _calculate_semantic_similarity(self, text1: str, text2: str) -> float:
        """
        Calcula similaridade semântica entre dois textos usando TF-IDF.
        
        Args:
            text1: Primeiro texto
            text2: Segundo texto
            
        Returns:
            Score de similaridade (0.0 a 1.0)
        """
        try:
            if not text1.strip() or not text2.strip():
                return 0.0
            
            # Vetoriza os textos
            vectors = self.vectorizer.fit_transform([text1, text2])
            
            # Calcula similaridade cosseno
            similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
            
            return float(similarity)
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao calcular similaridade: {e}")
            return 0.0
    
    def _detect_generic_patterns(self, test_context: TestContext) -> Tuple[bool, bool, List[str]]:
        """
        Detecta padrões genéricos/sintéticos no teste.
        
        Args:
            test_context: Contexto do teste
            
        Returns:
            Tuple com (is_generic, is_synthetic, issues_found)
        """
        issues = []
        is_generic = False
        is_synthetic = False
        
        # Verifica nomes genéricos
        for pattern in self.generic_patterns["generic_names"]:
            if re.search(pattern, test_context.test_name, re.IGNORECASE):
                issues.append(f"Nome genérico detectado: {test_context.test_name}")
                is_generic = True
        
        # Verifica dados sintéticos
        test_text = f"{test_context.test_description} {test_context.test_code}"
        for pattern in self.generic_patterns["synthetic_data"]:
            if re.search(rf"\b{pattern}\b", test_text, re.IGNORECASE):
                issues.append(f"Dados sintéticos detectados: {pattern}")
                is_synthetic = True
        
        # Verifica assertions genéricas
        for assertion in test_context.assertions:
            for pattern in self.generic_patterns["generic_assertions"]:
                if re.search(pattern, assertion, re.IGNORECASE):
                    issues.append(f"Assertion genérica detectada: {assertion}")
                    is_generic = True
        
        # Verifica mocks genéricos
        for mock in test_context.mocks:
            for pattern in self.generic_patterns["generic_mocks"]:
                if re.search(pattern, mock, re.IGNORECASE):
                    issues.append(f"Mock genérico detectado: {mock}")
                    is_generic = True
        
        return is_generic, is_synthetic, issues
    
    def validate_test_semantics(self, 
                               test_file_path: str, 
                               test_name: str,
                               target_function: str = None,
                               target_file_path: str = None) -> SemanticValidationResult:
        """
        Valida semântica de um teste específico.
        
        Args:
            test_file_path: Caminho do arquivo de teste
            test_name: Nome do teste
            target_function: Função que o teste deveria testar
            target_file_path: Arquivo da função alvo
            
        Returns:
            Resultado da validação semântica
        """
        test_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        logger.info(f"[{self.tracing_id}] Validando semântica do teste: {test_name}")
        
        try:
            # Extrai contextos
            test_context = self._extract_test_context(test_file_path, test_name)
            
            # Detecta padrões genéricos/sintéticos
            is_generic, is_synthetic, issues = self._detect_generic_patterns(test_context)
            
            # Calcula similaridade semântica
            semantic_score = 0.0
            code_similarity = 0.0
            context_similarity = 0.0
            
            if target_function and target_file_path:
                # Extrai contexto do código alvo
                code_context = self._extract_code_context(target_file_path, target_function)
                
                # Calcula similaridades
                code_similarity = self._calculate_semantic_similarity(
                    test_context.test_description, 
                    code_context.docstring
                )
                
                context_similarity = self._calculate_semantic_similarity(
                    test_context.test_code,
                    code_context.source_code
                )
                
                # Score semântico combinado
                semantic_score = (code_similarity + context_similarity) / 2
            
            # Determina se validação passou
            validation_passed = (
                semantic_score >= 0.7 and  # Similaridade mínima
                not is_generic and          # Não é genérico
                not is_synthetic and        # Não é sintético
                len(issues) == 0            # Sem problemas detectados
            )
            
            # Gera sugestões
            suggestions = []
            if semantic_score < 0.7:
                suggestions.append("Melhore a descrição do teste para refletir a funcionalidade real")
            if is_generic:
                suggestions.append("Use nomes específicos baseados na funcionalidade real")
            if is_synthetic:
                suggestions.append("Use dados realistas baseados no código real")
            if len(test_context.assertions) < 2:
                suggestions.append("Adicione mais assertions específicas")
            
            # Cria resultado
            result = SemanticValidationResult(
                test_id=test_id,
                test_name=test_name,
                file_path=test_file_path,
                timestamp=timestamp,
                semantic_score=semantic_score,
                code_similarity=code_similarity,
                context_similarity=context_similarity,
                is_generic=is_generic,
                is_synthetic=is_synthetic,
                validation_passed=validation_passed,
                issues_found=issues,
                suggestions=suggestions
            )
            
            # Salva resultado
            self._save_validation_result(result)
            
            logger.info(f"[{self.tracing_id}] Validação concluída: {test_name} - Passou: {validation_passed}")
            
            return result
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro na validação: {e}")
            
            result = SemanticValidationResult(
                test_id=test_id,
                test_name=test_name,
                file_path=test_file_path,
                timestamp=timestamp,
                semantic_score=0.0,
                code_similarity=0.0,
                context_similarity=0.0,
                is_generic=True,
                is_synthetic=True,
                validation_passed=False,
                issues_found=[f"Erro na validação: {str(e)}"],
                suggestions=["Corrija o erro e tente novamente"]
            )
            
            self._save_validation_result(result)
            return result
    
    def _save_validation_result(self, result: SemanticValidationResult):
        """Salva resultado de validação no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO semantic_validation_results (
                    test_id, test_name, file_path, timestamp, semantic_score,
                    code_similarity, context_similarity, is_generic, is_synthetic,
                    validation_passed, issues_found, suggestions, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.test_id, result.test_name, result.file_path,
                result.timestamp.isoformat(), result.semantic_score,
                result.code_similarity, result.context_similarity,
                result.is_generic, result.is_synthetic, result.validation_passed,
                json.dumps(result.issues_found), json.dumps(result.suggestions),
                result.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar resultado: {e}")
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Gera relatório completo de validação semântica.
        
        Returns:
            Relatório em formato JSON
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Estatísticas gerais
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_tests,
                    SUM(CASE WHEN validation_passed THEN 1 ELSE 0 END) as passed_tests,
                    SUM(CASE WHEN is_generic THEN 1 ELSE 0 END) as generic_tests,
                    SUM(CASE WHEN is_synthetic THEN 1 ELSE 0 END) as synthetic_tests,
                    AVG(semantic_score) as avg_semantic_score
                FROM semantic_validation_results
                WHERE timestamp >= datetime('now', '-24 hours')
            ''')
            
            stats = cursor.fetchone()
            
            # Testes com problemas
            cursor.execute('''
                SELECT test_name, file_path, issues_found, semantic_score
                FROM semantic_validation_results
                WHERE validation_passed = FALSE AND timestamp >= datetime('now', '-24 hours')
                ORDER BY semantic_score ASC
                LIMIT 10
            ''')
            
            problematic_tests = [
                {
                    "test_name": row[0],
                    "file_path": row[1],
                    "issues": json.loads(row[2]) if row[2] else [],
                    "semantic_score": row[3]
                }
                for row in cursor.fetchall()
            ]
            
            # Distribuição de scores
            cursor.execute('''
                SELECT 
                    CASE 
                        WHEN semantic_score >= 0.9 THEN 'Excelente'
                        WHEN semantic_score >= 0.7 THEN 'Bom'
                        WHEN semantic_score >= 0.5 THEN 'Regular'
                        ELSE 'Ruim'
                    END as quality_level,
                    COUNT(*) as count
                FROM semantic_validation_results
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY quality_level
            ''')
            
            quality_distribution = [
                {"level": row[0], "count": row[1]}
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                "tracing_id": self.tracing_id,
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_tests_24h": stats[0] or 0,
                    "passed_tests_24h": stats[1] or 0,
                    "generic_tests_24h": stats[2] or 0,
                    "synthetic_tests_24h": stats[3] or 0,
                    "avg_semantic_score": stats[4] or 0.0,
                    "success_rate": (stats[1] / stats[0] * 100) if stats[0] > 0 else 0
                },
                "problematic_tests": problematic_tests,
                "quality_distribution": quality_distribution
            }
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao gerar relatório: {e}")
            return {"error": str(e)}

# Instância global do framework
semantic_validation = SemanticValidationFramework()

def validate_test_semantics(test_file_path: str, test_name: str, target_function: str = None, target_file_path: str = None):
    """Valida semântica de um teste específico."""
    return semantic_validation.validate_test_semantics(test_file_path, test_name, target_function, target_file_path)

def get_semantic_validation_report():
    """Retorna relatório de validação semântica."""
    return semantic_validation.generate_report()

if __name__ == "__main__":
    # Teste do framework
    logger.info(f"[{self.tracing_id}] Testando framework de validação semântica")
    
    # Exemplo de validação
    result = validate_test_semantics(
        test_file_path="tests/integration/test_main_integration.py",
        test_name="test_integracao_fluxo_geracao",
        target_function="generate_article",
        target_file_path="app/services/generation_service.py"
    )
    
    # Gera relatório
    report = get_semantic_validation_report()
    
    print(json.dumps(report, indent=2)) 