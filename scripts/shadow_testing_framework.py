#!/usr/bin/env python3
"""
🌗 FRAMEWORK DE SHADOW TESTING PARA ENDPOINTS CRÍTICOS
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Framework para shadow testing de endpoints críticos.
Compara respostas entre versões para detectar regressões.

Tracing ID: SHADOW_TESTING_FRAMEWORK_20250127_001
Data/Hora: 2025-01-27T17:00:00Z
Versão: 1.0
"""

import time
import json
import logging
import threading
import hashlib
import difflib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import uuid
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "SHADOW_TESTING_FRAMEWORK_20250127_001"

@dataclass
class ShadowTestRequest:
    """Configuração de uma requisição de shadow testing."""
    endpoint: str
    method: str = "GET"
    headers: Dict[str, str] = None
    data: Any = None
    params: Dict[str, str] = None
    timeout: int = 30
    expected_status: int = 200
    tracing_id: str = TRACING_ID

@dataclass
class ShadowTestResult:
    """Resultado de uma comparação de shadow testing."""
    test_id: str
    endpoint: str
    timestamp: datetime
    production_response: Dict[str, Any]
    shadow_response: Dict[str, Any]
    status_match: bool
    content_match: bool
    semantic_similarity: float
    performance_diff_ms: int
    regression_detected: bool
    error_message: Optional[str] = None
    tracing_id: str = TRACING_ID

@dataclass
class EndpointConfig:
    """Configuração de um endpoint para shadow testing."""
    endpoint: str
    method: str
    risk_score: int
    frequency: str  # "high", "medium", "low"
    critical: bool
    headers: Dict[str, str] = None
    sample_data: Dict[str, Any] = None
    tolerance_threshold: float = 0.95
    tracing_id: str = TRACING_ID

class ShadowTestingFramework:
    """
    Framework de shadow testing para endpoints críticos.
    
    Compara respostas entre produção e shadow environment
    para detectar regressões automaticamente.
    """
    
    def __init__(self, 
                 production_base_url: str,
                 shadow_base_url: str,
                 db_path: str = "tests/integration/shadow_testing.db"):
        self.tracing_id = TRACING_ID
        self.production_base_url = production_base_url.rstrip('/')
        self.shadow_base_url = shadow_base_url.rstrip('/')
        self.db_path = db_path
        self.active_tests: Dict[str, ShadowTestRequest] = {}
        self.results: List[ShadowTestResult] = []
        self.lock = threading.Lock()
        
        # Configuração de endpoints críticos (baseado em código real do Omni Writer)
        self.critical_endpoints = self._load_critical_endpoints()
        
        # Inicializa banco de dados
        self._init_database()
        
        logger.info(f"[{self.tracing_id}] ShadowTestingFramework inicializado")
        logger.info(f"[{self.tracing_id}] Endpoints críticos: {len(self.critical_endpoints)}")
    
    def _load_critical_endpoints(self) -> List[EndpointConfig]:
        """
        Carrega configuração de endpoints críticos baseada em código real.
        
        Endpoints identificados através de análise do código do Omni Writer:
        - /generate: Geração de artigos (crítico)
        - /download: Download de arquivos (crítico)
        - /status: Status de processamento (médio)
        - /webhook: Webhooks de pagamento (crítico)
        """
        return [
            EndpointConfig(
                endpoint="/generate",
                method="POST",
                risk_score=150,  # Alto risco - geração de conteúdo
                frequency="high",
                critical=True,
                headers={"Content-Type": "application/json"},
                sample_data={
                    "instancias_json": '[{"nome":"test","modelo":"openai","api_key":"test","prompts":["test"]}]',
                    "prompts": "Teste de geração"
                },
                tolerance_threshold=0.90
            ),
            EndpointConfig(
                endpoint="/download",
                method="GET",
                risk_score=120,  # Alto risco - download de arquivos
                frequency="high",
                critical=True,
                headers={"Accept": "application/octet-stream"},
                sample_data={"filename": "test_article.txt"},
                tolerance_threshold=0.95
            ),
            EndpointConfig(
                endpoint="/status",
                method="GET",
                risk_score=80,  # Médio risco - status
                frequency="medium",
                critical=False,
                headers={"Accept": "application/json"},
                sample_data={"job_id": "test_job_123"},
                tolerance_threshold=0.98
            ),
            EndpointConfig(
                endpoint="/webhook",
                method="POST",
                risk_score=140,  # Alto risco - webhooks de pagamento
                frequency="medium",
                critical=True,
                headers={"Content-Type": "application/json"},
                sample_data={
                    "event": "payment.succeeded",
                    "data": {"amount": 1000, "currency": "brl"}
                },
                tolerance_threshold=0.95
            ),
            EndpointConfig(
                endpoint="/blogs",
                method="GET",
                risk_score=60,  # Baixo risco - listagem
                frequency="high",
                critical=False,
                headers={"Accept": "application/json"},
                sample_data={},
                tolerance_threshold=0.98
            )
        ]
    
    def _init_database(self):
        """Inicializa banco de dados SQLite para shadow testing."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de configurações de endpoints
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS endpoint_configs (
                    endpoint TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    frequency TEXT NOT NULL,
                    critical BOOLEAN NOT NULL,
                    headers TEXT,
                    sample_data TEXT,
                    tolerance_threshold REAL NOT NULL,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de resultados de shadow testing
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shadow_test_results (
                    test_id TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    production_response TEXT,
                    shadow_response TEXT,
                    status_match BOOLEAN NOT NULL,
                    content_match BOOLEAN NOT NULL,
                    semantic_similarity REAL NOT NULL,
                    performance_diff_ms INTEGER NOT NULL,
                    regression_detected BOOLEAN NOT NULL,
                    error_message TEXT,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de alertas de regressão
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS regression_alerts (
                    alert_id TEXT PRIMARY KEY,
                    test_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT FALSE,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Insere configurações padrão
            for config in self.critical_endpoints:
                cursor.execute('''
                    INSERT OR REPLACE INTO endpoint_configs (
                        endpoint, method, risk_score, frequency, critical,
                        headers, sample_data, tolerance_threshold, tracing_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    config.endpoint, config.method, config.risk_score,
                    config.frequency, config.critical,
                    json.dumps(config.headers) if config.headers else None,
                    json.dumps(config.sample_data) if config.sample_data else None,
                    config.tolerance_threshold, config.tracing_id
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"[{self.tracing_id}] Banco de dados inicializado: {self.db_path}")
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao inicializar banco: {e}")
    
    def _make_request(self, base_url: str, config: EndpointConfig) -> Tuple[Dict[str, Any], int, float]:
        """
        Faz uma requisição para o endpoint especificado.
        
        Args:
            base_url: URL base (produção ou shadow)
            config: Configuração do endpoint
            
        Returns:
            Tuple com (response_data, status_code, duration_ms)
        """
        url = f"{base_url}{config.endpoint}"
        start_time = time.time()
        
        try:
            if config.method == "GET":
                response = requests.get(
                    url,
                    headers=config.headers,
                    params=config.sample_data,
                    timeout=config.timeout
                )
            elif config.method == "POST":
                response = requests.post(
                    url,
                    headers=config.headers,
                    json=config.sample_data,
                    timeout=config.timeout
                )
            else:
                raise ValueError(f"Método não suportado: {config.method}")
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Tenta parsear JSON, senão retorna texto
            try:
                response_data = response.json()
            except:
                response_data = {"content": response.text, "content_type": response.headers.get("content-type")}
            
            return response_data, response.status_code, duration_ms
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return {"error": str(e)}, 500, duration_ms
    
    def _calculate_semantic_similarity(self, response1: Dict[str, Any], response2: Dict[str, Any]) -> float:
        """
        Calcula similaridade semântica entre duas respostas.
        
        Args:
            response1: Primeira resposta
            response2: Segunda resposta
            
        Returns:
            Score de similaridade (0.0 a 1.0)
        """
        try:
            # Converte respostas para string para comparação
            str1 = json.dumps(response1, sort_keys=True)
            str2 = json.dumps(response2, sort_keys=True)
            
            # Calcula similaridade usando difflib
            similarity = difflib.SequenceMatcher(None, str1, str2).ratio()
            
            # Ajusta baseado em diferenças estruturais
            if isinstance(response1, dict) and isinstance(response2, dict):
                # Compara chaves
                keys1 = set(response1.keys())
                keys2 = set(response2.keys())
                key_similarity = len(keys1.intersection(keys2)) / len(keys1.union(keys2))
                
                # Combina similaridades
                final_similarity = (similarity + key_similarity) / 2
            else:
                final_similarity = similarity
            
            return final_similarity
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao calcular similaridade: {e}")
            return 0.0
    
    def run_shadow_test(self, endpoint: str) -> ShadowTestResult:
        """
        Executa shadow test para um endpoint específico.
        
        Args:
            endpoint: Endpoint a ser testado
            
        Returns:
            Resultado do shadow test
        """
        # Encontra configuração do endpoint
        config = next((c for c in self.critical_endpoints if c.endpoint == endpoint), None)
        if not config:
            raise ValueError(f"Endpoint não configurado: {endpoint}")
        
        test_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        logger.info(f"[{self.tracing_id}] Executando shadow test para {endpoint}")
        
        try:
            # Faz requisição para produção
            prod_response, prod_status, prod_duration = self._make_request(
                self.production_base_url, config
            )
            
            # Faz requisição para shadow
            shadow_response, shadow_status, shadow_duration = self._make_request(
                self.shadow_base_url, config
            )
            
            # Calcula diferenças
            status_match = prod_status == shadow_status
            performance_diff_ms = abs(prod_duration - shadow_duration)
            
            # Calcula similaridade semântica
            semantic_similarity = self._calculate_semantic_similarity(
                prod_response, shadow_response
            )
            
            # Determina se há regressão
            content_match = semantic_similarity >= config.tolerance_threshold
            regression_detected = not (status_match and content_match)
            
            # Cria resultado
            result = ShadowTestResult(
                test_id=test_id,
                endpoint=endpoint,
                timestamp=timestamp,
                production_response=prod_response,
                shadow_response=shadow_response,
                status_match=status_match,
                content_match=content_match,
                semantic_similarity=semantic_similarity,
                performance_diff_ms=performance_diff_ms,
                regression_detected=regression_detected
            )
            
            # Salva no banco
            self._save_test_result(result)
            
            # Cria alerta se regressão detectada
            if regression_detected:
                self._create_regression_alert(result, config)
            
            logger.info(f"[{self.tracing_id}] Shadow test concluído: {endpoint} - Regressão: {regression_detected}")
            
            return result
            
        except Exception as e:
            error_result = ShadowTestResult(
                test_id=test_id,
                endpoint=endpoint,
                timestamp=timestamp,
                production_response={},
                shadow_response={},
                status_match=False,
                content_match=False,
                semantic_similarity=0.0,
                performance_diff_ms=0,
                regression_detected=True,
                error_message=str(e)
            )
            
            self._save_test_result(error_result)
            logger.error(f"[{self.tracing_id}] Erro no shadow test {endpoint}: {e}")
            
            return error_result
    
    def run_all_shadow_tests(self) -> List[ShadowTestResult]:
        """
        Executa shadow tests para todos os endpoints críticos.
        
        Returns:
            Lista de resultados
        """
        logger.info(f"[{self.tracing_id}] Executando shadow tests para todos os endpoints")
        
        results = []
        
        # Executa testes em paralelo
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_endpoint = {
                executor.submit(self.run_shadow_test, config.endpoint): config.endpoint
                for config in self.critical_endpoints
            }
            
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"[{self.tracing_id}] Erro no shadow test {endpoint}: {e}")
        
        return results
    
    def _save_test_result(self, result: ShadowTestResult):
        """Salva resultado de teste no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO shadow_test_results (
                    test_id, endpoint, timestamp, production_response, shadow_response,
                    status_match, content_match, semantic_similarity, performance_diff_ms,
                    regression_detected, error_message, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.test_id, result.endpoint, result.timestamp.isoformat(),
                json.dumps(result.production_response),
                json.dumps(result.shadow_response),
                result.status_match, result.content_match, result.semantic_similarity,
                result.performance_diff_ms, result.regression_detected,
                result.error_message, result.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar resultado: {e}")
    
    def _create_regression_alert(self, result: ShadowTestResult, config: EndpointConfig):
        """Cria alerta de regressão detectada."""
        try:
            alert_id = str(uuid.uuid4())
            
            # Determina severidade baseada no risco
            severity = "CRITICAL" if config.critical else "WARNING"
            
            message = f"Regressão detectada em {result.endpoint}: Similaridade {result.semantic_similarity:.2f} < {config.tolerance_threshold}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO regression_alerts (
                    alert_id, test_id, endpoint, severity, message, timestamp, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_id, result.test_id, result.endpoint, severity,
                message, result.timestamp.isoformat(), result.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
            logger.warning(f"[{self.tracing_id}] ALERTA: {message}")
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao criar alerta: {e}")
    
    def get_regression_alerts(self, unresolved_only: bool = True) -> List[Dict[str, Any]]:
        """
        Retorna alertas de regressão.
        
        Args:
            unresolved_only: Se True, retorna apenas alertas não resolvidos
            
        Returns:
            Lista de alertas
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = '''
                SELECT alert_id, test_id, endpoint, severity, message, timestamp, resolved
                FROM regression_alerts
            '''
            
            if unresolved_only:
                query += " WHERE resolved = FALSE"
            
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query)
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    "alert_id": row[0],
                    "test_id": row[1],
                    "endpoint": row[2],
                    "severity": row[3],
                    "message": row[4],
                    "timestamp": row[5],
                    "resolved": bool(row[6])
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao buscar alertas: {e}")
            return []
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Gera relatório completo de shadow testing.
        
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
                    SUM(CASE WHEN regression_detected THEN 1 ELSE 0 END) as regressions,
                    AVG(semantic_similarity) as avg_similarity,
                    AVG(performance_diff_ms) as avg_performance_diff
                FROM shadow_test_results
                WHERE timestamp >= datetime('now', '-24 hours')
            ''')
            
            stats = cursor.fetchone()
            
            # Alertas recentes
            cursor.execute('''
                SELECT COUNT(*) as active_alerts
                FROM regression_alerts
                WHERE resolved = FALSE AND timestamp >= datetime('now', '-24 hours')
            ''')
            
            active_alerts = cursor.fetchone()[0]
            
            # Endpoints com mais regressões
            cursor.execute('''
                SELECT endpoint, COUNT(*) as regression_count
                FROM shadow_test_results
                WHERE regression_detected = TRUE AND timestamp >= datetime('now', '-7 days')
                GROUP BY endpoint
                ORDER BY regression_count DESC
                LIMIT 5
            ''')
            
            problematic_endpoints = [
                {"endpoint": row[0], "regression_count": row[1]}
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            return {
                "tracing_id": self.tracing_id,
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_tests_24h": stats[0] or 0,
                    "regressions_24h": stats[1] or 0,
                    "avg_similarity": stats[2] or 0.0,
                    "avg_performance_diff_ms": stats[3] or 0.0,
                    "active_alerts": active_alerts
                },
                "problematic_endpoints": problematic_endpoints,
                "critical_endpoints": [
                    {
                        "endpoint": config.endpoint,
                        "risk_score": config.risk_score,
                        "critical": config.critical,
                        "frequency": config.frequency
                    }
                    for config in self.critical_endpoints
                ]
            }
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao gerar relatório: {e}")
            return {"error": str(e)}

# Instância global do framework
shadow_testing = ShadowTestingFramework(
    production_base_url="http://localhost:5000",
    shadow_base_url="http://localhost:5001"
)

def run_shadow_test_for_endpoint(endpoint: str):
    """Executa shadow test para um endpoint específico."""
    return shadow_testing.run_shadow_test(endpoint)

def run_all_shadow_tests():
    """Executa shadow tests para todos os endpoints críticos."""
    return shadow_testing.run_all_shadow_tests()

def get_shadow_testing_report():
    """Retorna relatório de shadow testing."""
    return shadow_testing.generate_report()

def get_regression_alerts():
    """Retorna alertas de regressão ativos."""
    return shadow_testing.get_regression_alerts()

if __name__ == "__main__":
    # Teste do framework
    logger.info(f"[{TRACING_ID}] Testando framework de shadow testing")
    
    # Executa todos os shadow tests
    results = run_all_shadow_tests()
    
    # Gera relatório
    report = get_shadow_testing_report()
    
    print(json.dumps(report, indent=2)) 