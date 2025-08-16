#!/usr/bin/env python3
"""
🧭 FRAMEWORK DE TELEMETRIA PARA TESTES DE INTEGRAÇÃO
📐 CoCoT + ToT + ReAct - Baseado em Código Real
🚫 PROIBIDO: Testes sintéticos, genéricos ou aleatórios
✅ PERMITIDO: Apenas testes baseados em código real do Omni Writer

Framework para telemetria em tempo real dos testes de integração.
Monitora execução, performance, falhas e regressões.

Tracing ID: TELEMETRY_FRAMEWORK_20250127_001
Data/Hora: 2025-01-27T16:00:00Z
Versão: 1.0
"""

import time
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import hashlib
import uuid

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger(__name__)

TRACING_ID = "TELEMETRY_FRAMEWORK_20250127_001"

@dataclass
class TestExecutionMetrics:
    """Métricas de execução de um teste."""
    test_id: str
    test_name: str
    file_path: str
    class_name: str
    risk_score: int
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[int] = None
    status: str = "running"  # running, passed, failed, skipped
    error_message: Optional[str] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    external_calls: int = 0
    database_queries: int = 0
    api_calls: int = 0
    tracing_id: str = TRACING_ID

@dataclass
class TestSuiteMetrics:
    """Métricas agregadas da suite de testes."""
    suite_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    total_duration_ms: int = 0
    avg_duration_ms: float = 0.0
    max_duration_ms: int = 0
    min_duration_ms: int = 0
    high_risk_tests: int = 0
    medium_risk_tests: int = 0
    low_risk_tests: int = 0
    regressions_detected: int = 0
    performance_degradations: int = 0
    tracing_id: str = TRACING_ID

class TelemetryCollector:
    """
    Coletor de telemetria para testes de integração.
    
    Coleta métricas em tempo real durante execução dos testes.
    """
    
    def __init__(self, db_path: str = "tests/integration/telemetry.db"):
        self.tracing_id = TRACING_ID
        self.db_path = db_path
        self.active_tests: Dict[str, TestExecutionMetrics] = {}
        self.suite_metrics: Optional[TestSuiteMetrics] = None
        self.lock = threading.Lock()
        
        # Inicializa banco de dados
        self._init_database()
        
        logger.info(f"[{self.tracing_id}] TelemetryCollector inicializado")
    
    def _init_database(self):
        """Inicializa banco de dados SQLite para telemetria."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de execuções de teste
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_executions (
                    id TEXT PRIMARY KEY,
                    test_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    class_name TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration_ms INTEGER,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    memory_usage_mb REAL,
                    cpu_usage_percent REAL,
                    external_calls INTEGER DEFAULT 0,
                    database_queries INTEGER DEFAULT 0,
                    api_calls INTEGER DEFAULT 0,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de métricas da suite
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suite_executions (
                    id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    total_tests INTEGER DEFAULT 0,
                    passed_tests INTEGER DEFAULT 0,
                    failed_tests INTEGER DEFAULT 0,
                    skipped_tests INTEGER DEFAULT 0,
                    total_duration_ms INTEGER DEFAULT 0,
                    avg_duration_ms REAL DEFAULT 0.0,
                    max_duration_ms INTEGER DEFAULT 0,
                    min_duration_ms INTEGER DEFAULT 0,
                    high_risk_tests INTEGER DEFAULT 0,
                    medium_risk_tests INTEGER DEFAULT 0,
                    low_risk_tests INTEGER DEFAULT 0,
                    regressions_detected INTEGER DEFAULT 0,
                    performance_degradations INTEGER DEFAULT 0,
                    tracing_id TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de baseline para comparação
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS performance_baseline (
                    test_name TEXT PRIMARY KEY,
                    avg_duration_ms REAL NOT NULL,
                    max_duration_ms INTEGER NOT NULL,
                    min_duration_ms INTEGER NOT NULL,
                    std_deviation REAL NOT NULL,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info(f"[{self.tracing_id}] Banco de dados inicializado: {self.db_path}")
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao inicializar banco: {e}")
    
    def start_suite_execution(self) -> str:
        """
        Inicia monitoramento da suite de testes.
        
        Returns:
            ID da execução da suite
        """
        suite_id = str(uuid.uuid4())
        
        with self.lock:
            self.suite_metrics = TestSuiteMetrics(
                suite_id=suite_id,
                start_time=datetime.now()
            )
        
        logger.info(f"[{self.tracing_id}] Suite iniciada: {suite_id}")
        return suite_id
    
    def start_test_execution(self, test_name: str, file_path: str, class_name: str, risk_score: int) -> str:
        """
        Inicia monitoramento de um teste específico.
        
        Args:
            test_name: Nome do teste
            file_path: Caminho do arquivo
            class_name: Nome da classe
            risk_score: RISK_SCORE do teste
            
        Returns:
            ID da execução do teste
        """
        test_id = str(uuid.uuid4())
        
        metrics = TestExecutionMetrics(
            test_id=test_id,
            test_name=test_name,
            file_path=file_path,
            class_name=class_name,
            risk_score=risk_score,
            start_time=datetime.now()
        )
        
        with self.lock:
            self.active_tests[test_id] = metrics
            
            if self.suite_metrics:
                self.suite_metrics.total_tests += 1
                
                # Categoriza por risco
                if risk_score >= 100:
                    self.suite_metrics.high_risk_tests += 1
                elif risk_score >= 50:
                    self.suite_metrics.medium_risk_tests += 1
                else:
                    self.suite_metrics.low_risk_tests += 1
        
        logger.info(f"[{self.tracing_id}] Teste iniciado: {test_name} (RISK_SCORE: {risk_score})")
        return test_id
    
    def update_test_metrics(self, test_id: str, **kwargs):
        """
        Atualiza métricas de um teste em execução.
        
        Args:
            test_id: ID da execução do teste
            **kwargs: Métricas a serem atualizadas
        """
        with self.lock:
            if test_id in self.active_tests:
                test_metrics = self.active_tests[test_id]
                
                for key, value in kwargs.items():
                    if hasattr(test_metrics, key):
                        setattr(test_metrics, key, value)
    
    def end_test_execution(self, test_id: str, status: str, error_message: Optional[str] = None):
        """
        Finaliza monitoramento de um teste.
        
        Args:
            test_id: ID da execução do teste
            status: Status final (passed, failed, skipped)
            error_message: Mensagem de erro se aplicável
        """
        with self.lock:
            if test_id in self.active_tests:
                test_metrics = self.active_tests[test_id]
                test_metrics.end_time = datetime.now()
                test_metrics.status = status
                test_metrics.error_message = error_message
                
                # Calcula duração
                if test_metrics.start_time and test_metrics.end_time:
                    duration = test_metrics.end_time - test_metrics.start_time
                    test_metrics.duration_ms = int(duration.total_seconds() * 1000)
                
                # Atualiza métricas da suite
                if self.suite_metrics:
                    if status == "passed":
                        self.suite_metrics.passed_tests += 1
                    elif status == "failed":
                        self.suite_metrics.failed_tests += 1
                    elif status == "skipped":
                        self.suite_metrics.skipped_tests += 1
                    
                    if test_metrics.duration_ms:
                        self.suite_metrics.total_duration_ms += test_metrics.duration_ms
                        self.suite_metrics.max_duration_ms = max(
                            self.suite_metrics.max_duration_ms, 
                            test_metrics.duration_ms
                        )
                        if self.suite_metrics.min_duration_ms == 0:
                            self.suite_metrics.min_duration_ms = test_metrics.duration_ms
                        else:
                            self.suite_metrics.min_duration_ms = min(
                                self.suite_metrics.min_duration_ms,
                                test_metrics.duration_ms
                            )
                
                # Salva no banco
                self._save_test_execution(test_metrics)
                
                # Remove da lista ativa
                del self.active_tests[test_id]
                
                logger.info(f"[{self.tracing_id}] Teste finalizado: {test_metrics.test_name} ({status}) em {test_metrics.duration_ms}ms")
    
    def end_suite_execution(self):
        """Finaliza monitoramento da suite de testes."""
        with self.lock:
            if self.suite_metrics:
                self.suite_metrics.end_time = datetime.now()
                
                # Calcula duração média
                if self.suite_metrics.total_tests > 0:
                    self.suite_metrics.avg_duration_ms = (
                        self.suite_metrics.total_duration_ms / self.suite_metrics.total_tests
                    )
                
                # Detecta regressões e degradações
                self._detect_regressions()
                
                # Salva no banco
                self._save_suite_execution(self.suite_metrics)
                
                logger.info(f"[{self.tracing_id}] Suite finalizada: {self.suite_metrics.passed_tests}/{self.suite_metrics.total_tests} testes passaram")
    
    def _save_test_execution(self, metrics: TestExecutionMetrics):
        """Salva execução de teste no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO test_executions (
                    id, test_name, file_path, class_name, risk_score,
                    start_time, end_time, duration_ms, status, error_message,
                    memory_usage_mb, cpu_usage_percent, external_calls,
                    database_queries, api_calls, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.test_id, metrics.test_name, metrics.file_path,
                metrics.class_name, metrics.risk_score,
                metrics.start_time.isoformat(),
                metrics.end_time.isoformat() if metrics.end_time else None,
                metrics.duration_ms, metrics.status, metrics.error_message,
                metrics.memory_usage_mb, metrics.cpu_usage_percent,
                metrics.external_calls, metrics.database_queries,
                metrics.api_calls, metrics.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar execução: {e}")
    
    def _save_suite_execution(self, metrics: TestSuiteMetrics):
        """Salva execução da suite no banco de dados."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO suite_executions (
                    id, start_time, end_time, total_tests, passed_tests,
                    failed_tests, skipped_tests, total_duration_ms, avg_duration_ms,
                    max_duration_ms, min_duration_ms, high_risk_tests,
                    medium_risk_tests, low_risk_tests, regressions_detected,
                    performance_degradations, tracing_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.suite_id, metrics.start_time.isoformat(),
                metrics.end_time.isoformat() if metrics.end_time else None,
                metrics.total_tests, metrics.passed_tests, metrics.failed_tests,
                metrics.skipped_tests, metrics.total_duration_ms,
                metrics.avg_duration_ms, metrics.max_duration_ms,
                metrics.min_duration_ms, metrics.high_risk_tests,
                metrics.medium_risk_tests, metrics.low_risk_tests,
                metrics.regressions_detected, metrics.performance_degradations,
                metrics.tracing_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao salvar suite: {e}")
    
    def _detect_regressions(self):
        """Detecta regressões comparando com baseline."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Busca baseline para cada teste
            cursor.execute('''
                SELECT test_name, avg_duration_ms, max_duration_ms, std_deviation
                FROM performance_baseline
            ''')
            
            baseline_data = {row[0]: row[1:] for row in cursor.fetchall()}
            
            regressions = 0
            degradations = 0
            
            # Compara com execuções atuais
            for test_id, metrics in self.active_tests.items():
                if metrics.test_name in baseline_data:
                    baseline_avg, baseline_max, std_dev = baseline_data[metrics.test_name]
                    
                    if metrics.duration_ms:
                        # Detecta regressão (falha)
                        if metrics.status == "failed":
                            regressions += 1
                        
                        # Detecta degradação de performance
                        if metrics.duration_ms > baseline_avg + (2 * std_dev):
                            degradations += 1
            
            if self.suite_metrics:
                self.suite_metrics.regressions_detected = regressions
                self.suite_metrics.performance_degradations = degradations
            
            conn.close()
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao detectar regressões: {e}")
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Retorna métricas atuais da execução.
        
        Returns:
            Dicionário com métricas atuais
        """
        with self.lock:
            return {
                "suite_metrics": asdict(self.suite_metrics) if self.suite_metrics else None,
                "active_tests": len(self.active_tests),
                "active_test_names": [m.test_name for m in self.active_tests.values()]
            }
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Gera relatório completo de telemetria.
        
        Returns:
            Relatório em formato JSON
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Últimas execuções da suite
            cursor.execute('''
                SELECT * FROM suite_executions 
                ORDER BY created_at DESC 
                LIMIT 10
            ''')
            
            suite_executions = []
            for row in cursor.fetchall():
                suite_executions.append({
                    "id": row[0],
                    "start_time": row[1],
                    "total_tests": row[3],
                    "passed_tests": row[4],
                    "failed_tests": row[5],
                    "avg_duration_ms": row[8],
                    "regressions_detected": row[14]
                })
            
            # Testes mais lentos
            cursor.execute('''
                SELECT test_name, AVG(duration_ms) as avg_duration
                FROM test_executions 
                WHERE duration_ms IS NOT NULL
                GROUP BY test_name 
                ORDER BY avg_duration DESC 
                LIMIT 10
            ''')
            
            slowest_tests = [{"test_name": row[0], "avg_duration_ms": row[1]} for row in cursor.fetchall()]
            
            # Testes com mais falhas
            cursor.execute('''
                SELECT test_name, COUNT(*) as failure_count
                FROM test_executions 
                WHERE status = 'failed'
                GROUP BY test_name 
                ORDER BY failure_count DESC 
                LIMIT 10
            ''')
            
            failing_tests = [{"test_name": row[0], "failure_count": row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                "tracing_id": self.tracing_id,
                "timestamp": datetime.now().isoformat(),
                "current_metrics": self.get_current_metrics(),
                "recent_suite_executions": suite_executions,
                "slowest_tests": slowest_tests,
                "failing_tests": failing_tests
            }
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] Erro ao gerar relatório: {e}")
            return {"error": str(e)}

# Instância global do coletor
telemetry_collector = TelemetryCollector()

def telemetry_decorator(func):
    """
    Decorator para adicionar telemetria automaticamente aos testes.
    
    Args:
        func: Função de teste a ser decorada
        
    Returns:
        Função decorada com telemetria
    """
    def wrapper(*args, **kwargs):
        # Extrai informações do teste
        test_name = func.__name__
        file_path = func.__module__
        class_name = "Unknown"
        
        # Tenta extrair RISK_SCORE se disponível
        risk_score = 50  # Padrão
        
        # Inicia telemetria
        test_id = telemetry_collector.start_test_execution(
            test_name=test_name,
            file_path=file_path,
            class_name=class_name,
            risk_score=risk_score
        )
        
        try:
            # Executa teste
            result = func(*args, **kwargs)
            
            # Finaliza com sucesso
            telemetry_collector.end_test_execution(test_id, "passed")
            
            return result
            
        except Exception as e:
            # Finaliza com falha
            telemetry_collector.end_test_execution(
                test_id, 
                "failed", 
                error_message=str(e)
            )
            raise
    
    return wrapper

def start_telemetry_suite():
    """Inicia monitoramento da suite de testes."""
    return telemetry_collector.start_suite_execution()

def end_telemetry_suite():
    """Finaliza monitoramento da suite de testes."""
    telemetry_collector.end_suite_execution()

def get_telemetry_report():
    """Retorna relatório de telemetria."""
    return telemetry_collector.generate_report()

if __name__ == "__main__":
    # Teste do framework
    logger.info(f"[{TRACING_ID}] Testando framework de telemetria")
    
    # Simula execução de suite
    suite_id = start_telemetry_suite()
    
    # Simula alguns testes
    @telemetry_decorator
    def test_example_1():
        time.sleep(0.1)
        return True
    
    @telemetry_decorator
    def test_example_2():
        time.sleep(0.2)
        raise Exception("Teste falhou")
    
    test_example_1()
    try:
        test_example_2()
    except:
        pass
    
    # Finaliza suite
    end_telemetry_suite()
    
    # Gera relatório
    report = get_telemetry_report()
    print(json.dumps(report, indent=2)) 