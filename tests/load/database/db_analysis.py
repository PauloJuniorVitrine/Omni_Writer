#!/usr/bin/env python3
"""
Database Performance Analysis - Omni Writer
==========================================

Análise de performance de banco de dados durante testes de carga
para identificar gargalos, locks, deadlocks e queries problemáticas.

Autor: Equipe de Performance
Data: 2025-01-27
Versão: 1.0
"""

import sqlite3
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from contextlib import contextmanager
import json
import os

# Importar profiling
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'profiling'))
from opentelemetry_config import setup_profiling

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[DB][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Métricas de uma query."""
    query: str
    execution_time: float
    timestamp: float
    success: bool
    error_message: Optional[str] = None
    rows_affected: Optional[int] = None
    lock_wait_time: Optional[float] = None

@dataclass
class DatabaseMetrics:
    """Métricas gerais do banco."""
    timestamp: float
    active_connections: int
    total_queries: int
    slow_queries: int
    failed_queries: int
    locks_detected: int
    deadlocks_detected: int
    avg_query_time: float
    max_query_time: float

class DatabaseAnalyzer:
    """Analisador de performance de banco de dados."""
    
    def __init__(self, db_path: str = "blog.db"):
        self.db_path = db_path
        self.profiler = setup_profiling()
        self.query_metrics: List[QueryMetrics] = []
        self.db_metrics: List[DatabaseMetrics] = []
        self.lock_detector = LockDetector()
        self.monitoring_active = False
        
    @contextmanager
    def get_connection(self):
        """Context manager para conexões com o banco."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            yield conn
        except Exception as e:
            logger.error(f"Erro na conexão com banco: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def execute_query_with_monitoring(self, query: str, params: tuple = ()) -> Tuple[bool, float, Optional[str]]:
        """
        Executa query com monitoramento de performance.
        
        Args:
            query: Query SQL
            params: Parâmetros da query
            
        Returns:
            Tuple[bool, float, Optional[str]]: (sucesso, tempo_execucao, erro)
        """
        start_time = time.time()
        lock_wait_time = None
        
        try:
            # Verificar locks antes da execução
            lock_wait_start = time.time()
            if self.lock_detector.check_for_locks(query):
                lock_wait_time = time.time() - lock_wait_start
                logger.warning(f"Lock detectado para query: {query[:50]}...")
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                # Para queries de modificação, verificar rows afetadas
                rows_affected = cursor.rowcount if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')) else None
                
                execution_time = time.time() - start_time
                
                # Registrar métricas
                metrics = QueryMetrics(
                    query=query,
                    execution_time=execution_time,
                    timestamp=time.time(),
                    success=True,
                    rows_affected=rows_affected,
                    lock_wait_time=lock_wait_time
                )
                
                self.query_metrics.append(metrics)
                
                # Traçar com OpenTelemetry
                self.profiler.trace_database_query(query, execution_time, True)
                
                return True, execution_time, None
                
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = str(e)
            
            # Registrar métricas de erro
            metrics = QueryMetrics(
                query=query,
                execution_time=execution_time,
                timestamp=time.time(),
                success=False,
                error_message=error_msg,
                lock_wait_time=lock_wait_time
            )
            
            self.query_metrics.append(metrics)
            
            # Traçar com OpenTelemetry
            self.profiler.trace_database_query(query, execution_time, False)
            
            logger.error(f"Erro na query: {error_msg}")
            return False, execution_time, error_msg
    
    def start_monitoring(self, interval: int = 5):
        """
        Inicia monitoramento contínuo do banco.
        
        Args:
            interval: Intervalo de monitoramento em segundos
        """
        if self.monitoring_active:
            logger.warning("Monitoramento já está ativo")
            return
        
        self.monitoring_active = True
        logger.info("Iniciando monitoramento de banco de dados...")
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    self.collect_database_metrics()
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Erro no monitoramento: {e}")
                    time.sleep(interval)
        
        # Executar em thread separada
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Para o monitoramento contínuo."""
        self.monitoring_active = False
        logger.info("Monitoramento de banco parado")
    
    def collect_database_metrics(self):
        """Coleta métricas gerais do banco."""
        try:
            with self.get_connection() as conn:
                # Contar conexões ativas (aproximação)
                active_connections = len(threading.enumerate())
                
                # Estatísticas de queries
                total_queries = len(self.query_metrics)
                slow_queries = len([q for q in self.query_metrics if q.execution_time > 1.0])
                failed_queries = len([q for q in self.query_metrics if not q.success])
                
                # Detectar locks
                locks_detected = len([q for q in self.query_metrics if q.lock_wait_time and q.lock_wait_time > 0])
                
                # Detectar deadlocks (simplificado)
                deadlocks_detected = self.detect_deadlocks()
                
                # Calcular tempos
                if self.query_metrics:
                    avg_query_time = sum(q.execution_time for q in self.query_metrics) / len(self.query_metrics)
                    max_query_time = max(q.execution_time for q in self.query_metrics)
                else:
                    avg_query_time = 0.0
                    max_query_time = 0.0
                
                metrics = DatabaseMetrics(
                    timestamp=time.time(),
                    active_connections=active_connections,
                    total_queries=total_queries,
                    slow_queries=slow_queries,
                    failed_queries=failed_queries,
                    locks_detected=locks_detected,
                    deadlocks_detected=deadlocks_detected,
                    avg_query_time=avg_query_time,
                    max_query_time=max_query_time
                )
                
                self.db_metrics.append(metrics)
                
        except Exception as e:
            logger.error(f"Erro ao coletar métricas: {e}")
    
    def detect_deadlocks(self) -> int:
        """
        Detecta deadlocks (implementação simplificada).
        
        Returns:
            int: Número de deadlocks detectados
        """
        # Em SQLite, deadlocks são raros, mas podemos detectar timeouts
        timeout_queries = [q for q in self.query_metrics if q.error_message and "timeout" in q.error_message.lower()]
        return len(timeout_queries)
    
    def analyze_slow_queries(self, threshold: float = 1.0) -> List[QueryMetrics]:
        """
        Identifica queries lentas.
        
        Args:
            threshold: Threshold em segundos
            
        Returns:
            List[QueryMetrics]: Lista de queries lentas
        """
        slow_queries = [q for q in self.query_metrics if q.execution_time > threshold]
        
        # Ordenar por tempo de execução
        slow_queries.sort(key=lambda x: x.execution_time, reverse=True)
        
        return slow_queries
    
    def analyze_query_patterns(self) -> Dict:
        """
        Analisa padrões de queries.
        
        Returns:
            Dict: Análise de padrões
        """
        if not self.query_metrics:
            return {"error": "Nenhuma query para analisar"}
        
        # Agrupar por tipo de query
        query_types = {}
        for query in self.query_metrics:
            query_type = self._classify_query(query.query)
            
            if query_type not in query_types:
                query_types[query_type] = {
                    "count": 0,
                    "total_time": 0.0,
                    "avg_time": 0.0,
                    "errors": 0,
                    "examples": []
                }
            
            query_types[query_type]["count"] += 1
            query_types[query_type]["total_time"] += query.execution_time
            
            if not query.success:
                query_types[query_type]["errors"] += 1
            
            # Manter exemplos (máximo 5)
            if len(query_types[query_type]["examples"]) < 5:
                query_types[query_type]["examples"].append(query.query[:100])
        
        # Calcular médias
        for query_type in query_types.values():
            if query_type["count"] > 0:
                query_type["avg_time"] = query_type["total_time"] / query_type["count"]
        
        return query_types
    
    def _classify_query(self, query: str) -> str:
        """
        Classifica o tipo de query.
        
        Args:
            query: Query SQL
            
        Returns:
            str: Tipo da query
        """
        query_upper = query.strip().upper()
        
        if query_upper.startswith("SELECT"):
            return "SELECT"
        elif query_upper.startswith("INSERT"):
            return "INSERT"
        elif query_upper.startswith("UPDATE"):
            return "UPDATE"
        elif query_upper.startswith("DELETE"):
            return "DELETE"
        elif query_upper.startswith("CREATE"):
            return "DDL"
        elif query_upper.startswith("ALTER"):
            return "DDL"
        else:
            return "OTHER"
    
    def check_index_usage(self) -> Dict:
        """
        Verifica uso de índices (implementação simplificada).
        
        Returns:
            Dict: Informações sobre índices
        """
        try:
            with self.get_connection() as conn:
                # Verificar índices existentes
                cursor = conn.cursor()
                cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
                indexes = cursor.fetchall()
                
                # Verificar tabelas
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                return {
                    "indexes": [dict(row) for row in indexes],
                    "tables": [row[0] for row in tables],
                    "index_count": len(indexes),
                    "table_count": len(tables)
                }
                
        except Exception as e:
            logger.error(f"Erro ao verificar índices: {e}")
            return {"error": str(e)}
    
    def generate_performance_report(self) -> str:
        """
        Gera relatório de performance do banco.
        
        Returns:
            str: Relatório em formato markdown
        """
        if not self.db_metrics:
            return "# Relatório de Performance do Banco - Sem dados coletados"
        
        latest_metrics = self.db_metrics[-1]
        slow_queries = self.analyze_slow_queries()
        query_patterns = self.analyze_query_patterns()
        index_info = self.check_index_usage()
        
        report = f"""
# Relatório de Performance do Banco de Dados - Omni Writer

## Métricas Gerais
- **Total de Queries**: {latest_metrics.total_queries}
- **Queries Lentas (>1s)**: {latest_metrics.slow_queries}
- **Queries com Erro**: {latest_metrics.failed_queries}
- **Locks Detectados**: {latest_metrics.locks_detected}
- **Deadlocks Detectados**: {latest_metrics.deadlocks_detected}
- **Tempo Médio de Query**: {latest_metrics.avg_query_time:.3f}s
- **Tempo Máximo de Query**: {latest_metrics.max_query_time:.3f}s
- **Conexões Ativas**: {latest_metrics.active_connections}

## Análise por Tipo de Query
"""
        
        for query_type, metrics in query_patterns.items():
            if isinstance(metrics, dict):
                report += f"""
### {query_type}
- **Total**: {metrics['count']}
- **Tempo Médio**: {metrics['avg_time']:.3f}s
- **Erros**: {metrics['errors']}
- **Exemplos**: {', '.join(metrics['examples'][:3])}
"""
        
        # Queries lentas
        if slow_queries:
            report += f"""
## Queries Mais Lentas
"""
            for i, query in enumerate(slow_queries[:10], 1):
                report += f"""
{i}. **{query.execution_time:.3f}s** - {query.query[:80]}...
   - Timestamp: {time.strftime('%H:%M:%S', time.localtime(query.timestamp))}
   - Sucesso: {'✅' if query.success else '❌'}
"""
        
        # Alertas
        alerts = []
        if latest_metrics.slow_queries > latest_metrics.total_queries * 0.1:
            alerts.append("🚨 Mais de 10% das queries são lentas")
        
        if latest_metrics.failed_queries > latest_metrics.total_queries * 0.05:
            alerts.append("🚨 Mais de 5% das queries falharam")
        
        if latest_metrics.locks_detected > 0:
            alerts.append("⚠️ Locks detectados - possível problema de concorrência")
        
        if latest_metrics.deadlocks_detected > 0:
            alerts.append("🚨 Deadlocks detectados - problema crítico de concorrência")
        
        if alerts:
            report += f"""
## Alertas
"""
            for alert in alerts:
                report += f"- {alert}\n"
        
        return report

class LockDetector:
    """Detector de locks no banco."""
    
    def __init__(self):
        self.lock_patterns = [
            "database is locked",
            "database table is locked",
            "timeout",
            "busy",
            "locked"
        ]
    
    def check_for_locks(self, query: str) -> bool:
        """
        Verifica se uma query pode causar locks.
        
        Args:
            query: Query SQL
            
        Returns:
            bool: True se pode causar locks
        """
        query_upper = query.strip().upper()
        
        # Queries que podem causar locks
        lock_queries = [
            "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"
        ]
        
        return any(lock_query in query_upper for lock_query in lock_queries)

def main():
    """Função principal para demonstração."""
    logger.info("Iniciando análise de performance do banco...")
    
    # Criar analisador
    analyzer = DatabaseAnalyzer()
    
    # Iniciar monitoramento
    analyzer.start_monitoring(interval=2)
    
    # Simular algumas queries
    test_queries = [
        "SELECT * FROM articles LIMIT 10",
        "INSERT INTO articles (title, content) VALUES (?, ?)",
        "UPDATE articles SET title = ? WHERE id = ?",
        "DELETE FROM articles WHERE id = ?",
        "SELECT COUNT(*) FROM articles"
    ]
    
    for i, query in enumerate(test_queries):
        logger.info(f"Executando query {i+1}: {query[:50]}...")
        success, execution_time, error = analyzer.execute_query_with_monitoring(query)
        
        if success:
            logger.info(f"Query executada em {execution_time:.3f}s")
        else:
            logger.error(f"Query falhou: {error}")
        
        time.sleep(0.5)  # Pequena pausa entre queries
    
    # Parar monitoramento
    analyzer.stop_monitoring()
    
    # Gerar relatório
    report = analyzer.generate_performance_report()
    print(report)
    
    # Salvar relatório
    with open("database_performance_report.md", "w") as f:
        f.write(report)
    
    logger.info("Análise de performance do banco concluída!")

if __name__ == "__main__":
    main() 