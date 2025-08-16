"""
Sistema de Otimização de Database - Omni Writer
==============================================

Implementa otimizações avançadas de database:
- Connection pooling otimizado
- Connection monitoring
- Health checks
- Retry logic
- Leak detection
- Query optimization
- Query caching
- Performance monitoring

Prompt: Implementação de Gargalos Médios - Database Connection Pooling
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T23:30:00Z
Tracing ID: DATABASE_OPTIMIZATION_20250127_001
"""

import time
import logging
import threading
import queue
import weakref
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import redis
from functools import wraps

logger = logging.getLogger(__name__)

@dataclass
class ConnectionMetrics:
    """Métricas de performance de conexões"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    connection_errors: int = 0
    avg_connection_time: float = 0.0
    avg_query_time: float = 0.0
    total_queries: int = 0
    slow_queries: int = 0
    last_updated: datetime = field(default_factory=datetime.utcnow)

@dataclass
class QueryMetrics:
    """Métricas de performance de queries"""
    query_hash: str
    query_text: str
    execution_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    last_execution: datetime = field(default_factory=datetime.utcnow)
    cache_hits: int = 0
    cache_misses: int = 0

@dataclass
class ConnectionInfo:
    """Informações de uma conexão"""
    connection_id: str
    created_at: datetime
    last_used: datetime
    query_count: int = 0
    total_time: float = 0.0
    is_active: bool = True
    error_count: int = 0

class OptimizedConnectionPool:
    """Pool de conexões otimizado com monitoring"""
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 5432,
                 database: str = "omni_writer",
                 user: str = "postgres",
                 password: str = "",
                 min_connections: int = 5,
                 max_connections: int = 20,
                 connection_timeout: int = 30,
                 idle_timeout: int = 300):
        
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.idle_timeout = idle_timeout
        
        # Pool de conexões
        self.pool = pool.ThreadedConnectionPool(
            minconn=min_connections,
            maxconn=max_connections,
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            cursor_factory=RealDictCursor
        )
        
        # Métricas e monitoring
        self.metrics = ConnectionMetrics()
        self.active_connections: Dict[str, ConnectionInfo] = {}
        self.connection_history = deque(maxlen=1000)
        
        # Thread de monitoramento
        self.monitoring_thread = None
        self.is_monitoring = False
        
        # Inicia monitoramento
        self.start_monitoring()
        
        logger.info(f"Connection Pool otimizado inicializado: {min_connections}-{max_connections} conexões")
    
    def get_connection(self) -> psycopg2.extensions.connection:
        """Obtém conexão do pool com monitoring"""
        start_time = time.time()
        
        try:
            connection = self.pool.getconn()
            
            # Registra conexão ativa
            connection_id = str(id(connection))
            connection_info = ConnectionInfo(
                connection_id=connection_id,
                created_at=datetime.utcnow(),
                last_used=datetime.utcnow()
            )
            
            self.active_connections[connection_id] = connection_info
            
            # Atualiza métricas
            connection_time = time.time() - start_time
            self.metrics.total_connections += 1
            self.metrics.avg_connection_time = (
                (self.metrics.avg_connection_time * (self.metrics.total_connections - 1) + connection_time) /
                self.metrics.total_connections
            )
            
            logger.debug(f"Conexão obtida: {connection_id} em {connection_time:.3f}s")
            
            return connection
            
        except Exception as e:
            self.metrics.connection_errors += 1
            logger.error(f"Erro ao obter conexão: {e}")
            raise
    
    def return_connection(self, connection: psycopg2.extensions.connection):
        """Retorna conexão ao pool com cleanup"""
        try:
            connection_id = str(id(connection))
            
            if connection_id in self.active_connections:
                # Registra uso da conexão
                connection_info = self.active_connections[connection_id]
                connection_info.last_used = datetime.utcnow()
                connection_info.is_active = False
                
                # Move para histórico
                self.connection_history.append(connection_info)
                del self.active_connections[connection_id]
            
            # Retorna ao pool
            self.pool.putconn(connection)
            
            logger.debug(f"Conexão retornada: {connection_id}")
            
        except Exception as e:
            logger.error(f"Erro ao retornar conexão: {e}")
    
    def start_monitoring(self):
        """Inicia monitoramento de conexões"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Monitoramento de conexões iniciado")
    
    def stop_monitoring(self):
        """Para monitoramento de conexões"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Monitoramento de conexões parado")
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento"""
        while self.is_monitoring:
            try:
                self._update_metrics()
                self._check_connection_health()
                self._detect_connection_leaks()
                time.sleep(30)  # Verifica a cada 30 segundos
                
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
                time.sleep(60)
    
    def _update_metrics(self):
        """Atualiza métricas de conexões"""
        self.metrics.active_connections = len(self.active_connections)
        self.metrics.idle_connections = self.max_connections - self.metrics.active_connections
        self.metrics.last_updated = datetime.utcnow()
    
    def _check_connection_health(self):
        """Verifica saúde das conexões ativas"""
        current_time = datetime.utcnow()
        unhealthy_connections = []
        
        for connection_id, connection_info in self.active_connections.items():
            # Verifica se conexão está muito tempo ativa
            if (current_time - connection_info.last_used).total_seconds() > self.idle_timeout:
                unhealthy_connections.append(connection_id)
                logger.warning(f"Conexão inativa detectada: {connection_id}")
        
        # Remove conexões não saudáveis
        for connection_id in unhealthy_connections:
            del self.active_connections[connection_id]
    
    def _detect_connection_leaks(self):
        """Detecta vazamentos de conexões"""
        if self.metrics.active_connections > self.max_connections * 0.8:
            logger.warning(f"Possível vazamento de conexões: {self.metrics.active_connections}/{self.max_connections}")
    
    def get_metrics(self) -> ConnectionMetrics:
        """Retorna métricas atuais"""
        return self.metrics
    
    def get_connection_report(self) -> Dict[str, Any]:
        """Gera relatório de conexões"""
        return {
            'pool_config': {
                'min_connections': self.min_connections,
                'max_connections': self.max_connections,
                'connection_timeout': self.connection_timeout,
                'idle_timeout': self.idle_timeout
            },
            'current_metrics': {
                'total_connections': self.metrics.total_connections,
                'active_connections': self.metrics.active_connections,
                'idle_connections': self.metrics.idle_connections,
                'connection_errors': self.metrics.connection_errors,
                'avg_connection_time': self.metrics.avg_connection_time
            },
            'active_connections': [
                {
                    'connection_id': conn_info.connection_id,
                    'created_at': conn_info.created_at.isoformat(),
                    'last_used': conn_info.last_used.isoformat(),
                    'query_count': conn_info.query_count,
                    'total_time': conn_info.total_time,
                    'error_count': conn_info.error_count
                }
                for conn_info in self.active_connections.values()
            ],
            'last_updated': self.metrics.last_updated.isoformat()
        }

class QueryOptimizer:
    """Otimizador de queries com caching e monitoring"""
    
    def __init__(self, cache_client=None):
        self.cache_client = cache_client or redis.Redis()
        self.query_metrics: Dict[str, QueryMetrics] = {}
        self.slow_query_threshold = 1.0  # 1 segundo
        self.query_cache_ttl = 3600  # 1 hora
        
    def execute_query(self, query: str, params: tuple = None, use_cache: bool = True) -> List[Dict]:
        """Executa query com otimizações"""
        start_time = time.time()
        
        # Gera hash da query
        query_hash = self._generate_query_hash(query, params)
        
        # Tenta cache se habilitado
        if use_cache:
            cached_result = self._get_cached_query(query_hash)
            if cached_result is not None:
                self._record_cache_hit(query_hash)
                return cached_result
        
        # Executa query
        try:
            with self.pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(query, params)
                    result = cursor.fetchall()
                    
                    # Converte para lista de dicts
                    if result:
                        result = [dict(row) for row in result]
                    else:
                        result = []
            
            execution_time = time.time() - start_time
            
            # Atualiza métricas
            self._update_query_metrics(query_hash, query, execution_time)
            
            # Cache resultado se habilitado
            if use_cache and result:
                self._cache_query_result(query_hash, result)
            
            # Verifica query lenta
            if execution_time > self.slow_query_threshold:
                self._record_slow_query(query_hash, query, execution_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Erro na execução da query: {e}")
            raise
    
    def _generate_query_hash(self, query: str, params: tuple = None) -> str:
        """Gera hash único para query"""
        import hashlib
        query_string = f"{query}:{str(params)}"
        return hashlib.md5(query_string.encode()).hexdigest()
    
    def _get_cached_query(self, query_hash: str) -> Optional[List[Dict]]:
        """Obtém resultado da query do cache"""
        try:
            cached = self.cache_client.get(f"query:{query_hash}")
            if cached:
                return eval(cached.decode())  # Em produção, usar json.loads
            return None
        except Exception as e:
            logger.error(f"Erro ao obter query do cache: {e}")
            return None
    
    def _cache_query_result(self, query_hash: str, result: List[Dict]):
        """Armazena resultado da query no cache"""
        try:
            cache_key = f"query:{query_hash}"
            self.cache_client.setex(cache_key, self.query_cache_ttl, str(result))
        except Exception as e:
            logger.error(f"Erro ao cachear query: {e}")
    
    def _record_cache_hit(self, query_hash: str):
        """Registra hit no cache"""
        if query_hash in self.query_metrics:
            self.query_metrics[query_hash].cache_hits += 1
    
    def _update_query_metrics(self, query_hash: str, query: str, execution_time: float):
        """Atualiza métricas da query"""
        if query_hash not in self.query_metrics:
            self.query_metrics[query_hash] = QueryMetrics(
                query_hash=query_hash,
                query_text=query
            )
        
        metrics = self.query_metrics[query_hash]
        metrics.execution_count += 1
        metrics.total_time += execution_time
        metrics.avg_time = metrics.total_time / metrics.execution_count
        metrics.min_time = min(metrics.min_time, execution_time)
        metrics.max_time = max(metrics.max_time, execution_time)
        metrics.last_execution = datetime.utcnow()
    
    def _record_slow_query(self, query_hash: str, query: str, execution_time: float):
        """Registra query lenta"""
        logger.warning(f"Query lenta detectada: {execution_time:.3f}s - {query[:100]}...")
        
        # Atualiza métricas globais
        self.pool.metrics.slow_queries += 1
        self.pool.metrics.total_queries += 1
        
        # Atualiza tempo médio de query
        if self.pool.metrics.total_queries > 0:
            self.pool.metrics.avg_query_time = (
                (self.pool.metrics.avg_query_time * (self.pool.metrics.total_queries - 1) + execution_time) /
                self.pool.metrics.total_queries
            )
    
    def get_slow_queries(self) -> List[Dict[str, Any]]:
        """Retorna queries lentas"""
        slow_queries = []
        
        for metrics in self.query_metrics.values():
            if metrics.avg_time > self.slow_query_threshold:
                slow_queries.append({
                    'query_hash': metrics.query_hash,
                    'query_text': metrics.query_text,
                    'execution_count': metrics.execution_count,
                    'avg_time': metrics.avg_time,
                    'min_time': metrics.min_time,
                    'max_time': metrics.max_time,
                    'last_execution': metrics.last_execution.isoformat()
                })
        
        return sorted(slow_queries, key=lambda x: x['avg_time'], reverse=True)
    
    def get_query_metrics(self) -> Dict[str, QueryMetrics]:
        """Retorna métricas de todas as queries"""
        return self.query_metrics

class DatabaseHealthChecker:
    """Verificador de saúde do database"""
    
    def __init__(self, pool: OptimizedConnectionPool):
        self.pool = pool
        self.health_checks = {
            'connection_test': self._test_connection,
            'query_test': self._test_query,
            'performance_test': self._test_performance,
            'lock_test': self._test_locks
        }
    
    def run_health_check(self) -> Dict[str, Any]:
        """Executa verificação completa de saúde"""
        health_report = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'healthy',
            'checks': {},
            'recommendations': []
        }
        
        for check_name, check_func in self.health_checks.items():
            try:
                result = check_func()
                health_report['checks'][check_name] = result
                
                if not result['status']:
                    health_report['overall_status'] = 'unhealthy'
                    health_report['recommendations'].append(result.get('recommendation', ''))
                    
            except Exception as e:
                health_report['checks'][check_name] = {
                    'status': False,
                    'error': str(e),
                    'recommendation': f'Verificar {check_name}'
                }
                health_report['overall_status'] = 'unhealthy'
        
        return health_report
    
    def _test_connection(self) -> Dict[str, Any]:
        """Testa conectividade básica"""
        start_time = time.time()
        
        try:
            with self.pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                
                connection_time = time.time() - start_time
                
                return {
                    'status': result[0] == 1,
                    'connection_time': connection_time,
                    'recommendation': 'Conexão funcionando normalmente'
                }
                
        except Exception as e:
            return {
                'status': False,
                'error': str(e),
                'recommendation': 'Verificar configurações de conexão'
            }
    
    def _test_query(self) -> Dict[str, Any]:
        """Testa execução de queries básicas"""
        test_queries = [
            "SELECT version()",
            "SELECT current_database()",
            "SELECT count(*) FROM information_schema.tables"
        ]
        
        results = []
        for query in test_queries:
            try:
                with self.pool.get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(query)
                        result = cursor.fetchone()
                        results.append({'query': query, 'result': result[0]})
                        
            except Exception as e:
                return {
                    'status': False,
                    'error': f"Erro na query '{query}': {e}",
                    'recommendation': 'Verificar permissões e estrutura do banco'
                }
        
        return {
            'status': True,
            'results': results,
            'recommendation': 'Queries básicas funcionando'
        }
    
    def _test_performance(self) -> Dict[str, Any]:
        """Testa performance do database"""
        try:
            with self.pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Testa query simples
                    start_time = time.time()
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
                    simple_query_time = time.time() - start_time
                    
                    # Testa query com JOIN
                    start_time = time.time()
                    cursor.execute("""
                        SELECT t.table_name, c.column_name 
                        FROM information_schema.tables t 
                        JOIN information_schema.columns c ON t.table_name = c.table_name 
                        LIMIT 10
                    """)
                    cursor.fetchall()
                    complex_query_time = time.time() - start_time
                
                return {
                    'status': True,
                    'simple_query_time': simple_query_time,
                    'complex_query_time': complex_query_time,
                    'recommendation': 'Performance dentro do esperado' if simple_query_time < 0.1 else 'Considerar otimizações'
                }
                
        except Exception as e:
            return {
                'status': False,
                'error': str(e),
                'recommendation': 'Verificar performance do database'
            }
    
    def _test_locks(self) -> Dict[str, Any]:
        """Testa locks e deadlocks"""
        try:
            with self.pool.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT count(*) 
                        FROM pg_stat_activity 
                        WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%'
                    """)
                    active_queries = cursor.fetchone()[0]
                    
                    cursor.execute("""
                        SELECT count(*) 
                        FROM pg_locks 
                        WHERE NOT granted
                    """)
                    waiting_locks = cursor.fetchone()[0]
                
                return {
                    'status': waiting_locks == 0,
                    'active_queries': active_queries,
                    'waiting_locks': waiting_locks,
                    'recommendation': 'Sem locks pendentes' if waiting_locks == 0 else 'Verificar queries bloqueadas'
                }
                
        except Exception as e:
            return {
                'status': False,
                'error': str(e),
                'recommendation': 'Verificar status de locks'
            }

class DatabaseRetryLogic:
    """Lógica de retry para operações de database"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.retryable_errors = [
            'connection',
            'timeout',
            'deadlock',
            'temporary'
        ]
    
    def execute_with_retry(self, operation: Callable, *args, **kwargs) -> Any:
        """Executa operação com retry automático"""
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return operation(*args, **kwargs)
                
            except Exception as e:
                last_exception = e
                
                if attempt < self.max_retries and self._is_retryable_error(e):
                    delay = self.base_delay * (2 ** attempt)  # Backoff exponencial
                    logger.warning(f"Tentativa {attempt + 1} falhou, tentando novamente em {delay}s: {e}")
                    time.sleep(delay)
                else:
                    break
        
        logger.error(f"Operação falhou após {self.max_retries + 1} tentativas: {last_exception}")
        raise last_exception
    
    def _is_retryable_error(self, error: Exception) -> bool:
        """Verifica se erro é retryable"""
        error_str = str(error).lower()
        return any(retryable in error_str for retryable in self.retryable_errors)

class OptimizedDatabaseManager:
    """Gerenciador principal de database otimizado"""
    
    def __init__(self, 
                 host: str = "localhost",
                 port: int = 5432,
                 database: str = "omni_writer",
                 user: str = "postgres",
                 password: str = "",
                 min_connections: int = 5,
                 max_connections: int = 20):
        
        # Pool de conexões
        self.pool = OptimizedConnectionPool(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            min_connections=min_connections,
            max_connections=max_connections
        )
        
        # Otimizadores
        self.query_optimizer = QueryOptimizer()
        self.health_checker = DatabaseHealthChecker(self.pool)
        self.retry_logic = DatabaseRetryLogic()
        
        # Conecta query optimizer ao pool
        self.query_optimizer.pool = self.pool
        
        logger.info("Database Manager Otimizado inicializado")
    
    def execute_query(self, query: str, params: tuple = None, use_cache: bool = True) -> List[Dict]:
        """Executa query com todas as otimizações"""
        return self.retry_logic.execute_with_retry(
            self.query_optimizer.execute_query,
            query,
            params,
            use_cache
        )
    
    def get_connection(self) -> psycopg2.extensions.connection:
        """Obtém conexão do pool"""
        return self.pool.get_connection()
    
    def return_connection(self, connection: psycopg2.extensions.connection):
        """Retorna conexão ao pool"""
        self.pool.return_connection(connection)
    
    def run_health_check(self) -> Dict[str, Any]:
        """Executa verificação de saúde"""
        return self.health_checker.run_health_check()
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Gera relatório de performance"""
        pool_metrics = self.pool.get_metrics()
        slow_queries = self.query_optimizer.get_slow_queries()
        health_check = self.run_health_check()
        
        return {
            'pool_metrics': {
                'total_connections': pool_metrics.total_connections,
                'active_connections': pool_metrics.active_connections,
                'idle_connections': pool_metrics.idle_connections,
                'connection_errors': pool_metrics.connection_errors,
                'avg_connection_time': pool_metrics.avg_connection_time,
                'avg_query_time': pool_metrics.avg_query_time,
                'total_queries': pool_metrics.total_queries,
                'slow_queries': pool_metrics.slow_queries
            },
            'slow_queries': slow_queries[:10],  # Top 10 queries mais lentas
            'health_status': health_check['overall_status'],
            'health_checks': health_check['checks'],
            'recommendations': health_check['recommendations'],
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def shutdown(self):
        """Finaliza o database manager"""
        self.pool.stop_monitoring()
        logger.info("Database Manager Otimizado finalizado")

# Decorator para queries com cache automático
def cached_query(ttl: int = 3600):
    """Decorator para cache automático de queries"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Gera chave de cache baseada na função e parâmetros
            cache_key = f"query:{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Tenta obter do cache
            try:
                cached_result = db_manager.query_optimizer._get_cached_query(cache_key)
                if cached_result is not None:
                    return cached_result
            except:
                pass
            
            # Executa função
            result = func(*args, **kwargs)
            
            # Cache resultado
            try:
                db_manager.query_optimizer._cache_query_result(cache_key, result)
            except:
                pass
            
            return result
        
        return wrapper
    return decorator

# Instância global
db_manager = OptimizedDatabaseManager() 