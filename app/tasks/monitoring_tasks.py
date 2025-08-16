"""
Tasks de monitoramento para sistema distribuído.
Implementa health checks, métricas e alertas.
"""
import os
import logging
import time
import psutil
from datetime import datetime
from typing import Dict, List
from celery import current_task
from celery.utils.log import get_task_logger
import redis
from prometheus_client import Counter, Histogram, Gauge

# Configuração de logging
logger = get_task_logger(__name__)

# Métricas Prometheus
HEALTH_CHECK_COUNTER = Counter('health_check_total', 'Total de health checks', ['status'])
SYSTEM_METRICS_GAUGE = Gauge('system_metrics', 'Métricas do sistema', ['metric_name'])
QUEUE_METRICS_GAUGE = Gauge('queue_metrics', 'Métricas das filas', ['queue_name', 'metric_type'])

@current_task.task(bind=True, name='app.tasks.monitoring_tasks.health_check')
def health_check(self) -> Dict:
    """
    Task para health check do sistema.
    
    Returns:
        Resultado do health check
    """
    start_time = time.time()
    
    try:
        # Verificações de saúde
        checks = {
            'redis_connection': False,
            'database_connection': False,
            'disk_space': False,
            'memory_usage': False,
            'cpu_usage': False
        }
        
        # Verifica Redis
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            redis_client = redis.from_url(redis_url)
            redis_client.ping()
            checks['redis_connection'] = True
            logger.info("Redis: OK")
        except Exception as e:
            logger.error(f"Redis: ERRO - {e}")
        
        # Verifica banco de dados
        try:
            import sqlite3
            if os.path.exists('blog.db'):
                conn = sqlite3.connect('blog.db')
                conn.execute('SELECT 1')
                conn.close()
                checks['database_connection'] = True
                logger.info("Database: OK")
        except Exception as e:
            logger.error(f"Database: ERRO - {e}")
        
        # Verifica espaço em disco
        try:
            total, used, free = psutil.disk_usage('.')
            free_percent = (free / total) * 100
            checks['disk_space'] = free_percent > 10  # Pelo menos 10% livre
            SYSTEM_METRICS_GAUGE.labels(metric_name='disk_free_percent').set(free_percent)
            logger.info(f"Disk: {free_percent:.1f}% livre")
        except Exception as e:
            logger.error(f"Disk: ERRO - {e}")
        
        # Verifica uso de memória
        try:
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            checks['memory_usage'] = memory_percent < 90  # Menos de 90% usado
            SYSTEM_METRICS_GAUGE.labels(metric_name='memory_usage_percent').set(memory_percent)
            logger.info(f"Memory: {memory_percent:.1f}% usado")
        except Exception as e:
            logger.error(f"Memory: ERRO - {e}")
        
        # Verifica uso de CPU
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            checks['cpu_usage'] = cpu_percent < 95  # Menos de 95% usado
            SYSTEM_METRICS_GAUGE.labels(metric_name='cpu_usage_percent').set(cpu_percent)
            logger.info(f"CPU: {cpu_percent:.1f}% usado")
        except Exception as e:
            logger.error(f"CPU: ERRO - {e}")
        
        # Calcula score de saúde
        health_score = sum(checks.values()) / len(checks) * 100
        status = 'healthy' if health_score >= 80 else 'degraded' if health_score >= 50 else 'unhealthy'
        
        # Registra métrica
        HEALTH_CHECK_COUNTER.labels(status=status).inc()
        
        return {
            'status': 'success',
            'health_score': round(health_score, 2),
            'system_status': status,
            'checks': checks,
            'timestamp': datetime.now().isoformat(),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro no health check: {exc}")
        HEALTH_CHECK_COUNTER.labels(status='error').inc()
        
        if self.request.retries < 2:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.monitoring_tasks.update_queue_metrics')
def update_queue_metrics(self) -> Dict:
    """
    Task para atualização de métricas das filas.
    
    Returns:
        Métricas atualizadas das filas
    """
    start_time = time.time()
    
    try:
        # Configuração do Redis
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(redis_url)
        
        # Métricas das filas
        queue_metrics = {}
        
        for queue_name in ['high_priority', 'default', 'low_priority']:
            queue_key = f'celery:{queue_name}'
            
            try:
                # Tamanho da fila
                queue_size = redis_client.llen(queue_key)
                QUEUE_METRICS_GAUGE.labels(queue_name=queue_name, metric_type='size').set(queue_size)
                
                # Workers ativos para esta fila
                active_workers = redis_client.smembers('celery:active')
                worker_count = len(active_workers)
                QUEUE_METRICS_GAUGE.labels(queue_name=queue_name, metric_type='workers').set(worker_count)
                
                queue_metrics[queue_name] = {
                    'size': queue_size,
                    'workers': worker_count
                }
                
            except Exception as e:
                logger.warning(f"Erro ao obter métricas da fila {queue_name}: {e}")
                queue_metrics[queue_name] = {'size': 0, 'workers': 0}
        
        return {
            'status': 'success',
            'queue_metrics': queue_metrics,
            'timestamp': datetime.now().isoformat(),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na atualização de métricas: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=30 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.monitoring_tasks.collect_system_metrics')
def collect_system_metrics(self) -> Dict:
    """
    Task para coleta de métricas do sistema.
    
    Returns:
        Métricas coletadas do sistema
    """
    start_time = time.time()
    
    try:
        # Métricas do sistema
        metrics = {}
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        metrics['cpu'] = {
            'usage_percent': cpu_percent,
            'count': cpu_count
        }
        SYSTEM_METRICS_GAUGE.labels(metric_name='cpu_usage_percent').set(cpu_percent)
        SYSTEM_METRICS_GAUGE.labels(metric_name='cpu_count').set(cpu_count)
        
        # Memória
        memory = psutil.virtual_memory()
        metrics['memory'] = {
            'total_gb': round(memory.total / (1024**3), 2),
            'available_gb': round(memory.available / (1024**3), 2),
            'used_gb': round(memory.used / (1024**3), 2),
            'percent': memory.percent
        }
        SYSTEM_METRICS_GAUGE.labels(metric_name='memory_total_gb').set(metrics['memory']['total_gb'])
        SYSTEM_METRICS_GAUGE.labels(metric_name='memory_available_gb').set(metrics['memory']['available_gb'])
        
        # Disco
        disk = psutil.disk_usage('.')
        metrics['disk'] = {
            'total_gb': round(disk.total / (1024**3), 2),
            'used_gb': round(disk.used / (1024**3), 2),
            'free_gb': round(disk.free / (1024**3), 2),
            'percent': round((disk.used / disk.total) * 100, 2)
        }
        SYSTEM_METRICS_GAUGE.labels(metric_name='disk_total_gb').set(metrics['disk']['total_gb'])
        SYSTEM_METRICS_GAUGE.labels(metric_name='disk_free_gb').set(metrics['disk']['free_gb'])
        
        # Rede
        network = psutil.net_io_counters()
        metrics['network'] = {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv
        }
        SYSTEM_METRICS_GAUGE.labels(metric_name='network_bytes_sent').set(network.bytes_sent)
        SYSTEM_METRICS_GAUGE.labels(metric_name='network_bytes_recv').set(network.bytes_recv)
        
        # Processos
        processes = len(psutil.pids())
        metrics['processes'] = {
            'total': processes
        }
        SYSTEM_METRICS_GAUGE.labels(metric_name='process_count').set(processes)
        
        return {
            'status': 'success',
            'metrics': metrics,
            'timestamp': datetime.now().isoformat(),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na coleta de métricas: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.monitoring_tasks.check_alerts')
def check_alerts(self) -> Dict:
    """
    Task para verificação de alertas do sistema.
    
    Returns:
        Alertas encontrados
    """
    start_time = time.time()
    
    try:
        alerts = []
        
        # Verifica uso de CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 90:
            alerts.append({
                'level': 'warning',
                'message': f'CPU usage high: {cpu_percent:.1f}%',
                'metric': 'cpu_usage',
                'value': cpu_percent
            })
        
        # Verifica uso de memória
        memory = psutil.virtual_memory()
        if memory.percent > 85:
            alerts.append({
                'level': 'warning',
                'message': f'Memory usage high: {memory.percent:.1f}%',
                'metric': 'memory_usage',
                'value': memory.percent
            })
        
        # Verifica espaço em disco
        disk = psutil.disk_usage('.')
        disk_percent = (disk.used / disk.total) * 100
        if disk_percent > 90:
            alerts.append({
                'level': 'critical',
                'message': f'Disk space low: {disk_percent:.1f}% used',
                'metric': 'disk_usage',
                'value': disk_percent
            })
        
        # Verifica filas Redis
        try:
            redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            redis_client = redis.from_url(redis_url)
            
            for queue_name in ['high_priority', 'default', 'low_priority']:
                queue_size = redis_client.llen(f'celery:{queue_name}')
                if queue_size > 100:
                    alerts.append({
                        'level': 'warning',
                        'message': f'Queue {queue_name} has {queue_size} pending tasks',
                        'metric': f'queue_{queue_name}_size',
                        'value': queue_size
                    })
        except Exception as e:
            alerts.append({
                'level': 'critical',
                'message': f'Redis connection failed: {e}',
                'metric': 'redis_connection',
                'value': 'error'
            })
        
        return {
            'status': 'success',
            'alerts': alerts,
            'alert_count': len(alerts),
            'timestamp': datetime.now().isoformat(),
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na verificação de alertas: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=120 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        }

@current_task.task(bind=True, name='app.tasks.monitoring_tasks.generate_monitoring_report')
def generate_monitoring_report(self) -> Dict:
    """
    Task para geração de relatório de monitoramento.
    
    Returns:
        Relatório de monitoramento
    """
    start_time = time.time()
    
    try:
        # Coleta todas as métricas
        health_result = health_check()
        queue_result = update_queue_metrics()
        system_result = collect_system_metrics()
        alerts_result = check_alerts()
        
        # Gera relatório
        report = {
            'timestamp': datetime.now().isoformat(),
            'health': health_result,
            'queues': queue_result,
            'system': system_result,
            'alerts': alerts_result,
            'summary': {
                'system_status': health_result.get('system_status', 'unknown'),
                'alert_count': alerts_result.get('alert_count', 0),
                'total_queued_tasks': sum(
                    queue.get('size', 0) 
                    for queue in queue_result.get('queue_metrics', {}).values()
                )
            }
        }
        
        # Salva relatório em arquivo
        report_file = f"logs/monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs('logs', exist_ok=True)
        
        import json
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return {
            'status': 'success',
            'report': report,
            'report_file': report_file,
            'duration': time.time() - start_time
        }
        
    except Exception as exc:
        logger.error(f"Erro na geração do relatório: {exc}")
        
        if self.request.retries < 2:
            raise self.retry(countdown=300 * (2 ** self.request.retries), exc=exc)
        
        return {
            'status': 'error',
            'error': str(exc),
            'duration': time.time() - start_time
        } 