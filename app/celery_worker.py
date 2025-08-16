"""
Configuração do Celery para sistema de filas distribuído.
Implementa broker Redis, workers distribuídos e monitoramento avançado.
"""
import os
import logging
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_init, worker_shutdown, task_prerun, task_postrun
from celery.utils.log import get_task_logger
from datetime import timedelta
import redis
from prometheus_client import Counter, Histogram, Gauge
import time

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = get_task_logger(__name__)

# Métricas Prometheus
TASK_COUNTER = Counter('celery_tasks_total', 'Total de tarefas processadas', ['task_name', 'status'])
TASK_DURATION = Histogram('celery_task_duration_seconds', 'Duração das tarefas', ['task_name'])
WORKER_GAUGE = Gauge('celery_workers_active', 'Número de workers ativos')
QUEUE_SIZE = Gauge('celery_queue_size', 'Tamanho das filas', ['queue_name'])

# Configuração do Celery
def make_celery(app_name: str = __name__) -> Celery:
    """
    Cria e configura instância do Celery com Redis como broker.
    
    Args:
        app_name: Nome da aplicação
        
    Returns:
        Instância configurada do Celery
    """
    # Configuração do broker Redis
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    celery_app = Celery(
        app_name,
        broker=redis_url,
        backend=redis_url,
        include=[
            'app.tasks.generation_tasks',
            'app.tasks.maintenance_tasks',
            'app.tasks.monitoring_tasks'
        ]
    )
    
    # Configurações avançadas
    celery_app.conf.update(
        # Configurações de broker
        broker_connection_retry_on_startup=True,
        broker_connection_max_retries=10,
        broker_connection_retry_delay=1.0,
        
        # Configurações de workers
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=1000,
        worker_max_memory_per_child=200000,  # 200MB
        
        # Configurações de tasks
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_always_eager=False,
        task_eager_propagates=True,
        
        # Configurações de filas
        task_default_queue='default',
        task_queues={
            'high_priority': {
                'exchange': 'high_priority',
                'routing_key': 'high_priority',
            },
            'default': {
                'exchange': 'default',
                'routing_key': 'default',
            },
            'low_priority': {
                'exchange': 'low_priority',
                'routing_key': 'low_priority',
            },
        },
        task_routes={
            'app.tasks.generation_tasks.generate_article': {'queue': 'high_priority'},
            'app.tasks.generation_tasks.batch_generate': {'queue': 'default'},
            'app.tasks.maintenance_tasks.cleanup_old_files': {'queue': 'low_priority'},
        },
        
        # Configurações de retry
        task_retry_policy={
            'max_retries': 3,
            'interval_start': 0,
            'interval_step': 0.2,
            'interval_max': 0.2,
        },
        
        # Configurações de serialização
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        
        # Configurações de beat (agendamento)
        beat_schedule={
            'health-check': {
                'task': 'app.tasks.monitoring_tasks.health_check',
                'schedule': timedelta(minutes=5),
            },
            'cleanup-old-files': {
                'task': 'app.tasks.maintenance_tasks.cleanup_old_files',
                'schedule': crontab(hour=2, minute=0),  # 2 AM UTC
            },
            'rotate-tokens': {
                'task': 'app.tasks.maintenance_tasks.rotate_api_tokens',
                'schedule': crontab(hour=0, minute=0),  # Midnight UTC
            },
            'update-metrics': {
                'task': 'app.tasks.monitoring_tasks.update_queue_metrics',
                'schedule': timedelta(minutes=1),
            },
        },
        
        # Configurações de monitoramento
        worker_send_task_events=True,
        task_send_sent_event=True,
        
        # Configurações de segurança
        security_key=os.getenv('CELERY_SECURITY_KEY', 'default-security-key'),
        security_certificate=os.getenv('CELERY_CERT_PATH'),
        security_cert_store=os.getenv('CELERY_CERT_STORE_PATH'),
    )
    
    return celery_app

# Instância global do Celery
celery_app = make_celery()

# Handlers de eventos
@worker_init.connect
def worker_init_handler(sender=None, **kwargs):
    """Handler executado quando worker é inicializado."""
    logger.info(f"Worker {sender} inicializado")
    WORKER_GAUGE.inc()

@worker_shutdown.connect
def worker_shutdown_handler(sender=None, **kwargs):
    """Handler executado quando worker é finalizado."""
    logger.info(f"Worker {sender} finalizado")
    WORKER_GAUGE.dec()

@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, **kwargs):
    """Handler executado antes de cada task."""
    logger.info(f"Task {task.name} iniciada (ID: {task_id})")
    TASK_COUNTER.labels(task_name=task.name, status='started').inc()

@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, retval=None, state=None, **kwargs):
    """Handler executado após cada task."""
    duration = time.time() - kwargs.get('start_time', time.time())
    TASK_DURATION.labels(task_name=task.name).observe(duration)
    
    status = 'success' if state == 'SUCCESS' else 'failed'
    TASK_COUNTER.labels(task_name=task.name, status=status).inc()
    
    logger.info(f"Task {task.name} finalizada (ID: {task_id}, Status: {state}, Duração: {duration:.2f}s)")

# Função para monitorar filas
def get_queue_metrics():
    """
    Obtém métricas das filas Redis.
    
    Returns:
        dict: Métricas das filas
    """
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        
        metrics = {}
        for queue_name in ['high_priority', 'default', 'low_priority']:
            queue_size = redis_client.llen(f'celery:{queue_name}')
            metrics[queue_name] = queue_size
            QUEUE_SIZE.labels(queue_name=queue_name).set(queue_size)
        
        return metrics
    except Exception as e:
        logger.error(f"Erro ao obter métricas das filas: {e}")
        return {}

# Função para health check do broker
def check_broker_health():
    """
    Verifica saúde do broker Redis.
    
    Returns:
        bool: True se saudável, False caso contrário
    """
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.ping()
        return True
    except Exception as e:
        logger.error(f"Broker Redis não está saudável: {e}")
        return False

# Função para limpar filas
def purge_queues(queue_names=None):
    """
    Limpa filas específicas ou todas as filas.
    
    Args:
        queue_names: Lista de nomes de filas para limpar (None = todas)
    """
    if queue_names is None:
        queue_names = ['high_priority', 'default', 'low_priority']
    
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        
        for queue_name in queue_names:
            queue_key = f'celery:{queue_name}'
            redis_client.delete(queue_key)
            logger.info(f"Fila {queue_name} limpa")
            
    except Exception as e:
        logger.error(f"Erro ao limpar filas: {e}")

# Função para obter estatísticas dos workers
def get_worker_stats():
    """
    Obtém estatísticas dos workers ativos.
    
    Returns:
        dict: Estatísticas dos workers
    """
    try:
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        
        # Obtém workers ativos
        active_workers = redis_client.smembers('celery:active')
        
        stats = {
            'active_workers': len(active_workers),
            'worker_names': [worker.decode() for worker in active_workers],
            'queue_metrics': get_queue_metrics(),
            'broker_health': check_broker_health()
        }
        
        return stats
    except Exception as e:
        logger.error(f"Erro ao obter estatísticas dos workers: {e}")
        return {}

if __name__ == '__main__':
    celery_app.start() 