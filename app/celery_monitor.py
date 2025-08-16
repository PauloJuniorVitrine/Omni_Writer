"""
Celery Monitor e Healthcheck - Omni Writer
==========================================

Sistema de monitoramento, healthcheck e recuperação automática para workers Celery.

Prompt: Implementação de fila Celery resiliente
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import os
import time
import logging
import threading
import subprocess
import signal
import psutil
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from contextlib import contextmanager
import redis
from celery import Celery
from celery.events.state import State
from celery.events.snapshot import Snapshot
from celery.utils.time import monotonic

# Configuração de logging estruturado
monitor_logger = logging.getLogger("celery_monitor")
monitor_logger.setLevel(logging.INFO)
if not monitor_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/celery_monitor.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [celery_monitor] %(message)s'
    )
    handler.setFormatter(formatter)
    monitor_logger.addHandler(handler)

# Configurações
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
HEALTHCHECK_INTERVAL = int(os.getenv('CELERY_HEALTHCHECK_INTERVAL', '30'))  # segundos
MAX_RESTART_ATTEMPTS = int(os.getenv('CELERY_MAX_RESTART_ATTEMPTS', '3'))
WORKER_TIMEOUT = int(os.getenv('CELERY_WORKER_TIMEOUT', '300'))  # segundos
TASK_TIMEOUT = int(os.getenv('CELERY_TASK_TIMEOUT', '600'))  # segundos

@dataclass
class WorkerStatus:
    """Status de um worker Celery."""
    name: str
    pid: int
    status: str  # 'running', 'stopped', 'failed'
    last_heartbeat: datetime
    tasks_processed: int
    tasks_failed: int
    memory_usage: float
    cpu_usage: float
    uptime: timedelta

@dataclass
class TaskMetrics:
    """Métricas de tasks."""
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    pending_tasks: int
    avg_processing_time: float
    queue_size: int

class CeleryMonitor:
    """
    Monitor de workers Celery com healthcheck e recuperação automática.
    
    Funcionalidades:
    - Healthcheck automático de workers
    - Auto-restart em caso de falha
    - Monitoramento de tasks stuck
    - Métricas de fila (tamanho, tempo de processamento)
    - Detecção de deadlocks e timeouts
    - Logs estruturados de monitoramento
    """
    
    def __init__(self):
        self.celery_app = Celery('omni_gerador', broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)
        self.redis_client = None
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        self.worker_processes = {}
        self.restart_attempts = {}
        self.metrics_history = []
        
        # Configurações
        self.healthcheck_interval = HEALTHCHECK_INTERVAL
        self.max_restart_attempts = MAX_RESTART_ATTEMPTS
        self.worker_timeout = WORKER_TIMEOUT
        self.task_timeout = TASK_TIMEOUT
        
        # Inicialização
        self._initialize_monitor()
    
    def _initialize_monitor(self):
        """Inicializa o monitor."""
        try:
            # Inicializa Redis
            self._init_redis()
            
            # Configura handlers de sinal
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            monitor_logger.info("Monitor Celery inicializado com sucesso")
            
        except Exception as e:
            monitor_logger.error(f"Erro ao inicializar monitor: {e}")
            raise
    
    def _init_redis(self):
        """Inicializa conexão Redis."""
        try:
            self.redis_client = redis.from_url(
                CELERY_BROKER_URL.replace('redis://', 'redis://'),
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Testa conexão
            self.redis_client.ping()
            
            monitor_logger.info("Redis inicializado para monitoramento")
            
        except Exception as e:
            monitor_logger.error(f"Erro ao inicializar Redis: {e}")
            self.redis_client = None
    
    def _signal_handler(self, signum, frame):
        """Handler para sinais de parada."""
        monitor_logger.info(f"Sinal {signum} recebido. Parando monitoramento...")
        self.stop_monitoring.set()
    
    def start_monitoring(self):
        """Inicia o monitoramento em background."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            monitor_logger.warning("Monitoramento já está em execução")
            return
        
        self.stop_monitoring.clear()
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        monitor_logger.info("Monitoramento iniciado")
    
    def stop_monitoring_service(self):
        """Para o monitoramento."""
        self.stop_monitoring.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
        
        monitor_logger.info("Monitoramento parado")
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento."""
        while not self.stop_monitoring.is_set():
            try:
                # Healthcheck de workers
                self._healthcheck_workers()
                
                # Monitoramento de tasks
                self._monitor_tasks()
                
                # Coleta de métricas
                self._collect_metrics()
                
                # Aguarda próximo ciclo
                self.stop_monitoring.wait(self.healthcheck_interval)
                
            except Exception as e:
                monitor_logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(5)  # Aguarda antes de tentar novamente
    
    def _healthcheck_workers(self):
        """Executa healthcheck dos workers."""
        try:
            # Obtém lista de workers ativos
            active_workers = self._get_active_workers()
            
            for worker_name in active_workers:
                worker_status = self._check_worker_health(worker_name)
                
                if worker_status.status == 'failed':
                    self._handle_worker_failure(worker_name, worker_status)
                elif worker_status.status == 'stopped':
                    self._handle_worker_stopped(worker_name, worker_status)
                else:
                    # Worker saudável
                    self.restart_attempts[worker_name] = 0
                    monitor_logger.debug(f"Worker {worker_name} saudável")
            
            # Verifica workers órfãos
            self._check_orphaned_workers()
            
        except Exception as e:
            monitor_logger.error(f"Erro no healthcheck: {e}")
    
    def _get_active_workers(self) -> List[str]:
        """Obtém lista de workers ativos."""
        try:
            if not self.redis_client:
                return []
            
            # Busca workers no Redis
            worker_keys = self.redis_client.keys('celery@*')
            workers = []
            
            for key in worker_keys:
                worker_name = key.replace('celery@', '')
                if self.redis_client.exists(key):
                    workers.append(worker_name)
            
            return workers
            
        except Exception as e:
            monitor_logger.error(f"Erro ao obter workers ativos: {e}")
            return []
    
    def _check_worker_health(self, worker_name: str) -> WorkerStatus:
        """Verifica saúde de um worker específico."""
        try:
            # Busca informações do worker no Redis
            worker_key = f'celery@{worker_name}'
            
            if not self.redis_client or not self.redis_client.exists(worker_key):
                return WorkerStatus(
                    name=worker_name,
                    pid=0,
                    status='stopped',
                    last_heartbeat=datetime.now(),
                    tasks_processed=0,
                    tasks_failed=0,
                    memory_usage=0.0,
                    cpu_usage=0.0,
                    uptime=timedelta(0)
                )
            
            # Obtém dados do worker
            worker_data = self.redis_client.hgetall(worker_key)
            
            # Verifica se o processo ainda existe
            pid = int(worker_data.get('pid', 0))
            process_exists = pid > 0 and psutil.pid_exists(pid)
            
            if not process_exists:
                return WorkerStatus(
                    name=worker_name,
                    pid=pid,
                    status='failed',
                    last_heartbeat=datetime.now(),
                    tasks_processed=0,
                    tasks_failed=0,
                    memory_usage=0.0,
                    cpu_usage=0.0,
                    uptime=timedelta(0)
                )
            
            # Obtém métricas do processo
            process = psutil.Process(pid)
            memory_usage = process.memory_percent()
            cpu_usage = process.cpu_percent()
            uptime = datetime.now() - datetime.fromtimestamp(process.create_time())
            
            # Verifica timeout
            last_heartbeat = datetime.fromtimestamp(float(worker_data.get('last_heartbeat', 0)))
            if datetime.now() - last_heartbeat > timedelta(seconds=self.worker_timeout):
                status = 'failed'
            else:
                status = 'running'
            
            return WorkerStatus(
                name=worker_name,
                pid=pid,
                status=status,
                last_heartbeat=last_heartbeat,
                tasks_processed=int(worker_data.get('tasks_processed', 0)),
                tasks_failed=int(worker_data.get('tasks_failed', 0)),
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                uptime=uptime
            )
            
        except Exception as e:
            monitor_logger.error(f"Erro ao verificar worker {worker_name}: {e}")
            return WorkerStatus(
                name=worker_name,
                pid=0,
                status='failed',
                last_heartbeat=datetime.now(),
                tasks_processed=0,
                tasks_failed=0,
                memory_usage=0.0,
                cpu_usage=0.0,
                uptime=timedelta(0)
            )
    
    def _handle_worker_failure(self, worker_name: str, status: WorkerStatus):
        """Trata falha de worker."""
        monitor_logger.warning(f"Worker {worker_name} falhou (PID: {status.pid})")
        
        # Incrementa contador de tentativas
        attempts = self.restart_attempts.get(worker_name, 0) + 1
        self.restart_attempts[worker_name] = attempts
        
        if attempts <= self.max_restart_attempts:
            monitor_logger.info(f"Tentativa {attempts}/{self.max_restart_attempts} de restart para {worker_name}")
            self._restart_worker(worker_name)
        else:
            monitor_logger.error(f"Worker {worker_name} excedeu tentativas de restart. Manual intervention required.")
    
    def _handle_worker_stopped(self, worker_name: str, status: WorkerStatus):
        """Trata worker parado."""
        monitor_logger.info(f"Worker {worker_name} parado. Iniciando...")
        self._start_worker(worker_name)
    
    def _check_orphaned_workers(self):
        """Verifica workers órfãos (processos sem registro no Redis)."""
        try:
            # Busca processos Celery
            celery_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if 'celery' in proc.info['name'].lower():
                        celery_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Verifica se há processos órfãos
            for proc in celery_processes:
                proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                if 'worker' in ' '.join(proc_info['cmdline'] or []):
                    # Verifica se está registrado no Redis
                    if not self._is_worker_registered(proc.info['pid']):
                        monitor_logger.warning(f"Worker órfão detectado (PID: {proc.info['pid']})")
                        self._terminate_orphaned_worker(proc.info['pid'])
            
        except Exception as e:
            monitor_logger.error(f"Erro ao verificar workers órfãos: {e}")
    
    def _is_worker_registered(self, pid: int) -> bool:
        """Verifica se worker está registrado no Redis."""
        try:
            if not self.redis_client:
                return False
            
            worker_keys = self.redis_client.keys('celery@*')
            for key in worker_keys:
                worker_pid = self.redis_client.hget(key, 'pid')
                if worker_pid and int(worker_pid) == pid:
                    return True
            
            return False
            
        except Exception as e:
            monitor_logger.error(f"Erro ao verificar registro de worker: {e}")
            return False
    
    def _terminate_orphaned_worker(self, pid: int):
        """Termina worker órfão."""
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=10)
            monitor_logger.info(f"Worker órfão terminado (PID: {pid})")
        except psutil.TimeoutExpired:
            process.kill()
            monitor_logger.warning(f"Worker órfão forçadamente terminado (PID: {pid})")
        except Exception as e:
            monitor_logger.error(f"Erro ao terminar worker órfão {pid}: {e}")
    
    def _start_worker(self, worker_name: str):
        """Inicia um worker."""
        try:
            cmd = [
                'celery', '-A', 'app.celery_worker', 'worker',
                '--loglevel=info',
                f'--hostname={worker_name}',
                '--concurrency=1'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.worker_processes[worker_name] = process
            monitor_logger.info(f"Worker {worker_name} iniciado (PID: {process.pid})")
            
        except Exception as e:
            monitor_logger.error(f"Erro ao iniciar worker {worker_name}: {e}")
    
    def _restart_worker(self, worker_name: str):
        """Reinicia um worker."""
        try:
            # Para worker atual
            if worker_name in self.worker_processes:
                process = self.worker_processes[worker_name]
                process.terminate()
                process.wait(timeout=10)
                del self.worker_processes[worker_name]
            
            # Inicia novo worker
            self._start_worker(worker_name)
            
        except Exception as e:
            monitor_logger.error(f"Erro ao reiniciar worker {worker_name}: {e}")
    
    def _monitor_tasks(self):
        """Monitora tasks em execução."""
        try:
            # Obtém tasks ativas
            active_tasks = self._get_active_tasks()
            
            for task_id, task_info in active_tasks.items():
                # Verifica timeout
                if self._is_task_stuck(task_info):
                    self._handle_stuck_task(task_id, task_info)
            
            # Monitora fila
            queue_metrics = self._get_queue_metrics()
            if queue_metrics['size'] > 100:  # Alerta se fila muito grande
                monitor_logger.warning(f"Fila grande detectada: {queue_metrics['size']} tasks")
            
        except Exception as e:
            monitor_logger.error(f"Erro no monitoramento de tasks: {e}")
    
    def _get_active_tasks(self) -> Dict[str, Dict[str, Any]]:
        """Obtém tasks ativas."""
        try:
            if not self.redis_client:
                return {}
            
            # Busca tasks ativas no Redis
            task_keys = self.redis_client.keys('celery-task-meta-*')
            active_tasks = {}
            
            for key in task_keys:
                task_data = self.redis_client.get(key)
                if task_data:
                    # Parse task data
                    import json
                    task_info = json.loads(task_data)
                    if task_info.get('status') == 'PENDING':
                        task_id = key.replace('celery-task-meta-', '')
                        active_tasks[task_id] = task_info
            
            return active_tasks
            
        except Exception as e:
            monitor_logger.error(f"Erro ao obter tasks ativas: {e}")
            return {}
    
    def _is_task_stuck(self, task_info: Dict[str, Any]) -> bool:
        """Verifica se task está stuck."""
        try:
            # Verifica tempo de execução
            timestamp = task_info.get('timestamp', 0)
            if timestamp:
                task_time = datetime.fromtimestamp(timestamp)
                if datetime.now() - task_time > timedelta(seconds=self.task_timeout):
                    return True
            
            return False
            
        except Exception as e:
            monitor_logger.error(f"Erro ao verificar task stuck: {e}")
            return False
    
    def _handle_stuck_task(self, task_id: str, task_info: Dict[str, Any]):
        """Trata task stuck."""
        monitor_logger.warning(f"Task stuck detectada: {task_id}")
        
        try:
            # Revoga task
            self.celery_app.control.revoke(task_id, terminate=True)
            monitor_logger.info(f"Task {task_id} revogada")
            
        except Exception as e:
            monitor_logger.error(f"Erro ao revogar task {task_id}: {e}")
    
    def _get_queue_metrics(self) -> Dict[str, Any]:
        """Obtém métricas da fila."""
        try:
            if not self.redis_client:
                return {'size': 0, 'oldest_task': None}
            
            # Conta tasks na fila
            queue_size = self.redis_client.llen('celery')
            
            # Obtém task mais antiga
            oldest_task = None
            if queue_size > 0:
                oldest_task = self.redis_client.lindex('celery', 0)
            
            return {
                'size': queue_size,
                'oldest_task': oldest_task
            }
            
        except Exception as e:
            monitor_logger.error(f"Erro ao obter métricas da fila: {e}")
            return {'size': 0, 'oldest_task': None}
    
    def _collect_metrics(self):
        """Coleta métricas do sistema."""
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'workers': len(self._get_active_workers()),
                'queue_size': self._get_queue_metrics()['size'],
                'active_tasks': len(self._get_active_tasks()),
                'restart_attempts': dict(self.restart_attempts)
            }
            
            self.metrics_history.append(metrics)
            
            # Mantém apenas últimas 100 métricas
            if len(self.metrics_history) > 100:
                self.metrics_history = self.metrics_history[-100:]
            
            monitor_logger.debug(f"Métricas coletadas: {metrics}")
            
        except Exception as e:
            monitor_logger.error(f"Erro ao coletar métricas: {e}")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Obtém status de saúde do sistema."""
        try:
            workers = self._get_active_workers()
            worker_statuses = []
            
            for worker_name in workers:
                status = self._check_worker_health(worker_name)
                worker_statuses.append({
                    'name': status.name,
                    'status': status.status,
                    'pid': status.pid,
                    'uptime': str(status.uptime),
                    'memory_usage': status.memory_usage,
                    'cpu_usage': status.cpu_usage,
                    'tasks_processed': status.tasks_processed,
                    'tasks_failed': status.tasks_failed
                })
            
            queue_metrics = self._get_queue_metrics()
            
            return {
                'status': 'healthy' if all(w['status'] == 'running' for w in worker_statuses) else 'degraded',
                'workers': worker_statuses,
                'queue': queue_metrics,
                'restart_attempts': dict(self.restart_attempts),
                'last_check': datetime.now().isoformat()
            }
            
        except Exception as e:
            monitor_logger.error(f"Erro ao obter status de saúde: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'last_check': datetime.now().isoformat()
            }
    
    def get_metrics_history(self) -> List[Dict[str, Any]]:
        """Obtém histórico de métricas."""
        return self.metrics_history.copy()

# Instância global do monitor
celery_monitor = CeleryMonitor()

def start_celery_monitoring():
    """Função de conveniência para iniciar monitoramento."""
    celery_monitor.start_monitoring()

def stop_celery_monitoring():
    """Função de conveniência para parar monitoramento."""
    celery_monitor.stop_monitoring_service()

def get_celery_health():
    """Função de conveniência para obter status de saúde."""
    return celery_monitor.get_health_status()

def get_celery_metrics():
    """Função de conveniência para obter métricas."""
    return celery_monitor.get_metrics_history() 