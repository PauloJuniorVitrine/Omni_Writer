"""
Testes unitários para o sistema de monitoramento do Celery.

Prompt: Testes para monitoramento do Celery
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import pytest
import os
import time
import json
import threading
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Importa o módulo de monitoramento
from app.celery_monitor import (
    CeleryMonitor, WorkerStatus, TaskMetrics,
    start_celery_monitoring, stop_celery_monitoring,
    get_celery_health, get_celery_metrics
)

class TestCeleryMonitor:
    """Testes para a classe CeleryMonitor."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        # Mock das variáveis de ambiente
        self.env_patcher = patch.dict(os.environ, {
            'CELERY_BROKER_URL': 'redis://localhost:6379/0',
            'CELERY_RESULT_BACKEND': 'redis://localhost:6379/0',
            'CELERY_HEALTHCHECK_INTERVAL': '30',
            'CELERY_MAX_RESTART_ATTEMPTS': '3'
        })
        self.env_patcher.start()
        
        # Cria instância de teste
        self.monitor = CeleryMonitor()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        self.env_patcher.stop()
        if hasattr(self.monitor, 'monitoring_thread') and self.monitor.monitoring_thread:
            self.monitor.stop_monitoring_service()
    
    @patch('app.celery_monitor.redis.from_url')
    def test_init_monitor(self, mock_redis):
        """Testa inicialização do monitor."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.ping.return_value = True
        mock_redis.return_value = mock_redis_instance
        
        monitor = CeleryMonitor()
        
        assert monitor.celery_app is not None
        assert monitor.redis_client is not None
        assert monitor.healthcheck_interval == 30
        assert monitor.max_restart_attempts == 3
    
    @patch('app.celery_monitor.redis.from_url')
    def test_get_active_workers(self, mock_redis):
        """Testa obtenção de workers ativos."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.keys.return_value = ['celery@worker1', 'celery@worker2']
        mock_redis_instance.exists.return_value = True
        mock_redis.return_value = mock_redis_instance
        
        self.monitor.redis_client = mock_redis_instance
        
        workers = self.monitor._get_active_workers()
        
        assert len(workers) == 2
        assert 'worker1' in workers
        assert 'worker2' in workers
    
    @patch('app.celery_monitor.psutil.Process')
    @patch('app.celery_monitor.redis.from_url')
    def test_check_worker_health(self, mock_redis, mock_process):
        """Testa verificação de saúde de worker."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.exists.return_value = True
        mock_redis_instance.hgetall.return_value = {
            'pid': '12345',
            'last_heartbeat': str(time.time()),
            'tasks_processed': '10',
            'tasks_failed': '1'
        }
        mock_redis.return_value = mock_redis_instance
        
        # Mock do processo
        mock_process_instance = Mock()
        mock_process_instance.memory_percent.return_value = 2.5
        mock_process_instance.cpu_percent.return_value = 1.2
        mock_process_instance.create_time.return_value = time.time() - 3600
        mock_process.return_value = mock_process_instance
        
        # Mock de psutil.pid_exists
        with patch('app.celery_monitor.psutil.pid_exists', return_value=True):
            status = self.monitor._check_worker_health('worker1')
            
            assert status.name == 'worker1'
            assert status.pid == 12345
            assert status.status == 'running'
            assert status.tasks_processed == 10
            assert status.tasks_failed == 1
            assert status.memory_usage == 2.5
            assert status.cpu_usage == 1.2
    
    @patch('app.celery_monitor.psutil.pid_exists')
    def test_check_worker_health_failed(self, mock_pid_exists):
        """Testa verificação de worker falhado."""
        mock_pid_exists.return_value = False
        
        status = self.monitor._check_worker_health('worker1')
        
        assert status.status == 'failed'
        assert status.pid == 0
    
    @patch('app.celery_monitor.subprocess.Popen')
    def test_start_worker(self, mock_popen):
        """Testa início de worker."""
        mock_process = Mock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        
        self.monitor._start_worker('worker1')
        
        assert 'worker1' in self.monitor.worker_processes
        assert self.monitor.worker_processes['worker1'] == mock_process
        mock_popen.assert_called_once()
    
    @patch('app.celery_monitor.subprocess.Popen')
    def test_restart_worker(self, mock_popen):
        """Testa reinício de worker."""
        # Mock do processo existente
        mock_old_process = Mock()
        self.monitor.worker_processes['worker1'] = mock_old_process
        
        # Mock do novo processo
        mock_new_process = Mock()
        mock_new_process.pid = 12346
        mock_popen.return_value = mock_new_process
        
        self.monitor._restart_worker('worker1')
        
        # Verifica se processo antigo foi terminado
        mock_old_process.terminate.assert_called_once()
        mock_old_process.wait.assert_called_once_with(timeout=10)
        
        # Verifica se novo processo foi iniciado
        assert self.monitor.worker_processes['worker1'] == mock_new_process
    
    @patch('app.celery_monitor.psutil.process_iter')
    def test_check_orphaned_workers(self, mock_process_iter):
        """Testa verificação de workers órfãos."""
        # Mock de processos
        mock_proc1 = Mock()
        mock_proc1.info = {'pid': 12345, 'name': 'celery', 'cmdline': ['celery', 'worker']}
        mock_proc1.as_dict.return_value = {'pid': 12345, 'name': 'celery', 'cmdline': ['celery', 'worker']}
        
        mock_proc2 = Mock()
        mock_proc2.info = {'pid': 12346, 'name': 'python', 'cmdline': ['python', 'app.py']}
        mock_proc2.as_dict.return_value = {'pid': 12346, 'name': 'python', 'cmdline': ['python', 'app.py']}
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        # Mock de verificação de registro
        with patch.object(self.monitor, '_is_worker_registered', return_value=False):
            with patch.object(self.monitor, '_terminate_orphaned_worker') as mock_terminate:
                self.monitor._check_orphaned_workers()
                
                # Verifica se worker órfão foi terminado
                mock_terminate.assert_called_once_with(12345)
    
    @patch('app.celery_monitor.psutil.Process')
    def test_terminate_orphaned_worker(self, mock_process):
        """Testa terminação de worker órfão."""
        mock_process_instance = Mock()
        mock_process.return_value = mock_process_instance
        
        self.monitor._terminate_orphaned_worker(12345)
        
        mock_process_instance.terminate.assert_called_once()
        mock_process_instance.wait.assert_called_once_with(timeout=10)
    
    @patch('app.celery_monitor.redis.from_url')
    def test_get_active_tasks(self, mock_redis):
        """Testa obtenção de tasks ativas."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.keys.return_value = ['celery-task-meta-task1', 'celery-task-meta-task2']
        mock_redis_instance.get.side_effect = [
            '{"status": "PENDING", "timestamp": 1234567890}',
            '{"status": "SUCCESS", "timestamp": 1234567891}'
        ]
        mock_redis.return_value = mock_redis_instance
        
        self.monitor.redis_client = mock_redis_instance
        
        tasks = self.monitor._get_active_tasks()
        
        assert len(tasks) == 1  # Apenas task PENDING
        assert 'task1' in tasks
    
    def test_is_task_stuck(self):
        """Testa detecção de task stuck."""
        # Task recente (não stuck)
        recent_task = {
            'timestamp': time.time() - 60  # 1 minuto atrás
        }
        assert not self.monitor._is_task_stuck(recent_task)
        
        # Task antiga (stuck)
        old_task = {
            'timestamp': time.time() - 700  # Mais de 10 minutos atrás
        }
        assert self.monitor._is_task_stuck(old_task)
    
    @patch('app.celery_monitor.redis.from_url')
    def test_get_queue_metrics(self, mock_redis):
        """Testa obtenção de métricas da fila."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.llen.return_value = 25
        mock_redis_instance.lindex.return_value = 'task_data'
        mock_redis.return_value = mock_redis_instance
        
        self.monitor.redis_client = mock_redis_instance
        
        metrics = self.monitor._get_queue_metrics()
        
        assert metrics['size'] == 25
        assert metrics['oldest_task'] == 'task_data'
    
    def test_handle_stuck_task(self):
        """Testa tratamento de task stuck."""
        task_info = {'timestamp': time.time() - 700}
        
        with patch.object(self.monitor.celery_app.control, 'revoke') as mock_revoke:
            self.monitor._handle_stuck_task('task1', task_info)
            
            mock_revoke.assert_called_once_with('task1', terminate=True)
    
    def test_collect_metrics(self):
        """Testa coleta de métricas."""
        with patch.object(self.monitor, '_get_active_workers', return_value=['worker1']):
            with patch.object(self.monitor, '_get_queue_metrics', return_value={'size': 10}):
                with patch.object(self.monitor, '_get_active_tasks', return_value={'task1': {}}):
                    self.monitor._collect_metrics()
                    
                    assert len(self.monitor.metrics_history) > 0
                    latest_metrics = self.monitor.metrics_history[-1]
                    assert 'timestamp' in latest_metrics
                    assert 'workers' in latest_metrics
                    assert 'queue_size' in latest_metrics
    
    def test_get_health_status(self):
        """Testa obtenção de status de saúde."""
        with patch.object(self.monitor, '_get_active_workers', return_value=['worker1']):
            with patch.object(self.monitor, '_check_worker_health') as mock_check:
                mock_check.return_value = Mock(
                    name='worker1',
                    status='running',
                    pid=12345,
                    uptime=timedelta(hours=1),
                    memory_usage=2.5,
                    cpu_usage=1.2,
                    tasks_processed=10,
                    tasks_failed=1
                )
                
                with patch.object(self.monitor, '_get_queue_metrics', return_value={'size': 5}):
                    health = self.monitor.get_health_status()
                    
                    assert health['status'] == 'healthy'
                    assert len(health['workers']) == 1
                    assert health['workers'][0]['name'] == 'worker1'
                    assert health['workers'][0]['status'] == 'running'
    
    def test_start_stop_monitoring(self):
        """Testa início e parada do monitoramento."""
        # Inicia monitoramento
        self.monitor.start_monitoring()
        assert self.monitor.monitoring_thread is not None
        assert self.monitor.monitoring_thread.is_alive()
        
        # Para monitoramento
        self.monitor.stop_monitoring_service()
        assert self.monitor.stop_monitoring.is_set()

class TestCeleryMonitorIntegration:
    """Testes de integração para o monitor."""
    
    @patch('app.celery_monitor.redis.from_url')
    def test_monitoring_lifecycle(self, mock_redis):
        """Testa ciclo completo de monitoramento."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.ping.return_value = True
        mock_redis_instance.keys.return_value = []
        mock_redis_instance.exists.return_value = False
        mock_redis_instance.llen.return_value = 0
        mock_redis.return_value = mock_redis_instance
        
        monitor = CeleryMonitor()
        
        # Simula um ciclo de monitoramento
        with patch.object(monitor, '_healthcheck_workers') as mock_healthcheck:
            with patch.object(monitor, '_monitor_tasks') as mock_monitor:
                with patch.object(monitor, '_collect_metrics') as mock_collect:
                    monitor._monitoring_loop()
                    
                    mock_healthcheck.assert_called_once()
                    mock_monitor.assert_called_once()
                    mock_collect.assert_called_once()

class TestCeleryMonitorErrorHandling:
    """Testes para tratamento de erros."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        self.env_patcher = patch.dict(os.environ, {
            'CELERY_BROKER_URL': 'redis://localhost:6379/0'
        })
        self.env_patcher.start()
        self.monitor = CeleryMonitor()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        self.env_patcher.stop()
    
    @patch('app.celery_monitor.redis.from_url')
    def test_redis_connection_error(self, mock_redis):
        """Testa erro de conexão com Redis."""
        mock_redis.side_effect = Exception("Connection failed")
        
        monitor = CeleryMonitor()
        
        assert monitor.redis_client is None
    
    def test_worker_health_check_error(self):
        """Testa erro na verificação de saúde de worker."""
        with patch.object(self.monitor, '_get_active_workers', side_effect=Exception("Redis error")):
            workers = self.monitor._get_active_workers()
            assert workers == []
    
    def test_task_monitoring_error(self):
        """Testa erro no monitoramento de tasks."""
        with patch.object(self.monitor, '_get_active_tasks', side_effect=Exception("Task error")):
            tasks = self.monitor._get_active_tasks()
            assert tasks == {}

class TestCeleryMonitorFunctions:
    """Testes para funções de conveniência."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        self.env_patcher = patch.dict(os.environ, {
            'CELERY_BROKER_URL': 'redis://localhost:6379/0'
        })
        self.env_patcher.start()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        self.env_patcher.stop()
    
    @patch('app.celery_monitor.celery_monitor')
    def test_start_celery_monitoring(self, mock_monitor):
        """Testa função start_celery_monitoring."""
        start_celery_monitoring()
        mock_monitor.start_monitoring.assert_called_once()
    
    @patch('app.celery_monitor.celery_monitor')
    def test_stop_celery_monitoring(self, mock_monitor):
        """Testa função stop_celery_monitoring."""
        stop_celery_monitoring()
        mock_monitor.stop_monitoring_service.assert_called_once()
    
    @patch('app.celery_monitor.celery_monitor')
    def test_get_celery_health(self, mock_monitor):
        """Testa função get_celery_health."""
        mock_health = {'status': 'healthy'}
        mock_monitor.get_health_status.return_value = mock_health
        
        health = get_celery_health()
        assert health == mock_health
        mock_monitor.get_health_status.assert_called_once()
    
    @patch('app.celery_monitor.celery_monitor')
    def test_get_celery_metrics(self, mock_monitor):
        """Testa função get_celery_metrics."""
        mock_metrics = [{'timestamp': '2025-01-27T10:00:00'}]
        mock_monitor.get_metrics_history.return_value = mock_metrics
        
        metrics = get_celery_metrics()
        assert metrics == mock_metrics
        mock_monitor.get_metrics_history.assert_called_once()

if __name__ == '__main__':
    pytest.main([__file__]) 