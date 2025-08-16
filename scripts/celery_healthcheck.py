#!/usr/bin/env python3
"""
Script de Healthcheck para Celery - Omni Writer
===============================================

Script standalone para verificar saúde dos workers Celery e executar ações corretivas.

Prompt: Script de healthcheck para Celery
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import os
import sys
import time
import json
import logging
import subprocess
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Adiciona o diretório raiz ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.celery_monitor import CeleryMonitor

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [healthcheck] %(message)s',
    handlers=[
        logging.FileHandler('logs/exec_trace/celery_healthcheck.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CeleryHealthcheck:
    """
    Healthcheck standalone para Celery.
    
    Funcionalidades:
    - Verificação de saúde dos workers
    - Detecção de workers mortos
    - Restart automático de workers falhados
    - Relatório de status
    - Ações corretivas automáticas
    """
    
    def __init__(self):
        self.monitor = CeleryMonitor()
        self.health_status = {}
        self.corrections_applied = []
        
    def run_healthcheck(self) -> bool:
        """
        Executa healthcheck completo.
        
        Returns:
            True se sistema saudável
        """
        try:
            logger.info("=== INICIANDO HEALTHCHECK CELERY ===")
            
            # Passo 1: Verificar conectividade
            if not self._check_connectivity():
                logger.error("Falha na conectividade. Healthcheck abortado.")
                return False
            
            # Passo 2: Verificar workers
            workers_healthy = self._check_workers()
            
            # Passo 3: Verificar fila
            queue_healthy = self._check_queue()
            
            # Passo 4: Verificar tasks
            tasks_healthy = self._check_tasks()
            
            # Passo 5: Aplicar correções se necessário
            if not (workers_healthy and queue_healthy and tasks_healthy):
                self._apply_corrections()
            
            # Passo 6: Gerar relatório
            self._generate_report()
            
            overall_healthy = workers_healthy and queue_healthy and tasks_healthy
            status = "SAUDÁVEL" if overall_healthy else "PROBLEMAS DETECTADOS"
            
            logger.info(f"=== HEALTHCHECK CONCLUÍDO: {status} ===")
            return overall_healthy
            
        except Exception as e:
            logger.error(f"Erro durante healthcheck: {e}")
            return False
    
    def _check_connectivity(self) -> bool:
        """Verifica conectividade com Redis e Celery."""
        try:
            logger.info("Verificando conectividade...")
            
            # Testa Redis
            if not self.monitor.redis_client:
                logger.error("Redis não disponível")
                return False
            
            self.monitor.redis_client.ping()
            logger.info("✓ Redis conectado")
            
            # Testa Celery
            try:
                self.monitor.celery_app.control.inspect().active()
                logger.info("✓ Celery conectado")
            except Exception as e:
                logger.warning(f"Celery não respondeu: {e}")
                # Não é fatal, pode ser que não há workers ativos
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na verificação de conectividade: {e}")
            return False
    
    def _check_workers(self) -> bool:
        """Verifica saúde dos workers."""
        try:
            logger.info("Verificando workers...")
            
            active_workers = self.monitor._get_active_workers()
            if not active_workers:
                logger.warning("Nenhum worker ativo encontrado")
                return False
            
            healthy_workers = 0
            total_workers = len(active_workers)
            
            for worker_name in active_workers:
                status = self.monitor._check_worker_health(worker_name)
                
                if status.status == 'running':
                    healthy_workers += 1
                    logger.info(f"✓ Worker {worker_name} saudável (PID: {status.pid})")
                else:
                    logger.warning(f"✗ Worker {worker_name} com problema: {status.status}")
            
            health_ratio = healthy_workers / total_workers if total_workers > 0 else 0
            logger.info(f"Workers: {healthy_workers}/{total_workers} saudáveis ({health_ratio:.1%})")
            
            return health_ratio >= 0.5  # Pelo menos 50% dos workers saudáveis
            
        except Exception as e:
            logger.error(f"Erro na verificação de workers: {e}")
            return False
    
    def _check_queue(self) -> bool:
        """Verifica saúde da fila."""
        try:
            logger.info("Verificando fila...")
            
            queue_metrics = self.monitor._get_queue_metrics()
            queue_size = queue_metrics['size']
            
            if queue_size == 0:
                logger.info("✓ Fila vazia")
                return True
            elif queue_size < 50:
                logger.info(f"✓ Fila normal: {queue_size} tasks")
                return True
            elif queue_size < 200:
                logger.warning(f"⚠ Fila grande: {queue_size} tasks")
                return True
            else:
                logger.error(f"✗ Fila crítica: {queue_size} tasks")
                return False
            
        except Exception as e:
            logger.error(f"Erro na verificação da fila: {e}")
            return False
    
    def _check_tasks(self) -> bool:
        """Verifica tasks em execução."""
        try:
            logger.info("Verificando tasks...")
            
            active_tasks = self.monitor._get_active_tasks()
            stuck_tasks = 0
            
            for task_id, task_info in active_tasks.items():
                if self.monitor._is_task_stuck(task_info):
                    stuck_tasks += 1
                    logger.warning(f"Task stuck: {task_id}")
            
            if stuck_tasks == 0:
                logger.info(f"✓ {len(active_tasks)} tasks ativas, nenhuma stuck")
                return True
            else:
                logger.warning(f"⚠ {stuck_tasks} tasks stuck de {len(active_tasks)} ativas")
                return stuck_tasks < len(active_tasks) * 0.3  # Menos de 30% stuck
            
        except Exception as e:
            logger.error(f"Erro na verificação de tasks: {e}")
            return False
    
    def _apply_corrections(self):
        """Aplica correções automáticas."""
        try:
            logger.info("Aplicando correções...")
            
            # Correção 1: Restart de workers falhados
            self._restart_failed_workers()
            
            # Correção 2: Limpeza de tasks stuck
            self._cleanup_stuck_tasks()
            
            # Correção 3: Limpeza de workers órfãos
            self._cleanup_orphaned_workers()
            
            logger.info("Correções aplicadas")
            
        except Exception as e:
            logger.error(f"Erro ao aplicar correções: {e}")
    
    def _restart_failed_workers(self):
        """Reinicia workers falhados."""
        try:
            active_workers = self.monitor._get_active_workers()
            
            for worker_name in active_workers:
                status = self.monitor._check_worker_health(worker_name)
                
                if status.status != 'running':
                    logger.info(f"Reiniciando worker falhado: {worker_name}")
                    self.monitor._restart_worker(worker_name)
                    self.corrections_applied.append(f"Restart worker: {worker_name}")
            
        except Exception as e:
            logger.error(f"Erro ao reiniciar workers: {e}")
    
    def _cleanup_stuck_tasks(self):
        """Limpa tasks stuck."""
        try:
            active_tasks = self.monitor._get_active_tasks()
            
            for task_id, task_info in active_tasks.items():
                if self.monitor._is_task_stuck(task_info):
                    logger.info(f"Revogando task stuck: {task_id}")
                    self.monitor._handle_stuck_task(task_id, task_info)
                    self.corrections_applied.append(f"Revogar task: {task_id}")
            
        except Exception as e:
            logger.error(f"Erro ao limpar tasks stuck: {e}")
    
    def _cleanup_orphaned_workers(self):
        """Limpa workers órfãos."""
        try:
            self.monitor._check_orphaned_workers()
            self.corrections_applied.append("Limpeza workers órfãos")
            
        except Exception as e:
            logger.error(f"Erro ao limpar workers órfãos: {e}")
    
    def _generate_report(self):
        """Gera relatório de healthcheck."""
        try:
            health_status = self.monitor.get_health_status()
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'health_status': health_status,
                'corrections_applied': self.corrections_applied,
                'summary': {
                    'workers_healthy': health_status['status'] == 'healthy',
                    'queue_size': health_status.get('queue', {}).get('size', 0),
                    'total_workers': len(health_status.get('workers', [])),
                    'active_workers': len([w for w in health_status.get('workers', []) if w['status'] == 'running'])
                }
            }
            
            # Salva relatório
            report_file = f"logs/exec_trace/celery_healthcheck_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs(os.path.dirname(report_file), exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"Relatório salvo: {report_file}")
            
            # Log resumido
            summary = report['summary']
            logger.info(f"Resumo: {summary['active_workers']}/{summary['total_workers']} workers ativos, "
                       f"fila: {summary['queue_size']} tasks")
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
    
    def start_monitoring_mode(self, interval: int = 60):
        """
        Inicia modo de monitoramento contínuo.
        
        Args:
            interval: Intervalo entre healthchecks em segundos
        """
        logger.info(f"Iniciando monitoramento contínuo (intervalo: {interval}s)")
        
        def signal_handler(signum, frame):
            logger.info("Sinal de parada recebido. Parando monitoramento...")
            sys.exit(0)
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while True:
                self.run_healthcheck()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info("Monitoramento interrompido pelo usuário")
        except Exception as e:
            logger.error(f"Erro no monitoramento: {e}")

def main():
    """Função principal do script."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Healthcheck para Celery')
    parser.add_argument('--monitor', action='store_true', help='Modo monitoramento contínuo')
    parser.add_argument('--interval', type=int, default=60, help='Intervalo em segundos (modo monitor)')
    parser.add_argument('--json', action='store_true', help='Saída em formato JSON')
    
    args = parser.parse_args()
    
    try:
        healthcheck = CeleryHealthcheck()
        
        if args.monitor:
            healthcheck.start_monitoring_mode(args.interval)
        else:
            success = healthcheck.run_healthcheck()
            
            if args.json:
                result = {
                    'success': success,
                    'timestamp': datetime.now().isoformat(),
                    'health_status': healthcheck.monitor.get_health_status()
                }
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                exit_code = 0 if success else 1
                sys.exit(exit_code)
                
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        if args.json:
            result = {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            sys.exit(1)

if __name__ == '__main__':
    main() 