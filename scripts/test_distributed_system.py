#!/usr/bin/env python3
"""
Script para testar o sistema distribuído com Celery e Redis.
Valida funcionalidade das filas, workers e monitoramento.
"""
import os
import sys
import time
import json
import logging
from datetime import datetime
from typing import Dict, List
import redis
import requests

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DistributedSystemTester:
    """Classe para testar o sistema distribuído."""
    
    def __init__(self):
        """Inicializa o testador."""
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.app_url = os.getenv('APP_URL', 'http://localhost:5000')
        self.redis_client = None
        self.test_results = []
        
    def connect_redis(self) -> bool:
        """Conecta ao Redis."""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            self.redis_client.ping()
            logger.info("✅ Conexão com Redis estabelecida")
            return True
        except Exception as e:
            logger.error(f"❌ Erro ao conectar com Redis: {e}")
            return False
    
    def test_redis_queues(self) -> Dict:
        """Testa as filas Redis."""
        logger.info("🧪 Testando filas Redis...")
        
        try:
            # Verifica filas existentes
            queue_names = ['high_priority', 'default', 'low_priority']
            queue_status = {}
            
            for queue_name in queue_names:
                queue_key = f'celery:{queue_name}'
                queue_size = self.redis_client.llen(queue_key)
                queue_status[queue_name] = {
                    'size': queue_size,
                    'exists': True
                }
                logger.info(f"  📊 Fila {queue_name}: {queue_size} tarefas")
            
            # Testa inserção de tarefa de teste
            test_task = {
                'task': 'app.tasks.monitoring_tasks.health_check',
                'args': [],
                'kwargs': {},
                'id': f'test-{int(time.time())}'
            }
            
            self.redis_client.lpush('celery:default', json.dumps(test_task))
            logger.info("  ✅ Tarefa de teste inserida na fila default")
            
            return {
                'status': 'success',
                'queues': queue_status,
                'test_task_inserted': True
            }
            
        except Exception as e:
            logger.error(f"❌ Erro ao testar filas Redis: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def test_celery_workers(self) -> Dict:
        """Testa workers do Celery."""
        logger.info("🧪 Testando workers Celery...")
        
        try:
            # Verifica workers ativos
            active_workers = self.redis_client.smembers('celery:active')
            worker_count = len(active_workers)
            
            logger.info(f"  👥 Workers ativos: {worker_count}")
            for worker in active_workers:
                logger.info(f"    - {worker.decode()}")
            
            # Verifica workers registrados
            registered_workers = self.redis_client.smembers('celery:registered')
            registered_count = len(registered_workers)
            
            logger.info(f"  📝 Workers registrados: {registered_count}")
            
            return {
                'status': 'success',
                'active_workers': worker_count,
                'registered_workers': registered_count,
                'worker_names': [w.decode() for w in active_workers]
            }
            
        except Exception as e:
            logger.error(f"❌ Erro ao testar workers Celery: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def test_application_health(self) -> Dict:
        """Testa saúde da aplicação."""
        logger.info("🧪 Testando saúde da aplicação...")
        
        try:
            # Testa endpoint de health
            health_url = f"{self.app_url}/health"
            response = requests.get(health_url, timeout=10)
            
            if response.status_code == 200:
                health_data = response.json()
                logger.info(f"  ✅ Aplicação saudável: {health_data.get('status', 'unknown')}")
                return {
                    'status': 'success',
                    'app_health': health_data,
                    'response_time': response.elapsed.total_seconds()
                }
            else:
                logger.warning(f"  ⚠️ Status da aplicação: {response.status_code}")
                return {
                    'status': 'warning',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erro ao testar aplicação: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def test_metrics_endpoint(self) -> Dict:
        """Testa endpoint de métricas Prometheus."""
        logger.info("🧪 Testando endpoint de métricas...")
        
        try:
            metrics_url = f"{self.app_url}/metrics"
            response = requests.get(metrics_url, timeout=10)
            
            if response.status_code == 200:
                metrics_content = response.text
                metric_lines = len(metrics_content.split('\n'))
                logger.info(f"  ✅ Métricas disponíveis: {metric_lines} linhas")
                
                # Verifica métricas específicas
                has_celery_metrics = 'celery_tasks_total' in metrics_content
                has_system_metrics = 'system_metrics' in metrics_content
                
                return {
                    'status': 'success',
                    'metric_lines': metric_lines,
                    'has_celery_metrics': has_celery_metrics,
                    'has_system_metrics': has_system_metrics
                }
            else:
                logger.warning(f"  ⚠️ Endpoint de métricas: {response.status_code}")
                return {
                    'status': 'warning',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erro ao testar métricas: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def test_task_execution(self) -> Dict:
        """Testa execução de tarefas."""
        logger.info("🧪 Testando execução de tarefas...")
        
        try:
            # Envia tarefa de teste via API
            task_url = f"{self.app_url}/api/test-task"
            task_data = {
                'task_type': 'health_check',
                'priority': 'default'
            }
            
            response = requests.post(task_url, json=task_data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"  ✅ Tarefa executada: {result.get('task_id', 'unknown')}")
                return {
                    'status': 'success',
                    'task_id': result.get('task_id'),
                    'execution_time': result.get('duration', 0)
                }
            else:
                logger.warning(f"  ⚠️ Execução de tarefa: {response.status_code}")
                return {
                    'status': 'warning',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erro ao testar execução de tarefas: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def test_monitoring_services(self) -> Dict:
        """Testa serviços de monitoramento."""
        logger.info("🧪 Testando serviços de monitoramento...")
        
        services = {
            'prometheus': 'http://localhost:9090',
            'grafana': 'http://localhost:3000',
            'flower': 'http://localhost:5555'
        }
        
        results = {}
        
        for service_name, service_url in services.items():
            try:
                response = requests.get(service_url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"  ✅ {service_name}: Disponível")
                    results[service_name] = 'available'
                else:
                    logger.warning(f"  ⚠️ {service_name}: Status {response.status_code}")
                    results[service_name] = f'status_{response.status_code}'
            except requests.exceptions.RequestException:
                logger.warning(f"  ⚠️ {service_name}: Indisponível")
                results[service_name] = 'unavailable'
        
        return {
            'status': 'success',
            'services': results
        }
    
    def run_all_tests(self) -> Dict:
        """Executa todos os testes."""
        logger.info("🚀 Iniciando testes do sistema distribuído...")
        
        start_time = time.time()
        
        # Conecta ao Redis
        if not self.connect_redis():
            return {'status': 'error', 'message': 'Falha na conexão com Redis'}
        
        # Executa testes
        tests = [
            ('redis_queues', self.test_redis_queues),
            ('celery_workers', self.test_celery_workers),
            ('app_health', self.test_application_health),
            ('metrics', self.test_metrics_endpoint),
            ('task_execution', self.test_task_execution),
            ('monitoring', self.test_monitoring_services)
        ]
        
        results = {}
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, test_func in tests:
            logger.info(f"\n📋 Executando teste: {test_name}")
            try:
                result = test_func()
                results[test_name] = result
                
                if result.get('status') == 'success':
                    passed_tests += 1
                    logger.info(f"  ✅ Teste {test_name} passou")
                else:
                    logger.warning(f"  ⚠️ Teste {test_name} falhou: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                logger.error(f"  ❌ Erro no teste {test_name}: {e}")
                results[test_name] = {
                    'status': 'error',
                    'error': str(e)
                }
        
        # Gera relatório
        duration = time.time() - start_time
        success_rate = (passed_tests / total_tests) * 100
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'duration': round(duration, 2),
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'success_rate': round(success_rate, 2),
            'overall_status': 'success' if success_rate >= 80 else 'warning' if success_rate >= 50 else 'error',
            'results': results
        }
        
        # Salva relatório
        report_file = f"test_results_distributed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Exibe resumo
        logger.info(f"\n📊 RESUMO DOS TESTES:")
        logger.info(f"  ⏱️  Duração: {duration:.2f}s")
        logger.info(f"  ✅ Testes passaram: {passed_tests}/{total_tests}")
        logger.info(f"  📈 Taxa de sucesso: {success_rate:.1f}%")
        logger.info(f"  📄 Relatório salvo: {report_file}")
        
        if success_rate >= 80:
            logger.info("🎉 Sistema distribuído funcionando corretamente!")
        elif success_rate >= 50:
            logger.warning("⚠️ Sistema distribuído com problemas menores")
        else:
            logger.error("❌ Sistema distribuído com problemas críticos")
        
        return report

def main():
    """Função principal."""
    tester = DistributedSystemTester()
    report = tester.run_all_tests()
    
    # Retorna código de saída baseado no status
    if report['overall_status'] == 'success':
        sys.exit(0)
    elif report['overall_status'] == 'warning':
        sys.exit(1)
    else:
        sys.exit(2)

if __name__ == '__main__':
    main() 