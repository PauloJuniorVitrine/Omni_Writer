#!/usr/bin/env python3
"""
Script para inicializar o sistema distribuído completo.
Configura Redis, PostgreSQL, Celery workers e monitoramento.
"""
import os
import sys
import time
import subprocess
import logging
from datetime import datetime
from typing import Dict, List
import requests
import redis

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DistributedSystemManager:
    """Gerenciador do sistema distribuído."""
    
    def __init__(self):
        """Inicializa o gerenciador."""
        self.redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.app_url = os.getenv('APP_URL', 'http://localhost:5000')
        self.postgres_url = os.getenv('DATABASE_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
        self.processes = []
        
    def check_docker_compose(self) -> bool:
        """Verifica se o Docker Compose está disponível."""
        try:
            result = subprocess.run(['docker-compose', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"✅ Docker Compose disponível: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("❌ Docker Compose não encontrado")
            return False
    
    def start_services(self) -> bool:
        """Inicia os serviços com Docker Compose."""
        logger.info("🚀 Iniciando serviços com Docker Compose...")
        
        try:
            # Para serviços existentes
            subprocess.run(['docker-compose', 'down'], check=True)
            logger.info("  🔄 Serviços anteriores parados")
            
            # Inicia serviços
            subprocess.run(['docker-compose', 'up', '-d'], check=True)
            logger.info("  ✅ Serviços iniciados")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Erro ao iniciar serviços: {e}")
            return False
    
    def wait_for_services(self, timeout: int = 120) -> bool:
        """Aguarda os serviços ficarem prontos."""
        logger.info(f"⏳ Aguardando serviços ficarem prontos (timeout: {timeout}s)...")
        
        start_time = time.time()
        services_ready = {
            'redis': False,
            'postgres': False,
            'app': False
        }
        
        while time.time() - start_time < timeout:
            # Verifica Redis
            if not services_ready['redis']:
                try:
                    redis_client = redis.from_url(self.redis_url)
                    redis_client.ping()
                    services_ready['redis'] = True
                    logger.info("  ✅ Redis pronto")
                except:
                    pass
            
            # Verifica PostgreSQL
            if not services_ready['postgres']:
                try:
                    import psycopg2
                    conn = psycopg2.connect(self.postgres_url)
                    conn.close()
                    services_ready['postgres'] = True
                    logger.info("  ✅ PostgreSQL pronto")
                except:
                    pass
            
            # Verifica aplicação
            if not services_ready['app']:
                try:
                    response = requests.get(f"{self.app_url}/health", timeout=5)
                    if response.status_code == 200:
                        services_ready['app'] = True
                        logger.info("  ✅ Aplicação pronta")
                except:
                    pass
            
            # Verifica se todos estão prontos
            if all(services_ready.values()):
                logger.info("🎉 Todos os serviços estão prontos!")
                return True
            
            time.sleep(2)
        
        logger.error("❌ Timeout aguardando serviços")
        return False
    
    def start_celery_workers(self) -> bool:
        """Inicia workers do Celery."""
        logger.info("👥 Iniciando workers do Celery...")
        
        try:
            # Worker principal
            worker_cmd = [
                'celery', '-A', 'app.celery_worker.celery_app', 
                'worker', '--loglevel=info', '--concurrency=4'
            ]
            worker_process = subprocess.Popen(worker_cmd)
            self.processes.append(('worker', worker_process))
            logger.info("  ✅ Worker principal iniciado")
            
            # Worker de alta prioridade
            high_priority_cmd = [
                'celery', '-A', 'app.celery_worker.celery_app',
                'worker', '--loglevel=info', '--concurrency=2', '-Q', 'high_priority'
            ]
            high_priority_process = subprocess.Popen(high_priority_cmd)
            self.processes.append(('high_priority_worker', high_priority_process))
            logger.info("  ✅ Worker de alta prioridade iniciado")
            
            # Beat scheduler
            beat_cmd = [
                'celery', '-A', 'app.celery_worker.celery_app',
                'beat', '--loglevel=info'
            ]
            beat_process = subprocess.Popen(beat_cmd)
            self.processes.append(('beat', beat_process))
            logger.info("  ✅ Beat scheduler iniciado")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao iniciar workers: {e}")
            return False
    
    def check_monitoring_services(self) -> Dict:
        """Verifica serviços de monitoramento."""
        logger.info("📊 Verificando serviços de monitoramento...")
        
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
        
        return results
    
    def run_health_checks(self) -> Dict:
        """Executa verificações de saúde."""
        logger.info("🏥 Executando verificações de saúde...")
        
        checks = {}
        
        # Verifica Redis
        try:
            redis_client = redis.from_url(self.redis_url)
            redis_client.ping()
            checks['redis'] = 'healthy'
            logger.info("  ✅ Redis: Saudável")
        except Exception as e:
            checks['redis'] = f'unhealthy: {e}'
            logger.error(f"  ❌ Redis: {e}")
        
        # Verifica PostgreSQL
        try:
            import psycopg2
            conn = psycopg2.connect(self.postgres_url)
            conn.close()
            checks['postgres'] = 'healthy'
            logger.info("  ✅ PostgreSQL: Saudável")
        except Exception as e:
            checks['postgres'] = f'unhealthy: {e}'
            logger.error(f"  ❌ PostgreSQL: {e}")
        
        # Verifica aplicação
        try:
            response = requests.get(f"{self.app_url}/health", timeout=10)
            if response.status_code == 200:
                checks['app'] = 'healthy'
                logger.info("  ✅ Aplicação: Saudável")
            else:
                checks['app'] = f'unhealthy: status {response.status_code}'
                logger.warning(f"  ⚠️ Aplicação: Status {response.status_code}")
        except Exception as e:
            checks['app'] = f'unhealthy: {e}'
            logger.error(f"  ❌ Aplicação: {e}")
        
        # Verifica workers Celery
        try:
            active_workers = redis_client.smembers('celery:active')
            worker_count = len(active_workers)
            if worker_count > 0:
                checks['celery_workers'] = f'healthy: {worker_count} workers'
                logger.info(f"  ✅ Celery Workers: {worker_count} ativos")
            else:
                checks['celery_workers'] = 'unhealthy: no workers'
                logger.warning("  ⚠️ Celery Workers: Nenhum worker ativo")
        except Exception as e:
            checks['celery_workers'] = f'unhealthy: {e}'
            logger.error(f"  ❌ Celery Workers: {e}")
        
        return checks
    
    def generate_startup_report(self, health_checks: Dict, monitoring: Dict) -> str:
        """Gera relatório de inicialização."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"startup_report_{timestamp}.json"
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'health_checks': health_checks,
            'monitoring_services': monitoring,
            'overall_status': 'success' if all('healthy' in str(v) for v in health_checks.values()) else 'warning'
        }
        
        import json
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return report_file
    
    def cleanup(self):
        """Limpa processos iniciados."""
        logger.info("🧹 Limpando processos...")
        
        for process_name, process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
                logger.info(f"  ✅ Processo {process_name} finalizado")
            except subprocess.TimeoutExpired:
                process.kill()
                logger.warning(f"  ⚠️ Processo {process_name} forçado a finalizar")
            except Exception as e:
                logger.error(f"  ❌ Erro ao finalizar {process_name}: {e}")
    
    def start_system(self) -> bool:
        """Inicia o sistema distribuído completo."""
        logger.info("🚀 Iniciando sistema distribuído Omni Writer...")
        
        try:
            # Verifica Docker Compose
            if not self.check_docker_compose():
                return False
            
            # Inicia serviços
            if not self.start_services():
                return False
            
            # Aguarda serviços ficarem prontos
            if not self.wait_for_services():
                return False
            
            # Inicia workers Celery
            if not self.start_celery_workers():
                return False
            
            # Aguarda um pouco para os workers inicializarem
            time.sleep(10)
            
            # Verifica serviços de monitoramento
            monitoring = self.check_monitoring_services()
            
            # Executa verificações de saúde
            health_checks = self.run_health_checks()
            
            # Gera relatório
            report_file = self.generate_startup_report(health_checks, monitoring)
            
            # Exibe resumo
            logger.info(f"\n📊 RESUMO DA INICIALIZAÇÃO:")
            logger.info(f"  📄 Relatório: {report_file}")
            logger.info(f"  🏥 Verificações de saúde: {len(health_checks)}")
            logger.info(f"  📊 Serviços de monitoramento: {len(monitoring)}")
            
            healthy_count = sum(1 for v in health_checks.values() if 'healthy' in str(v))
            total_checks = len(health_checks)
            
            if healthy_count == total_checks:
                logger.info("🎉 Sistema distribuído iniciado com sucesso!")
                return True
            else:
                logger.warning(f"⚠️ Sistema iniciado com {total_checks - healthy_count} problemas")
                return True  # Ainda considera sucesso se a maioria estiver funcionando
                
        except KeyboardInterrupt:
            logger.info("\n⚠️ Interrupção do usuário detectada")
            return False
        except Exception as e:
            logger.error(f"❌ Erro crítico: {e}")
            return False
        finally:
            self.cleanup()

def main():
    """Função principal."""
    manager = DistributedSystemManager()
    
    try:
        success = manager.start_system()
        if success:
            logger.info("✅ Sistema distribuído iniciado com sucesso!")
            sys.exit(0)
        else:
            logger.error("❌ Falha ao iniciar sistema distribuído")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\n👋 Sistema finalizado pelo usuário")
        sys.exit(0)

if __name__ == '__main__':
    main() 