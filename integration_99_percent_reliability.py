"""
Integração Completa para 99% de Confiabilidade - Omni Writer
==========================================================

Script principal que integra todos os componentes para atingir 99% de confiabilidade.
Baseado em análise do código real e padrões enterprise.

Prompt: Integração Completa para 99% de Confiabilidade
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-28T11:00:00Z
Tracing ID: INTEGRATION_99_PERCENT_20250128_001
"""

import asyncio
import logging
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import subprocess
import threading
import signal

# Importa os sistemas de confiabilidade
from health_checks_advanced import health_checker, run_health_checks
from circuit_breaker_advanced import circuit_breaker_manager
from proactive_monitoring_system import proactive_monitoring, start_proactive_monitoring, stop_proactive_monitoring

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler('logs/reliability_integration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("reliability_integration")

class ReliabilityIntegrationManager:
    """
    Gerenciador de integração para 99% de confiabilidade.
    
    Funcionalidades:
    - Integração de todos os sistemas de confiabilidade
    - Verificação de dependências
    - Testes de validação
    - Métricas agregadas
    - Relatórios de status
    """
    
    def __init__(self):
        self.integration_status = {
            'health_checks': False,
            'circuit_breakers': False,
            'proactive_monitoring': False,
            'system_validation': False
        }
        self.start_time = None
        self.metrics_history = []
        self.validation_results = []
        
        # Configurações
        self.validation_interval = 60  # segundos
        self.max_validation_history = 100
        
        logger.info("Reliability Integration Manager inicializado")
    
    async def initialize_all_systems(self) -> bool:
        """Inicializa todos os sistemas de confiabilidade"""
        logger.info("Iniciando inicialização de todos os sistemas de confiabilidade")
        
        try:
            # 1. Inicializa health checks
            logger.info("1. Inicializando sistema de health checks...")
            await self._initialize_health_checks()
            
            # 2. Inicializa circuit breakers
            logger.info("2. Inicializando sistema de circuit breakers...")
            await self._initialize_circuit_breakers()
            
            # 3. Inicializa monitoramento proativo
            logger.info("3. Inicializando sistema de monitoramento proativo...")
            await self._initialize_proactive_monitoring()
            
            # 4. Validação inicial do sistema
            logger.info("4. Executando validação inicial do sistema...")
            await self._validate_system_initial_state()
            
            self.start_time = datetime.utcnow()
            logger.info("✅ Todos os sistemas de confiabilidade inicializados com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na inicialização: {e}")
            return False
    
    async def _initialize_health_checks(self):
        """Inicializa sistema de health checks"""
        try:
            # Executa health check inicial
            initial_results = await run_health_checks()
            
            # Verifica se todos os componentes críticos estão saudáveis
            critical_components = ['database', 'redis', 'file_system']
            unhealthy_components = []
            
            for component in critical_components:
                if component in initial_results:
                    result = initial_results[component]
                    if result.status.value != 'healthy':
                        unhealthy_components.append(component)
            
            if unhealthy_components:
                logger.warning(f"Componentes não saudáveis detectados: {unhealthy_components}")
                # Em produção, isso poderia disparar alertas ou ações corretivas
            
            self.integration_status['health_checks'] = True
            logger.info("✅ Sistema de health checks inicializado")
            
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar health checks: {e}")
            raise
    
    async def _initialize_circuit_breakers(self):
        """Inicializa sistema de circuit breakers"""
        try:
            # Verifica se os circuit breakers estão configurados
            cb_metrics = circuit_breaker_manager.get_all_metrics()
            
            if cb_metrics['total_circuit_breakers'] == 0:
                logger.warning("Nenhum circuit breaker configurado")
            else:
                logger.info(f"Circuit breakers configurados: {cb_metrics['total_circuit_breakers']}")
            
            self.integration_status['circuit_breakers'] = True
            logger.info("✅ Sistema de circuit breakers inicializado")
            
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar circuit breakers: {e}")
            raise
    
    async def _initialize_proactive_monitoring(self):
        """Inicializa sistema de monitoramento proativo"""
        try:
            # Inicia monitoramento proativo
            start_proactive_monitoring()
            
            # Aguarda um pouco para o sistema estabilizar
            await asyncio.sleep(5)
            
            # Verifica se o monitoramento está ativo
            monitoring_metrics = proactive_monitoring.get_metrics()
            if monitoring_metrics['monitoring_active']:
                self.integration_status['proactive_monitoring'] = True
                logger.info("✅ Sistema de monitoramento proativo inicializado")
            else:
                raise Exception("Monitoramento proativo não está ativo")
                
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar monitoramento proativo: {e}")
            raise
    
    async def _validate_system_initial_state(self):
        """Valida estado inicial do sistema"""
        try:
            # Executa validações básicas
            validations = [
                ("Health Checks Ativos", await self._validate_health_checks()),
                ("Circuit Breakers Configurados", await self._validate_circuit_breakers()),
                ("Monitoramento Proativo Ativo", await self._validate_proactive_monitoring()),
                ("Recursos do Sistema", await self._validate_system_resources()),
                ("Configurações de Ambiente", await self._validate_environment_config())
            ]
            
            failed_validations = [name for name, success in validations if not success]
            
            if failed_validations:
                logger.warning(f"Validações falharam: {failed_validations}")
                self.integration_status['system_validation'] = False
            else:
                self.integration_status['system_validation'] = True
                logger.info("✅ Validação inicial do sistema concluída com sucesso")
            
        except Exception as e:
            logger.error(f"❌ Erro na validação inicial: {e}")
            self.integration_status['system_validation'] = False
    
    async def _validate_health_checks(self) -> bool:
        """Valida sistema de health checks"""
        try:
            results = await run_health_checks()
            overall_status, details = health_checker.get_overall_health_status()
            
            if overall_status.value == 'healthy':
                return True
            elif overall_status.value == 'degraded':
                logger.warning("Sistema em estado degradado")
                return True  # Ainda funcional
            else:
                logger.error("Sistema em estado crítico")
                return False
                
        except Exception as e:
            logger.error(f"Erro na validação de health checks: {e}")
            return False
    
    async def _validate_circuit_breakers(self) -> bool:
        """Valida sistema de circuit breakers"""
        try:
            metrics = circuit_breaker_manager.get_all_metrics()
            health_status = circuit_breaker_manager.get_health_status()
            
            if health_status['status'] in ['healthy', 'degraded']:
                return True
            else:
                logger.error("Circuit breakers em estado crítico")
                return False
                
        except Exception as e:
            logger.error(f"Erro na validação de circuit breakers: {e}")
            return False
    
    async def _validate_proactive_monitoring(self) -> bool:
        """Valida sistema de monitoramento proativo"""
        try:
            metrics = proactive_monitoring.get_metrics()
            health_status = proactive_monitoring.get_health_status()
            
            if metrics['monitoring_active'] and health_status['status'] != 'critical':
                return True
            else:
                logger.error("Monitoramento proativo não está funcionando corretamente")
                return False
                
        except Exception as e:
            logger.error(f"Erro na validação de monitoramento proativo: {e}")
            return False
    
    async def _validate_system_resources(self) -> bool:
        """Valida recursos do sistema"""
        try:
            import psutil
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 95:
                logger.warning(f"CPU muito alta: {cpu_percent}%")
                return False
            
            # Memória
            memory = psutil.virtual_memory()
            if memory.percent > 95:
                logger.warning(f"Memória muito alta: {memory.percent}%")
                return False
            
            # Disco
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > 95:
                logger.warning(f"Disco muito cheio: {disk_percent}%")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação de recursos: {e}")
            return False
    
    async def _validate_environment_config(self) -> bool:
        """Valida configurações de ambiente"""
        try:
            required_vars = [
                'FLASK_SECRET_KEY',
                'REDIS_URL',
                'DATABASE_URL'
            ]
            
            missing_vars = []
            for var in required_vars:
                if not os.getenv(var):
                    missing_vars.append(var)
            
            if missing_vars:
                logger.warning(f"Variáveis de ambiente ausentes: {missing_vars}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro na validação de ambiente: {e}")
            return False
    
    async def run_continuous_monitoring(self):
        """Executa monitoramento contínuo"""
        logger.info("Iniciando monitoramento contínuo")
        
        while True:
            try:
                # Coleta métricas de todos os sistemas
                metrics = await self._collect_all_metrics()
                self.metrics_history.append(metrics)
                
                # Mantém apenas histórico recente
                if len(self.metrics_history) > self.max_validation_history:
                    self.metrics_history = self.metrics_history[-self.max_validation_history:]
                
                # Executa validações periódicas
                validation_result = await self._run_periodic_validations()
                self.validation_results.append(validation_result)
                
                # Mantém apenas histórico recente de validações
                if len(self.validation_results) > self.max_validation_history:
                    self.validation_results = self.validation_results[-self.max_validation_history:]
                
                # Log de status
                self._log_current_status(metrics, validation_result)
                
                # Aguarda próximo ciclo
                await asyncio.sleep(self.validation_interval)
                
            except Exception as e:
                logger.error(f"Erro no monitoramento contínuo: {e}")
                await asyncio.sleep(10)  # Espera antes de tentar novamente
    
    async def _collect_all_metrics(self) -> Dict:
        """Coleta métricas de todos os sistemas"""
        timestamp = datetime.utcnow()
        
        try:
            # Health checks
            health_results = await run_health_checks()
            health_status, health_details = health_checker.get_overall_health_status()
            health_metrics = health_checker.get_health_metrics()
            
            # Circuit breakers
            cb_metrics = circuit_breaker_manager.get_all_metrics()
            cb_health = circuit_breaker_manager.get_health_status()
            
            # Monitoramento proativo
            monitoring_metrics = proactive_monitoring.get_metrics()
            monitoring_health = proactive_monitoring.get_health_status()
            
            # Recursos do sistema
            import psutil
            system_metrics = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
            }
            
            return {
                'timestamp': timestamp.isoformat(),
                'health_checks': {
                    'status': health_status.value,
                    'details': health_details,
                    'metrics': health_metrics
                },
                'circuit_breakers': {
                    'status': cb_health['status'],
                    'metrics': cb_metrics
                },
                'proactive_monitoring': {
                    'status': monitoring_health['status'],
                    'metrics': monitoring_metrics
                },
                'system_resources': system_metrics,
                'integration_status': self.integration_status
            }
            
        except Exception as e:
            logger.error(f"Erro ao coletar métricas: {e}")
            return {
                'timestamp': timestamp.isoformat(),
                'error': str(e)
            }
    
    async def _run_periodic_validations(self) -> Dict:
        """Executa validações periódicas"""
        timestamp = datetime.utcnow()
        
        try:
            validations = [
                ("health_checks", await self._validate_health_checks()),
                ("circuit_breakers", await self._validate_circuit_breakers()),
                ("proactive_monitoring", await self._validate_proactive_monitoring()),
                ("system_resources", await self._validate_system_resources())
            ]
            
            success_count = sum(1 for _, success in validations if success)
            total_count = len(validations)
            
            return {
                'timestamp': timestamp.isoformat(),
                'success_rate': success_count / total_count if total_count > 0 else 0,
                'validations': dict(validations),
                'overall_success': success_count == total_count
            }
            
        except Exception as e:
            logger.error(f"Erro nas validações periódicas: {e}")
            return {
                'timestamp': timestamp.isoformat(),
                'error': str(e),
                'overall_success': False
            }
    
    def _log_current_status(self, metrics: Dict, validation: Dict):
        """Log do status atual"""
        if 'error' in metrics:
            logger.error(f"Erro na coleta de métricas: {metrics['error']}")
            return
        
        # Status geral
        health_status = metrics['health_checks']['status']
        cb_status = metrics['circuit_breakers']['status']
        monitoring_status = metrics['proactive_monitoring']['status']
        validation_success = validation.get('overall_success', False)
        
        # Determina status geral
        if all(status in ['healthy', 'degraded'] for status in [health_status, cb_status, monitoring_status]) and validation_success:
            overall_status = "✅ SAUDÁVEL"
        elif any(status == 'critical' for status in [health_status, cb_status, monitoring_status]):
            overall_status = "❌ CRÍTICO"
        else:
            overall_status = "⚠️ DEGRADADO"
        
        # Log resumido
        logger.info(f"Status Geral: {overall_status} | Health: {health_status} | CB: {cb_status} | Monitor: {monitoring_status} | Validação: {'✅' if validation_success else '❌'}")
        
        # Log detalhado a cada 10 minutos
        if len(self.metrics_history) % 10 == 0:
            self._log_detailed_status(metrics, validation)
    
    def _log_detailed_status(self, metrics: Dict, validation: Dict):
        """Log detalhado do status"""
        logger.info("=== STATUS DETALHADO ===")
        
        # Health checks
        health_metrics = metrics['health_checks']['metrics']
        logger.info(f"Health Checks - Status: {metrics['health_checks']['status']}")
        logger.info(f"  Componentes verificados: {health_metrics.get('components_checked', 0)}")
        logger.info(f"  Circuit breakers ativos: {health_metrics.get('circuit_breakers_active', 0)}")
        
        # Circuit breakers
        cb_metrics = metrics['circuit_breakers']['metrics']
        logger.info(f"Circuit Breakers - Status: {metrics['circuit_breakers']['status']}")
        logger.info(f"  Total: {cb_metrics.get('total_circuit_breakers', 0)}")
        logger.info(f"  Abertos: {cb_metrics.get('open_circuit_breakers', 0)}")
        logger.info(f"  Half-open: {cb_metrics.get('half_open_circuit_breakers', 0)}")
        
        # Monitoramento proativo
        monitoring_metrics = metrics['proactive_monitoring']['metrics']
        logger.info(f"Monitoramento Proativo - Status: {metrics['proactive_monitoring']['status']}")
        logger.info(f"  Alertas ativos: {monitoring_metrics.get('active_alerts', 0)}")
        logger.info(f"  Regras configuradas: {monitoring_metrics.get('total_rules', 0)}")
        
        # Recursos do sistema
        system_metrics = metrics['system_resources']
        logger.info(f"Recursos do Sistema:")
        logger.info(f"  CPU: {system_metrics.get('cpu_percent', 0):.1f}%")
        logger.info(f"  Memória: {system_metrics.get('memory_percent', 0):.1f}%")
        logger.info(f"  Disco: {system_metrics.get('disk_percent', 0):.1f}%")
        
        # Validação
        validation_rate = validation.get('success_rate', 0) * 100
        logger.info(f"Taxa de Sucesso da Validação: {validation_rate:.1f}%")
        
        logger.info("========================")
    
    def get_reliability_score(self) -> float:
        """Calcula score de confiabilidade (0-100)"""
        if not self.validation_results:
            return 0.0
        
        # Calcula taxa de sucesso das validações
        recent_validations = self.validation_results[-10:]  # Últimas 10 validações
        success_rate = sum(1 for v in recent_validations if v.get('overall_success', False)) / len(recent_validations)
        
        # Calcula score baseado em múltiplos fatores
        score = 0.0
        
        # 1. Taxa de sucesso das validações (40%)
        score += success_rate * 40
        
        # 2. Status dos health checks (30%)
        if self.metrics_history:
            latest_metrics = self.metrics_history[-1]
            health_status = latest_metrics.get('health_checks', {}).get('status', 'unknown')
            if health_status == 'healthy':
                score += 30
            elif health_status == 'degraded':
                score += 20
            else:
                score += 0
        
        # 3. Status dos circuit breakers (20%)
        if self.metrics_history:
            cb_status = latest_metrics.get('circuit_breakers', {}).get('status', 'unknown')
            if cb_status == 'healthy':
                score += 20
            elif cb_status == 'degraded':
                score += 15
            else:
                score += 0
        
        # 4. Status do monitoramento proativo (10%)
        if self.metrics_history:
            monitoring_status = latest_metrics.get('proactive_monitoring', {}).get('status', 'unknown')
            if monitoring_status == 'healthy':
                score += 10
            elif monitoring_status == 'degraded':
                score += 7
            else:
                score += 0
        
        return min(score, 100.0)
    
    def generate_reliability_report(self) -> Dict:
        """Gera relatório de confiabilidade"""
        if not self.start_time:
            return {"error": "Sistema não foi inicializado"}
        
        uptime = datetime.utcnow() - self.start_time
        reliability_score = self.get_reliability_score()
        
        # Estatísticas das validações
        if self.validation_results:
            total_validations = len(self.validation_results)
            successful_validations = sum(1 for v in self.validation_results if v.get('overall_success', False))
            validation_success_rate = (successful_validations / total_validations) * 100
        else:
            total_validations = 0
            successful_validations = 0
            validation_success_rate = 0
        
        # Status atual
        current_status = "UNKNOWN"
        if self.metrics_history:
            latest_metrics = self.metrics_history[-1]
            health_status = latest_metrics.get('health_checks', {}).get('status', 'unknown')
            cb_status = latest_metrics.get('circuit_breakers', {}).get('status', 'unknown')
            monitoring_status = latest_metrics.get('proactive_monitoring', {}).get('status', 'unknown')
            
            if all(status in ['healthy', 'degraded'] for status in [health_status, cb_status, monitoring_status]):
                current_status = "HEALTHY"
            elif any(status == 'critical' for status in [health_status, cb_status, monitoring_status]):
                current_status = "CRITICAL"
            else:
                current_status = "DEGRADED"
        
        return {
            "report_generated_at": datetime.utcnow().isoformat(),
            "system_start_time": self.start_time.isoformat(),
            "uptime_seconds": uptime.total_seconds(),
            "reliability_score": reliability_score,
            "current_status": current_status,
            "validation_statistics": {
                "total_validations": total_validations,
                "successful_validations": successful_validations,
                "success_rate_percent": validation_success_rate
            },
            "integration_status": self.integration_status,
            "latest_metrics": self.metrics_history[-1] if self.metrics_history else None,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Gera recomendações baseadas no estado atual"""
        recommendations = []
        
        if not self.metrics_history:
            return ["Sistema não possui histórico suficiente para gerar recomendações"]
        
        latest_metrics = self.metrics_history[-1]
        
        # Verifica health checks
        health_status = latest_metrics.get('health_checks', {}).get('status', 'unknown')
        if health_status == 'critical':
            recommendations.append("Investigar componentes críticos com falha nos health checks")
        
        # Verifica circuit breakers
        cb_metrics = latest_metrics.get('circuit_breakers', {}).get('metrics', {})
        open_cbs = cb_metrics.get('open_circuit_breakers', 0)
        if open_cbs > 0:
            recommendations.append(f"Investigar {open_cbs} circuit breaker(s) aberto(s)")
        
        # Verifica recursos do sistema
        system_metrics = latest_metrics.get('system_resources', {})
        cpu_percent = system_metrics.get('cpu_percent', 0)
        memory_percent = system_metrics.get('memory_percent', 0)
        disk_percent = system_metrics.get('disk_percent', 0)
        
        if cpu_percent > 80:
            recommendations.append(f"CPU alta ({cpu_percent:.1f}%) - Considerar otimização ou escalonamento")
        if memory_percent > 80:
            recommendations.append(f"Memória alta ({memory_percent:.1f}%) - Verificar vazamentos de memória")
        if disk_percent > 80:
            recommendations.append(f"Disco cheio ({disk_percent:.1f}%) - Limpar arquivos temporários ou expandir storage")
        
        # Verifica monitoramento proativo
        monitoring_metrics = latest_metrics.get('proactive_monitoring', {}).get('metrics', {})
        active_alerts = monitoring_metrics.get('active_alerts', 0)
        if active_alerts > 0:
            recommendations.append(f"Investigar {active_alerts} alerta(s) ativo(s) no monitoramento proativo")
        
        if not recommendations:
            recommendations.append("Sistema funcionando adequadamente - manter monitoramento")
        
        return recommendations
    
    def shutdown(self):
        """Desliga todos os sistemas de confiabilidade"""
        logger.info("Desligando sistemas de confiabilidade...")
        
        try:
            # Para monitoramento proativo
            stop_proactive_monitoring()
            
            # Gera relatório final
            final_report = self.generate_reliability_report()
            
            # Salva relatório
            with open('logs/final_reliability_report.json', 'w') as f:
                json.dump(final_report, f, indent=2)
            
            logger.info("Sistemas de confiabilidade desligados com sucesso")
            logger.info(f"Relatório final salvo em: logs/final_reliability_report.json")
            
        except Exception as e:
            logger.error(f"Erro ao desligar sistemas: {e}")

# Instância global
reliability_manager = ReliabilityIntegrationManager()

async def main():
    """Função principal"""
    logger.info("🚀 Iniciando integração para 99% de confiabilidade")
    
    try:
        # Inicializa todos os sistemas
        success = await reliability_manager.initialize_all_systems()
        
        if not success:
            logger.error("❌ Falha na inicialização dos sistemas")
            return
        
        logger.info("✅ Todos os sistemas inicializados com sucesso")
        
        # Executa monitoramento contínuo
        await reliability_manager.run_continuous_monitoring()
        
    except KeyboardInterrupt:
        logger.info("Interrupção recebida, desligando sistemas...")
    except Exception as e:
        logger.error(f"Erro na execução principal: {e}")
    finally:
        reliability_manager.shutdown()

def signal_handler(signum, frame):
    """Handler para sinais de interrupção"""
    logger.info(f"Sinal {signum} recebido, iniciando shutdown...")
    asyncio.create_task(shutdown_async())

async def shutdown_async():
    """Shutdown assíncrono"""
    reliability_manager.shutdown()
    sys.exit(0)

if __name__ == "__main__":
    # Configura handlers de sinal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Cria diretório de logs se não existir
    os.makedirs('logs', exist_ok=True)
    
    # Executa sistema
    asyncio.run(main()) 