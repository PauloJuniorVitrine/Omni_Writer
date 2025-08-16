#!/usr/bin/env python3
"""
Chaos Testing Framework - Omni Writer
=====================================

Framework de chaos testing para testar resiliência do sistema
em cenários de falha controlados.

Tracing ID: CHAOS_TESTING_20250127_001
Ruleset: enterprise_control_layer.yaml
"""

import json
import os
import time
import random
import asyncio
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
import logging
import requests
import psutil
import subprocess
import signal
import sys

@dataclass
class ChaosExperiment:
    """Representa um experimento de chaos testing."""
    name: str
    description: str
    category: str  # 'network', 'infrastructure', 'application', 'data'
    severity: str  # 'low', 'medium', 'high', 'critical'
    duration: int  # segundos
    target: str
    parameters: Dict[str, Any]
    rollback_strategy: str

@dataclass
class ChaosResult:
    """Resultado de um experimento de chaos testing."""
    experiment_name: str
    start_time: datetime
    end_time: datetime
    duration: float
    success: bool
    error_message: Optional[str]
    metrics_before: Dict[str, float]
    metrics_after: Dict[str, float]
    impact_score: float
    recovery_time: float

@dataclass
class ChaosTestSuite:
    """Suite de testes de chaos testing."""
    name: str
    description: str
    experiments: List[ChaosExperiment]
    total_experiments: int
    successful_experiments: int
    failed_experiments: int
    average_impact_score: float
    total_duration: float

class ChaosTestingFramework:
    """Framework de chaos testing com experimentos controlados."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.audit_log_path = self.project_root / "logs" / "chaos_testing.log"
        self.results_path = self.project_root / "monitoring" / "chaos_testing_results.json"
        self.tracing_id = f"CHAOS_TESTING_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Configurar logging estruturado
        self._setup_logging()
        
        # Configurações do sistema
        self.base_url = "http://localhost:5000"  # URL base da aplicação
        self.health_check_endpoint = "/health"
        self.metrics_endpoint = "/metrics"
        
        # Estado do framework
        self.running_experiments = {}
        self.experiment_results = []
        self.system_metrics = {}
        
    def _setup_logging(self):
        """Configura logging estruturado para chaos testing."""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [%(levelname)s] [CHAOS_TESTING] %(message)s',
            handlers=[
                logging.FileHandler(self.audit_log_path),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _log_chaos_event(self, event: str, details: Dict = None):
        """Registra evento de chaos testing com metadados."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tracing_id": self.tracing_id,
            "event": event,
            "details": details or {}
        }
        self.logger.info(f"Chaos Testing Event: {json.dumps(log_entry)}")
        
    def get_system_metrics(self) -> Dict[str, float]:
        """Coleta métricas do sistema antes/durante/depois dos experimentos."""
        metrics = {}
        
        try:
            # Métricas de CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics['cpu_percent'] = cpu_percent
            
            # Métricas de memória
            memory = psutil.virtual_memory()
            metrics['memory_percent'] = memory.percent
            metrics['memory_available_mb'] = memory.available / (1024 * 1024)
            
            # Métricas de disco
            disk = psutil.disk_usage('/')
            metrics['disk_percent'] = disk.percent
            metrics['disk_free_gb'] = disk.free / (1024 * 1024 * 1024)
            
            # Métricas de rede
            network = psutil.net_io_counters()
            metrics['network_bytes_sent'] = network.bytes_sent
            metrics['network_bytes_recv'] = network.bytes_recv
            
            # Métricas de processos
            processes = len(psutil.pids())
            metrics['process_count'] = processes
            
            # Health check da aplicação
            try:
                response = requests.get(f"{self.base_url}{self.health_check_endpoint}", timeout=5)
                metrics['app_health_status'] = response.status_code
                metrics['app_response_time'] = response.elapsed.total_seconds()
            except Exception as e:
                metrics['app_health_status'] = 0
                metrics['app_response_time'] = -1
                metrics['app_health_error'] = str(e)
                
        except Exception as e:
            self.logger.warning(f"Erro ao coletar métricas do sistema: {e}")
            
        return metrics
    
    def check_system_health(self) -> bool:
        """Verifica se o sistema está saudável."""
        try:
            response = requests.get(f"{self.base_url}{self.health_check_endpoint}", timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.warning(f"Health check falhou: {e}")
            return False
    
    def create_network_chaos_experiments(self) -> List[ChaosExperiment]:
        """Cria experimentos de chaos testing para rede."""
        experiments = []
        
        # Latência alta
        experiments.append(ChaosExperiment(
            name="High Network Latency",
            description="Simula latência alta de rede",
            category="network",
            severity="medium",
            duration=60,
            target="network",
            parameters={
                "latency_ms": 1000,
                "jitter_ms": 200,
                "packet_loss_percent": 5
            },
            rollback_strategy="Remove network rules"
        ))
        
        # Perda de pacotes
        experiments.append(ChaosExperiment(
            name="Packet Loss",
            description="Simula perda de pacotes de rede",
            category="network",
            severity="high",
            duration=30,
            target="network",
            parameters={
                "packet_loss_percent": 20,
                "latency_ms": 100
            },
            rollback_strategy="Remove packet loss rules"
        ))
        
        # DNS failure
        experiments.append(ChaosExperiment(
            name="DNS Failure",
            description="Simula falha de DNS",
            category="network",
            severity="high",
            duration=45,
            target="dns",
            parameters={
                "dns_timeout_seconds": 30,
                "dns_failure_rate": 80
            },
            rollback_strategy="Restore DNS configuration"
        ))
        
        return experiments
    
    def create_infrastructure_chaos_experiments(self) -> List[ChaosExperiment]:
        """Cria experimentos de chaos testing para infraestrutura."""
        experiments = []
        
        # CPU stress
        experiments.append(ChaosExperiment(
            name="CPU Stress",
            description="Aplica stress na CPU",
            category="infrastructure",
            severity="medium",
            duration=120,
            target="cpu",
            parameters={
                "cpu_load_percent": 90,
                "stress_duration": 60
            },
            rollback_strategy="Stop stress processes"
        ))
        
        # Memory exhaustion
        experiments.append(ChaosExperiment(
            name="Memory Exhaustion",
            description="Simula esgotamento de memória",
            category="infrastructure",
            severity="high",
            duration=60,
            target="memory",
            parameters={
                "memory_usage_percent": 95,
                "allocation_size_mb": 1024
            },
            rollback_strategy="Free allocated memory"
        ))
        
        # Disk space exhaustion
        experiments.append(ChaosExperiment(
            name="Disk Space Exhaustion",
            description="Simula esgotamento de espaço em disco",
            category="infrastructure",
            severity="critical",
            duration=30,
            target="disk",
            parameters={
                "disk_usage_percent": 98,
                "file_size_mb": 100
            },
            rollback_strategy="Remove test files"
        ))
        
        return experiments
    
    def create_application_chaos_experiments(self) -> List[ChaosExperiment]:
        """Cria experimentos de chaos testing para aplicação."""
        experiments = []
        
        # Service restart
        experiments.append(ChaosExperiment(
            name="Service Restart",
            description="Reinicia serviços críticos",
            category="application",
            severity="high",
            duration=30,
            target="service",
            parameters={
                "service_name": "omni_writer",
                "restart_delay_seconds": 5
            },
            rollback_strategy="Restart service if needed"
        ))
        
        # Database connection failure
        experiments.append(ChaosExperiment(
            name="Database Connection Failure",
            description="Simula falha de conexão com banco",
            category="application",
            severity="critical",
            duration=45,
            target="database",
            parameters={
                "connection_timeout_seconds": 30,
                "failure_rate": 100
            },
            rollback_strategy="Restore database connection"
        ))
        
        # Cache failure
        experiments.append(ChaosExperiment(
            name="Cache Failure",
            description="Simula falha de cache",
            category="application",
            severity="medium",
            duration=60,
            target="cache",
            parameters={
                "cache_timeout_seconds": 10,
                "cache_failure_rate": 80
            },
            rollback_strategy="Restore cache service"
        ))
        
        return experiments
    
    def create_data_chaos_experiments(self) -> List[ChaosExperiment]:
        """Cria experimentos de chaos testing para dados."""
        experiments = []
        
        # Data corruption
        experiments.append(ChaosExperiment(
            name="Data Corruption",
            description="Simula corrupção de dados",
            category="data",
            severity="critical",
            duration=20,
            target="data",
            parameters={
                "corruption_rate": 10,
                "affected_tables": ["blogs", "users"]
            },
            rollback_strategy="Restore from backup"
        ))
        
        # Backup failure
        experiments.append(ChaosExperiment(
            name="Backup Failure",
            description="Simula falha de backup",
            category="data",
            severity="high",
            duration=60,
            target="backup",
            parameters={
                "backup_timeout_seconds": 30,
                "failure_rate": 100
            },
            rollback_strategy="Manual backup trigger"
        ))
        
        return experiments
    
    def execute_network_chaos(self, experiment: ChaosExperiment) -> ChaosResult:
        """Executa experimento de chaos testing de rede."""
        self._log_chaos_event("executing_network_chaos", {"experiment": experiment.name})
        
        start_time = datetime.now()
        metrics_before = self.get_system_metrics()
        
        try:
            # Simular latência alta usando tc (Linux)
            if experiment.parameters.get("latency_ms"):
                latency = experiment.parameters["latency_ms"]
                jitter = experiment.parameters.get("jitter_ms", 0)
                
                # Comando tc para adicionar latência
                cmd = f"tc qdisc add dev lo root netem delay {latency}ms {jitter}ms"
                subprocess.run(cmd, shell=True, check=True)
                
                # Aguardar duração do experimento
                time.sleep(experiment.duration)
                
                # Remover regras de latência
                cleanup_cmd = "tc qdisc del dev lo root"
                subprocess.run(cleanup_cmd, shell=True)
            
            # Simular perda de pacotes
            elif experiment.parameters.get("packet_loss_percent"):
                loss_rate = experiment.parameters["packet_loss_percent"]
                
                cmd = f"tc qdisc add dev lo root netem loss {loss_rate}%"
                subprocess.run(cmd, shell=True, check=True)
                
                time.sleep(experiment.duration)
                
                cleanup_cmd = "tc qdisc del dev lo root"
                subprocess.run(cleanup_cmd, shell=True)
            
            end_time = datetime.now()
            metrics_after = self.get_system_metrics()
            
            # Verificar se o sistema se recuperou
            recovery_time = self._measure_recovery_time()
            impact_score = self._calculate_impact_score(metrics_before, metrics_after)
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=True,
                error_message=None,
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                impact_score=impact_score,
                recovery_time=recovery_time
            )
            
        except Exception as e:
            end_time = datetime.now()
            self._log_chaos_event("network_chaos_failed", {"error": str(e)})
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=False,
                error_message=str(e),
                metrics_before=metrics_before,
                metrics_after=self.get_system_metrics(),
                impact_score=0.0,
                recovery_time=0.0
            )
    
    def execute_infrastructure_chaos(self, experiment: ChaosExperiment) -> ChaosResult:
        """Executa experimento de chaos testing de infraestrutura."""
        self._log_chaos_event("executing_infrastructure_chaos", {"experiment": experiment.name})
        
        start_time = datetime.now()
        metrics_before = self.get_system_metrics()
        
        try:
            # CPU stress
            if experiment.target == "cpu":
                cpu_load = experiment.parameters.get("cpu_load_percent", 90)
                stress_duration = experiment.parameters.get("stress_duration", 60)
                
                # Usar stress-ng se disponível, senão usar stress
                try:
                    cmd = f"stress-ng --cpu 1 --cpu-load {cpu_load} --timeout {stress_duration}s"
                    subprocess.run(cmd, shell=True, check=True)
                except:
                    cmd = f"stress --cpu 1 --timeout {stress_duration}s"
                    subprocess.run(cmd, shell=True, check=True)
            
            # Memory exhaustion
            elif experiment.target == "memory":
                memory_usage = experiment.parameters.get("memory_usage_percent", 95)
                allocation_size = experiment.parameters.get("allocation_size_mb", 1024)
                
                # Alocar memória para simular esgotamento
                memory_blocks = []
                while psutil.virtual_memory().percent < memory_usage:
                    try:
                        # Alocar blocos de memória
                        block = bytearray(allocation_size * 1024 * 1024)
                        memory_blocks.append(block)
                        time.sleep(1)
                    except MemoryError:
                        break
                
                time.sleep(experiment.duration)
                
                # Liberar memória
                memory_blocks.clear()
            
            # Disk space exhaustion
            elif experiment.target == "disk":
                disk_usage = experiment.parameters.get("disk_usage_percent", 98)
                file_size = experiment.parameters.get("file_size_mb", 100)
                
                # Criar arquivos grandes para simular esgotamento
                test_files = []
                while psutil.disk_usage('/').percent < disk_usage:
                    try:
                        filename = f"/tmp/chaos_test_{len(test_files)}.dat"
                        with open(filename, 'wb') as f:
                            f.write(b'0' * file_size * 1024 * 1024)
                        test_files.append(filename)
                    except OSError:
                        break
                
                time.sleep(experiment.duration)
                
                # Remover arquivos de teste
                for filename in test_files:
                    try:
                        os.remove(filename)
                    except:
                        pass
            
            end_time = datetime.now()
            metrics_after = self.get_system_metrics()
            
            recovery_time = self._measure_recovery_time()
            impact_score = self._calculate_impact_score(metrics_before, metrics_after)
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=True,
                error_message=None,
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                impact_score=impact_score,
                recovery_time=recovery_time
            )
            
        except Exception as e:
            end_time = datetime.now()
            self._log_chaos_event("infrastructure_chaos_failed", {"error": str(e)})
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=False,
                error_message=str(e),
                metrics_before=metrics_before,
                metrics_after=self.get_system_metrics(),
                impact_score=0.0,
                recovery_time=0.0
            )
    
    def execute_application_chaos(self, experiment: ChaosExperiment) -> ChaosResult:
        """Executa experimento de chaos testing de aplicação."""
        self._log_chaos_event("executing_application_chaos", {"experiment": experiment.name})
        
        start_time = datetime.now()
        metrics_before = self.get_system_metrics()
        
        try:
            # Service restart
            if experiment.target == "service":
                service_name = experiment.parameters.get("service_name", "omni_writer")
                restart_delay = experiment.parameters.get("restart_delay_seconds", 5)
                
                # Encontrar processo da aplicação
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if service_name in str(proc.info['cmdline']):
                        # Parar processo
                        proc.terminate()
                        time.sleep(restart_delay)
                        
                        # Reiniciar processo (simulado)
                        # Em produção, usar systemctl ou supervisor
                        break
            
            # Database connection failure (simulado)
            elif experiment.target == "database":
                # Simular falha de conexão com banco
                # Em produção, usar ferramentas específicas do banco
                time.sleep(experiment.duration)
            
            # Cache failure (simulado)
            elif experiment.target == "cache":
                # Simular falha de cache
                # Em produção, usar ferramentas específicas do Redis/Memcached
                time.sleep(experiment.duration)
            
            end_time = datetime.now()
            metrics_after = self.get_system_metrics()
            
            recovery_time = self._measure_recovery_time()
            impact_score = self._calculate_impact_score(metrics_before, metrics_after)
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=True,
                error_message=None,
                metrics_before=metrics_before,
                metrics_after=metrics_after,
                impact_score=impact_score,
                recovery_time=recovery_time
            )
            
        except Exception as e:
            end_time = datetime.now()
            self._log_chaos_event("application_chaos_failed", {"error": str(e)})
            
            return ChaosResult(
                experiment_name=experiment.name,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=False,
                error_message=str(e),
                metrics_before=metrics_before,
                metrics_after=self.get_system_metrics(),
                impact_score=0.0,
                recovery_time=0.0
            )
    
    def _measure_recovery_time(self) -> float:
        """Mede tempo de recuperação do sistema."""
        start_time = time.time()
        max_wait_time = 300  # 5 minutos
        
        while time.time() - start_time < max_wait_time:
            if self.check_system_health():
                return time.time() - start_time
            time.sleep(5)
        
        return max_wait_time
    
    def _calculate_impact_score(self, metrics_before: Dict[str, float], metrics_after: Dict[str, float]) -> float:
        """Calcula score de impacto do experimento (0-100)."""
        impact_score = 0.0
        
        # Comparar métricas antes e depois
        for key in metrics_before:
            if key in metrics_after:
                before_val = metrics_before[key]
                after_val = metrics_after[key]
                
                if before_val > 0:
                    change_percent = abs(after_val - before_val) / before_val * 100
                    impact_score += min(change_percent, 20)  # Máximo 20 pontos por métrica
        
        return min(impact_score, 100.0)
    
    def run_chaos_test_suite(self, suite_name: str = "Default Chaos Suite") -> ChaosTestSuite:
        """Executa uma suite completa de testes de chaos testing."""
        self._log_chaos_event("starting_chaos_test_suite", {"suite_name": suite_name})
        
        # Criar experimentos
        experiments = []
        experiments.extend(self.create_network_chaos_experiments())
        experiments.extend(self.create_infrastructure_chaos_experiments())
        experiments.extend(self.create_application_chaos_experiments())
        experiments.extend(self.create_data_chaos_experiments())
        
        # Executar experimentos
        successful_experiments = 0
        failed_experiments = 0
        total_duration = 0.0
        impact_scores = []
        
        for experiment in experiments:
            self._log_chaos_event("executing_experiment", {"experiment": experiment.name})
            
            # Verificar se o sistema está saudável antes do experimento
            if not self.check_system_health():
                self.logger.warning(f"Sistema não saudável antes do experimento {experiment.name}")
                continue
            
            # Executar experimento baseado na categoria
            if experiment.category == "network":
                result = self.execute_network_chaos(experiment)
            elif experiment.category == "infrastructure":
                result = self.execute_infrastructure_chaos(experiment)
            elif experiment.category == "application":
                result = self.execute_application_chaos(experiment)
            else:
                result = self.execute_application_chaos(experiment)  # Default
            
            # Registrar resultado
            self.experiment_results.append(result)
            total_duration += result.duration
            impact_scores.append(result.impact_score)
            
            if result.success:
                successful_experiments += 1
            else:
                failed_experiments += 1
            
            # Aguardar entre experimentos
            time.sleep(10)
        
        # Calcular métricas da suite
        average_impact_score = sum(impact_scores) / len(impact_scores) if impact_scores else 0.0
        
        suite = ChaosTestSuite(
            name=suite_name,
            description=f"Suite de chaos testing executada em {datetime.now().isoformat()}",
            experiments=experiments,
            total_experiments=len(experiments),
            successful_experiments=successful_experiments,
            failed_experiments=failed_experiments,
            average_impact_score=average_impact_score,
            total_duration=total_duration
        )
        
        # Salvar resultados
        self._save_results(suite)
        
        self._log_chaos_event("chaos_test_suite_completed", {
            "suite_name": suite_name,
            "total_experiments": len(experiments),
            "successful": successful_experiments,
            "failed": failed_experiments,
            "average_impact": average_impact_score
        })
        
        return suite
    
    def _save_results(self, suite: ChaosTestSuite):
        """Salva resultados dos experimentos de chaos testing."""
        results_data = {
            "suite": asdict(suite),
            "experiment_results": [asdict(result) for result in self.experiment_results],
            "metadata": {
                "tracing_id": self.tracing_id,
                "generated_at": datetime.now().isoformat(),
                "ruleset": "enterprise_control_layer.yaml"
            }
        }
        
        # Converter datetime para string
        for result in results_data["experiment_results"]:
            result["start_time"] = result["start_time"].isoformat()
            result["end_time"] = result["end_time"].isoformat()
        
        # Salvar em JSON
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.results_path, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self._log_chaos_event("results_saved", {"path": str(self.results_path)})
    
    def generate_report(self) -> str:
        """Gera relatório em markdown dos experimentos de chaos testing."""
        if not self.results_path.exists():
            return "❌ Nenhum resultado de chaos testing encontrado."
        
        with open(self.results_path, 'r') as f:
            data = json.load(f)
        
        suite = data["suite"]
        experiment_results = data["experiment_results"]
        
        report = f"""# 🌀 Chaos Testing Report

**Tracing ID:** {data['metadata']['tracing_id']}  
**Generated:** {data['metadata']['generated_at']}  
**Ruleset:** {data['metadata']['ruleset']}

## 📊 Suite Summary

- **Suite Name:** {suite['name']}
- **Description:** {suite['description']}
- **Total Experiments:** {suite['total_experiments']}
- **Successful:** {suite['successful_experiments']}
- **Failed:** {suite['failed_experiments']}
- **Success Rate:** {(suite['successful_experiments'] / suite['total_experiments'] * 100):.1f}%
- **Average Impact Score:** {suite['average_impact_score']:.1f}/100
- **Total Duration:** {suite['total_duration']:.1f}s

## 🚨 Experiment Results

"""
        
        for result in experiment_results:
            status = "✅" if result['success'] else "❌"
            report += f"### {status} {result['experiment_name']}\n"
            report += f"- **Duration:** {result['duration']:.1f}s\n"
            report += f"- **Impact Score:** {result['impact_score']:.1f}/100\n"
            report += f"- **Recovery Time:** {result['recovery_time']:.1f}s\n"
            
            if result['error_message']:
                report += f"- **Error:** {result['error_message']}\n"
            
            report += "\n"
        
        # Análise por categoria
        categories = {}
        for result in experiment_results:
            # Encontrar categoria do experimento
            for exp in suite['experiments']:
                if exp['name'] == result['experiment_name']:
                    category = exp['category']
                    if category not in categories:
                        categories[category] = {'success': 0, 'failed': 0, 'total': 0}
                    categories[category]['total'] += 1
                    if result['success']:
                        categories[category]['success'] += 1
                    else:
                        categories[category]['failed'] += 1
                    break
        
        report += "## 📈 Analysis by Category\n\n"
        for category, stats in categories.items():
            success_rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            report += f"### {category.title()}\n"
            report += f"- **Total:** {stats['total']}\n"
            report += f"- **Success Rate:** {success_rate:.1f}%\n"
            report += f"- **Failed:** {stats['failed']}\n\n"
        
        return report

def main():
    """Função principal para execução do chaos testing."""
    project_root = os.getcwd()
    framework = ChaosTestingFramework(project_root)
    
    print("🌀 Iniciando framework de chaos testing...")
    
    # Verificar se o sistema está saudável
    if not framework.check_system_health():
        print("❌ Sistema não está saudável. Abortando chaos testing.")
        return
    
    print("✅ Sistema saudável. Iniciando experimentos...")
    
    # Executar suite de chaos testing
    suite = framework.run_chaos_test_suite("Omni Writer Chaos Testing Suite")
    
    print(f"\n📊 Resultados da Suite:")
    print(f"   Total Experiments: {suite.total_experiments}")
    print(f"   Successful: {suite.successful_experiments}")
    print(f"   Failed: {suite.failed_experiments}")
    print(f"   Success Rate: {(suite.successful_experiments / suite.total_experiments * 100):.1f}%")
    print(f"   Average Impact Score: {suite.average_impact_score:.1f}/100")
    
    # Gerar relatório
    report = framework.generate_report()
    report_path = Path(project_root) / "docs" / f"chaos_testing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\n📄 Relatório salvo em: {report_path}")
    print(f"📊 Resultados JSON: {framework.results_path}")

if __name__ == "__main__":
    main() 