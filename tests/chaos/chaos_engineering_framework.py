"""
Chaos Engineering Framework - IMP-200
Prompt: Chaos Engineering - Fase 2
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:30:00Z
Tracing ID: ENTERPRISE_20250127_200

Framework de Chaos Engineering para testar resiliência do sistema
em condições extremas e falhas controladas.
"""

import time
import random
import logging
import threading
from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import asyncio
import subprocess
import psutil

logger = logging.getLogger("chaos.engineering")

class ChaosType(Enum):
    """Tipos de experimentos de chaos"""
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    DATA = "data"
    NETWORK = "network"
    SECURITY = "security"

class ChaosState(Enum):
    """Estados do experimento de chaos"""
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

@dataclass
class ChaosExperiment:
    """Configuração de um experimento de chaos"""
    name: str
    description: str
    chaos_type: ChaosType
    duration_seconds: int = 60
    probability: float = 1.0  # Probabilidade de execução
    rollback_automatically: bool = True
    metrics_collection: bool = True
    safety_checks: List[str] = field(default_factory=list)
    tags: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ChaosResult:
    """Resultado de um experimento de chaos"""
    experiment: ChaosExperiment
    start_time: datetime
    end_time: Optional[datetime] = None
    state: ChaosState = ChaosState.PLANNED
    success: Optional[bool] = None
    error_message: Optional[str] = None
    metrics_before: Dict[str, Any] = field(default_factory=dict)
    metrics_during: Dict[str, Any] = field(default_factory=dict)
    metrics_after: Dict[str, Any] = field(default_factory=dict)
    recovery_time_seconds: Optional[float] = None

class ChaosEngineeringFramework:
    """
    Framework de Chaos Engineering para testar resiliência.
    
    Funcionalidades:
    - Execução de experimentos controlados
    - Coleta de métricas antes/durante/depois
    - Rollback automático
    - Análise de impacto
    - Relatórios detalhados
    """
    
    def __init__(self):
        self.experiments: List[ChaosExperiment] = []
        self.results: List[ChaosResult] = []
        self.active_experiments: Dict[str, ChaosResult] = {}
        self.safety_thresholds: Dict[str, float] = {}
        self._lock = threading.RLock()
        
        logger.info("Chaos Engineering Framework inicializado")
    
    def add_experiment(self, experiment: ChaosExperiment):
        """Adiciona experimento ao framework"""
        with self._lock:
            self.experiments.append(experiment)
        logger.info(f"Experimento adicionado: {experiment.name}")
    
    def run_experiment(self, experiment_name: str) -> ChaosResult:
        """Executa um experimento específico"""
        experiment = self._find_experiment(experiment_name)
        if not experiment:
            raise ValueError(f"Experimento não encontrado: {experiment_name}")
        
        # Verificar se deve executar baseado na probabilidade
        if random.random() > experiment.probability:
            logger.info(f"Experimento {experiment_name} pulado devido à probabilidade")
            return None
        
        # Executar verificações de segurança
        if not self._run_safety_checks(experiment):
            raise RuntimeError(f"Verificações de segurança falharam para {experiment_name}")
        
        # Coletar métricas antes
        metrics_before = self._collect_system_metrics()
        
        # Criar resultado
        result = ChaosResult(
            experiment=experiment,
            start_time=datetime.utcnow(),
            state=ChaosState.RUNNING,
            metrics_before=metrics_before
        )
        
        with self._lock:
            self.active_experiments[experiment_name] = result
        
        try:
            logger.info(f"Iniciando experimento: {experiment_name}")
            
            # Executar experimento
            self._execute_chaos_experiment(experiment, result)
            
            # Coletar métricas durante
            result.metrics_during = self._collect_system_metrics()
            
            # Aguardar duração do experimento
            time.sleep(experiment.duration_seconds)
            
            # Rollback automático se configurado
            if experiment.rollback_automatically:
                self._rollback_experiment(experiment, result)
            
            # Coletar métricas após
            result.metrics_after = self._collect_system_metrics()
            
            # Finalizar experimento
            result.end_time = datetime.utcnow()
            result.state = ChaosState.COMPLETED
            result.success = True
            
            if result.recovery_time_seconds:
                logger.info(f"Experimento {experiment_name} completado. Tempo de recuperação: {result.recovery_time_seconds:.2f}s")
            else:
                logger.info(f"Experimento {experiment_name} completado com sucesso")
            
        except Exception as e:
            result.end_time = datetime.utcnow()
            result.state = ChaosState.FAILED
            result.success = False
            result.error_message = str(e)
            
            logger.error(f"Experimento {experiment_name} falhou: {e}")
            
            # Rollback de emergência
            self._emergency_rollback(experiment, result)
        
        finally:
            with self._lock:
                if experiment_name in self.active_experiments:
                    del self.active_experiments[experiment_name]
                self.results.append(result)
        
        return result
    
    def _find_experiment(self, name: str) -> Optional[ChaosExperiment]:
        """Encontra experimento pelo nome"""
        for exp in self.experiments:
            if exp.name == name:
                return exp
        return None
    
    def _run_safety_checks(self, experiment: ChaosExperiment) -> bool:
        """Executa verificações de segurança"""
        logger.info(f"Executando verificações de segurança para {experiment.name}")
        
        # Verificar se sistema está saudável
        if not self._is_system_healthy():
            logger.warning("Sistema não está saudável, abortando experimento")
            return False
        
        # Verificar thresholds de segurança
        for check in experiment.safety_checks:
            if not self._run_safety_check(check):
                logger.warning(f"Verificação de segurança falhou: {check}")
                return False
        
        return True
    
    def _is_system_healthy(self) -> bool:
        """Verifica se sistema está saudável"""
        try:
            # Verificar CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                logger.warning(f"CPU muito alta: {cpu_percent}%")
                return False
            
            # Verificar memória
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                logger.warning(f"Memória muito alta: {memory.percent}%")
                return False
            
            # Verificar disco
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                logger.warning(f"Disco muito cheio: {disk.percent}%")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao verificar saúde do sistema: {e}")
            return False
    
    def _run_safety_check(self, check_name: str) -> bool:
        """Executa verificação de segurança específica"""
        # Implementar verificações específicas baseadas no nome
        if check_name == "database_connection":
            return self._check_database_connection()
        elif check_name == "api_health":
            return self._check_api_health()
        elif check_name == "circuit_breaker_status":
            return self._check_circuit_breaker_status()
        
        return True  # Por padrão, permite execução
    
    def _execute_chaos_experiment(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa o experimento de chaos"""
        if experiment.chaos_type == ChaosType.INFRASTRUCTURE:
            self._execute_infrastructure_chaos(experiment, result)
        elif experiment.chaos_type == ChaosType.APPLICATION:
            self._execute_application_chaos(experiment, result)
        elif experiment.chaos_type == ChaosType.NETWORK:
            self._execute_network_chaos(experiment, result)
        elif experiment.chaos_type == ChaosType.DATA:
            self._execute_data_chaos(experiment, result)
        elif experiment.chaos_type == ChaosType.SECURITY:
            self._execute_security_chaos(experiment, result)
    
    def _execute_infrastructure_chaos(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa chaos de infraestrutura"""
        # Simular falha de CPU
        if "cpu_stress" in experiment.tags:
            self._stress_cpu(experiment.tags.get("cpu_stress_duration", 30))
        
        # Simular falha de memória
        if "memory_stress" in experiment.tags:
            self._stress_memory(experiment.tags.get("memory_stress_mb", 100))
        
        # Simular falha de disco
        if "disk_stress" in experiment.tags:
            self._stress_disk(experiment.tags.get("disk_stress_mb", 50))
    
    def _execute_application_chaos(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa chaos de aplicação"""
        # Simular falha de processo
        if "kill_process" in experiment.tags:
            process_name = experiment.tags.get("process_name", "python")
            self._kill_process(process_name)
        
        # Simular falha de thread
        if "thread_stress" in experiment.tags:
            self._stress_threads(experiment.tags.get("thread_count", 10))
    
    def _execute_network_chaos(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa chaos de rede"""
        # Simular latência
        if "network_latency" in experiment.tags:
            latency_ms = experiment.tags.get("latency_ms", 100)
            self._add_network_latency(latency_ms)
        
        # Simular perda de pacotes
        if "packet_loss" in experiment.tags:
            loss_percent = experiment.tags.get("loss_percent", 10)
            self._simulate_packet_loss(loss_percent)
    
    def _execute_data_chaos(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa chaos de dados"""
        # Simular corrupção de dados
        if "data_corruption" in experiment.tags:
            self._simulate_data_corruption()
        
        # Simular perda de dados
        if "data_loss" in experiment.tags:
            self._simulate_data_loss()
    
    def _execute_security_chaos(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa chaos de segurança"""
        # Simular ataque de força bruta
        if "brute_force" in experiment.tags:
            self._simulate_brute_force_attack()
        
        # Simular DDoS
        if "ddos" in experiment.tags:
            self._simulate_ddos_attack()
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Coleta métricas do sistema"""
        try:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "network_io": psutil.net_io_counters()._asdict(),
                "process_count": len(psutil.pids())
            }
        except Exception as e:
            logger.error(f"Erro ao coletar métricas: {e}")
            return {"error": str(e)}
    
    def _rollback_experiment(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa rollback do experimento"""
        logger.info(f"Executando rollback para {experiment.name}")
        start_time = time.time()
        
        try:
            # Implementar rollback específico baseado no tipo de chaos
            if experiment.chaos_type == ChaosType.INFRASTRUCTURE:
                self._rollback_infrastructure_chaos(experiment)
            elif experiment.chaos_type == ChaosType.NETWORK:
                self._rollback_network_chaos(experiment)
            
            result.recovery_time_seconds = time.time() - start_time
            logger.info(f"Rollback completado em {result.recovery_time_seconds:.2f}s")
            
        except Exception as e:
            logger.error(f"Erro no rollback: {e}")
            result.error_message = f"Rollback falhou: {e}"
    
    def _emergency_rollback(self, experiment: ChaosExperiment, result: ChaosResult):
        """Executa rollback de emergência"""
        logger.warning(f"Executando rollback de emergência para {experiment.name}")
        self._rollback_experiment(experiment, result)
    
    def get_experiment_results(self, experiment_name: Optional[str] = None) -> List[ChaosResult]:
        """Retorna resultados dos experimentos"""
        if experiment_name:
            return [r for r in self.results if r.experiment.name == experiment_name]
        return self.results.copy()
    
    def generate_report(self) -> Dict[str, Any]:
        """Gera relatório dos experimentos"""
        total_experiments = len(self.results)
        successful_experiments = len([r for r in self.results if r.success])
        failed_experiments = total_experiments - successful_experiments
        
        avg_recovery_time = 0
        if successful_experiments > 0:
            recovery_times = [r.recovery_time_seconds for r in self.results if r.recovery_time_seconds]
            avg_recovery_time = sum(recovery_times) / len(recovery_times) if recovery_times else 0
        
        return {
            "summary": {
                "total_experiments": total_experiments,
                "successful_experiments": successful_experiments,
                "failed_experiments": failed_experiments,
                "success_rate": successful_experiments / total_experiments if total_experiments > 0 else 0,
                "average_recovery_time_seconds": avg_recovery_time
            },
            "experiments": [
                {
                    "name": r.experiment.name,
                    "type": r.experiment.chaos_type.value,
                    "state": r.state.value,
                    "success": r.success,
                    "duration_seconds": (r.end_time - r.start_time).total_seconds() if r.end_time else 0,
                    "recovery_time_seconds": r.recovery_time_seconds
                }
                for r in self.results
            ]
        }

# Métodos auxiliares para simulação de chaos
def _stress_cpu(self, duration_seconds: int):
    """Simula stress de CPU"""
    logger.info(f"Simulando stress de CPU por {duration_seconds}s")
    # Implementar stress de CPU

def _stress_memory(self, memory_mb: int):
    """Simula stress de memória"""
    logger.info(f"Simulando stress de memória: {memory_mb}MB")
    # Implementar stress de memória

def _stress_disk(self, size_mb: int):
    """Simula stress de disco"""
    logger.info(f"Simulando stress de disco: {size_mb}MB")
    # Implementar stress de disco

# Instância global do framework
chaos_framework: Optional[ChaosEngineeringFramework] = None

def initialize_chaos_framework() -> ChaosEngineeringFramework:
    """Inicializa o framework de chaos engineering"""
    global chaos_framework
    chaos_framework = ChaosEngineeringFramework()
    return chaos_framework

def get_chaos_framework() -> ChaosEngineeringFramework:
    """Retorna instância do framework"""
    if chaos_framework is None:
        raise RuntimeError("Chaos Framework não foi inicializado.")
    return chaos_framework 