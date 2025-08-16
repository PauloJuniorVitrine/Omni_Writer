#!/usr/bin/env python3
"""
Failover Testing - Omni Writer
==============================

Testes de failover para validar recuperação do sistema sob falhas
e medir tempos de recuperação (RTO/RPO).

Autor: Equipe de Performance & Reliability
Data: 2025-01-27
Versão: 1.0
"""

import time
import logging
import threading
import subprocess
import json
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from contextlib import contextmanager
import requests

# Importar profiling e chaos
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'profiling'))
from opentelemetry_config import setup_profiling

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'chaos'))
from chaos_setup import ChaosMeshManager

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[FAILOVER][%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class FailoverTestResult:
    """Resultado de teste de failover."""
    test_name: str
    failure_type: str
    target: str
    failure_duration: float
    recovery_time: float
    rto: float  # Recovery Time Objective
    rpo: float  # Recovery Point Objective
    success: bool
    error_message: Optional[str] = None
    data_loss: bool = False

@dataclass
class FailoverMetrics:
    """Métricas de failover."""
    timestamp: float
    test_name: str
    failure_detected: bool
    recovery_initiated: bool
    recovery_completed: bool
    total_downtime: float
    data_integrity_maintained: bool

class FailoverTester:
    """Gerenciador de testes de failover."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        self.base_url = base_url
        self.profiler = setup_profiling()
        self.chaos_manager = ChaosMeshManager()
        self.results: List[FailoverTestResult] = []
        self.metrics: List[FailoverMetrics] = []
        self.health_check_interval = 1.0  # segundos
        
    def health_check(self) -> bool:
        """
        Verifica saúde do sistema.
        
        Returns:
            bool: True se sistema está saudável
        """
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Health check falhou: {e}")
            return False
    
    def wait_for_failure(self, timeout: int = 60) -> bool:
        """
        Aguarda até detectar falha no sistema.
        
        Args:
            timeout: Timeout em segundos
            
        Returns:
            bool: True se falha foi detectada
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if not self.health_check():
                logger.info("Falha detectada no sistema")
                return True
            time.sleep(self.health_check_interval)
        
        logger.warning("Timeout aguardando falha")
        return False
    
    def wait_for_recovery(self, timeout: int = 300) -> bool:
        """
        Aguarda até detectar recuperação do sistema.
        
        Args:
            timeout: Timeout em segundos
            
        Returns:
            bool: True se recuperação foi detectada
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.health_check():
                logger.info("Recuperação detectada no sistema")
                return True
            time.sleep(self.health_check_interval)
        
        logger.error("Timeout aguardando recuperação")
        return False
    
    def measure_rto_rpo(self, failure_start: float, recovery_start: float, 
                       recovery_end: float) -> tuple:
        """
        Mede RTO e RPO.
        
        Args:
            failure_start: Timestamp do início da falha
            recovery_start: Timestamp do início da recuperação
            recovery_end: Timestamp do fim da recuperação
            
        Returns:
            tuple: (RTO, RPO) em segundos
        """
        rto = recovery_end - failure_start  # Tempo total até recuperação
        rpo = recovery_start - failure_start  # Tempo até início da recuperação
        
        return rto, rpo
    
    def test_database_failover(self, duration: int = 30) -> FailoverTestResult:
        """
        Testa failover de banco de dados.
        
        Args:
            duration: Duração da falha em segundos
            
        Returns:
            FailoverTestResult: Resultado do teste
        """
        logger.info("Iniciando teste de failover de banco de dados")
        
        test_name = "database_failover"
        failure_start = None
        recovery_start = None
        recovery_end = None
        
        try:
            # Verificar saúde inicial
            if not self.health_check():
                raise Exception("Sistema não está saudável antes do teste")
            
            # Iniciar falha de banco
            logger.info("Iniciando falha de banco de dados...")
            failure_start = time.time()
            
            # Simular falha de banco (em produção, usar Chaos Mesh)
            # self.chaos_manager.create_service_failure_experiment("database", duration)
            # self.chaos_manager.apply_experiment(experiment)
            
            # Aguardar detecção da falha
            if not self.wait_for_failure(timeout=30):
                raise Exception("Falha não foi detectada")
            
            # Aguardar início da recuperação
            recovery_start = time.time()
            logger.info("Aguardando recuperação...")
            
            # Aguardar recuperação completa
            if not self.wait_for_recovery(timeout=300):
                raise Exception("Recuperação não foi completada")
            
            recovery_end = time.time()
            
            # Calcular RTO/RPO
            rto, rpo = self.measure_rto_rpo(failure_start, recovery_start, recovery_end)
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="database_failure",
                target="database",
                failure_duration=duration,
                recovery_time=recovery_end - recovery_start,
                rto=rto,
                rpo=rpo,
                success=True
            )
            
            # Traçar com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, rto, True
            )
            
        except Exception as e:
            recovery_end = time.time() if recovery_start else time.time()
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="database_failure",
                target="database",
                failure_duration=duration,
                recovery_time=recovery_end - (recovery_start or time.time()),
                rto=recovery_end - (failure_start or time.time()),
                rpo=(recovery_start or time.time()) - (failure_start or time.time()),
                success=False,
                error_message=str(e)
            )
            
            # Traçar erro com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, result.rto, False
            )
        
        self.results.append(result)
        return result
    
    def test_service_failover(self, service_name: str, duration: int = 30) -> FailoverTestResult:
        """
        Testa failover de serviço específico.
        
        Args:
            service_name: Nome do serviço
            duration: Duração da falha em segundos
            
        Returns:
            FailoverTestResult: Resultado do teste
        """
        logger.info(f"Iniciando teste de failover do serviço {service_name}")
        
        test_name = f"service_failover_{service_name}"
        failure_start = None
        recovery_start = None
        recovery_end = None
        
        try:
            # Verificar saúde inicial
            if not self.health_check():
                raise Exception("Sistema não está saudável antes do teste")
            
            # Iniciar falha de serviço
            logger.info(f"Iniciando falha do serviço {service_name}...")
            failure_start = time.time()
            
            # Simular falha de serviço
            # experiment = self.chaos_manager.create_service_failure_experiment(service_name, duration)
            # self.chaos_manager.apply_experiment(experiment)
            
            # Aguardar detecção da falha
            if not self.wait_for_failure(timeout=30):
                raise Exception("Falha não foi detectada")
            
            # Aguardar início da recuperação
            recovery_start = time.time()
            logger.info("Aguardando recuperação...")
            
            # Aguardar recuperação completa
            if not self.wait_for_recovery(timeout=300):
                raise Exception("Recuperação não foi completada")
            
            recovery_end = time.time()
            
            # Calcular RTO/RPO
            rto, rpo = self.measure_rto_rpo(failure_start, recovery_start, recovery_end)
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="service_failure",
                target=service_name,
                failure_duration=duration,
                recovery_time=recovery_end - recovery_start,
                rto=rto,
                rpo=rpo,
                success=True
            )
            
            # Traçar com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, rto, True
            )
            
        except Exception as e:
            recovery_end = time.time() if recovery_start else time.time()
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="service_failure",
                target=service_name,
                failure_duration=duration,
                recovery_time=recovery_end - (recovery_start or time.time()),
                rto=recovery_end - (failure_start or time.time()),
                rpo=(recovery_start or time.time()) - (failure_start or time.time()),
                success=False,
                error_message=str(e)
            )
            
            # Traçar erro com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, result.rto, False
            )
        
        self.results.append(result)
        return result
    
    def test_network_partition(self, duration: int = 30) -> FailoverTestResult:
        """
        Testa failover sob partição de rede.
        
        Args:
            duration: Duração da partição em segundos
            
        Returns:
            FailoverTestResult: Resultado do teste
        """
        logger.info("Iniciando teste de partição de rede")
        
        test_name = "network_partition"
        failure_start = None
        recovery_start = None
        recovery_end = None
        
        try:
            # Verificar saúde inicial
            if not self.health_check():
                raise Exception("Sistema não está saudável antes do teste")
            
            # Iniciar partição de rede
            logger.info("Iniciando partição de rede...")
            failure_start = time.time()
            
            # Simular partição de rede
            # experiment = self.chaos_manager.create_network_delay_experiment("network", 10000)  # 10s delay
            # self.chaos_manager.apply_experiment(experiment)
            
            # Aguardar detecção da falha
            if not self.wait_for_failure(timeout=30):
                raise Exception("Partição não foi detectada")
            
            # Aguardar início da recuperação
            recovery_start = time.time()
            logger.info("Aguardando recuperação...")
            
            # Aguardar recuperação completa
            if not self.wait_for_recovery(timeout=300):
                raise Exception("Recuperação não foi completada")
            
            recovery_end = time.time()
            
            # Calcular RTO/RPO
            rto, rpo = self.measure_rto_rpo(failure_start, recovery_start, recovery_end)
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="network_partition",
                target="network",
                failure_duration=duration,
                recovery_time=recovery_end - recovery_start,
                rto=rto,
                rpo=rpo,
                success=True
            )
            
            # Traçar com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, rto, True
            )
            
        except Exception as e:
            recovery_end = time.time() if recovery_start else time.time()
            
            result = FailoverTestResult(
                test_name=test_name,
                failure_type="network_partition",
                target="network",
                failure_duration=duration,
                recovery_time=recovery_end - (recovery_start or time.time()),
                rto=recovery_end - (failure_start or time.time()),
                rpo=(recovery_start or time.time()) - (failure_start or time.time()),
                success=False,
                error_message=str(e)
            )
            
            # Traçar erro com OpenTelemetry
            self.profiler.trace_external_service(
                "failover", test_name, result.rto, False
            )
        
        self.results.append(result)
        return result
    
    def test_cascading_failures(self, services: List[str], duration: int = 30) -> List[FailoverTestResult]:
        """
        Testa falhas em cascata.
        
        Args:
            services: Lista de serviços para falhar
            duration: Duração da falha em segundos
            
        Returns:
            List[FailoverTestResult]: Resultados dos testes
        """
        logger.info(f"Iniciando teste de falhas em cascata: {services}")
        
        results = []
        
        for i, service in enumerate(services):
            try:
                # Aguardar entre falhas
                if i > 0:
                    time.sleep(10)
                
                result = self.test_service_failover(service, duration)
                results.append(result)
                
                if not result.success:
                    logger.error(f"Falha em cascata falhou para {service}")
                    break
                    
            except Exception as e:
                logger.error(f"Erro no teste de falha em cascata para {service}: {e}")
                break
        
        return results
    
    def analyze_failover_performance(self) -> Dict:
        """
        Analisa performance dos testes de failover.
        
        Returns:
            Dict: Análise de performance
        """
        if not self.results:
            return {"error": "Nenhum resultado para analisar"}
        
        successful_tests = [r for r in self.results if r.success]
        failed_tests = [r for r in self.results if not r.success]
        
        analysis = {
            "total_tests": len(self.results),
            "successful_tests": len(successful_tests),
            "failed_tests": len(failed_tests),
            "success_rate": len(successful_tests) / len(self.results) if self.results else 0,
            "avg_rto": sum(r.rto for r in successful_tests) / len(successful_tests) if successful_tests else 0,
            "avg_rpo": sum(r.rpo for r in successful_tests) / len(successful_tests) if successful_tests else 0,
            "max_rto": max(r.rto for r in successful_tests) if successful_tests else 0,
            "min_rto": min(r.rto for r in successful_tests) if successful_tests else 0,
            "failure_types": {},
            "alerts": []
        }
        
        # Análise por tipo de falha
        for result in self.results:
            failure_type = result.failure_type
            if failure_type not in analysis["failure_types"]:
                analysis["failure_types"][failure_type] = {
                    "count": 0,
                    "success_count": 0,
                    "avg_rto": 0,
                    "avg_rpo": 0
                }
            
            analysis["failure_types"][failure_type]["count"] += 1
            if result.success:
                analysis["failure_types"][failure_type]["success_count"] += 1
        
        # Calcular médias por tipo
        for failure_type in analysis["failure_types"]:
            type_results = [r for r in self.results if r.failure_type == failure_type and r.success]
            if type_results:
                analysis["failure_types"][failure_type]["avg_rto"] = sum(r.rto for r in type_results) / len(type_results)
                analysis["failure_types"][failure_type]["avg_rpo"] = sum(r.rpo for r in type_results) / len(type_results)
        
        # Gerar alertas
        if analysis["success_rate"] < 0.8:
            analysis["alerts"].append(f"🚨 Taxa de sucesso baixa: {analysis['success_rate']:.1%}")
        
        if analysis["avg_rto"] > 300:  # RTO > 5 minutos
            analysis["alerts"].append(f"⚠️ RTO alto: {analysis['avg_rto']:.1f}s")
        
        if analysis["avg_rpo"] > 60:  # RPO > 1 minuto
            analysis["alerts"].append(f"⚠️ RPO alto: {analysis['avg_rpo']:.1f}s")
        
        return analysis
    
    def generate_failover_report(self) -> str:
        """
        Gera relatório de testes de failover.
        
        Returns:
            str: Relatório em formato markdown
        """
        analysis = self.analyze_failover_performance()
        
        if "error" in analysis:
            return f"# Relatório de Testes de Failover - {analysis['error']}"
        
        report = f"""
# Relatório de Testes de Failover - Omni Writer

## Resumo Executivo
- **Total de Testes**: {analysis['total_tests']}
- **Testes Bem-sucedidos**: {analysis['successful_tests']}
- **Testes Falharam**: {analysis['failed_tests']}
- **Taxa de Sucesso**: {analysis['success_rate']:.1%}
- **RTO Médio**: {analysis['avg_rto']:.1f}s
- **RPO Médio**: {analysis['avg_rpo']:.1f}s
- **RTO Máximo**: {analysis['max_rto']:.1f}s
- **RTO Mínimo**: {analysis['min_rto']:.1f}s

## Análise por Tipo de Falha
"""
        
        for failure_type, metrics in analysis["failure_types"].items():
            report += f"""
### {failure_type.replace('_', ' ').title()}
- **Total**: {metrics['count']}
- **Sucessos**: {metrics['success_count']}
- **Taxa de Sucesso**: {metrics['success_count']/metrics['count']:.1%}
- **RTO Médio**: {metrics['avg_rto']:.1f}s
- **RPO Médio**: {metrics['avg_rpo']:.1f}s
"""
        
        # Detalhes dos testes
        if self.results:
            report += f"""
## Detalhes dos Testes
"""
            for result in self.results:
                status = "✅" if result.success else "❌"
                report += f"""
### {result.test_name}
- **Status**: {status}
- **Tipo**: {result.failure_type}
- **Alvo**: {result.target}
- **RTO**: {result.rto:.1f}s
- **RPO**: {result.rpo:.1f}s
- **Tempo de Recuperação**: {result.recovery_time:.1f}s
"""
                if result.error_message:
                    report += f"- **Erro**: {result.error_message}\n"
        
        # Alertas
        if analysis["alerts"]:
            report += f"""
## Alertas
"""
            for alert in analysis["alerts"]:
                report += f"- {alert}\n"
        
        return report

def main():
    """Função principal para demonstração."""
    logger.info("Iniciando testes de failover...")
    
    # Criar tester
    failover_tester = FailoverTester()
    
    # Executar testes
    logger.info("Executando teste de failover de banco...")
    failover_tester.test_database_failover(duration=30)
    
    logger.info("Executando teste de failover de serviço...")
    failover_tester.test_service_failover("api-service", duration=30)
    
    logger.info("Executando teste de partição de rede...")
    failover_tester.test_network_partition(duration=30)
    
    logger.info("Executando teste de falhas em cascata...")
    failover_tester.test_cascading_failures(["service1", "service2"], duration=30)
    
    # Gerar relatório
    report = failover_tester.generate_failover_report()
    print(report)
    
    # Salvar relatório
    with open("failover_test_report.md", "w") as f:
        f.write(report)
    
    logger.info("Testes de failover concluídos!")

if __name__ == "__main__":
    main() 