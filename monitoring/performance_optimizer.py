"""
Performance Optimizer Module - IMP-300
Prompt: Performance Optimization - Fase 3
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:45:00Z
Tracing ID: ENTERPRISE_20250127_300

Sistema de otimização de performance com detecção automática
de gargalos e sugestões de melhoria.
"""

import time
import psutil
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import cProfile
import pstats
import io
from functools import wraps

logger = logging.getLogger("monitoring.performance")

class PerformanceMetric(Enum):
    """Tipos de métricas de performance"""
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"

class OptimizationLevel(Enum):
    """Níveis de otimização"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class PerformanceThreshold:
    """Threshold de performance"""
    metric: PerformanceMetric
    warning_threshold: float
    critical_threshold: float
    optimization_level: OptimizationLevel

@dataclass
class PerformanceData:
    """Dados de performance coletados"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_io: Dict[str, float]
    network_io: Dict[str, float]
    response_time_ms: Optional[float] = None
    throughput_rps: Optional[float] = None
    error_rate_percent: Optional[float] = None

@dataclass
class PerformanceIssue:
    """Problema de performance identificado"""
    metric: PerformanceMetric
    current_value: float
    threshold: float
    severity: OptimizationLevel
    description: str
    recommendations: List[str]
    detected_at: datetime

@dataclass
class OptimizationRecommendation:
    """Recomendação de otimização"""
    title: str
    description: str
    impact_level: OptimizationLevel
    implementation_effort: str  # low, medium, high
    estimated_improvement: str
    code_changes_required: bool
    configuration_changes: bool

class PerformanceOptimizer:
    """
    Sistema de otimização de performance.
    
    Funcionalidades:
    - Monitoramento contínuo de performance
    - Detecção automática de gargalos
    - Análise de perfil de código
    - Recomendações de otimização
    - Alertas proativos
    """
    
    def __init__(self):
        self.thresholds: Dict[PerformanceMetric, PerformanceThreshold] = {}
        self.performance_history: List[PerformanceData] = []
        self.detected_issues: List[PerformanceIssue] = []
        self.recommendations: List[OptimizationRecommendation] = []
        self.monitoring_active = False
        self._lock = threading.RLock()
        
        self._initialize_default_thresholds()
        logger.info("Performance Optimizer inicializado")
    
    def _initialize_default_thresholds(self):
        """Inicializa thresholds padrão"""
        self.thresholds = {
            PerformanceMetric.CPU_USAGE: PerformanceThreshold(
                metric=PerformanceMetric.CPU_USAGE,
                warning_threshold=70.0,
                critical_threshold=90.0,
                optimization_level=OptimizationLevel.HIGH
            ),
            PerformanceMetric.MEMORY_USAGE: PerformanceThreshold(
                metric=PerformanceMetric.MEMORY_USAGE,
                warning_threshold=80.0,
                critical_threshold=95.0,
                optimization_level=OptimizationLevel.HIGH
            ),
            PerformanceMetric.RESPONSE_TIME: PerformanceThreshold(
                metric=PerformanceMetric.RESPONSE_TIME,
                warning_threshold=1000.0,  # 1 segundo
                critical_threshold=5000.0,  # 5 segundos
                optimization_level=OptimizationLevel.CRITICAL
            ),
            PerformanceMetric.ERROR_RATE: PerformanceThreshold(
                metric=PerformanceMetric.ERROR_RATE,
                warning_threshold=5.0,  # 5%
                critical_threshold=10.0,  # 10%
                optimization_level=OptimizationLevel.CRITICAL
            )
        }
    
    def start_monitoring(self, interval_seconds: int = 30):
        """Inicia monitoramento contínuo"""
        if self.monitoring_active:
            logger.warning("Monitoramento já está ativo")
            return
        
        self.monitoring_active = True
        logger.info(f"Iniciando monitoramento de performance (intervalo: {interval_seconds}s)")
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    self.collect_performance_data()
                    self.analyze_performance()
                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error(f"Erro no monitoramento: {e}")
                    time.sleep(interval_seconds)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Para monitoramento contínuo"""
        self.monitoring_active = False
        logger.info("Monitoramento de performance parado")
    
    def collect_performance_data(self) -> PerformanceData:
        """Coleta dados de performance atuais"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memória
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            disk_io_data = {
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0,
                "read_count": disk_io.read_count if disk_io else 0,
                "write_count": disk_io.write_count if disk_io else 0
            }
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_io_data = {
                "bytes_sent": network_io.bytes_sent,
                "bytes_recv": network_io.bytes_recv,
                "packets_sent": network_io.packets_sent,
                "packets_recv": network_io.packets_recv
            }
            
            performance_data = PerformanceData(
                timestamp=datetime.utcnow(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_io=disk_io_data,
                network_io=network_io_data
            )
            
            with self._lock:
                self.performance_history.append(performance_data)
                
                # Manter apenas últimas 1000 medições
                if len(self.performance_history) > 1000:
                    self.performance_history = self.performance_history[-1000:]
            
            return performance_data
            
        except Exception as e:
            logger.error(f"Erro ao coletar dados de performance: {e}")
            return None
    
    def analyze_performance(self):
        """Analisa dados de performance e detecta problemas"""
        if not self.performance_history:
            return
        
        latest_data = self.performance_history[-1]
        
        # Verificar CPU
        self._check_cpu_performance(latest_data)
        
        # Verificar memória
        self._check_memory_performance(latest_data)
        
        # Verificar response time
        self._check_response_time_performance(latest_data)
        
        # Verificar error rate
        self._check_error_rate_performance(latest_data)
        
        # Gerar recomendações
        self._generate_recommendations()
    
    def _check_cpu_performance(self, data: PerformanceData):
        """Verifica performance de CPU"""
        threshold = self.thresholds[PerformanceMetric.CPU_USAGE]
        
        if data.cpu_percent >= threshold.critical_threshold:
            self._add_performance_issue(
                PerformanceMetric.CPU_USAGE,
                data.cpu_percent,
                threshold.critical_threshold,
                OptimizationLevel.CRITICAL,
                f"CPU usage crítico: {data.cpu_percent:.1f}%",
                [
                    "Otimizar algoritmos computacionalmente intensivos",
                    "Implementar cache para reduzir processamento",
                    "Considerar horizontal scaling",
                    "Analisar perfil de código para gargalos"
                ]
            )
        elif data.cpu_percent >= threshold.warning_threshold:
            self._add_performance_issue(
                PerformanceMetric.CPU_USAGE,
                data.cpu_percent,
                threshold.warning_threshold,
                OptimizationLevel.HIGH,
                f"CPU usage alto: {data.cpu_percent:.1f}%",
                [
                    "Monitorar tendência de uso de CPU",
                    "Otimizar queries de banco de dados",
                    "Implementar lazy loading"
                ]
            )
    
    def _check_memory_performance(self, data: PerformanceData):
        """Verifica performance de memória"""
        threshold = self.thresholds[PerformanceMetric.MEMORY_USAGE]
        
        if data.memory_percent >= threshold.critical_threshold:
            self._add_performance_issue(
                PerformanceMetric.MEMORY_USAGE,
                data.memory_percent,
                threshold.critical_threshold,
                OptimizationLevel.CRITICAL,
                f"Memory usage crítico: {data.memory_percent:.1f}%",
                [
                    "Investigar memory leaks",
                    "Otimizar uso de memória em algoritmos",
                    "Implementar garbage collection manual",
                    "Considerar paginação de dados"
                ]
            )
        elif data.memory_percent >= threshold.warning_threshold:
            self._add_performance_issue(
                PerformanceMetric.MEMORY_USAGE,
                data.memory_percent,
                threshold.warning_threshold,
                OptimizationLevel.HIGH,
                f"Memory usage alto: {data.memory_percent:.1f}%",
                [
                    "Monitorar uso de memória",
                    "Otimizar estruturas de dados",
                    "Implementar cache com TTL"
                ]
            )
    
    def _check_response_time_performance(self, data: PerformanceData):
        """Verifica performance de response time"""
        if data.response_time_ms is None:
            return
        
        threshold = self.thresholds[PerformanceMetric.RESPONSE_TIME]
        
        if data.response_time_ms >= threshold.critical_threshold:
            self._add_performance_issue(
                PerformanceMetric.RESPONSE_TIME,
                data.response_time_ms,
                threshold.critical_threshold,
                OptimizationLevel.CRITICAL,
                f"Response time crítico: {data.response_time_ms:.0f}ms",
                [
                    "Otimizar queries de banco de dados",
                    "Implementar cache Redis",
                    "Considerar CDN para assets estáticos",
                    "Analisar gargalos na aplicação"
                ]
            )
        elif data.response_time_ms >= threshold.warning_threshold:
            self._add_performance_issue(
                PerformanceMetric.RESPONSE_TIME,
                data.response_time_ms,
                threshold.warning_threshold,
                OptimizationLevel.HIGH,
                f"Response time alto: {data.response_time_ms:.0f}ms",
                [
                    "Otimizar endpoints lentos",
                    "Implementar lazy loading",
                    "Considerar paginação"
                ]
            )
    
    def _check_error_rate_performance(self, data: PerformanceData):
        """Verifica performance de error rate"""
        if data.error_rate_percent is None:
            return
        
        threshold = self.thresholds[PerformanceMetric.ERROR_RATE]
        
        if data.error_rate_percent >= threshold.critical_threshold:
            self._add_performance_issue(
                PerformanceMetric.ERROR_RATE,
                data.error_rate_percent,
                threshold.critical_threshold,
                OptimizationLevel.CRITICAL,
                f"Error rate crítico: {data.error_rate_percent:.1f}%",
                [
                    "Investigar causas raiz dos erros",
                    "Implementar retry logic",
                    "Melhorar tratamento de exceções",
                    "Adicionar circuit breakers"
                ]
            )
        elif data.error_rate_percent >= threshold.warning_threshold:
            self._add_performance_issue(
                PerformanceMetric.ERROR_RATE,
                data.error_rate_percent,
                threshold.warning_threshold,
                OptimizationLevel.HIGH,
                f"Error rate alto: {data.error_rate_percent:.1f}%",
                [
                    "Monitorar tendência de erros",
                    "Melhorar logging de erros",
                    "Implementar health checks"
                ]
            )
    
    def _add_performance_issue(self, metric: PerformanceMetric, current_value: float,
                              threshold: float, severity: OptimizationLevel,
                              description: str, recommendations: List[str]):
        """Adiciona problema de performance detectado"""
        issue = PerformanceIssue(
            metric=metric,
            current_value=current_value,
            threshold=threshold,
            severity=severity,
            description=description,
            recommendations=recommendations,
            detected_at=datetime.utcnow()
        )
        
        with self._lock:
            self.detected_issues.append(issue)
            
            # Manter apenas últimas 100 issues
            if len(self.detected_issues) > 100:
                self.detected_issues = self.detected_issues[-100:]
        
        logger.warning(f"Problema de performance detectado: {description}")
    
    def _generate_recommendations(self):
        """Gera recomendações de otimização baseadas nos problemas detectados"""
        recommendations = []
        
        # Analisar problemas críticos
        critical_issues = [i for i in self.detected_issues if i.severity == OptimizationLevel.CRITICAL]
        
        if critical_issues:
            recommendations.append(OptimizationRecommendation(
                title="Otimização Crítica de Performance",
                description="Múltiplos problemas críticos detectados que requerem atenção imediata",
                impact_level=OptimizationLevel.CRITICAL,
                implementation_effort="high",
                estimated_improvement="50-80%",
                code_changes_required=True,
                configuration_changes=True
            ))
        
        # Analisar problemas de CPU
        cpu_issues = [i for i in self.detected_issues if i.metric == PerformanceMetric.CPU_USAGE]
        if cpu_issues:
            recommendations.append(OptimizationRecommendation(
                title="Otimização de CPU",
                description="Alto uso de CPU detectado, otimizações necessárias",
                impact_level=OptimizationLevel.HIGH,
                implementation_effort="medium",
                estimated_improvement="30-50%",
                code_changes_required=True,
                configuration_changes=False
            ))
        
        # Analisar problemas de memória
        memory_issues = [i for i in self.detected_issues if i.metric == PerformanceMetric.MEMORY_USAGE]
        if memory_issues:
            recommendations.append(OptimizationRecommendation(
                title="Otimização de Memória",
                description="Alto uso de memória detectado, otimizações necessárias",
                impact_level=OptimizationLevel.HIGH,
                implementation_effort="medium",
                estimated_improvement="25-40%",
                code_changes_required=True,
                configuration_changes=True
            ))
        
        with self._lock:
            self.recommendations = recommendations
    
    def profile_function(self, func, *args, **kwargs):
        """Executa profiling de uma função"""
        profiler = cProfile.Profile()
        profiler.enable()
        
        try:
            result = func(*args, **kwargs)
        finally:
            profiler.disable()
        
        # Analisar resultados
        s = io.StringIO()
        stats = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 funções
        
        profile_output = s.getvalue()
        logger.info(f"Profiling de {func.__name__}:\n{profile_output}")
        
        return result, profile_output
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Retorna resumo de performance"""
        if not self.performance_history:
            return {"error": "Nenhum dado de performance coletado"}
        
        latest_data = self.performance_history[-1]
        
        # Calcular médias das últimas 10 medições
        recent_data = self.performance_history[-10:]
        avg_cpu = sum(d.cpu_percent for d in recent_data) / len(recent_data)
        avg_memory = sum(d.memory_percent for d in recent_data) / len(recent_data)
        
        return {
            "current": {
                "cpu_percent": latest_data.cpu_percent,
                "memory_percent": latest_data.memory_percent,
                "response_time_ms": latest_data.response_time_ms,
                "error_rate_percent": latest_data.error_rate_percent
            },
            "averages": {
                "cpu_percent": avg_cpu,
                "memory_percent": avg_memory
            },
            "issues": {
                "total": len(self.detected_issues),
                "critical": len([i for i in self.detected_issues if i.severity == OptimizationLevel.CRITICAL]),
                "high": len([i for i in self.detected_issues if i.severity == OptimizationLevel.HIGH])
            },
            "recommendations": len(self.recommendations)
        }
    
    def get_optimization_recommendations(self) -> List[OptimizationRecommendation]:
        """Retorna recomendações de otimização"""
        return self.recommendations.copy()

def performance_monitor(operation_name: str):
    """Decorator para monitoramento de performance"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                response_time_ms = (time.time() - start_time) * 1000
                
                # Registrar performance se optimizer estiver disponível
                try:
                    optimizer = get_performance_optimizer()
                    optimizer.collect_performance_data()
                except:
                    pass
                
                return result
                
            except Exception as e:
                response_time_ms = (time.time() - start_time) * 1000
                logger.error(f"Erro em {operation_name}: {e} (tempo: {response_time_ms:.2f}ms)")
                raise
        
        return wrapper
    return decorator

# Instância global do optimizer
performance_optimizer: Optional[PerformanceOptimizer] = None

def initialize_performance_optimizer() -> PerformanceOptimizer:
    """Inicializa o performance optimizer"""
    global performance_optimizer
    performance_optimizer = PerformanceOptimizer()
    return performance_optimizer

def get_performance_optimizer() -> PerformanceOptimizer:
    """Retorna instância do performance optimizer"""
    if performance_optimizer is None:
        raise RuntimeError("Performance Optimizer não foi inicializado.")
    return performance_optimizer 