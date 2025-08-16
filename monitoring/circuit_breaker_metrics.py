"""
Circuit Breaker Metrics - Omni Writer
====================================

Sistema de métricas detalhadas de circuit breakers para monitoramento
avançado e análise de resiliência.

Prompt: Circuit Breaker Metrics - Item 8
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T19:55:00Z
Tracing ID: CIRCUIT_BREAKER_METRICS_20250127_008

Análise CoCoT:
- Comprovação: Baseado em Site Reliability Engineering (SRE) e Observability Engineering
- Causalidade: Valida métricas de circuit breakers para monitoramento de resiliência
- Contexto: Integração com sistema de circuit breaker existente e monitoring
- Tendência: Usa métricas estruturadas e análise preditiva

Decisões ToT:
- Abordagem 1: Métricas básicas (simples, mas limitado)
- Abordagem 2: Métricas avançadas + análise (complexo, mas completo)
- Abordagem 3: Métricas detalhadas + alertas + dashboards (equilibrado)
- Escolha: Abordagem 3 - métricas completas com alertas inteligentes

Simulação ReAct:
- Antes: Métricas básicas de circuit breakers, monitoramento limitado
- Durante: Coleta detalhada de métricas e análise de padrões
- Depois: Monitoramento avançado, alertas proativos, resiliência melhorada

Validação de Falsos Positivos:
- Regra: Circuit breaker pode abrir por falha temporária legítima
- Validação: Verificar se falha é persistente ou temporária
- Log: Registrar contexto da falha para análise
"""

import os
import sys
import json
import time
import threading
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
import logging
from collections import defaultdict, deque
import statistics
from pathlib import Path

# Adiciona o diretório raiz ao path para importações
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.logging_config import get_structured_logger
from shared.feature_flags import is_feature_enabled
from monitoring.metrics_collector import metrics_collector
from infraestructure.circuit_breaker import CircuitBreaker, CircuitBreakerManager


class MetricType(Enum):
    """Tipos de métricas de circuit breaker."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Níveis de severidade de alertas."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class CircuitBreakerMetric:
    """Métrica individual de circuit breaker."""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerAlert:
    """Alerta de circuit breaker."""
    id: str
    circuit_breaker_name: str
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime
    metrics: Dict[str, Any]
    recommendations: List[str]
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerHealth:
    """Saúde de um circuit breaker."""
    name: str
    state: str
    health_score: float  # 0.0 - 1.0
    failure_rate: float
    avg_response_time: float
    last_state_change: datetime
    consecutive_failures: int
    consecutive_successes: int
    total_requests: int
    alerts: List[CircuitBreakerAlert]
    recommendations: List[str]


@dataclass
class CircuitBreakerMetricsReport:
    """Relatório completo de métricas de circuit breakers."""
    report_id: str
    timestamp: datetime
    total_circuit_breakers: int
    healthy_circuit_breakers: int
    unhealthy_circuit_breakers: int
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    health_scores: Dict[str, float]
    recommendations: List[str]
    summary: str
    details: Dict[str, CircuitBreakerHealth]


class CircuitBreakerMetricsCollector:
    """
    Coletor de métricas detalhadas de circuit breakers.
    
    Funcionalidades:
    - Coleta de métricas em tempo real
    - Análise de saúde de circuit breakers
    - Geração de alertas inteligentes
    - Relatórios de resiliência
    - Integração com Prometheus
    """
    
    def __init__(self):
        self.logger = get_structured_logger(__name__)
        
        # Configurações
        self.enabled = is_feature_enabled("circuit_breaker_metrics_enabled")
        self.alerting_enabled = is_feature_enabled("circuit_breaker_alerting_enabled")
        self.prometheus_enabled = is_feature_enabled("prometheus_metrics_enabled")
        
        # Dados
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.alerts: List[CircuitBreakerAlert] = []
        self.health_scores: Dict[str, float] = {}
        
        # Thresholds de alerta
        self.alert_thresholds = {
            'failure_rate_warning': 0.1,      # 10%
            'failure_rate_critical': 0.3,     # 30%
            'response_time_warning': 2.0,     # 2 segundos
            'response_time_critical': 5.0,    # 5 segundos
            'consecutive_failures_warning': 3,
            'consecutive_failures_critical': 5,
            'circuit_open_duration_warning': 60,  # 1 minuto
            'circuit_open_duration_critical': 300  # 5 minutos
        }
        
        # Circuit breaker manager
        self.circuit_breaker_manager = CircuitBreakerManager()
        
        # Thread safety
        self.metrics_lock = threading.RLock()
        self.alerts_lock = threading.RLock()
        
        # Inicialização
        self._initialize_metrics_collection()
        
        self.logger.info("Circuit Breaker Metrics Collector inicializado", extra={
            'tracing_id': 'CIRCUIT_BREAKER_METRICS_20250127_008',
            'enabled': self.enabled,
            'alerting_enabled': self.alerting_enabled,
            'prometheus_enabled': self.prometheus_enabled
        })
    
    def _initialize_metrics_collection(self):
        """Inicializa coleta de métricas."""
        if not self.enabled:
            return
        
        # Configura callbacks para circuit breakers existentes
        for name, circuit_breaker in self.circuit_breaker_manager.circuit_breakers.items():
            circuit_breaker.add_on_open_callback(self._on_circuit_open)
            circuit_breaker.add_on_close_callback(self._on_circuit_close)
            circuit_breaker.add_on_half_open_callback(self._on_circuit_half_open)
        
        # Inicia thread de coleta periódica
        self._start_metrics_collection_thread()
    
    def _start_metrics_collection_thread(self):
        """Inicia thread para coleta periódica de métricas."""
        def collect_metrics_periodically():
            while self.enabled:
                try:
                    self._collect_all_metrics()
                    self._analyze_health_scores()
                    self._generate_alerts()
                    time.sleep(30)  # Coleta a cada 30 segundos
                except Exception as e:
                    self.logger.error(f"Erro na coleta periódica de métricas: {e}")
                    time.sleep(60)  # Espera mais tempo em caso de erro
        
        thread = threading.Thread(target=collect_metrics_periodically, daemon=True)
        thread.start()
    
    def _collect_all_metrics(self):
        """Coleta métricas de todos os circuit breakers."""
        with self.metrics_lock:
            all_metrics = self.circuit_breaker_manager.get_all_metrics()
            
            for cb_name, cb_metrics in all_metrics.items():
                self._collect_circuit_breaker_metrics(cb_name, cb_metrics)
    
    def _collect_circuit_breaker_metrics(self, cb_name: str, cb_metrics: Dict[str, Any]):
        """Coleta métricas de um circuit breaker específico."""
        timestamp = datetime.now()
        
        # Métricas básicas
        metrics_to_collect = [
            ('total_requests', MetricType.COUNTER),
            ('successful_requests', MetricType.COUNTER),
            ('failed_requests', MetricType.COUNTER),
            ('failure_rate', MetricType.GAUGE),
            ('consecutive_failures', MetricType.GAUGE),
            ('consecutive_successes', MetricType.GAUGE),
            ('circuit_open_count', MetricType.COUNTER),
            ('circuit_half_open_count', MetricType.COUNTER),
            ('time_in_current_state', MetricType.GAUGE)
        ]
        
        for metric_name, metric_type in metrics_to_collect:
            if metric_name in cb_metrics:
                metric = CircuitBreakerMetric(
                    name=f"circuit_breaker_{metric_name}",
                    value=float(cb_metrics[metric_name]),
                    metric_type=metric_type,
                    timestamp=timestamp,
                    labels={'circuit_breaker': cb_name, 'state': cb_metrics.get('state', 'unknown')},
                    metadata={'raw_metrics': cb_metrics}
                )
                
                self.metrics_history[f"{cb_name}_{metric_name}"].append(metric)
        
        # Métricas de estado
        state_metric = CircuitBreakerMetric(
            name="circuit_breaker_state",
            value=1.0 if cb_metrics.get('state') == 'open' else 0.0,
            metric_type=MetricType.GAUGE,
            timestamp=timestamp,
            labels={'circuit_breaker': cb_name, 'state': cb_metrics.get('state', 'unknown')},
            metadata={'state': cb_metrics.get('state', 'unknown')}
        )
        
        self.metrics_history[f"{cb_name}_state"].append(state_metric)
        
        # Envia para Prometheus se habilitado
        if self.prometheus_enabled:
            self._send_to_prometheus(cb_name, cb_metrics)
    
    def _send_to_prometheus(self, cb_name: str, cb_metrics: Dict[str, Any]):
        """Envia métricas para Prometheus."""
        try:
            # Métricas básicas
            metrics_collector.record_gauge(
                f"circuit_breaker_failure_rate",
                cb_metrics.get('failure_rate', 0.0),
                labels={'circuit_breaker': cb_name}
            )
            
            metrics_collector.record_counter(
                f"circuit_breaker_requests_total",
                cb_metrics.get('total_requests', 0),
                labels={'circuit_breaker': cb_name, 'status': 'total'}
            )
            
            metrics_collector.record_counter(
                f"circuit_breaker_requests_total",
                cb_metrics.get('successful_requests', 0),
                labels={'circuit_breaker': cb_name, 'status': 'success'}
            )
            
            metrics_collector.record_counter(
                f"circuit_breaker_requests_total",
                cb_metrics.get('failed_requests', 0),
                labels={'circuit_breaker': cb_name, 'status': 'failure'}
            )
            
            # Estado do circuit breaker
            state_value = 0
            if cb_metrics.get('state') == 'open':
                state_value = 1
            elif cb_metrics.get('state') == 'half_open':
                state_value = 2
            
            metrics_collector.record_gauge(
                f"circuit_breaker_state",
                state_value,
                labels={'circuit_breaker': cb_name, 'state': cb_metrics.get('state', 'unknown')}
            )
            
            # Contadores de transições
            metrics_collector.record_counter(
                f"circuit_breaker_transitions_total",
                cb_metrics.get('circuit_open_count', 0),
                labels={'circuit_breaker': cb_name, 'transition': 'open'}
            )
            
            metrics_collector.record_counter(
                f"circuit_breaker_transitions_total",
                cb_metrics.get('circuit_half_open_count', 0),
                labels={'circuit_breaker': cb_name, 'transition': 'half_open'}
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar métricas para Prometheus: {e}")
    
    def _analyze_health_scores(self):
        """Analisa e calcula scores de saúde dos circuit breakers."""
        with self.metrics_lock:
            for cb_name in self.circuit_breaker_manager.circuit_breakers.keys():
                health_score = self._calculate_health_score(cb_name)
                self.health_scores[cb_name] = health_score
    
    def _calculate_health_score(self, cb_name: str) -> float:
        """Calcula score de saúde de um circuit breaker (0.0 - 1.0)."""
        try:
            # Obtém métricas recentes (últimas 10 medições)
            failure_rate_metrics = list(self.metrics_history.get(f"{cb_name}_failure_rate", []))[-10:]
            state_metrics = list(self.metrics_history.get(f"{cb_name}_state", []))[-10:]
            
            if not failure_rate_metrics:
                return 1.0  # Sem dados = saudável
            
            # Calcula score baseado em múltiplos fatores
            scores = []
            
            # 1. Taxa de falha (40% do peso)
            avg_failure_rate = statistics.mean([m.value for m in failure_rate_metrics])
            failure_score = max(0.0, 1.0 - avg_failure_rate)
            scores.append(failure_score * 0.4)
            
            # 2. Estado atual (30% do peso)
            current_state = state_metrics[-1].metadata.get('state', 'closed') if state_metrics else 'closed'
            if current_state == 'closed':
                state_score = 1.0
            elif current_state == 'half_open':
                state_score = 0.5
            else:  # open
                state_score = 0.0
            scores.append(state_score * 0.3)
            
            # 3. Estabilidade (30% do peso)
            # Calcula variação da taxa de falha
            if len(failure_rate_metrics) > 1:
                failure_rates = [m.value for m in failure_rate_metrics]
                stability_score = 1.0 - statistics.stdev(failure_rates)
                stability_score = max(0.0, min(1.0, stability_score))
            else:
                stability_score = 1.0
            scores.append(stability_score * 0.3)
            
            return sum(scores)
            
        except Exception as e:
            self.logger.error(f"Erro ao calcular health score para {cb_name}: {e}")
            return 0.5  # Score neutro em caso de erro
    
    def _generate_alerts(self):
        """Gera alertas baseados nas métricas coletadas."""
        if not self.alerting_enabled:
            return
        
        with self.metrics_lock:
            for cb_name in self.circuit_breaker_manager.circuit_breakers.keys():
                self._check_circuit_breaker_alerts(cb_name)
    
    def _check_circuit_breaker_alerts(self, cb_name: str):
        """Verifica alertas para um circuit breaker específico."""
        # Obtém métricas recentes
        failure_rate_metrics = list(self.metrics_history.get(f"{cb_name}_failure_rate", []))[-5:]
        state_metrics = list(self.metrics_history.get(f"{cb_name}_state", []))[-5:]
        
        if not failure_rate_metrics:
            return
        
        current_failure_rate = failure_rate_metrics[-1].value
        current_state = state_metrics[-1].metadata.get('state', 'closed') if state_metrics else 'closed'
        
        # Alerta de taxa de falha crítica
        if current_failure_rate >= self.alert_thresholds['failure_rate_critical']:
            self._create_alert(
                cb_name=cb_name,
                severity=AlertSeverity.CRITICAL,
                title=f"Taxa de falha crítica em {cb_name}",
                description=f"Taxa de falha de {current_failure_rate:.1%} excede threshold crítico",
                metrics={'failure_rate': current_failure_rate, 'state': current_state},
                recommendations=[
                    "Verificar saúde do serviço externo",
                    "Analisar logs de erro",
                    "Considerar fallback ou retry com backoff",
                    "Verificar configuração do circuit breaker"
                ]
            )
        
        # Alerta de taxa de falha alta
        elif current_failure_rate >= self.alert_thresholds['failure_rate_warning']:
            self._create_alert(
                cb_name=cb_name,
                severity=AlertSeverity.WARNING,
                title=f"Taxa de falha alta em {cb_name}",
                description=f"Taxa de falha de {current_failure_rate:.1%} excede threshold de warning",
                metrics={'failure_rate': current_failure_rate, 'state': current_state},
                recommendations=[
                    "Monitorar tendência de falhas",
                    "Verificar logs de erro",
                    "Considerar ajuste de configuração"
                ]
            )
        
        # Alerta de circuit breaker aberto por muito tempo
        if current_state == 'open':
            open_duration = self._get_circuit_open_duration(cb_name)
            if open_duration >= self.alert_thresholds['circuit_open_duration_critical']:
                self._create_alert(
                    cb_name=cb_name,
                    severity=AlertSeverity.CRITICAL,
                    title=f"Circuit breaker {cb_name} aberto por muito tempo",
                    description=f"Circuit breaker está aberto há {open_duration:.0f} segundos",
                    metrics={'open_duration': open_duration, 'state': current_state},
                    recommendations=[
                        "Verificar se serviço externo está funcionando",
                        "Analisar causa raiz das falhas",
                        "Considerar reset manual do circuit breaker",
                        "Implementar fallback alternativo"
                    ]
                )
            elif open_duration >= self.alert_thresholds['circuit_open_duration_warning']:
                self._create_alert(
                    cb_name=cb_name,
                    severity=AlertSeverity.WARNING,
                    title=f"Circuit breaker {cb_name} aberto",
                    description=f"Circuit breaker está aberto há {open_duration:.0f} segundos",
                    metrics={'open_duration': open_duration, 'state': current_state},
                    recommendations=[
                        "Monitorar tempo de abertura",
                        "Verificar logs de erro",
                        "Aguardar recuperação automática"
                    ]
                )
    
    def _get_circuit_open_duration(self, cb_name: str) -> float:
        """Obtém duração que o circuit breaker está aberto."""
        try:
            state_metrics = list(self.metrics_history.get(f"{cb_name}_state", []))
            
            # Encontra quando o circuit breaker abriu
            for i, metric in enumerate(reversed(state_metrics)):
                if metric.metadata.get('state') == 'open':
                    # Calcula duração desde a abertura
                    open_time = metric.timestamp
                    return (datetime.now() - open_time).total_seconds()
            
            return 0.0
            
        except Exception as e:
            self.logger.error(f"Erro ao calcular duração de abertura para {cb_name}: {e}")
            return 0.0
    
    def _create_alert(self, cb_name: str, severity: AlertSeverity, title: str, 
                     description: str, metrics: Dict[str, Any], recommendations: List[str]):
        """Cria um novo alerta."""
        alert_id = f"cb_alert_{cb_name}_{int(time.time())}"
        
        # Verifica se já existe alerta similar não resolvido
        with self.alerts_lock:
            for alert in self.alerts:
                if (alert.circuit_breaker_name == cb_name and 
                    alert.title == title and 
                    not alert.resolved):
                    return  # Alerta já existe
        
        alert = CircuitBreakerAlert(
            id=alert_id,
            circuit_breaker_name=cb_name,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.now(),
            metrics=metrics,
            recommendations=recommendations
        )
        
        with self.alerts_lock:
            self.alerts.append(alert)
        
        # Log do alerta
        self.logger.warning(
            f"Alerta de circuit breaker criado: {title}",
            extra={
                'tracing_id': 'CIRCUIT_BREAKER_METRICS_20250127_008',
                'alert_id': alert_id,
                'circuit_breaker': cb_name,
                'severity': severity.value,
                'metrics': metrics
            }
        )
    
    def _on_circuit_open(self, circuit_breaker: CircuitBreaker):
        """Callback quando circuit breaker abre."""
        self.logger.warning(
            f"Circuit breaker {circuit_breaker.config.name} aberto",
            extra={
                'tracing_id': 'CIRCUIT_BREAKER_METRICS_20250127_008',
                'circuit_breaker': circuit_breaker.config.name,
                'failure_count': circuit_breaker.metrics.consecutive_failures,
                'failure_rate': circuit_breaker._calculate_failure_rate()
            }
        )
    
    def _on_circuit_close(self, circuit_breaker: CircuitBreaker):
        """Callback quando circuit breaker fecha."""
        self.logger.info(
            f"Circuit breaker {circuit_breaker.config.name} fechado",
            extra={
                'tracing_id': 'CIRCUIT_BREAKER_METRICS_20250127_008',
                'circuit_breaker': circuit_breaker.config.name,
                'success_count': circuit_breaker.metrics.consecutive_successes
            }
        )
        
        # Resolve alertas relacionados
        self._resolve_circuit_breaker_alerts(circuit_breaker.config.name)
    
    def _on_circuit_half_open(self, circuit_breaker: CircuitBreaker):
        """Callback quando circuit breaker vai para half-open."""
        self.logger.info(
            f"Circuit breaker {circuit_breaker.config.name} em half-open",
            extra={
                'tracing_id': 'CIRCUIT_BREAKER_METRICS_20250127_008',
                'circuit_breaker': circuit_breaker.config.name
            }
        )
    
    def _resolve_circuit_breaker_alerts(self, cb_name: str):
        """Resolve alertas de um circuit breaker."""
        with self.alerts_lock:
            for alert in self.alerts:
                if (alert.circuit_breaker_name == cb_name and 
                    not alert.resolved):
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
    
    def get_circuit_breaker_health(self, cb_name: str) -> Optional[CircuitBreakerHealth]:
        """Obtém saúde de um circuit breaker específico."""
        try:
            circuit_breaker = self.circuit_breaker_manager.get_circuit_breaker(cb_name)
            if not circuit_breaker:
                return None
            
            metrics = circuit_breaker.get_metrics()
            
            # Obtém alertas ativos
            with self.alerts_lock:
                active_alerts = [
                    alert for alert in self.alerts 
                    if alert.circuit_breaker_name == cb_name and not alert.resolved
                ]
            
            # Calcula recomendações
            recommendations = self._generate_recommendations(cb_name, metrics)
            
            return CircuitBreakerHealth(
                name=cb_name,
                state=metrics.get('state', 'unknown'),
                health_score=self.health_scores.get(cb_name, 0.0),
                failure_rate=metrics.get('failure_rate', 0.0),
                avg_response_time=0.0,  # Não disponível nas métricas atuais
                last_state_change=datetime.fromisoformat(metrics.get('last_state_change', datetime.now().isoformat())),
                consecutive_failures=metrics.get('consecutive_failures', 0),
                consecutive_successes=metrics.get('consecutive_successes', 0),
                total_requests=metrics.get('total_requests', 0),
                alerts=active_alerts,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao obter saúde do circuit breaker {cb_name}: {e}")
            return None
    
    def _generate_recommendations(self, cb_name: str, metrics: Dict[str, Any]) -> List[str]:
        """Gera recomendações para um circuit breaker."""
        recommendations = []
        
        failure_rate = metrics.get('failure_rate', 0.0)
        state = metrics.get('state', 'closed')
        consecutive_failures = metrics.get('consecutive_failures', 0)
        
        if failure_rate > 0.5:
            recommendations.append("Taxa de falha muito alta - verificar serviço externo")
        
        if consecutive_failures > 10:
            recommendations.append("Muitas falhas consecutivas - analisar causa raiz")
        
        if state == 'open':
            recommendations.append("Circuit breaker aberto - aguardar recuperação ou reset manual")
        
        if metrics.get('total_requests', 0) == 0:
            recommendations.append("Nenhuma requisição - verificar se serviço está sendo usado")
        
        return recommendations
    
    def get_metrics_report(self) -> CircuitBreakerMetricsReport:
        """Gera relatório completo de métricas."""
        try:
            # Obtém saúde de todos os circuit breakers
            health_data = {}
            total_circuit_breakers = 0
            healthy_circuit_breakers = 0
            unhealthy_circuit_breakers = 0
            
            for cb_name in self.circuit_breaker_manager.circuit_breakers.keys():
                health = self.get_circuit_breaker_health(cb_name)
                if health:
                    health_data[cb_name] = health
                    total_circuit_breakers += 1
                    
                    if health.health_score >= 0.7:
                        healthy_circuit_breakers += 1
                    else:
                        unhealthy_circuit_breakers += 1
            
            # Conta alertas por severidade
            with self.alerts_lock:
                alerts_by_severity = defaultdict(int)
                for alert in self.alerts:
                    if not alert.resolved:
                        alerts_by_severity[alert.severity.value] += 1
            
            # Gera recomendações globais
            global_recommendations = self._generate_global_recommendations(health_data)
            
            # Gera resumo
            if unhealthy_circuit_breakers == 0:
                summary = "✅ Todos os circuit breakers estão saudáveis"
            elif unhealthy_circuit_breakers <= 2:
                summary = f"⚠️ {unhealthy_circuit_breakers} circuit breakers com problemas"
            else:
                summary = f"❌ {unhealthy_circuit_breakers} circuit breakers críticos"
            
            return CircuitBreakerMetricsReport(
                report_id=f"cb_metrics_report_{int(time.time())}",
                timestamp=datetime.now(),
                total_circuit_breakers=total_circuit_breakers,
                healthy_circuit_breakers=healthy_circuit_breakers,
                unhealthy_circuit_breakers=unhealthy_circuit_breakers,
                total_alerts=sum(alerts_by_severity.values()),
                alerts_by_severity=dict(alerts_by_severity),
                health_scores=self.health_scores.copy(),
                recommendations=global_recommendations,
                summary=summary,
                details=health_data
            )
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar relatório de métricas: {e}")
            return CircuitBreakerMetricsReport(
                report_id=f"cb_metrics_report_error_{int(time.time())}",
                timestamp=datetime.now(),
                total_circuit_breakers=0,
                healthy_circuit_breakers=0,
                unhealthy_circuit_breakers=0,
                total_alerts=0,
                alerts_by_severity={},
                health_scores={},
                recommendations=["Erro ao gerar relatório"],
                summary="❌ Erro ao gerar relatório",
                details={}
            )
    
    def _generate_global_recommendations(self, health_data: Dict[str, CircuitBreakerHealth]) -> List[str]:
        """Gera recomendações globais baseadas na saúde de todos os circuit breakers."""
        recommendations = []
        
        # Análise de padrões
        open_circuits = [h for h in health_data.values() if h.state == 'open']
        high_failure_rates = [h for h in health_data.values() if h.failure_rate > 0.3]
        low_health_scores = [h for h in health_data.values() if h.health_score < 0.5]
        
        if len(open_circuits) > 0:
            recommendations.append(f"{len(open_circuits)} circuit breakers abertos - verificar serviços externos")
        
        if len(high_failure_rates) > 0:
            recommendations.append(f"{len(high_failure_rates)} circuit breakers com alta taxa de falha")
        
        if len(low_health_scores) > 0:
            recommendations.append(f"{len(low_health_scores)} circuit breakers com saúde baixa")
        
        # Recomendações gerais
        recommendations.extend([
            "Monitorar tendências de falha",
            "Revisar configurações de circuit breakers",
            "Implementar fallbacks para serviços críticos",
            "Configurar alertas proativos"
        ])
        
        return recommendations
    
    def export_metrics(self, output_file: str = "circuit_breaker_metrics.json") -> str:
        """Exporta métricas para arquivo JSON."""
        try:
            report = self.get_metrics_report()
            
            # Converte para formato serializável
            export_data = {
                'report': asdict(report),
                'metrics_history': {
                    key: [asdict(metric) for metric in metrics]
                    for key, metrics in self.metrics_history.items()
                },
                'alerts': [asdict(alert) for alert in self.alerts],
                'health_scores': self.health_scores,
                'export_timestamp': datetime.now().isoformat()
            }
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Métricas exportadas para: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Erro ao exportar métricas: {e}")
            raise


# Funções utilitárias
def get_circuit_breaker_metrics_collector() -> CircuitBreakerMetricsCollector:
    """Obtém instância do coletor de métricas de circuit breakers."""
    return CircuitBreakerMetricsCollector()


def get_circuit_breaker_health(cb_name: str) -> Optional[CircuitBreakerHealth]:
    """Obtém saúde de um circuit breaker específico."""
    collector = get_circuit_breaker_metrics_collector()
    return collector.get_circuit_breaker_health(cb_name)


def get_circuit_breaker_metrics_report() -> CircuitBreakerMetricsReport:
    """Obtém relatório completo de métricas de circuit breakers."""
    collector = get_circuit_breaker_metrics_collector()
    return collector.get_metrics_report()


def export_circuit_breaker_metrics(output_file: str = "circuit_breaker_metrics.json") -> str:
    """Exporta métricas de circuit breakers para arquivo."""
    collector = get_circuit_breaker_metrics_collector()
    return collector.export_metrics(output_file) 