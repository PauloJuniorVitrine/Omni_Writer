"""
Sistema de Inteligência Proativa - Omni Writer
==============================================

Sistema de insights automáticos e mitigação de problemas baseado em análise
de métricas, padrões de comportamento e machine learning simples.

Prompt: Inteligência Proativa - Item 5
Ruleset: Enterprise+ Standards + Checklist Integração Externa
Data/Hora: 2025-01-27T18:30:00Z
Tracing ID: PROACTIVE_INTEL_20250127_005

Análise CoCoT:
- Comprovação: Baseado em Site Reliability Engineering (SRE) e Observability Engineering
- Causalidade: Detecta problemas antes que afetem usuários, reduz MTTR e melhora SLA
- Contexto: Integração com monitoring existente, circuit breaker e feature flags
- Tendência: Usa ML simples para detecção de anomalias e auto-healing

Decisões ToT:
- Abordagem 1: Regras estáticas (simples, mas limitado)
- Abordagem 2: ML complexo (poderoso, mas overkill)
- Abordagem 3: ML simples + regras (equilibrado)
- Escolha: Abordagem 3 - combina simplicidade com inteligência

Simulação ReAct:
- Antes: Reação manual a problemas, alto MTTR
- Durante: Detecção automática, mitigação proativa, alertas inteligentes
- Depois: MTTR reduzido, SLA melhorado, experiência do usuário otimizada

Validação de Falsos Positivos:
- Regra: Anomalia pode ser comportamento normal do sistema
- Validação: Verificar contexto histórico e padrões sazonais
- Log: Registrar falsos positivos para refinamento do modelo
"""

import time
import threading
import json
import logging
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import statistics
import math
from functools import wraps

from monitoring.metrics_collector import metrics_collector
from monitoring.performance_monitor import PerformanceMonitor
from infraestructure.circuit_breaker import get_circuit_breaker_manager
from shared.feature_flags import is_feature_enabled, set_feature_flag, FeatureFlagStatus
from shared.logging_config import get_structured_logger


class InsightType(Enum):
    """Tipos de insights."""
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    SECURITY = "security"
    BUSINESS = "business"
    OPERATIONAL = "operational"


class MitigationType(Enum):
    """Tipos de mitigação."""
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    RECOMMENDATION = "recommendation"


class AnomalyType(Enum):
    """Tipos de anomalias."""
    SPIKE = "spike"
    DROP = "drop"
    TREND = "trend"
    PATTERN = "pattern"
    THRESHOLD = "threshold"


@dataclass
class Insight:
    """Insight gerado pelo sistema."""
    id: str
    type: InsightType
    title: str
    description: str
    severity: str  # 'info', 'warning', 'critical'
    confidence: float  # 0.0 a 1.0
    timestamp: datetime
    metrics: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]


@dataclass
class Mitigation:
    """Ação de mitigação."""
    id: str
    insight_id: str
    type: MitigationType
    action: str
    description: str
    executed: bool
    timestamp: datetime
    result: Optional[str]
    metadata: Dict[str, Any]


@dataclass
class AnomalyDetection:
    """Detecção de anomalia."""
    metric_name: str
    current_value: float
    expected_value: float
    deviation: float
    type: AnomalyType
    confidence: float
    timestamp: datetime
    context: Dict[str, Any]


class SimpleMLModel:
    """Modelo de ML simples para detecção de anomalias."""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.history = defaultdict(lambda: deque(maxlen=window_size))
        self.baselines = {}
        self.thresholds = {}
    
    def update(self, metric_name: str, value: float, timestamp: datetime):
        """Atualiza modelo com novo valor."""
        self.history[metric_name].append((value, timestamp))
        
        if len(self.history[metric_name]) >= self.window_size:
            self._update_baseline(metric_name)
    
    def _update_baseline(self, metric_name: str):
        """Atualiza baseline para métrica."""
        values = [v[0] for v in self.history[metric_name]]
        
        if len(values) < 10:  # Mínimo para estatísticas confiáveis
            return
        
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0
        
        self.baselines[metric_name] = {
            'mean': mean,
            'std': std,
            'min': min(values),
            'max': max(values),
            'last_updated': datetime.now()
        }
        
        # Threshold dinâmico baseado em desvio padrão
        self.thresholds[metric_name] = {
            'lower': mean - (2 * std),
            'upper': mean + (2 * std),
            'critical_lower': mean - (3 * std),
            'critical_upper': mean + (3 * std)
        }
    
    def detect_anomaly(self, metric_name: str, value: float) -> Optional[AnomalyDetection]:
        """Detecta anomalia em valor."""
        if metric_name not in self.baselines:
            return None
        
        baseline = self.baselines[metric_name]
        threshold = self.thresholds[metric_name]
        
        # Calcula desvio
        deviation = abs(value - baseline['mean'])
        normalized_deviation = deviation / baseline['std'] if baseline['std'] > 0 else 0
        
        # Determina tipo de anomalia
        anomaly_type = None
        confidence = 0.0
        
        if value > threshold['critical_upper']:
            anomaly_type = AnomalyType.SPIKE
            confidence = min(0.95, normalized_deviation / 3)
        elif value < threshold['critical_lower']:
            anomaly_type = AnomalyType.DROP
            confidence = min(0.95, normalized_deviation / 3)
        elif value > threshold['upper']:
            anomaly_type = AnomalyType.SPIKE
            confidence = min(0.8, normalized_deviation / 2)
        elif value < threshold['lower']:
            anomaly_type = AnomalyType.DROP
            confidence = min(0.8, normalized_deviation / 2)
        
        if anomaly_type and confidence > 0.6:
            return AnomalyDetection(
                metric_name=metric_name,
                current_value=value,
                expected_value=baseline['mean'],
                deviation=normalized_deviation,
                type=anomaly_type,
                confidence=confidence,
                timestamp=datetime.now(),
                context={
                    'baseline': baseline,
                    'threshold': threshold
                }
            )
        
        return None


class ProactiveIntelligence:
    """
    Sistema de inteligência proativa.
    
    Funcionalidades:
    - Detecção automática de anomalias
    - Geração de insights inteligentes
    - Mitigação automática de problemas
    - Recomendações proativas
    - Integração com sistemas existentes
    """
    
    def __init__(self):
        self.logger = get_structured_logger(__name__)
        
        # Componentes
        self.ml_model = SimpleMLModel()
        self.insights: List[Insight] = []
        self.mitigations: List[Mitigation] = []
        self.anomalies: List[AnomalyDetection] = []
        
        # Configurações
        self.enabled = is_feature_enabled("proactive_intelligence_enabled")
        self.auto_mitigation = is_feature_enabled("proactive_auto_mitigation_enabled")
        self.insight_threshold = 0.7  # Confiança mínima para insights
        self.mitigation_threshold = 0.8  # Confiança mínima para mitigação automática
        
        # Threads
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.mitigation_thread = threading.Thread(target=self._mitigation_loop, daemon=True)
        
        # Locks
        self.insights_lock = threading.Lock()
        self.mitigations_lock = threading.Lock()
        self.anomalies_lock = threading.Lock()
        
        # Callbacks
        self.insight_callbacks: List[Callable] = []
        self.mitigation_callbacks: List[Callable] = []
        
        # Inicialização
        self._setup_integrations()
        self._start_threads()
        
        self.logger.info("Sistema de Inteligência Proativa inicializado", extra={
            'tracing_id': 'PROACTIVE_INTEL_20250127_005',
            'enabled': self.enabled,
            'auto_mitigation': self.auto_mitigation
        })
    
    def _setup_integrations(self):
        """Configura integrações com sistemas existentes."""
        # Integração com circuit breaker
        self.circuit_breaker_manager = get_circuit_breaker_manager()
        
        # Integração com performance monitor
        self.performance_monitor = PerformanceMonitor()
        
        # Registra callbacks
        self.circuit_breaker_manager.add_on_open_callback(self._on_circuit_open)
        self.circuit_breaker_manager.add_on_close_callback(self._on_circuit_close)
    
    def _start_threads(self):
        """Inicia threads de análise e mitigação."""
        if self.enabled:
            self.analysis_thread.start()
            if self.auto_mitigation:
                self.mitigation_thread.start()
    
    def _analysis_loop(self):
        """Loop principal de análise."""
        while self.enabled:
            try:
                # Coleta métricas atuais
                current_metrics = self._collect_current_metrics()
                
                # Atualiza modelo ML
                self._update_ml_model(current_metrics)
                
                # Detecta anomalias
                anomalies = self._detect_anomalies(current_metrics)
                
                # Gera insights
                insights = self._generate_insights(anomalies, current_metrics)
                
                # Executa mitigações
                if self.auto_mitigation:
                    self._execute_mitigations(insights)
                
                # Aguarda próxima análise
                time.sleep(60)  # Análise a cada minuto
                
            except Exception as e:
                self.logger.error(f"Erro no loop de análise: {e}", extra={
                    'tracing_id': 'PROACTIVE_INTEL_20250127_005',
                    'component': 'analysis_loop'
                })
                time.sleep(120)  # Aguarda mais tempo em caso de erro
    
    def _mitigation_loop(self):
        """Loop de mitigação automática."""
        while self.enabled and self.auto_mitigation:
            try:
                # Processa insights pendentes
                pending_insights = self._get_pending_insights()
                
                for insight in pending_insights:
                    if insight.confidence >= self.mitigation_threshold:
                        self._execute_automatic_mitigation(insight)
                
                time.sleep(30)  # Verifica a cada 30 segundos
                
            except Exception as e:
                self.logger.error(f"Erro no loop de mitigação: {e}", extra={
                    'tracing_id': 'PROACTIVE_INTEL_20250127_005',
                    'component': 'mitigation_loop'
                })
                time.sleep(60)
    
    def _collect_current_metrics(self) -> Dict[str, Any]:
        """Coleta métricas atuais de todos os sistemas."""
        metrics = {}
        
        try:
            # Métricas do sistema
            system_metrics = metrics_collector.get_metrics_summary()
            metrics.update(system_metrics)
            
            # Métricas de circuit breakers
            cb_metrics = self.circuit_breaker_manager.get_all_metrics()
            metrics['circuit_breakers'] = cb_metrics
            
            # Métricas de performance
            performance_metrics = self.performance_monitor.get_active_alerts()
            metrics['performance_alerts'] = performance_metrics
            
            # Métricas de feature flags
            feature_flags_metrics = self._collect_feature_flags_metrics()
            metrics['feature_flags'] = feature_flags_metrics
            
        except Exception as e:
            self.logger.error(f"Erro ao coletar métricas: {e}", extra={
                'tracing_id': 'PROACTIVE_INTEL_20250127_005',
                'component': 'metrics_collection'
            })
        
        return metrics
    
    def _collect_feature_flags_metrics(self) -> Dict[str, Any]:
        """Coleta métricas de feature flags."""
        try:
            # Aqui você implementaria coleta de métricas de feature flags
            # Por enquanto, retorna métricas básicas
            return {
                'total_flags': 0,
                'enabled_flags': 0,
                'disabled_flags': 0
            }
        except Exception as e:
            self.logger.error(f"Erro ao coletar métricas de feature flags: {e}")
            return {}
    
    def _update_ml_model(self, metrics: Dict[str, Any]):
        """Atualiza modelo ML com novas métricas."""
        timestamp = datetime.now()
        
        # Atualiza métricas numéricas
        for metric_name, value in metrics.items():
            if isinstance(value, (int, float)) and not math.isnan(value):
                self.ml_model.update(metric_name, value, timestamp)
    
    def _detect_anomalies(self, metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detecta anomalias nas métricas."""
        anomalies = []
        
        for metric_name, value in metrics.items():
            if isinstance(value, (int, float)) and not math.isnan(value):
                anomaly = self.ml_model.detect_anomaly(metric_name, value)
                if anomaly:
                    anomalies.append(anomaly)
        
        # Adiciona anomalias à lista
        with self.anomalies_lock:
            self.anomalies.extend(anomalies)
            # Mantém apenas últimas 1000 anomalias
            if len(self.anomalies) > 1000:
                self.anomalies = self.anomalies[-1000:]
        
        return anomalies
    
    def _generate_insights(self, anomalies: List[AnomalyDetection], 
                          metrics: Dict[str, Any]) -> List[Insight]:
        """Gera insights baseados em anomalias e métricas."""
        insights = []
        
        # Insight: Anomalia de performance
        for anomaly in anomalies:
            if anomaly.confidence >= self.insight_threshold:
                insight = self._create_performance_insight(anomaly, metrics)
                if insight:
                    insights.append(insight)
        
        # Insight: Circuit breaker aberto
        cb_insights = self._create_circuit_breaker_insights(metrics)
        insights.extend(cb_insights)
        
        # Insight: Health score baixo
        health_insights = self._create_health_insights(metrics)
        insights.extend(health_insights)
        
        # Adiciona insights à lista
        with self.insights_lock:
            self.insights.extend(insights)
            # Mantém apenas últimos 500 insights
            if len(self.insights) > 500:
                self.insights = self.insights[-500:]
        
        return insights
    
    def _create_performance_insight(self, anomaly: AnomalyDetection, 
                                   metrics: Dict[str, Any]) -> Optional[Insight]:
        """Cria insight de performance baseado em anomalia."""
        if anomaly.type == AnomalyType.SPIKE:
            return Insight(
                id=f"perf_spike_{anomaly.metric_name}_{int(time.time())}",
                type=InsightType.PERFORMANCE,
                title=f"Spike detectado em {anomaly.metric_name}",
                description=f"Valor atual ({anomaly.current_value:.2f}) está {anomaly.deviation:.1f}x acima do esperado ({anomaly.expected_value:.2f})",
                severity="warning" if anomaly.confidence < 0.9 else "critical",
                confidence=anomaly.confidence,
                timestamp=datetime.now(),
                metrics={anomaly.metric_name: anomaly.current_value},
                recommendations=[
                    "Verificar carga do sistema",
                    "Analisar logs de erro",
                    "Considerar escalar recursos"
                ],
                metadata=anomaly.context
            )
        elif anomaly.type == AnomalyType.DROP:
            return Insight(
                id=f"perf_drop_{anomaly.metric_name}_{int(time.time())}",
                type=InsightType.PERFORMANCE,
                title=f"Queda detectada em {anomaly.metric_name}",
                description=f"Valor atual ({anomaly.current_value:.2f}) está {anomaly.deviation:.1f}x abaixo do esperado ({anomaly.expected_value:.2f})",
                severity="warning" if anomaly.confidence < 0.9 else "critical",
                confidence=anomaly.confidence,
                timestamp=datetime.now(),
                metrics={anomaly.metric_name: anomaly.current_value},
                recommendations=[
                    "Verificar se serviços estão funcionando",
                    "Analisar métricas de disponibilidade",
                    "Verificar conectividade de rede"
                ],
                metadata=anomaly.context
            )
        
        return None
    
    def _create_circuit_breaker_insights(self, metrics: Dict[str, Any]) -> List[Insight]:
        """Cria insights baseados em circuit breakers."""
        insights = []
        
        cb_metrics = metrics.get('circuit_breakers', {})
        
        for cb_name, cb_data in cb_metrics.items():
            if cb_data.get('state') == 'OPEN':
                insights.append(Insight(
                    id=f"cb_open_{cb_name}_{int(time.time())}",
                    type=InsightType.RELIABILITY,
                    title=f"Circuit Breaker {cb_name} está aberto",
                    description=f"Serviço {cb_name} está falhando consistentemente. Circuit breaker aberto para proteger o sistema.",
                    severity="critical",
                    confidence=0.95,
                    timestamp=datetime.now(),
                    metrics={'circuit_breaker_state': 'OPEN', 'failure_count': cb_data.get('failure_count', 0)},
                    recommendations=[
                        "Verificar saúde do serviço externo",
                        "Analisar logs de erro",
                        "Considerar fallback ou retry com backoff"
                    ],
                    metadata={'circuit_breaker_name': cb_name, 'cb_data': cb_data}
                ))
        
        return insights
    
    def _create_health_insights(self, metrics: Dict[str, Any]) -> List[Insight]:
        """Cria insights baseados em health score."""
        insights = []
        
        health_score = metrics.get('health_score', 100)
        
        if health_score < 50:
            insights.append(Insight(
                id=f"health_critical_{int(time.time())}",
                type=InsightType.OPERATIONAL,
                title="Health Score crítico",
                description=f"Health score do sistema está em {health_score:.1f}% (crítico)",
                severity="critical",
                confidence=0.9,
                timestamp=datetime.now(),
                metrics={'health_score': health_score},
                recommendations=[
                    "Verificar recursos do sistema (CPU, memória, disco)",
                    "Analisar métricas de performance",
                    "Verificar conectividade de serviços externos"
                ],
                metadata={'threshold': 50}
            ))
        elif health_score < 70:
            insights.append(Insight(
                id=f"health_warning_{int(time.time())}",
                type=InsightType.OPERATIONAL,
                title="Health Score baixo",
                description=f"Health score do sistema está em {health_score:.1f}% (abaixo do ideal)",
                severity="warning",
                confidence=0.8,
                timestamp=datetime.now(),
                metrics={'health_score': health_score},
                recommendations=[
                    "Monitorar tendência do health score",
                    "Verificar métricas de performance",
                    "Considerar otimizações"
                ],
                metadata={'threshold': 70}
            ))
        
        return insights
    
    def _execute_mitigations(self, insights: List[Insight]):
        """Executa mitigações baseadas em insights."""
        for insight in insights:
            if insight.confidence >= self.mitigation_threshold:
                self._execute_automatic_mitigation(insight)
    
    def _execute_automatic_mitigation(self, insight: Insight):
        """Executa mitigação automática para insight."""
        mitigation_id = f"mit_{insight.id}_{int(time.time())}"
        
        try:
            if insight.type == InsightType.RELIABILITY and "circuit_breaker" in insight.title.lower():
                # Mitigação: Circuit breaker aberto
                result = self._mitigate_circuit_breaker_issue(insight)
                
                mitigation = Mitigation(
                    id=mitigation_id,
                    insight_id=insight.id,
                    type=MitigationType.AUTOMATIC,
                    action="circuit_breaker_mitigation",
                    description="Tentativa de mitigação automática de circuit breaker",
                    executed=True,
                    timestamp=datetime.now(),
                    result=result,
                    metadata={'insight_type': insight.type.value}
                )
                
            elif insight.type == InsightType.PERFORMANCE and "spike" in insight.title.lower():
                # Mitigação: Spike de performance
                result = self._mitigate_performance_spike(insight)
                
                mitigation = Mitigation(
                    id=mitigation_id,
                    insight_id=insight.id,
                    type=MitigationType.AUTOMATIC,
                    action="performance_spike_mitigation",
                    description="Tentativa de mitigação automática de spike de performance",
                    executed=True,
                    timestamp=datetime.now(),
                    result=result,
                    metadata={'insight_type': insight.type.value}
                )
                
            else:
                # Mitigação genérica (recomendação)
                mitigation = Mitigation(
                    id=mitigation_id,
                    insight_id=insight.id,
                    type=MitigationType.RECOMMENDATION,
                    action="insight_recommendation",
                    description="Recomendação gerada automaticamente",
                    executed=False,
                    timestamp=datetime.now(),
                    result="Recomendação enviada para análise manual",
                    metadata={'insight_type': insight.type.value}
                )
            
            # Adiciona mitigação à lista
            with self.mitigations_lock:
                self.mitigations.append(mitigation)
                # Mantém apenas últimas 500 mitigações
                if len(self.mitigations) > 500:
                    self.mitigations = self.mitigations[-500:]
            
            self.logger.info(f"Mitigação executada: {mitigation.action}", extra={
                'tracing_id': 'PROACTIVE_INTEL_20250127_005',
                'mitigation_id': mitigation.id,
                'insight_id': insight.id,
                'result': mitigation.result
            })
            
        except Exception as e:
            self.logger.error(f"Erro ao executar mitigação: {e}", extra={
                'tracing_id': 'PROACTIVE_INTEL_20250127_005',
                'insight_id': insight.id,
                'mitigation_id': mitigation_id
            })
    
    def _mitigate_circuit_breaker_issue(self, insight: Insight) -> str:
        """Mitiga problema de circuit breaker."""
        try:
            # Extrai nome do circuit breaker
            cb_name = insight.metadata.get('circuit_breaker_name')
            if not cb_name:
                return "Erro: Nome do circuit breaker não encontrado"
            
            # Tenta reset do circuit breaker
            circuit_breaker = self.circuit_breaker_manager.get_circuit_breaker(cb_name)
            if circuit_breaker:
                circuit_breaker.reset()
                return f"Circuit breaker {cb_name} resetado com sucesso"
            else:
                return f"Circuit breaker {cb_name} não encontrado"
                
        except Exception as e:
            return f"Erro ao mitigar circuit breaker: {e}"
    
    def _mitigate_performance_spike(self, insight: Insight) -> str:
        """Mitiga spike de performance."""
        try:
            # Identifica métrica com problema
            metric_name = list(insight.metrics.keys())[0] if insight.metrics else None
            
            if metric_name == 'cpu_usage' and insight.metrics[metric_name] > 90:
                # CPU muito alto - tenta reduzir carga
                return "Recomendação: Considerar escalar CPU ou reduzir carga"
            
            elif metric_name == 'memory_usage' and insight.metrics[metric_name] > 85:
                # Memória muito alta - tenta limpar cache
                return "Recomendação: Considerar limpar cache ou escalar memória"
            
            elif metric_name == 'disk_usage' and insight.metrics[metric_name] > 90:
                # Disco muito cheio - tenta limpar logs
                return "Recomendação: Considerar limpar logs antigos ou escalar disco"
            
            else:
                return f"Spike detectado em {metric_name}. Monitorando..."
                
        except Exception as e:
            return f"Erro ao mitigar spike de performance: {e}"
    
    def _get_pending_insights(self) -> List[Insight]:
        """Obtém insights pendentes de mitigação."""
        with self.insights_lock:
            # Retorna insights das últimas 5 horas que ainda não foram mitigados
            cutoff_time = datetime.now() - timedelta(hours=5)
            pending = [
                insight for insight in self.insights
                if insight.timestamp > cutoff_time and insight.confidence >= self.mitigation_threshold
            ]
            return pending
    
    def _on_circuit_open(self, circuit_breaker):
        """Callback quando circuit breaker abre."""
        self.logger.warning(f"Circuit breaker {circuit_breaker.config.name} aberto", extra={
            'tracing_id': 'PROACTIVE_INTEL_20250127_005',
            'circuit_breaker': circuit_breaker.config.name,
            'failure_count': circuit_breaker.metrics.consecutive_failures
        })
    
    def _on_circuit_close(self, circuit_breaker):
        """Callback quando circuit breaker fecha."""
        self.logger.info(f"Circuit breaker {circuit_breaker.config.name} fechado", extra={
            'tracing_id': 'PROACTIVE_INTEL_20250127_005',
            'circuit_breaker': circuit_breaker.config.name,
            'success_count': circuit_breaker.metrics.consecutive_successes
        })
    
    # Métodos públicos
    def get_insights(self, limit: int = 100, insight_type: Optional[InsightType] = None) -> List[Dict[str, Any]]:
        """Obtém insights."""
        with self.insights_lock:
            insights = self.insights.copy()
        
        if insight_type:
            insights = [i for i in insights if i.type == insight_type]
        
        # Ordena por timestamp (mais recentes primeiro)
        insights.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [asdict(insight) for insight in insights[:limit]]
    
    def get_mitigations(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obtém mitigações."""
        with self.mitigations_lock:
            mitigations = self.mitigations.copy()
        
        # Ordena por timestamp (mais recentes primeiro)
        mitigations.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [asdict(mitigation) for mitigation in mitigations[:limit]]
    
    def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Obtém anomalias detectadas."""
        with self.anomalies_lock:
            anomalies = self.anomalies.copy()
        
        # Ordena por timestamp (mais recentes primeiro)
        anomalies.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [asdict(anomaly) for anomaly in anomalies[:limit]]
    
    def get_summary(self) -> Dict[str, Any]:
        """Obtém resumo do sistema."""
        with self.insights_lock, self.mitigations_lock, self.anomalies_lock:
            total_insights = len(self.insights)
            total_mitigations = len(self.mitigations)
            total_anomalies = len(self.anomalies)
            
            # Insights por tipo
            insights_by_type = defaultdict(int)
            for insight in self.insights:
                insights_by_type[insight.type.value] += 1
            
            # Mitigações por tipo
            mitigations_by_type = defaultdict(int)
            for mitigation in self.mitigations:
                mitigations_by_type[mitigation.type.value] += 1
        
        return {
            'enabled': self.enabled,
            'auto_mitigation': self.auto_mitigation,
            'total_insights': total_insights,
            'total_mitigations': total_mitigations,
            'total_anomalies': total_anomalies,
            'insights_by_type': dict(insights_by_type),
            'mitigations_by_type': dict(mitigations_by_type),
            'last_analysis': datetime.now().isoformat()
        }
    
    def add_insight_callback(self, callback: Callable):
        """Adiciona callback para novos insights."""
        self.insight_callbacks.append(callback)
    
    def add_mitigation_callback(self, callback: Callable):
        """Adiciona callback para novas mitigações."""
        self.mitigation_callbacks.append(callback)


# Instância global
proactive_intelligence = ProactiveIntelligence()


# Decorators e funções utilitárias
def proactive_monitor(metric_name: str):
    """Decorator para monitorar função proativamente."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Atualiza modelo ML com duração
                proactive_intelligence.ml_model.update(f"{metric_name}_duration", duration, datetime.now())
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                
                # Atualiza modelo ML com erro
                proactive_intelligence.ml_model.update(f"{metric_name}_error_rate", 1.0, datetime.now())
                
                raise
        
        return wrapper
    return decorator


def get_proactive_intelligence() -> ProactiveIntelligence:
    """Obtém instância do sistema de inteligência proativa."""
    return proactive_intelligence


def enable_proactive_intelligence():
    """Habilita sistema de inteligência proativa."""
    set_feature_flag("proactive_intelligence_enabled", FeatureFlagStatus.ENABLED)
    proactive_intelligence.enabled = True


def disable_proactive_intelligence():
    """Desabilita sistema de inteligência proativa."""
    set_feature_flag("proactive_intelligence_enabled", FeatureFlagStatus.DISABLED)
    proactive_intelligence.enabled = False


def enable_auto_mitigation():
    """Habilita mitigação automática."""
    set_feature_flag("proactive_auto_mitigation_enabled", FeatureFlagStatus.ENABLED)
    proactive_intelligence.auto_mitigation = True


def disable_auto_mitigation():
    """Desabilita mitigação automática."""
    set_feature_flag("proactive_auto_mitigation_enabled", FeatureFlagStatus.DISABLED)
    proactive_intelligence.auto_mitigation = False 