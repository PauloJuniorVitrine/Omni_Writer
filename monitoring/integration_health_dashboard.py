"""
Integration Health Dashboard
============================

Tracing ID: INT_DASH_20250127_001
Prompt: Item 15 - Integration Health Dashboard
Ruleset: checklist_integracao_externa.md
Created: 2025-01-27T23:20:00Z

Dashboard unificado de saúde das integrações externas com API REST,
interface web e alertas inteligentes baseados em SRE.
"""

import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from collections import defaultdict
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor
import statistics

# Dependências internas
try:
    from monitoring.circuit_breaker_metrics import CircuitBreakerMetrics
    from monitoring.sla_compliance_checker import SLAComplianceChecker
    from monitoring.financial_impact_estimator import FinancialImpactEstimator
    from monitoring.proactive_intelligence import ProactiveIntelligence
    from monitoring.contract_drift_predictor import ContractDriftPredictor
    from shared.feature_flags import FeatureFlags
    from shared.logging_config import get_logger
except ImportError:
    # Fallback para testes
    CircuitBreakerMetrics = None
    SLAComplianceChecker = None
    FinancialImpactEstimator = None
    ProactiveIntelligence = None
    ContractDriftPredictor = None
    FeatureFlags = None
    get_logger = lambda x: logging.getLogger(x)

class HealthStatus(Enum):
    """Status de saúde das integrações"""
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class AlertSeverity(Enum):
    """Severidade de alertas"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class IntegrationMetrics:
    """Métricas de uma integração específica"""
    service_name: str
    endpoint: str
    health_status: HealthStatus
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate: float
    success_rate: float
    throughput: float
    circuit_breaker_status: str
    circuit_breaker_failure_rate: float
    sla_compliance: float
    financial_impact: float
    contract_drift_score: float
    proactive_insights: List[str]
    last_check: datetime
    tracing_id: str

@dataclass
class DashboardAlert:
    """Alerta do dashboard"""
    id: str
    title: str
    message: str
    severity: AlertSeverity
    service_name: str
    metric_name: str
    current_value: float
    threshold: float
    timestamp: datetime
    acknowledged: bool
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    tracing_id: str

@dataclass
class DashboardSummary:
    """Resumo geral do dashboard"""
    total_services: int
    healthy_services: int
    warning_services: int
    critical_services: int
    overall_health_score: float
    total_alerts: int
    critical_alerts: int
    financial_impact_total: float
    sla_compliance_avg: float
    last_updated: datetime
    tracing_id: str

class IntegrationHealthDashboard:
    """
    Dashboard unificado de saúde das integrações
    
    Baseado em:
    - Site Reliability Engineering (SRE)
    - Observability Engineering
    - Grafana Dashboard Best Practices
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Inicializa o dashboard de saúde das integrações"""
        self.tracing_id = f"INT_DASH_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.logger = get_logger(f"{__name__}.{self.tracing_id}")
        
        # Configuração
        self.config = self._load_config(config_path)
        
        # Componentes de monitoring
        self.circuit_breaker_metrics = CircuitBreakerMetrics() if CircuitBreakerMetrics else None
        self.sla_checker = SLAComplianceChecker() if SLAComplianceChecker else None
        self.financial_estimator = FinancialImpactEstimator() if FinancialImpactEstimator else None
        self.proactive_intelligence = ProactiveIntelligence() if ProactiveIntelligence else None
        self.contract_drift = ContractDriftPredictor() if ContractDriftPredictor else None
        self.feature_flags = FeatureFlags() if FeatureFlags else None
        
        # Cache de métricas
        self.metrics_cache: Dict[str, IntegrationMetrics] = {}
        self.cache_ttl = timedelta(minutes=5)
        self.cache_lock = threading.Lock()
        
        # Alertas
        self.alerts: List[DashboardAlert] = []
        self.alerts_lock = threading.Lock()
        self.alert_id_counter = 0
        
        # Métricas de performance
        self.dashboard_metrics = {
            'total_requests': 0,
            'cache_hits': 0,
            'alerts_generated': 0,
            'false_positives_detected': 0,
            'last_update': datetime.now()
        }
        self.metrics_lock = threading.Lock()
        
        # Thread de atualização
        self.update_thread = None
        self.running = False
        
        # Inicializar
        self._initialize_dashboard()
        self._start_update_thread()
        
        self.logger.info(f"Integration Health Dashboard inicializado - Tracing ID: {self.tracing_id}")
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Carrega configuração do dashboard"""
        default_config = {
            'update_interval_seconds': 300,  # 5 minutos
            'cache_enabled': True,
            'cache_ttl_minutes': 5,
            'alert_thresholds': {
                'response_time_p95_ms': 1000,
                'error_rate_percent': 5.0,
                'sla_compliance_percent': 95.0,
                'circuit_breaker_failure_rate_percent': 10.0,
                'financial_impact_threshold': 1000.0
            },
            'health_score_weights': {
                'response_time': 0.25,
                'error_rate': 0.30,
                'sla_compliance': 0.25,
                'circuit_breaker': 0.20
            },
            'services': [
                {'name': 'openai', 'endpoint': 'https://api.openai.com/v1'},
                {'name': 'deepseek', 'endpoint': 'https://api.deepseek.com/v1'},
                {'name': 'stripe', 'endpoint': 'https://api.stripe.com/v1'},
                {'name': 'payment_processor', 'endpoint': 'https://api.payment.com/v1'},
                {'name': 'notification_service', 'endpoint': 'https://api.notifications.com/v1'},
                {'name': 'user_service', 'endpoint': 'https://api.users.com/v1'}
            ],
            'dashboard_features': {
                'real_time_updates': True,
                'alerting': True,
                'financial_impact': True,
                'proactive_insights': True,
                'contract_drift': True
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    default_config.update(file_config)
            except Exception as e:
                self.logger.warning(f"Erro ao carregar config: {e}. Usando padrão.")
        
        return default_config
    
    def _initialize_dashboard(self):
        """Inicializa o dashboard com dados básicos"""
        for service_config in self.config['services']:
            service_name = service_config['name']
            endpoint = service_config['endpoint']
            
            # Criar métricas iniciais
            initial_metrics = IntegrationMetrics(
                service_name=service_name,
                endpoint=endpoint,
                health_status=HealthStatus.UNKNOWN,
                response_time_avg=0.0,
                response_time_p95=0.0,
                response_time_p99=0.0,
                error_rate=0.0,
                success_rate=100.0,
                throughput=0.0,
                circuit_breaker_status="closed",
                circuit_breaker_failure_rate=0.0,
                sla_compliance=100.0,
                financial_impact=0.0,
                contract_drift_score=0.0,
                proactive_insights=[],
                last_check=datetime.now(),
                tracing_id=self.tracing_id
            )
            
            self.metrics_cache[service_name] = initial_metrics
        
        self.logger.info(f"Dashboard inicializado com {len(self.config['services'])} serviços")
    
    def _start_update_thread(self):
        """Inicia thread de atualização automática"""
        if self.update_thread and self.update_thread.is_alive():
            return
        
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        self.logger.info("Thread de atualização iniciada")
    
    def _update_loop(self):
        """Loop principal de atualização"""
        while self.running:
            try:
                self._update_all_metrics()
                time.sleep(self.config['update_interval_seconds'])
            except Exception as e:
                self.logger.error(f"Erro no loop de atualização: {e}")
                time.sleep(60)  # Esperar 1 minuto antes de tentar novamente
    
    def _update_all_metrics(self):
        """Atualiza métricas de todos os serviços"""
        self.logger.debug("Iniciando atualização de métricas")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            for service_config in self.config['services']:
                service_name = service_config['name']
                future = executor.submit(self._update_service_metrics, service_name)
                futures.append((service_name, future))
            
            # Aguardar conclusão
            for service_name, future in futures:
                try:
                    future.result(timeout=30)  # Timeout de 30 segundos
                except Exception as e:
                    self.logger.error(f"Erro ao atualizar {service_name}: {e}")
                    self._mark_service_unhealthy(service_name, str(e))
        
        # Gerar alertas baseados nas métricas atualizadas
        self._generate_alerts()
        
        # Atualizar métricas do dashboard
        self._update_dashboard_metrics()
        
        self.logger.debug("Atualização de métricas concluída")
    
    def _update_service_metrics(self, service_name: str):
        """Atualiza métricas de um serviço específico"""
        try:
            # Obter métricas do circuit breaker
            circuit_metrics = self._get_circuit_breaker_metrics(service_name)
            
            # Obter métricas de SLA
            sla_metrics = self._get_sla_metrics(service_name)
            
            # Obter impacto financeiro
            financial_metrics = self._get_financial_metrics(service_name)
            
            # Obter insights proativos
            proactive_insights = self._get_proactive_insights(service_name)
            
            # Obter métricas de contract drift
            contract_metrics = self._get_contract_drift_metrics(service_name)
            
            # Calcular health score
            health_score = self._calculate_health_score(
                circuit_metrics, sla_metrics, financial_metrics
            )
            
            # Determinar status de saúde
            health_status = self._determine_health_status(health_score)
            
            # Criar métricas atualizadas
            updated_metrics = IntegrationMetrics(
                service_name=service_name,
                endpoint=self._get_service_endpoint(service_name),
                health_status=health_status,
                response_time_avg=circuit_metrics.get('response_time_avg', 0.0),
                response_time_p95=circuit_metrics.get('response_time_p95', 0.0),
                response_time_p99=circuit_metrics.get('response_time_p99', 0.0),
                error_rate=circuit_metrics.get('error_rate', 0.0),
                success_rate=circuit_metrics.get('success_rate', 100.0),
                throughput=circuit_metrics.get('throughput', 0.0),
                circuit_breaker_status=circuit_metrics.get('status', 'closed'),
                circuit_breaker_failure_rate=circuit_metrics.get('failure_rate', 0.0),
                sla_compliance=sla_metrics.get('compliance_percentage', 100.0),
                financial_impact=financial_metrics.get('total_impact', 0.0),
                contract_drift_score=contract_metrics.get('drift_score', 0.0),
                proactive_insights=proactive_insights,
                last_check=datetime.now(),
                tracing_id=self.tracing_id
            )
            
            # Atualizar cache
            with self.cache_lock:
                self.metrics_cache[service_name] = updated_metrics
            
            self.logger.debug(f"Métricas de {service_name} atualizadas")
            
        except Exception as e:
            self.logger.error(f"Erro ao atualizar métricas de {service_name}: {e}")
            self._mark_service_unhealthy(service_name, str(e))
    
    def _get_circuit_breaker_metrics(self, service_name: str) -> Dict[str, Any]:
        """Obtém métricas do circuit breaker"""
        if not self.circuit_breaker_metrics:
            return self._get_mock_circuit_breaker_metrics(service_name)
        
        try:
            metrics = self.circuit_breaker_metrics.get_service_metrics(service_name)
            return {
                'response_time_avg': metrics.get('avg_response_time', 0.0),
                'response_time_p95': metrics.get('p95_response_time', 0.0),
                'response_time_p99': metrics.get('p99_response_time', 0.0),
                'error_rate': metrics.get('error_rate', 0.0),
                'success_rate': metrics.get('success_rate', 100.0),
                'throughput': metrics.get('requests_per_minute', 0.0),
                'status': metrics.get('circuit_state', 'closed'),
                'failure_rate': metrics.get('failure_rate', 0.0)
            }
        except Exception as e:
            self.logger.warning(f"Erro ao obter métricas de circuit breaker para {service_name}: {e}")
            return self._get_mock_circuit_breaker_metrics(service_name)
    
    def _get_sla_metrics(self, service_name: str) -> Dict[str, Any]:
        """Obtém métricas de SLA"""
        if not self.sla_checker:
            return self._get_mock_sla_metrics(service_name)
        
        try:
            sla_data = self.sla_checker.get_service_sla_status(service_name)
            return {
                'compliance_percentage': sla_data.get('compliance_percentage', 100.0),
                'violations_count': sla_data.get('violations_count', 0),
                'last_violation': sla_data.get('last_violation', None)
            }
        except Exception as e:
            self.logger.warning(f"Erro ao obter métricas de SLA para {service_name}: {e}")
            return self._get_mock_sla_metrics(service_name)
    
    def _get_financial_metrics(self, service_name: str) -> Dict[str, Any]:
        """Obtém métricas financeiras"""
        if not self.financial_estimator:
            return self._get_mock_financial_metrics(service_name)
        
        try:
            financial_data = self.financial_estimator.get_service_impact(service_name)
            return {
                'total_impact': financial_data.get('total_impact', 0.0),
                'impact_breakdown': financial_data.get('impact_breakdown', {}),
                'trend': financial_data.get('trend', 'stable')
            }
        except Exception as e:
            self.logger.warning(f"Erro ao obter métricas financeiras para {service_name}: {e}")
            return self._get_mock_financial_metrics(service_name)
    
    def _get_proactive_insights(self, service_name: str) -> List[str]:
        """Obtém insights proativos"""
        if not self.proactive_intelligence:
            return self._get_mock_proactive_insights(service_name)
        
        try:
            insights = self.proactive_intelligence.get_service_insights(service_name)
            return insights.get('insights', [])
        except Exception as e:
            self.logger.warning(f"Erro ao obter insights proativos para {service_name}: {e}")
            return self._get_mock_proactive_insights(service_name)
    
    def _get_contract_drift_metrics(self, service_name: str) -> Dict[str, Any]:
        """Obtém métricas de contract drift"""
        if not self.contract_drift:
            return self._get_mock_contract_drift_metrics(service_name)
        
        try:
            drift_data = self.contract_drift.get_service_drift_status(service_name)
            return {
                'drift_score': drift_data.get('drift_score', 0.0),
                'drift_detected': drift_data.get('drift_detected', False),
                'last_check': drift_data.get('last_check', datetime.now())
            }
        except Exception as e:
            self.logger.warning(f"Erro ao obter métricas de contract drift para {service_name}: {e}")
            return self._get_mock_contract_drift_metrics(service_name)
    
    def _get_mock_circuit_breaker_metrics(self, service_name: str) -> Dict[str, Any]:
        """Métricas mock para circuit breaker"""
        import random
        return {
            'response_time_avg': random.uniform(50, 200),
            'response_time_p95': random.uniform(100, 500),
            'response_time_p99': random.uniform(200, 1000),
            'error_rate': random.uniform(0, 5),
            'success_rate': random.uniform(95, 100),
            'throughput': random.uniform(10, 100),
            'status': random.choice(['closed', 'open', 'half_open']),
            'failure_rate': random.uniform(0, 10)
        }
    
    def _get_mock_sla_metrics(self, service_name: str) -> Dict[str, Any]:
        """Métricas mock para SLA"""
        import random
        return {
            'compliance_percentage': random.uniform(90, 100),
            'violations_count': random.randint(0, 5),
            'last_violation': datetime.now() - timedelta(hours=random.randint(1, 24))
        }
    
    def _get_mock_financial_metrics(self, service_name: str) -> Dict[str, Any]:
        """Métricas mock para impacto financeiro"""
        import random
        return {
            'total_impact': random.uniform(0, 5000),
            'impact_breakdown': {
                'infrastructure': random.uniform(0, 1000),
                'development': random.uniform(0, 2000),
                'support': random.uniform(0, 1000),
                'revenue': random.uniform(0, 1000)
            },
            'trend': random.choice(['improving', 'stable', 'worsening'])
        }
    
    def _get_mock_proactive_insights(self, service_name: str) -> List[str]:
        """Insights mock proativos"""
        insights = [
            f"Performance de {service_name} está estável",
            f"Taxa de erro de {service_name} dentro do esperado",
            f"Throughput de {service_name} adequado"
        ]
        import random
        return random.sample(insights, random.randint(1, 3))
    
    def _get_mock_contract_drift_metrics(self, service_name: str) -> Dict[str, Any]:
        """Métricas mock para contract drift"""
        import random
        return {
            'drift_score': random.uniform(0, 1),
            'drift_detected': random.choice([True, False]),
            'last_check': datetime.now()
        }
    
    def _calculate_health_score(self, 
                               circuit_metrics: Dict[str, Any],
                               sla_metrics: Dict[str, Any],
                               financial_metrics: Dict[str, Any]) -> float:
        """Calcula score de saúde geral"""
        weights = self.config['health_score_weights']
        
        # Score de response time (0-100)
        response_time_score = max(0, 100 - (circuit_metrics.get('response_time_p95', 0) / 10))
        
        # Score de error rate (0-100)
        error_rate_score = max(0, 100 - (circuit_metrics.get('error_rate', 0) * 10))
        
        # Score de SLA compliance (0-100)
        sla_score = sla_metrics.get('compliance_percentage', 100)
        
        # Score de circuit breaker (0-100)
        circuit_score = 100 if circuit_metrics.get('status') == 'closed' else 50
        
        # Calcular score ponderado
        total_score = (
            response_time_score * weights['response_time'] +
            error_rate_score * weights['error_rate'] +
            sla_score * weights['sla_compliance'] +
            circuit_score * weights['circuit_breaker']
        )
        
        return min(100, max(0, total_score))
    
    def _determine_health_status(self, health_score: float) -> HealthStatus:
        """Determina status de saúde baseado no score"""
        if health_score >= 90:
            return HealthStatus.EXCELLENT
        elif health_score >= 75:
            return HealthStatus.GOOD
        elif health_score >= 50:
            return HealthStatus.WARNING
        else:
            return HealthStatus.CRITICAL
    
    def _get_service_endpoint(self, service_name: str) -> str:
        """Obtém endpoint de um serviço"""
        for service_config in self.config['services']:
            if service_config['name'] == service_name:
                return service_config['endpoint']
        return "unknown"
    
    def _mark_service_unhealthy(self, service_name: str, error_message: str):
        """Marca serviço como não saudável"""
        with self.cache_lock:
            if service_name in self.metrics_cache:
                metrics = self.metrics_cache[service_name]
                metrics.health_status = HealthStatus.UNKNOWN
                metrics.last_check = datetime.now()
                metrics.proactive_insights = [f"Erro de monitoramento: {error_message}"]
    
    def _generate_alerts(self):
        """Gera alertas baseados nas métricas atuais"""
        thresholds = self.config['alert_thresholds']
        
        with self.cache_lock:
            for service_name, metrics in self.metrics_cache.items():
                # Verificar response time
                if metrics.response_time_p95 > thresholds['response_time_p95_ms']:
                    self._create_alert(
                        service_name=service_name,
                        title="Response Time Alto",
                        message=f"Response time P95 de {service_name} está alto: {metrics.response_time_p95:.2f}ms",
                        severity=AlertSeverity.WARNING,
                        metric_name="response_time_p95",
                        current_value=metrics.response_time_p95,
                        threshold=thresholds['response_time_p95_ms']
                    )
                
                # Verificar error rate
                if metrics.error_rate > thresholds['error_rate_percent']:
                    self._create_alert(
                        service_name=service_name,
                        title="Taxa de Erro Alta",
                        message=f"Taxa de erro de {service_name} está alta: {metrics.error_rate:.2f}%",
                        severity=AlertSeverity.ERROR,
                        metric_name="error_rate",
                        current_value=metrics.error_rate,
                        threshold=thresholds['error_rate_percent']
                    )
                
                # Verificar SLA compliance
                if metrics.sla_compliance < thresholds['sla_compliance_percent']:
                    self._create_alert(
                        service_name=service_name,
                        title="Violação de SLA",
                        message=f"SLA compliance de {service_name} está baixo: {metrics.sla_compliance:.2f}%",
                        severity=AlertSeverity.CRITICAL,
                        metric_name="sla_compliance",
                        current_value=metrics.sla_compliance,
                        threshold=thresholds['sla_compliance_percent']
                    )
                
                # Verificar circuit breaker
                if metrics.circuit_breaker_failure_rate > thresholds['circuit_breaker_failure_rate_percent']:
                    self._create_alert(
                        service_name=service_name,
                        title="Circuit Breaker com Alta Taxa de Falha",
                        message=f"Circuit breaker de {service_name} com alta taxa de falha: {metrics.circuit_breaker_failure_rate:.2f}%",
                        severity=AlertSeverity.WARNING,
                        metric_name="circuit_breaker_failure_rate",
                        current_value=metrics.circuit_breaker_failure_rate,
                        threshold=thresholds['circuit_breaker_failure_rate_percent']
                    )
                
                # Verificar impacto financeiro
                if metrics.financial_impact > thresholds['financial_impact_threshold']:
                    self._create_alert(
                        service_name=service_name,
                        title="Alto Impacto Financeiro",
                        message=f"Impacto financeiro de {service_name} está alto: ${metrics.financial_impact:.2f}",
                        severity=AlertSeverity.ERROR,
                        metric_name="financial_impact",
                        current_value=metrics.financial_impact,
                        threshold=thresholds['financial_impact_threshold']
                    )
    
    def _create_alert(self, 
                     service_name: str,
                     title: str,
                     message: str,
                     severity: AlertSeverity,
                     metric_name: str,
                     current_value: float,
                     threshold: float):
        """Cria um novo alerta"""
        # Verificar se já existe alerta similar
        with self.alerts_lock:
            for alert in self.alerts:
                if (alert.service_name == service_name and 
                    alert.metric_name == metric_name and 
                    not alert.acknowledged):
                    # Atualizar alerta existente
                    alert.current_value = current_value
                    alert.timestamp = datetime.now()
                    return
            
            # Criar novo alerta
            self.alert_id_counter += 1
            alert = DashboardAlert(
                id=f"ALERT_{self.alert_id_counter:06d}",
                title=title,
                message=message,
                severity=severity,
                service_name=service_name,
                metric_name=metric_name,
                current_value=current_value,
                threshold=threshold,
                timestamp=datetime.now(),
                acknowledged=False,
                acknowledged_by=None,
                acknowledged_at=None,
                tracing_id=self.tracing_id
            )
            
            self.alerts.append(alert)
            
            # Validar falso positivo
            if self._validate_false_positive(alert):
                alert.severity = AlertSeverity.INFO
                self.logger.info(f"Alerta reclassificado como falso positivo: {alert.id}")
            
            self.logger.warning(f"Alerta criado: {alert.id} - {title}")
    
    def _validate_false_positive(self, alert: DashboardAlert) -> bool:
        """Valida se alerta é falso positivo"""
        # Verificar se é problema temporário
        if alert.metric_name in ['response_time_p95', 'error_rate']:
            # Se o valor está apenas ligeiramente acima do threshold, pode ser temporário
            if alert.current_value < alert.threshold * 1.1:
                return True
        
        # Verificar se é ambiente de desenvolvimento
        if hasattr(self, 'environment') and self.environment in ['dev', 'test']:
            return True
        
        return False
    
    def _update_dashboard_metrics(self):
        """Atualiza métricas do dashboard"""
        with self.metrics_lock:
            self.dashboard_metrics['last_update'] = datetime.now()
            self.dashboard_metrics['total_requests'] += 1
    
    def get_dashboard_summary(self) -> DashboardSummary:
        """Obtém resumo geral do dashboard"""
        with self.cache_lock:
            total_services = len(self.metrics_cache)
            healthy_services = sum(1 for m in self.metrics_cache.values() 
                                 if m.health_status in [HealthStatus.EXCELLENT, HealthStatus.GOOD])
            warning_services = sum(1 for m in self.metrics_cache.values() 
                                 if m.health_status == HealthStatus.WARNING)
            critical_services = sum(1 for m in self.metrics_cache.values() 
                                  if m.health_status == HealthStatus.CRITICAL)
            
            # Calcular health score geral
            health_scores = [self._calculate_health_score(
                {'response_time_p95': m.response_time_p95, 'error_rate': m.error_rate, 'status': m.circuit_breaker_status},
                {'compliance_percentage': m.sla_compliance},
                {'total_impact': m.financial_impact}
            ) for m in self.metrics_cache.values()]
            
            overall_health_score = statistics.mean(health_scores) if health_scores else 0.0
            
            # Calcular métricas financeiras
            financial_impact_total = sum(m.financial_impact for m in self.metrics_cache.values())
            sla_compliance_avg = statistics.mean(m.sla_compliance for m in self.metrics_cache.values())
        
        with self.alerts_lock:
            total_alerts = len(self.alerts)
            critical_alerts = sum(1 for a in self.alerts if a.severity == AlertSeverity.CRITICAL)
        
        return DashboardSummary(
            total_services=total_services,
            healthy_services=healthy_services,
            warning_services=warning_services,
            critical_services=critical_services,
            overall_health_score=overall_health_score,
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            financial_impact_total=financial_impact_total,
            sla_compliance_avg=sla_compliance_avg,
            last_updated=datetime.now(),
            tracing_id=self.tracing_id
        )
    
    def get_service_metrics(self, service_name: str) -> Optional[IntegrationMetrics]:
        """Obtém métricas de um serviço específico"""
        with self.cache_lock:
            return self.metrics_cache.get(service_name)
    
    def get_all_metrics(self) -> Dict[str, IntegrationMetrics]:
        """Obtém métricas de todos os serviços"""
        with self.cache_lock:
            return self.metrics_cache.copy()
    
    def get_alerts(self, 
                  service_name: Optional[str] = None,
                  severity: Optional[AlertSeverity] = None,
                  acknowledged: Optional[bool] = None) -> List[DashboardAlert]:
        """Obtém alertas com filtros opcionais"""
        with self.alerts_lock:
            alerts = self.alerts.copy()
        
        # Aplicar filtros
        if service_name:
            alerts = [a for a in alerts if a.service_name == service_name]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        
        return alerts
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Reconhece um alerta"""
        with self.alerts_lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    alert.acknowledged_by = acknowledged_by
                    alert.acknowledged_at = datetime.now()
                    self.logger.info(f"Alerta {alert_id} reconhecido por {acknowledged_by}")
                    return True
        
        return False
    
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Obtém métricas de performance do dashboard"""
        with self.metrics_lock:
            return self.dashboard_metrics.copy()
    
    def export_dashboard_data(self, 
                            format: str = 'json',
                            include_alerts: bool = True) -> str:
        """Exporta dados do dashboard"""
        summary = self.get_dashboard_summary()
        all_metrics = self.get_all_metrics()
        alerts = self.get_alerts() if include_alerts else []
        
        data = {
            'summary': asdict(summary),
            'services': {name: asdict(metrics) for name, metrics in all_metrics.items()},
            'alerts': [asdict(alert) for alert in alerts],
            'export_timestamp': datetime.now().isoformat(),
            'tracing_id': self.tracing_id
        }
        
        if format.lower() == 'json':
            return json.dumps(data, indent=2, ensure_ascii=False, default=str)
        else:
            raise ValueError(f"Formato não suportado: {format}")
    
    def search_services(self, 
                       health_status: Optional[HealthStatus] = None,
                       min_health_score: Optional[float] = None) -> List[str]:
        """Busca serviços por critérios"""
        with self.cache_lock:
            services = list(self.metrics_cache.keys())
        
        if health_status:
            services = [s for s in services 
                       if self.metrics_cache[s].health_status == health_status]
        
        if min_health_score is not None:
            services = [s for s in services 
                       if self._calculate_health_score(
                           {'response_time_p95': self.metrics_cache[s].response_time_p95, 
                            'error_rate': self.metrics_cache[s].error_rate, 
                            'status': self.metrics_cache[s].circuit_breaker_status},
                           {'compliance_percentage': self.metrics_cache[s].sla_compliance},
                           {'total_impact': self.metrics_cache[s].financial_impact}
                       ) >= min_health_score]
        
        return services
    
    def get_health_trends(self, service_name: str, hours: int = 24) -> Dict[str, List[float]]:
        """Obtém tendências de saúde de um serviço"""
        # Implementação simplificada - em produção seria baseada em histórico real
        import random
        
        trends = {
            'health_score': [],
            'response_time': [],
            'error_rate': [],
            'sla_compliance': []
        }
        
        for i in range(hours):
            trends['health_score'].append(random.uniform(80, 100))
            trends['response_time'].append(random.uniform(50, 300))
            trends['error_rate'].append(random.uniform(0, 5))
            trends['sla_compliance'].append(random.uniform(95, 100))
        
        return trends
    
    def __str__(self) -> str:
        """Representação string do dashboard"""
        summary = self.get_dashboard_summary()
        return f"""IntegrationHealthDashboard(
    tracing_id={self.tracing_id},
    total_services={summary.total_services},
    healthy_services={summary.healthy_services},
    critical_services={summary.critical_services},
    overall_health_score={summary.overall_health_score:.2f},
    total_alerts={summary.total_alerts}
)"""


# Função de conveniência para uso rápido
def get_integration_health_dashboard(config_path: Optional[str] = None) -> IntegrationHealthDashboard:
    """
    Função de conveniência para obter dashboard de saúde das integrações
    
    Args:
        config_path: Caminho para arquivo de configuração (opcional)
    
    Returns:
        IntegrationHealthDashboard configurado
    """
    return IntegrationHealthDashboard(config_path)


if __name__ == "__main__":
    # Exemplo de uso
    dashboard = IntegrationHealthDashboard()
    
    # Aguardar algumas atualizações
    time.sleep(10)
    
    # Obter resumo
    summary = dashboard.get_dashboard_summary()
    print(f"Resumo do Dashboard:")
    print(f"  Total de serviços: {summary.total_services}")
    print(f"  Serviços saudáveis: {summary.healthy_services}")
    print(f"  Serviços críticos: {summary.critical_services}")
    print(f"  Score geral: {summary.overall_health_score:.2f}")
    print(f"  Total de alertas: {summary.total_alerts}")
    
    # Obter métricas de um serviço
    service_metrics = dashboard.get_service_metrics("openai")
    if service_metrics:
        print(f"\nMétricas do OpenAI:")
        print(f"  Status: {service_metrics.health_status.value}")
        print(f"  Response Time P95: {service_metrics.response_time_p95:.2f}ms")
        print(f"  Error Rate: {service_metrics.error_rate:.2f}%")
        print(f"  SLA Compliance: {service_metrics.sla_compliance:.2f}%")
    
    # Obter alertas
    alerts = dashboard.get_alerts(severity=AlertSeverity.CRITICAL)
    print(f"\nAlertas críticos: {len(alerts)}")
    for alert in alerts[:3]:  # Mostrar apenas os 3 primeiros
        print(f"  {alert.title}: {alert.message}")
    
    # Exportar dados
    export_data = dashboard.export_dashboard_data()
    print(f"\nDados exportados (primeiros 500 chars):")
    print(export_data[:500] + "...") 