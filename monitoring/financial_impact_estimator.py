"""
Financial Impact Estimation System
==================================

Sistema para estimar impacto financeiro de falhas e retries em integrações externas.

Tracing ID: FIN_IMPACT_20250127_001
Prompt: checklist_integracao_externa.md - Item 12
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:00:00Z

Baseado em:
- Site Reliability Engineering (SRE) - Google
- FinOps Framework - Cloud Financial Management
- Observability Engineering - Charity Majors
- Cost Optimization Best Practices - AWS/Azure/GCP
"""

import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from threading import Lock, Thread
import asyncio

from shared.feature_flags import FeatureFlags
from shared.config import Config
from monitoring.circuit_breaker_metrics import CircuitBreakerMetrics
from monitoring.sla_compliance_checker import SLAComplianceChecker


class CostType(Enum):
    """Tipos de custo para análise financeira."""
    INFRASTRUCTURE = "infrastructure"
    DEVELOPMENT = "development"
    SUPPORT = "support"
    REVENUE_LOSS = "revenue_loss"
    OPPORTUNITY = "opportunity_cost"
    COMPLIANCE = "compliance_penalty"


class ImpactSeverity(Enum):
    """Severidade do impacto financeiro."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CostConfiguration:
    """Configuração de custos para diferentes cenários."""
    # Custos de infraestrutura por hora
    compute_cost_per_hour: Decimal = Decimal("0.50")
    storage_cost_per_gb_month: Decimal = Decimal("0.10")
    network_cost_per_gb: Decimal = Decimal("0.08")
    
    # Custos de desenvolvimento
    developer_hourly_rate: Decimal = Decimal("75.00")
    incident_response_hours: Decimal = Decimal("4.00")
    
    # Custos de suporte
    support_ticket_cost: Decimal = Decimal("25.00")
    customer_churn_penalty: Decimal = Decimal("500.00")
    
    # Custos de compliance
    sla_violation_penalty: Decimal = Decimal("1000.00")
    security_incident_cost: Decimal = Decimal("5000.00")
    
    # Taxa de conversão para perda de receita
    conversion_rate: Decimal = Decimal("0.02")
    average_order_value: Decimal = Decimal("50.00")


@dataclass
class FinancialImpact:
    """Resultado da análise de impacto financeiro."""
    incident_id: str
    timestamp: datetime
    service_name: str
    failure_type: str
    duration_minutes: int
    affected_requests: int
    retry_count: int
    
    # Custos calculados
    infrastructure_cost: Decimal
    development_cost: Decimal
    support_cost: Decimal
    revenue_loss: Decimal
    opportunity_cost: Decimal
    compliance_cost: Decimal
    
    # Totais
    total_direct_cost: Decimal
    total_indirect_cost: Decimal
    total_cost: Decimal
    
    # Métricas
    cost_per_request: Decimal
    cost_per_minute: Decimal
    roi_impact: Decimal
    
    # Severidade
    severity: ImpactSeverity
    recommendations: List[str]
    
    # Metadados
    environment: str
    tracing_id: str


class FinancialImpactEstimator:
    """
    Estimador de impacto financeiro para falhas e retries.
    
    Integra com:
    - Circuit Breaker Metrics
    - SLA Compliance Checker
    - Feature Flags
    - Configuração de custos
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Inicializa o estimador de impacto financeiro."""
        self.config = config or Config()
        self.feature_flags = FeatureFlags()
        self.circuit_breaker_metrics = CircuitBreakerMetrics()
        self.sla_checker = SLAComplianceChecker()
        
        # Configuração de custos
        self.cost_config = self._load_cost_configuration()
        
        # Cache de impactos
        self.impact_cache: Dict[str, FinancialImpact] = {}
        self.cache_lock = Lock()
        
        # Métricas agregadas
        self.daily_costs: Dict[str, Decimal] = {}
        self.monthly_totals: Dict[str, Decimal] = {}
        
        # Thread de monitoramento
        self.monitoring_thread = None
        self.should_monitor = True
        
        # Logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Iniciar monitoramento se feature flag ativo
        if self.feature_flags.is_enabled("financial_impact_monitoring"):
            self._start_monitoring()
    
    def _load_cost_configuration(self) -> CostConfiguration:
        """Carrega configuração de custos do ambiente."""
        try:
            # Tentar carregar configuração customizada
            config_path = self.config.get("financial_impact.cost_config_path")
            if config_path and self.config.file_exists(config_path):
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                    return CostConfiguration(**config_data)
            
            # Configuração padrão baseada no ambiente
            env = self.config.get("ENVIRONMENT", "development")
            
            if env == "production":
                return CostConfiguration(
                    compute_cost_per_hour=Decimal("2.00"),
                    developer_hourly_rate=Decimal("100.00"),
                    sla_violation_penalty=Decimal("2000.00"),
                    customer_churn_penalty=Decimal("1000.00")
                )
            elif env == "staging":
                return CostConfiguration(
                    compute_cost_per_hour=Decimal("1.00"),
                    developer_hourly_rate=Decimal("75.00"),
                    sla_violation_penalty=Decimal("500.00")
                )
            else:
                # Development - custos reduzidos
                return CostConfiguration(
                    compute_cost_per_hour=Decimal("0.10"),
                    developer_hourly_rate=Decimal("50.00"),
                    sla_violation_penalty=Decimal("0.00")
                )
                
        except Exception as e:
            self.logger.warning(f"Erro ao carregar configuração de custos: {e}")
            return CostConfiguration()
    
    def estimate_incident_impact(
        self,
        service_name: str,
        failure_type: str,
        duration_minutes: int,
        affected_requests: int,
        retry_count: int,
        incident_id: Optional[str] = None,
        tracing_id: Optional[str] = None
    ) -> FinancialImpact:
        """
        Estima o impacto financeiro de um incidente.
        
        Args:
            service_name: Nome do serviço afetado
            failure_type: Tipo de falha (timeout, error, circuit_open, etc.)
            duration_minutes: Duração do incidente em minutos
            affected_requests: Número de requisições afetadas
            retry_count: Número de retries realizados
            incident_id: ID único do incidente
            tracing_id: ID de rastreamento
            
        Returns:
            FinancialImpact com análise completa
        """
        incident_id = incident_id or f"incident_{int(time.time())}"
        tracing_id = tracing_id or f"fin_impact_{int(time.time())}"
        
        # Validar falsos positivos
        if self._is_false_positive(service_name, failure_type, duration_minutes):
            self.logger.info(f"Falso positivo detectado para {service_name}: {failure_type}")
            return self._create_minimal_impact(
                incident_id, service_name, failure_type, tracing_id
            )
        
        # Calcular custos por categoria
        infrastructure_cost = self._calculate_infrastructure_cost(
            duration_minutes, affected_requests, retry_count
        )
        
        development_cost = self._calculate_development_cost(
            failure_type, duration_minutes
        )
        
        support_cost = self._calculate_support_cost(
            affected_requests, failure_type
        )
        
        revenue_loss = self._calculate_revenue_loss(
            affected_requests, duration_minutes
        )
        
        opportunity_cost = self._calculate_opportunity_cost(
            affected_requests, duration_minutes
        )
        
        compliance_cost = self._calculate_compliance_cost(
            service_name, failure_type, duration_minutes
        )
        
        # Calcular totais
        total_direct_cost = infrastructure_cost + development_cost + support_cost
        total_indirect_cost = revenue_loss + opportunity_cost + compliance_cost
        total_cost = total_direct_cost + total_indirect_cost
        
        # Calcular métricas
        cost_per_request = total_cost / affected_requests if affected_requests > 0 else Decimal("0")
        cost_per_minute = total_cost / duration_minutes if duration_minutes > 0 else Decimal("0")
        roi_impact = self._calculate_roi_impact(total_cost, duration_minutes)
        
        # Determinar severidade
        severity = self._determine_severity(total_cost, affected_requests, duration_minutes)
        
        # Gerar recomendações
        recommendations = self._generate_recommendations(
            failure_type, total_cost, severity, affected_requests
        )
        
        # Criar impacto financeiro
        impact = FinancialImpact(
            incident_id=incident_id,
            timestamp=datetime.utcnow(),
            service_name=service_name,
            failure_type=failure_type,
            duration_minutes=duration_minutes,
            affected_requests=affected_requests,
            retry_count=retry_count,
            infrastructure_cost=infrastructure_cost,
            development_cost=development_cost,
            support_cost=support_cost,
            revenue_loss=revenue_loss,
            opportunity_cost=opportunity_cost,
            compliance_cost=compliance_cost,
            total_direct_cost=total_direct_cost,
            total_indirect_cost=total_indirect_cost,
            total_cost=total_cost,
            cost_per_request=cost_per_request,
            cost_per_minute=cost_per_minute,
            roi_impact=roi_impact,
            severity=severity,
            recommendations=recommendations,
            environment=self.config.get("ENVIRONMENT", "unknown"),
            tracing_id=tracing_id
        )
        
        # Cache e logging
        with self.cache_lock:
            self.impact_cache[incident_id] = impact
        
        self.logger.info(
            f"Impacto financeiro calculado: {incident_id} - "
            f"Total: ${total_cost:.2f}, Severidade: {severity.value}",
            extra={
                "tracing_id": tracing_id,
                "incident_id": incident_id,
                "total_cost": float(total_cost),
                "severity": severity.value
            }
        )
        
        return impact
    
    def _is_false_positive(
        self, service_name: str, failure_type: str, duration_minutes: int
    ) -> bool:
        """Valida se o incidente é um falso positivo."""
        env = self.config.get("ENVIRONMENT", "development")
        
        # Em desenvolvimento, incidentes curtos são provavelmente falsos positivos
        if env == "development" and duration_minutes < 5:
            return True
        
        # Testes e serviços de desenvolvimento
        if any(keyword in service_name.lower() for keyword in ["test", "mock", "dev", "staging"]):
            return True
        
        # Falhas esperadas em desenvolvimento
        if env == "development" and failure_type in ["timeout", "rate_limit"]:
            return True
        
        return False
    
    def _create_minimal_impact(
        self, incident_id: str, service_name: str, failure_type: str, tracing_id: str
    ) -> FinancialImpact:
        """Cria impacto mínimo para falsos positivos."""
        return FinancialImpact(
            incident_id=incident_id,
            timestamp=datetime.utcnow(),
            service_name=service_name,
            failure_type=failure_type,
            duration_minutes=0,
            affected_requests=0,
            retry_count=0,
            infrastructure_cost=Decimal("0"),
            development_cost=Decimal("0"),
            support_cost=Decimal("0"),
            revenue_loss=Decimal("0"),
            opportunity_cost=Decimal("0"),
            compliance_cost=Decimal("0"),
            total_direct_cost=Decimal("0"),
            total_indirect_cost=Decimal("0"),
            total_cost=Decimal("0"),
            cost_per_request=Decimal("0"),
            cost_per_minute=Decimal("0"),
            roi_impact=Decimal("0"),
            severity=ImpactSeverity.LOW,
            recommendations=["Falso positivo detectado - sem ação necessária"],
            environment=self.config.get("ENVIRONMENT", "unknown"),
            tracing_id=tracing_id
        )
    
    def _calculate_infrastructure_cost(
        self, duration_minutes: int, affected_requests: int, retry_count: int
    ) -> Decimal:
        """Calcula custo de infraestrutura."""
        hours = Decimal(str(duration_minutes)) / Decimal("60")
        
        # Custo de computação
        compute_cost = self.cost_config.compute_cost_per_hour * hours
        
        # Custo de rede (estimativa baseada em requisições)
        network_gb = Decimal(str(affected_requests)) * Decimal("0.001")  # 1KB por requisição
        network_cost = self.cost_config.network_cost_per_gb * network_gb
        
        # Custo adicional de retries
        retry_cost = Decimal(str(retry_count)) * Decimal("0.01")
        
        return compute_cost + network_cost + retry_cost
    
    def _calculate_development_cost(
        self, failure_type: str, duration_minutes: int
    ) -> Decimal:
        """Calcula custo de desenvolvimento."""
        # Tempo de resposta ao incidente
        response_hours = self.cost_config.incident_response_hours
        
        # Ajuste baseado no tipo de falha
        if failure_type in ["circuit_open", "timeout"]:
            response_hours *= Decimal("0.5")  # Falhas conhecidas
        elif failure_type in ["security", "compliance"]:
            response_hours *= Decimal("2.0")  # Falhas críticas
        
        return self.cost_config.developer_hourly_rate * response_hours
    
    def _calculate_support_cost(
        self, affected_requests: int, failure_type: str
    ) -> Decimal:
        """Calcula custo de suporte."""
        # Estimativa de tickets de suporte
        support_tickets = max(1, affected_requests // 100)  # 1 ticket a cada 100 requisições
        
        # Custo base de tickets
        ticket_cost = self.cost_config.support_ticket_cost * Decimal(str(support_tickets))
        
        # Custo de churn de clientes
        churn_probability = Decimal("0.001")  # 0.1% de churn por incidente
        churn_cost = self.cost_config.customer_churn_penalty * churn_probability
        
        return ticket_cost + churn_cost
    
    def _calculate_revenue_loss(
        self, affected_requests: int, duration_minutes: int
    ) -> Decimal:
        """Calcula perda de receita."""
        # Estimativa de conversões perdidas
        lost_conversions = Decimal(str(affected_requests)) * self.cost_config.conversion_rate
        
        # Receita perdida
        revenue_loss = lost_conversions * self.cost_config.average_order_value
        
        # Ajuste por duração
        duration_factor = Decimal(str(duration_minutes)) / Decimal("60")  # Por hora
        revenue_loss *= duration_factor
        
        return revenue_loss
    
    def _calculate_opportunity_cost(
        self, affected_requests: int, duration_minutes: int
    ) -> Decimal:
        """Calcula custo de oportunidade."""
        # Custo de oportunidade baseado em tempo de inatividade
        hourly_rate = self.cost_config.developer_hourly_rate
        opportunity_cost = hourly_rate * (Decimal(str(duration_minutes)) / Decimal("60"))
        
        # Multiplicador baseado no volume de requisições
        volume_factor = min(Decimal("5.0"), Decimal(str(affected_requests)) / Decimal("1000"))
        opportunity_cost *= volume_factor
        
        return opportunity_cost
    
    def _calculate_compliance_cost(
        self, service_name: str, failure_type: str, duration_minutes: int
    ) -> Decimal:
        """Calcula custo de compliance."""
        compliance_cost = Decimal("0")
        
        # Verificar violações de SLA
        sla_violations = self.sla_checker.get_recent_violations(service_name, hours=1)
        if sla_violations:
            compliance_cost += self.cost_config.sla_violation_penalty
        
        # Custos de segurança
        if failure_type in ["security", "authentication", "authorization"]:
            compliance_cost += self.cost_config.security_incident_cost
        
        # Ajuste por duração
        if duration_minutes > 60:  # Mais de 1 hora
            compliance_cost *= Decimal("1.5")
        
        return compliance_cost
    
    def _calculate_roi_impact(self, total_cost: Decimal, duration_minutes: int) -> Decimal:
        """Calcula impacto no ROI."""
        # ROI negativo baseado no custo do incidente
        # Quanto maior o custo, maior o impacto negativo no ROI
        roi_impact = -(total_cost / Decimal("1000"))  # Impacto por $1000
        
        return roi_impact
    
    def _determine_severity(
        self, total_cost: Decimal, affected_requests: int, duration_minutes: int
    ) -> ImpactSeverity:
        """Determina severidade do impacto financeiro."""
        if total_cost > Decimal("10000") or affected_requests > 10000 or duration_minutes > 120:
            return ImpactSeverity.CRITICAL
        elif total_cost > Decimal("1000") or affected_requests > 1000 or duration_minutes > 60:
            return ImpactSeverity.HIGH
        elif total_cost > Decimal("100") or affected_requests > 100 or duration_minutes > 30:
            return ImpactSeverity.MEDIUM
        else:
            return ImpactSeverity.LOW
    
    def _generate_recommendations(
        self, failure_type: str, total_cost: Decimal, severity: ImpactSeverity, affected_requests: int
    ) -> List[str]:
        """Gera recomendações baseadas no impacto."""
        recommendations = []
        
        if severity in [ImpactSeverity.HIGH, ImpactSeverity.CRITICAL]:
            recommendations.append("Implementar circuit breaker mais agressivo")
            recommendations.append("Adicionar fallback mechanisms")
            recommendations.append("Revisar estratégia de retry")
        
        if total_cost > Decimal("1000"):
            recommendations.append("Considerar redundância de serviços")
            recommendations.append("Implementar cache distribuído")
        
        if affected_requests > 1000:
            recommendations.append("Otimizar rate limiting")
            recommendations.append("Implementar load balancing")
        
        if failure_type in ["timeout", "circuit_open"]:
            recommendations.append("Ajustar timeouts de integração")
            recommendations.append("Implementar health checks proativos")
        
        if not recommendations:
            recommendations.append("Monitorar tendências para otimização futura")
        
        return recommendations
    
    def get_daily_summary(self, date: Optional[datetime] = None) -> Dict[str, Any]:
        """Obtém resumo financeiro diário."""
        date = date or datetime.utcnow().date()
        date_key = date.strftime("%Y-%m-%d")
        
        # Filtrar impactos do dia
        daily_impacts = [
            impact for impact in self.impact_cache.values()
            if impact.timestamp.date() == date
        ]
        
        if not daily_impacts:
            return {
                "date": date_key,
                "total_incidents": 0,
                "total_cost": 0.0,
                "cost_breakdown": {},
                "severity_distribution": {},
                "recommendations": []
            }
        
        # Calcular totais
        total_cost = sum(impact.total_cost for impact in daily_impacts)
        total_incidents = len(daily_impacts)
        
        # Breakdown por categoria
        cost_breakdown = {
            "infrastructure": sum(impact.infrastructure_cost for impact in daily_impacts),
            "development": sum(impact.development_cost for impact in daily_impacts),
            "support": sum(impact.support_cost for impact in daily_impacts),
            "revenue_loss": sum(impact.revenue_loss for impact in daily_impacts),
            "opportunity": sum(impact.opportunity_cost for impact in daily_impacts),
            "compliance": sum(impact.compliance_cost for impact in daily_impacts)
        }
        
        # Distribuição de severidade
        severity_distribution = {}
        for impact in daily_impacts:
            severity = impact.severity.value
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # Recomendações consolidadas
        all_recommendations = []
        for impact in daily_impacts:
            all_recommendations.extend(impact.recommendations)
        
        # Remover duplicatas e contar frequência
        recommendation_counts = {}
        for rec in all_recommendations:
            recommendation_counts[rec] = recommendation_counts.get(rec, 0) + 1
        
        # Top 5 recomendações
        top_recommendations = sorted(
            recommendation_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        return {
            "date": date_key,
            "total_incidents": total_incidents,
            "total_cost": float(total_cost),
            "cost_breakdown": {k: float(v) for k, v in cost_breakdown.items()},
            "severity_distribution": severity_distribution,
            "top_recommendations": [{"recommendation": rec, "count": count} 
                                  for rec, count in top_recommendations]
        }
    
    def get_monthly_report(self, year: int, month: int) -> Dict[str, Any]:
        """Gera relatório financeiro mensal."""
        # Filtrar impactos do mês
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)
        
        monthly_impacts = [
            impact for impact in self.impact_cache.values()
            if start_date <= impact.timestamp < end_date
        ]
        
        if not monthly_impacts:
            return {
                "year": year,
                "month": month,
                "total_incidents": 0,
                "total_cost": 0.0,
                "daily_average": 0.0,
                "cost_trends": [],
                "top_services": [],
                "roi_analysis": {}
            }
        
        # Métricas básicas
        total_cost = sum(impact.total_cost for impact in monthly_impacts)
        total_incidents = len(monthly_impacts)
        daily_average = total_cost / 30  # Assumindo 30 dias
        
        # Tendências diárias
        daily_costs = {}
        for impact in monthly_impacts:
            day = impact.timestamp.strftime("%Y-%m-%d")
            daily_costs[day] = daily_costs.get(day, Decimal("0")) + impact.total_cost
        
        cost_trends = [
            {"date": day, "cost": float(cost)}
            for day, cost in sorted(daily_costs.items())
        ]
        
        # Top serviços por custo
        service_costs = {}
        for impact in monthly_impacts:
            service = impact.service_name
            service_costs[service] = service_costs.get(service, Decimal("0")) + impact.total_cost
        
        top_services = [
            {"service": service, "cost": float(cost)}
            for service, cost in sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Análise de ROI
        total_roi_impact = sum(impact.roi_impact for impact in monthly_impacts)
        avg_incident_cost = total_cost / total_incidents if total_incidents > 0 else Decimal("0")
        
        roi_analysis = {
            "total_roi_impact": float(total_roi_impact),
            "average_incident_cost": float(avg_incident_cost),
            "cost_per_day": float(daily_average),
            "incidents_per_day": total_incidents / 30
        }
        
        return {
            "year": year,
            "month": month,
            "total_incidents": total_incidents,
            "total_cost": float(total_cost),
            "daily_average": float(daily_average),
            "cost_trends": cost_trends,
            "top_services": top_services,
            "roi_analysis": roi_analysis
        }
    
    def _start_monitoring(self):
        """Inicia thread de monitoramento contínuo."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.monitoring_thread = Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("Monitoramento financeiro iniciado")
    
    def _monitoring_loop(self):
        """Loop de monitoramento contínuo."""
        while self.should_monitor:
            try:
                # Analisar métricas de circuit breaker
                circuit_metrics = self.circuit_breaker_metrics.get_health_summary()
                
                for service, metrics in circuit_metrics.items():
                    if metrics.get("failure_rate", 0) > 0.1:  # 10% de falha
                        # Estimar impacto
                        self.estimate_incident_impact(
                            service_name=service,
                            failure_type="circuit_breaker",
                            duration_minutes=metrics.get("failure_duration_minutes", 5),
                            affected_requests=metrics.get("failed_requests", 100),
                            retry_count=metrics.get("retry_count", 0)
                        )
                
                # Limpar cache antigo (manter 30 dias)
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                with self.cache_lock:
                    old_incidents = [
                        incident_id for incident_id, impact in self.impact_cache.items()
                        if impact.timestamp < cutoff_date
                    ]
                    for incident_id in old_incidents:
                        del self.impact_cache[incident_id]
                
                time.sleep(300)  # Verificar a cada 5 minutos
                
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(60)  # Aguardar 1 minuto em caso de erro
    
    def stop_monitoring(self):
        """Para o monitoramento contínuo."""
        self.should_monitor = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("Monitoramento financeiro parado")
    
    def export_data(self, format: str = "json") -> str:
        """Exporta dados de impacto financeiro."""
        if format.lower() == "json":
            data = {
                "impacts": [asdict(impact) for impact in self.impact_cache.values()],
                "export_timestamp": datetime.utcnow().isoformat(),
                "total_impacts": len(self.impact_cache)
            }
            
            # Converter Decimal para float para serialização
            def convert_decimals(obj):
                if isinstance(obj, dict):
                    return {k: convert_decimals(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_decimals(item) for item in obj]
                elif isinstance(obj, Decimal):
                    return float(obj)
                elif isinstance(obj, datetime):
                    return obj.isoformat()
                elif isinstance(obj, ImpactSeverity):
                    return obj.value
                else:
                    return obj
            
            data = convert_decimals(data)
            return json.dumps(data, indent=2)
        
        else:
            raise ValueError(f"Formato não suportado: {format}")


# Instância global
financial_impact_estimator = FinancialImpactEstimator() 