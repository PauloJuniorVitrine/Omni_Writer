"""
Monitor de performance para Omni Writer.

Prompt: Monitoramento de Performance - IMP-008
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T19:50:00Z
Tracing ID: ENTERPRISE_20250127_008
"""

import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import logging

from prometheus_client import Counter, Histogram, Gauge

from shared.logging_config import get_structured_logger
from monitoring.metrics_collector import metrics_collector


@dataclass
class AlertRule:
    """Regra de alerta."""
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    severity: str  # 'info', 'warning', 'critical'
    message: str
    cooldown_seconds: int = 300  # 5 minutos


@dataclass
class Alert:
    """Alerta gerado."""
    rule_name: str
    severity: str
    message: str
    timestamp: datetime
    metadata: Dict[str, Any]


class PerformanceMonitor:
    """Monitor de performance com alertas automáticos."""
    
    def __init__(self):
        """Inicializa o monitor de performance."""
        self.logger = get_structured_logger(__name__)
        self.alerts_lock = threading.Lock()
        self.active_alerts = deque(maxlen=100)  # Últimos 100 alertas
        self.alert_history = deque(maxlen=1000)  # Histórico de alertas
        
        # Métricas de alertas
        self.alert_counter = Counter(
            'omni_writer_alerts_total',
            'Total de alertas',
            ['severity', 'rule_name']
        )
        
        self.alert_duration = Histogram(
            'omni_writer_alert_duration_seconds',
            'Duração dos alertas',
            ['severity', 'rule_name']
        )
        
        # Regras de alerta
        self.alert_rules = self._setup_alert_rules()
        
        # Thread de monitoramento
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        self.logger.info("Monitor de performance inicializado", extra={
            'tracing_id': 'ENTERPRISE_20250127_008',
            'component': 'performance_monitor',
            'alert_rules_count': len(self.alert_rules)
        })
    
    def _setup_alert_rules(self) -> List[AlertRule]:
        """Configura regras de alerta."""
        rules = []
        
        # Regra: CPU alto
        rules.append(AlertRule(
            name="high_cpu_usage",
            condition=lambda metrics: metrics.get('cpu_usage', 0) > 80,
            severity="warning",
            message="CPU usage is high: {cpu_usage}%",
            cooldown_seconds=300
        ))
        
        # Regra: CPU crítico
        rules.append(AlertRule(
            name="critical_cpu_usage",
            condition=lambda metrics: metrics.get('cpu_usage', 0) > 95,
            severity="critical",
            message="CPU usage is critical: {cpu_usage}%",
            cooldown_seconds=60
        ))
        
        # Regra: Memória alta
        rules.append(AlertRule(
            name="high_memory_usage",
            condition=lambda metrics: metrics.get('memory_usage', 0) > 85,
            severity="warning",
            message="Memory usage is high: {memory_usage}%",
            cooldown_seconds=300
        ))
        
        # Regra: Disco cheio
        rules.append(AlertRule(
            name="disk_space_low",
            condition=lambda metrics: metrics.get('disk_usage', 0) > 90,
            severity="critical",
            message="Disk space is low: {disk_usage}%",
            cooldown_seconds=180
        ))
        
        # Regra: Taxa de erro alta
        rules.append(AlertRule(
            name="high_error_rate",
            condition=lambda metrics: metrics.get('error_rate', 0) > 0.05,  # 5%
            severity="warning",
            message="Error rate is high: {error_rate:.2%}",
            cooldown_seconds=120
        ))
        
        # Regra: Latência alta
        rules.append(AlertRule(
            name="high_latency",
            condition=lambda metrics: metrics.get('avg_latency', 0) > 5.0,  # 5 segundos
            severity="warning",
            message="Average latency is high: {avg_latency:.2f}s",
            cooldown_seconds=180
        ))
        
        # Regra: Workers inativos
        rules.append(AlertRule(
            name="no_active_workers",
            condition=lambda metrics: metrics.get('active_workers', 0) == 0,
            severity="critical",
            message="No active workers detected",
            cooldown_seconds=60
        ))
        
        # Regra: Fila muito grande
        rules.append(AlertRule(
            name="large_queue_size",
            condition=lambda metrics: metrics.get('queue_size', 0) > 100,
            severity="warning",
            message="Queue size is large: {queue_size} items",
            cooldown_seconds=120
        ))
        
        # Regra: Health score baixo
        rules.append(AlertRule(
            name="low_health_score",
            condition=lambda metrics: metrics.get('health_score', 100) < 50,
            severity="critical",
            message="System health score is low: {health_score}",
            cooldown_seconds=120
        ))
        
        # Regra: Cache miss rate alto
        rules.append(AlertRule(
            name="high_cache_miss_rate",
            condition=lambda metrics: metrics.get('cache_miss_rate', 0) > 0.3,  # 30%
            severity="warning",
            message="Cache miss rate is high: {cache_miss_rate:.2%}",
            cooldown_seconds=300
        ))
        
        return rules
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento."""
        while True:
            try:
                # Coleta métricas atuais
                current_metrics = self._collect_current_metrics()
                
                # Avalia regras de alerta
                self._evaluate_alert_rules(current_metrics)
                
                # Limpa alertas antigos
                self._cleanup_old_alerts()
                
                # Aguarda próxima verificação
                time.sleep(30)  # Verifica a cada 30 segundos
                
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}", extra={
                    'tracing_id': 'ENTERPRISE_20250127_008',
                    'component': 'monitoring_loop'
                })
                time.sleep(60)  # Aguarda mais tempo em caso de erro
    
    def _collect_current_metrics(self) -> Dict[str, Any]:
        """Coleta métricas atuais do sistema."""
        try:
            import psutil
            
            # Métricas do sistema
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Health score
            health_score = self._calculate_health_score(cpu_percent, memory.percent, disk.percent)
            
            # Métricas de performance (simuladas - em produção viriam do metrics_collector)
            metrics = {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_usage': disk.percent,
                'health_score': health_score,
                'active_workers': 2,  # Simulado
                'queue_size': 15,     # Simulado
                'error_rate': 0.02,   # Simulado - 2%
                'avg_latency': 1.5,   # Simulado - 1.5s
                'cache_miss_rate': 0.15,  # Simulado - 15%
                'timestamp': datetime.now()
            }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Erro ao coletar métricas atuais: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'collect_metrics'
            })
            return {}
    
    def _calculate_health_score(self, cpu_percent: float, memory_percent: float, disk_percent: float) -> float:
        """Calcula score de saúde do sistema."""
        try:
            # CPU: 0-100%, peso 40%
            cpu_score = max(0, 100 - cpu_percent)
            
            # Memória: 0-100%, peso 35%
            memory_score = max(0, 100 - memory_percent)
            
            # Disco: 0-100%, peso 25%
            disk_score = max(0, 100 - disk_percent)
            
            # Score ponderado
            health_score = (cpu_score * 0.4) + (memory_score * 0.35) + (disk_score * 0.25)
            
            return round(health_score, 2)
            
        except Exception as e:
            self.logger.error(f"Erro ao calcular health score: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'health_score'
            })
            return 0.0
    
    def _evaluate_alert_rules(self, metrics: Dict[str, Any]):
        """Avalia regras de alerta."""
        try:
            for rule in self.alert_rules:
                # Verifica se a regra deve ser avaliada
                if self._should_evaluate_rule(rule, metrics):
                    # Testa a condição
                    if rule.condition(metrics):
                        # Gera alerta
                        self._generate_alert(rule, metrics)
                    else:
                        # Resolve alerta se estava ativo
                        self._resolve_alert(rule.name)
                        
        except Exception as e:
            self.logger.error(f"Erro ao avaliar regras de alerta: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'evaluate_rules'
            })
    
    def _should_evaluate_rule(self, rule: AlertRule, metrics: Dict[str, Any]) -> bool:
        """Verifica se a regra deve ser avaliada (respeitando cooldown)."""
        try:
            with self.alerts_lock:
                # Procura por alerta ativo da mesma regra
                for alert in self.active_alerts:
                    if alert.rule_name == rule.name:
                        # Verifica se ainda está no período de cooldown
                        time_since_alert = (datetime.now() - alert.timestamp).total_seconds()
                        return time_since_alert >= rule.cooldown_seconds
                
                # Se não há alerta ativo, pode avaliar
                return True
                
        except Exception as e:
            self.logger.error(f"Erro ao verificar se regra deve ser avaliada: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'rule_name': rule.name
            })
            return False
    
    def _generate_alert(self, rule: AlertRule, metrics: Dict[str, Any]):
        """Gera um novo alerta."""
        try:
            # Formata mensagem
            message = rule.message.format(**metrics)
            
            # Cria alerta
            alert = Alert(
                rule_name=rule.name,
                severity=rule.severity,
                message=message,
                timestamp=datetime.now(),
                metadata=metrics.copy()
            )
            
            # Adiciona à lista de alertas ativos
            with self.alerts_lock:
                self.active_alerts.append(alert)
                self.alert_history.append(alert)
            
            # Incrementa contador
            self.alert_counter.labels(severity=rule.severity, rule_name=rule.name).inc()
            
            # Log do alerta
            self.logger.warning(f"Alerta gerado: {message}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'alert_rule': rule.name,
                'severity': rule.severity,
                'metrics': metrics
            })
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar alerta: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'rule_name': rule.name
            })
    
    def _resolve_alert(self, rule_name: str):
        """Resolve um alerta (remove da lista de ativos)."""
        try:
            with self.alerts_lock:
                # Remove alertas da regra da lista de ativos
                self.active_alerts = deque(
                    [alert for alert in self.active_alerts if alert.rule_name != rule_name],
                    maxlen=100
                )
                
        except Exception as e:
            self.logger.error(f"Erro ao resolver alerta: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'rule_name': rule_name
            })
    
    def _cleanup_old_alerts(self):
        """Remove alertas antigos do histórico."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=24)  # 24 horas
            
            with self.alerts_lock:
                # Remove alertas antigos do histórico
                self.alert_history = deque(
                    [alert for alert in self.alert_history if alert.timestamp > cutoff_time],
                    maxlen=1000
                )
                
        except Exception as e:
            self.logger.error(f"Erro ao limpar alertas antigos: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'cleanup_alerts'
            })
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Retorna alertas ativos."""
        try:
            with self.alerts_lock:
                return [
                    {
                        'rule_name': alert.rule_name,
                        'severity': alert.severity,
                        'message': alert.message,
                        'timestamp': alert.timestamp.isoformat(),
                        'duration_seconds': (datetime.now() - alert.timestamp).total_seconds()
                    }
                    for alert in self.active_alerts
                ]
                
        except Exception as e:
            self.logger.error(f"Erro ao obter alertas ativos: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'get_active_alerts'
            })
            return []
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Retorna resumo dos alertas."""
        try:
            with self.alerts_lock:
                active_alerts = list(self.active_alerts)
                recent_alerts = [alert for alert in self.alert_history 
                               if alert.timestamp > datetime.now() - timedelta(hours=1)]
                
                # Conta por severidade
                severity_counts = defaultdict(int)
                for alert in active_alerts:
                    severity_counts[alert.severity] += 1
                
                summary = {
                    'active_alerts_count': len(active_alerts),
                    'recent_alerts_count': len(recent_alerts),
                    'severity_distribution': dict(severity_counts),
                    'timestamp': datetime.now().isoformat()
                }
                
                return summary
                
        except Exception as e:
            self.logger.error(f"Erro ao gerar resumo de alertas: {e}", extra={
                'tracing_id': 'ENTERPRISE_20250127_008',
                'component': 'alert_summary'
            })
            return {}


# Instância global do monitor
performance_monitor = PerformanceMonitor() 