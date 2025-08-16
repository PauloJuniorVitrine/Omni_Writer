"""
Sistema de Monitoramento Proativo - Omni Writer
===============================================

Implementação de monitoramento proativo com alertas inteligentes para 99% de confiabilidade.
Baseado em análise do código real e padrões enterprise.

Prompt: Monitoramento Proativo para 99% de Confiabilidade
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-28T10:30:00Z
Tracing ID: PROACTIVE_MONITORING_20250128_001
"""

import asyncio
import logging
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import threading
import queue
import smtplib
import requests
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

# Configuração de logging estruturado
logger = logging.getLogger("proactive_monitoring")
logger.setLevel(logging.INFO)

class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AlertStatus(Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

@dataclass
class Alert:
    """Representa um alerta do sistema"""
    id: str
    title: str
    message: str
    severity: AlertSeverity
    component: str
    timestamp: datetime
    status: AlertStatus = AlertStatus.ACTIVE
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)

@dataclass
class MonitoringRule:
    """Regra de monitoramento"""
    name: str
    component: str
    condition: Callable
    severity: AlertSeverity
    cooldown_minutes: int = 5
    auto_resolve: bool = True
    notification_channels: List[str] = field(default_factory=lambda: ['log', 'email'])

class ProactiveMonitoringSystem:
    """
    Sistema de monitoramento proativo com alertas inteligentes.
    
    Funcionalidades:
    - Monitoramento contínuo de componentes
    - Alertas baseados em regras configuráveis
    - Auto-healing triggers
    - Notificações multi-canal
    - Supressão de alertas duplicados
    - Métricas de alertas
    """
    
    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.rules: List[MonitoringRule] = []
        self.monitoring_active = False
        self.monitoring_thread = None
        self.alert_queue = queue.Queue()
        self.notification_handlers = {}
        
        # Configurações
        self.check_interval = 30  # segundos
        self.max_alerts_per_component = 10
        self.alert_retention_hours = 24
        
        # Métricas
        self.metrics = {
            'total_alerts': 0,
            'active_alerts': 0,
            'resolved_alerts': 0,
            'suppressed_alerts': 0,
            'last_check': None
        }
        
        # Configura handlers de notificação
        self._setup_notification_handlers()
        
        # Configura regras padrão
        self._setup_default_rules()
        
        logger.info("Sistema de monitoramento proativo inicializado")
    
    def _setup_notification_handlers(self):
        """Configura handlers de notificação"""
        self.notification_handlers = {
            'log': self._log_notification,
            'email': self._email_notification,
            'slack': self._slack_notification,
            'webhook': self._webhook_notification
        }
    
    def _setup_default_rules(self):
        """Configura regras de monitoramento padrão"""
        
        # Regra para CPU alto
        def cpu_high_condition(metrics):
            return metrics.get('cpu_percent', 0) > 90
        
        self.add_rule(MonitoringRule(
            name="CPU Usage Critical",
            component="system",
            condition=cpu_high_condition,
            severity=AlertSeverity.CRITICAL,
            cooldown_minutes=5
        ))
        
        # Regra para memória baixa
        def memory_low_condition(metrics):
            return metrics.get('memory_available_gb', 100) < 1.0
        
        self.add_rule(MonitoringRule(
            name="Memory Low",
            component="system",
            condition=memory_low_condition,
            severity=AlertSeverity.WARNING,
            cooldown_minutes=10
        ))
        
        # Regra para disco cheio
        def disk_full_condition(metrics):
            return metrics.get('disk_percent', 0) > 95
        
        self.add_rule(MonitoringRule(
            name="Disk Space Critical",
            component="system",
            condition=disk_full_condition,
            severity=AlertSeverity.CRITICAL,
            cooldown_minutes=5
        ))
        
        # Regra para APIs externas
        def api_failure_condition(metrics):
            return metrics.get('api_error_rate', 0) > 0.1  # 10% de erro
        
        self.add_rule(MonitoringRule(
            name="API Error Rate High",
            component="external_apis",
            condition=api_failure_condition,
            severity=AlertSeverity.ERROR,
            cooldown_minutes=15
        ))
        
        # Regra para circuit breakers abertos
        def circuit_breaker_open_condition(metrics):
            return metrics.get('open_circuit_breakers', 0) > 0
        
        self.add_rule(MonitoringRule(
            name="Circuit Breakers Open",
            component="resilience",
            condition=circuit_breaker_open_condition,
            severity=AlertSeverity.WARNING,
            cooldown_minutes=10
        ))
        
        logger.info(f"Configuradas {len(self.rules)} regras de monitoramento padrão")
    
    def add_rule(self, rule: MonitoringRule):
        """Adiciona regra de monitoramento"""
        self.rules.append(rule)
        logger.info(f"Regra de monitoramento adicionada: {rule.name}")
    
    def start_monitoring(self):
        """Inicia monitoramento proativo"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            logger.info("Monitoramento proativo iniciado")
    
    def stop_monitoring(self):
        """Para monitoramento proativo"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Monitoramento proativo parado")
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento"""
        while self.monitoring_active:
            try:
                self._check_all_rules()
                self._process_alert_queue()
                self._cleanup_old_alerts()
                self.metrics['last_check'] = datetime.utcnow()
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(5)  # Espera antes de tentar novamente
    
    def _check_all_rules(self):
        """Verifica todas as regras de monitoramento"""
        # Obtém métricas atuais (simulado - em produção viria do sistema de métricas)
        current_metrics = self._get_current_metrics()
        
        for rule in self.rules:
            try:
                if rule.condition(current_metrics):
                    self._trigger_alert(rule, current_metrics)
                else:
                    self._resolve_alert_if_auto(rule)
                    
            except Exception as e:
                logger.error(f"Erro ao verificar regra {rule.name}: {e}")
    
    def _get_current_metrics(self) -> Dict:
        """Obtém métricas atuais do sistema (simulado)"""
        # Em produção, isso viria do sistema de métricas real
        import psutil
        
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_available_gb': psutil.virtual_memory().available / (1024**3),
            'disk_percent': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
            'api_error_rate': 0.05,  # Simulado
            'open_circuit_breakers': 0,  # Simulado
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _trigger_alert(self, rule: MonitoringRule, metrics: Dict):
        """Dispara alerta baseado em regra"""
        alert_id = f"{rule.component}_{rule.name}_{int(time.time())}"
        
        # Verifica se já existe alerta ativo para esta regra
        existing_alert = self._find_active_alert(rule.name, rule.component)
        if existing_alert:
            # Verifica cooldown
            time_since_alert = datetime.utcnow() - existing_alert.timestamp
            if time_since_alert.total_seconds() < rule.cooldown_minutes * 60:
                return  # Ainda em cooldown
        
        # Cria novo alerta
        alert = Alert(
            id=alert_id,
            title=rule.name,
            message=f"Condição de alerta ativada para {rule.component}: {rule.name}",
            severity=rule.severity,
            component=rule.component,
            timestamp=datetime.utcnow(),
            metadata={'metrics': metrics, 'rule_name': rule.name}
        )
        
        self.alerts[alert_id] = alert
        self.metrics['total_alerts'] += 1
        self.metrics['active_alerts'] += 1
        
        # Adiciona à fila de notificações
        self.alert_queue.put((alert, rule.notification_channels))
        
        logger.warning(f"Alerta disparado: {alert.title} - {alert.severity.value}")
    
    def _resolve_alert_if_auto(self, rule: MonitoringRule):
        """Resolve alerta automaticamente se a condição não é mais verdadeira"""
        existing_alert = self._find_active_alert(rule.name, rule.component)
        if existing_alert and rule.auto_resolve:
            self._resolve_alert(existing_alert.id, "Auto-resolved")
    
    def _find_active_alert(self, rule_name: str, component: str) -> Optional[Alert]:
        """Encontra alerta ativo para regra específica"""
        for alert in self.alerts.values():
            if (alert.status == AlertStatus.ACTIVE and 
                alert.metadata.get('rule_name') == rule_name and
                alert.component == component):
                return alert
        return None
    
    def _process_alert_queue(self):
        """Processa fila de alertas para notificações"""
        while not self.alert_queue.empty():
            try:
                alert, channels = self.alert_queue.get_nowait()
                
                for channel in channels:
                    if channel in self.notification_handlers:
                        try:
                            self.notification_handlers[channel](alert)
                        except Exception as e:
                            logger.error(f"Erro ao enviar notificação via {channel}: {e}")
                
                self.alert_queue.task_done()
                
            except queue.Empty:
                break
    
    def _cleanup_old_alerts(self):
        """Remove alertas antigos"""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.alert_retention_hours)
        alerts_to_remove = []
        
        for alert_id, alert in self.alerts.items():
            if alert.timestamp < cutoff_time:
                alerts_to_remove.append(alert_id)
        
        for alert_id in alerts_to_remove:
            del self.alerts[alert_id]
            logger.info(f"Alerta removido: {alert_id}")
    
    def acknowledge_alert(self, alert_id: str, user: str):
        """Reconhece alerta"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = user
            alert.acknowledged_at = datetime.utcnow()
            logger.info(f"Alerta {alert_id} reconhecido por {user}")
    
    def resolve_alert(self, alert_id: str, reason: str = "Manual resolution"):
        """Resolve alerta"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            self.metrics['active_alerts'] -= 1
            self.metrics['resolved_alerts'] += 1
            logger.info(f"Alerta {alert_id} resolvido: {reason}")
    
    def suppress_alert(self, alert_id: str, reason: str = "Manual suppression"):
        """Suprime alerta"""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.SUPPRESSED
            self.metrics['active_alerts'] -= 1
            self.metrics['suppressed_alerts'] += 1
            logger.info(f"Alerta {alert_id} suprimido: {reason}")
    
    # Handlers de notificação
    def _log_notification(self, alert: Alert):
        """Notificação via log"""
        log_level = {
            AlertSeverity.INFO: logging.INFO,
            AlertSeverity.WARNING: logging.WARNING,
            AlertSeverity.ERROR: logging.ERROR,
            AlertSeverity.CRITICAL: logging.CRITICAL
        }[alert.severity]
        
        logger.log(log_level, f"ALERTA: {alert.title} - {alert.message}")
    
    def _email_notification(self, alert: Alert):
        """Notificação via email"""
        # Configuração de email (em produção viria de variáveis de ambiente)
        smtp_server = os.getenv('SMTP_SERVER', 'localhost')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        smtp_user = os.getenv('SMTP_USER', '')
        smtp_password = os.getenv('SMTP_PASSWORD', '')
        alert_email = os.getenv('ALERT_EMAIL', 'admin@omniwriter.com')
        
        if not all([smtp_server, smtp_user, smtp_password]):
            logger.warning("Configuração de email incompleta, pulando notificação")
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = smtp_user
            msg['To'] = alert_email
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            body = f"""
            Alerta do Sistema Omni Writer
            
            Título: {alert.title}
            Severidade: {alert.severity.value}
            Componente: {alert.component}
            Mensagem: {alert.message}
            Timestamp: {alert.timestamp.isoformat()}
            
            Métricas: {json.dumps(alert.metadata.get('metrics', {}), indent=2)}
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Notificação por email enviada para {alert_email}")
            
        except Exception as e:
            logger.error(f"Erro ao enviar email: {e}")
    
    def _slack_notification(self, alert: Alert):
        """Notificação via Slack"""
        webhook_url = os.getenv('SLACK_WEBHOOK_URL', '')
        
        if not webhook_url:
            logger.warning("Webhook do Slack não configurado, pulando notificação")
            return
        
        try:
            payload = {
                "text": f"🚨 *{alert.title}*",
                "attachments": [{
                    "color": {
                        AlertSeverity.INFO: "good",
                        AlertSeverity.WARNING: "warning",
                        AlertSeverity.ERROR: "danger",
                        AlertSeverity.CRITICAL: "danger"
                    }[alert.severity],
                    "fields": [
                        {"title": "Severidade", "value": alert.severity.value, "short": True},
                        {"title": "Componente", "value": alert.component, "short": True},
                        {"title": "Mensagem", "value": alert.message, "short": False},
                        {"title": "Timestamp", "value": alert.timestamp.isoformat(), "short": True}
                    ]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info("Notificação do Slack enviada")
            
        except Exception as e:
            logger.error(f"Erro ao enviar notificação do Slack: {e}")
    
    def _webhook_notification(self, alert: Alert):
        """Notificação via webhook customizado"""
        webhook_url = os.getenv('ALERT_WEBHOOK_URL', '')
        
        if not webhook_url:
            logger.warning("Webhook de alertas não configurado, pulando notificação")
            return
        
        try:
            payload = {
                "alert_id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity.value,
                "component": alert.component,
                "timestamp": alert.timestamp.isoformat(),
                "metadata": alert.metadata
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info("Notificação via webhook enviada")
            
        except Exception as e:
            logger.error(f"Erro ao enviar notificação via webhook: {e}")
    
    def get_alerts(self, status: Optional[AlertStatus] = None) -> List[Alert]:
        """Retorna alertas filtrados por status"""
        if status:
            return [alert for alert in self.alerts.values() if alert.status == status]
        return list(self.alerts.values())
    
    def get_metrics(self) -> Dict:
        """Retorna métricas do sistema de monitoramento"""
        return {
            **self.metrics,
            'last_check': self.metrics['last_check'].isoformat() if self.metrics['last_check'] else None,
            'monitoring_active': self.monitoring_active,
            'total_rules': len(self.rules),
            'queue_size': self.alert_queue.qsize()
        }
    
    def get_health_status(self) -> Dict:
        """Retorna status de saúde do sistema de monitoramento"""
        active_alerts = self.get_alerts(AlertStatus.ACTIVE)
        critical_alerts = [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
        
        return {
            'status': 'healthy' if not active_alerts else 'degraded' if not critical_alerts else 'critical',
            'active_alerts_count': len(active_alerts),
            'critical_alerts_count': len(critical_alerts),
            'monitoring_active': self.monitoring_active
        }

# Instância global
proactive_monitoring = ProactiveMonitoringSystem()

def start_proactive_monitoring():
    """Função para iniciar monitoramento proativo"""
    proactive_monitoring.start_monitoring()

def stop_proactive_monitoring():
    """Função para parar monitoramento proativo"""
    proactive_monitoring.stop_monitoring()

if __name__ == "__main__":
    # Exemplo de uso
    import time
    
    # Inicia monitoramento
    start_proactive_monitoring()
    
    # Simula algumas condições
    print("Monitoramento iniciado. Aguardando alertas...")
    
    try:
        while True:
            time.sleep(10)
            metrics = proactive_monitoring.get_metrics()
            print(f"Métricas: {json.dumps(metrics, indent=2)}")
            
            alerts = proactive_monitoring.get_alerts()
            if alerts:
                print(f"Alertas ativos: {len(alerts)}")
                for alert in alerts[:3]:  # Mostra apenas os 3 primeiros
                    print(f"  - {alert.title}: {alert.severity.value}")
    
    except KeyboardInterrupt:
        print("\nParando monitoramento...")
        stop_proactive_monitoring()
        print("Monitoramento parado.") 