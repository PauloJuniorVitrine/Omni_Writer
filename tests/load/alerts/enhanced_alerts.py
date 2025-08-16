"""
Enhanced Early Alerts - Omni Writer
===================================

Sistema de alertas aprimorados com integração multi-canal.
Suporte a Slack, PagerDuty e alertas em tempo real.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 16
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:20:00Z
"""

import os
import json
import time
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Callable
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
from enum import Enum
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import websockets
import ssl

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('enhanced_alerts')

class AlertSeverity(Enum):
    """Níveis de severidade de alerta."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AlertChannel(Enum):
    """Canais de alerta disponíveis."""
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"
    WEBSOCKET = "websocket"
    CONSOLE = "console"

@dataclass
class AlertRule:
    """Regra de alerta."""
    rule_id: str
    name: str
    description: str
    metric: str
    threshold: float
    operator: str  # 'gt', 'lt', 'eq', 'gte', 'lte'
    severity: AlertSeverity
    channels: List[AlertChannel]
    cooldown_minutes: int = 5
    active: bool = True

@dataclass
class Alert:
    """Estrutura de alerta."""
    alert_id: str
    rule_id: str
    severity: AlertSeverity
    message: str
    metric_value: float
    threshold: float
    timestamp: datetime
    acknowledged: bool = False
    acknowledged_by: str = ""
    acknowledged_at: datetime = None

class EnhancedAlertSystem:
    """
    Sistema de alertas aprimorado com múltiplos canais.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/alerts/config.json"):
        """
        Inicializa o sistema de alertas aprimorado.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/alerts/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações de canais
        self.channel_configs = {
            AlertChannel.SLACK: {
                "webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
                "channel": "#load-tests",
                "username": "Load Test Alerts",
                "icon_emoji": ":warning:"
            },
            AlertChannel.PAGERDUTY: {
                "api_key": os.getenv("PAGERDUTY_API_KEY", ""),
                "service_id": os.getenv("PAGERDUTY_SERVICE_ID", ""),
                "escalation_policy": os.getenv("PAGERDUTY_ESCALATION_POLICY", "")
            },
            AlertChannel.EMAIL: {
                "smtp_server": os.getenv("SMTP_SERVER", "smtp.gmail.com"),
                "smtp_port": int(os.getenv("SMTP_PORT", "587")),
                "username": os.getenv("EMAIL_USERNAME", ""),
                "password": os.getenv("EMAIL_PASSWORD", ""),
                "from_email": os.getenv("FROM_EMAIL", ""),
                "to_emails": os.getenv("TO_EMAILS", "").split(",") if os.getenv("TO_EMAILS") else []
            },
            AlertChannel.WEBHOOK: {
                "webhook_url": os.getenv("WEBHOOK_URL", ""),
                "headers": {"Content-Type": "application/json"}
            }
        }
        
        # Regras de alerta
        self.alert_rules: List[AlertRule] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        
        # Configurações do sistema
        self.alert_config = {
            "enable_real_time": True,
            "enable_escalation": True,
            "max_alerts_per_minute": 10,
            "alert_retention_days": 30,
            "suppression_enabled": True,
            "suppression_window_minutes": 15
        }
        
        # Estado do sistema
        self.is_monitoring = False
        self.monitor_thread = None
        self.alert_counters = {}
        self.last_alert_times = {}
        
        # WebSocket para alertas em tempo real
        self.websocket_server = None
        self.websocket_clients = set()
        
        # Carrega configuração
        self.load_config()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")
        logger.info(f"Regras de alerta: {len(self.alert_rules)}")

    def load_config(self) -> None:
        """
        Carrega configuração de alertas.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Carrega regras de alerta
                for rule_data in config.get('alert_rules', []):
                    rule = AlertRule(**rule_data)
                    self.alert_rules.append(rule)
                
                # Carrega configurações
                self.alert_config.update(config.get('alert_config', {}))
                self.channel_configs.update(config.get('channel_configs', {}))
                
                logger.info("Configuração carregada do arquivo")
            else:
                self._create_default_rules()
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")
            self._create_default_rules()

    def _create_default_rules(self) -> None:
        """
        Cria regras de alerta padrão baseadas no código real.
        """
        default_rules = [
            AlertRule(
                rule_id="high_response_time",
                name="High Response Time",
                description="Tempo de resposta médio muito alto",
                metric="response_time_avg",
                threshold=800,
                operator="gt",
                severity=AlertSeverity.WARNING,
                channels=[AlertChannel.SLACK, AlertChannel.EMAIL],
                cooldown_minutes=5
            ),
            AlertRule(
                rule_id="critical_response_time",
                name="Critical Response Time",
                description="Tempo de resposta crítico",
                metric="response_time_avg",
                threshold=2000,
                operator="gt",
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.SLACK, AlertChannel.PAGERDUTY, AlertChannel.EMAIL],
                cooldown_minutes=2
            ),
            AlertRule(
                rule_id="high_error_rate",
                name="High Error Rate",
                description="Taxa de erro muito alta",
                metric="error_rate",
                threshold=0.05,
                operator="gt",
                severity=AlertSeverity.ERROR,
                channels=[AlertChannel.SLACK, AlertChannel.PAGERDUTY],
                cooldown_minutes=3
            ),
            AlertRule(
                rule_id="critical_error_rate",
                name="Critical Error Rate",
                description="Taxa de erro crítica",
                metric="error_rate",
                threshold=0.10,
                operator="gt",
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.SLACK, AlertChannel.PAGERDUTY, AlertChannel.EMAIL],
                cooldown_minutes=1
            ),
            AlertRule(
                rule_id="low_throughput",
                name="Low Throughput",
                description="Throughput muito baixo",
                metric="throughput",
                threshold=10,
                operator="lt",
                severity=AlertSeverity.WARNING,
                channels=[AlertChannel.SLACK],
                cooldown_minutes=5
            ),
            AlertRule(
                rule_id="system_overload",
                name="System Overload",
                description="Sistema sobrecarregado",
                metric="cpu_usage",
                threshold=90,
                operator="gt",
                severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.SLACK, AlertChannel.PAGERDUTY, AlertChannel.EMAIL],
                cooldown_minutes=2
            )
        ]
        
        self.alert_rules = default_rules

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'alert_rules': [asdict(rule) for rule in self.alert_rules],
                'alert_config': self.alert_config,
                'channel_configs': self.channel_configs,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def evaluate_alert_rules(self, metrics: Dict[str, float]) -> List[Alert]:
        """
        Avalia regras de alerta contra métricas atuais.
        """
        triggered_alerts = []
        
        for rule in self.alert_rules:
            if not rule.active:
                continue
            
            # Verifica se métrica existe
            if rule.metric not in metrics:
                continue
            
            metric_value = metrics[rule.metric]
            
            # Avalia condição
            is_triggered = False
            if rule.operator == "gt":
                is_triggered = metric_value > rule.threshold
            elif rule.operator == "lt":
                is_triggered = metric_value < rule.threshold
            elif rule.operator == "eq":
                is_triggered = abs(metric_value - rule.threshold) < 0.01
            elif rule.operator == "gte":
                is_triggered = metric_value >= rule.threshold
            elif rule.operator == "lte":
                is_triggered = metric_value <= rule.threshold
            
            if is_triggered:
                # Verifica cooldown
                if self._is_in_cooldown(rule.rule_id):
                    continue
                
                # Verifica supressão
                if self._is_suppressed(rule.rule_id):
                    continue
                
                # Cria alerta
                alert = Alert(
                    alert_id=f"{rule.rule_id}_{int(time.time())}",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    message=f"{rule.description}: {metric_value:.2f} {rule.operator} {rule.threshold}",
                    metric_value=metric_value,
                    threshold=rule.threshold,
                    timestamp=datetime.now()
                )
                
                triggered_alerts.append(alert)
                
                # Registra tempo do alerta
                self.last_alert_times[rule.rule_id] = datetime.now()
                
                logger.warning(f"Alerta disparado: {rule.name} - {alert.message}")
        
        return triggered_alerts

    def _is_in_cooldown(self, rule_id: str) -> bool:
        """
        Verifica se regra está em cooldown.
        """
        if rule_id not in self.last_alert_times:
            return False
        
        rule = next((r for r in self.alert_rules if r.rule_id == rule_id), None)
        if not rule:
            return False
        
        time_since_last = datetime.now() - self.last_alert_times[rule_id]
        return time_since_last.total_seconds() < (rule.cooldown_minutes * 60)

    def _is_suppressed(self, rule_id: str) -> bool:
        """
        Verifica se alerta está suprimido.
        """
        if not self.alert_config["suppression_enabled"]:
            return False
        
        # Implementa lógica de supressão baseada em padrões
        # Por exemplo, se muitos alertas similares foram disparados recentemente
        recent_alerts = [
            alert for alert in self.alert_history
            if alert.rule_id == rule_id and 
            (datetime.now() - alert.timestamp).total_seconds() < (self.alert_config["suppression_window_minutes"] * 60)
        ]
        
        return len(recent_alerts) >= 3  # Suprime se 3+ alertas similares em 15 minutos

    async def send_alert_to_slack(self, alert: Alert) -> bool:
        """
        Envia alerta para Slack.
        """
        try:
            config = self.channel_configs[AlertChannel.SLACK]
            webhook_url = config["webhook_url"]
            
            if not webhook_url:
                logger.warning("Slack webhook URL não configurada")
                return False
            
            # Prepara mensagem
            color_map = {
                AlertSeverity.INFO: "#36a64f",
                AlertSeverity.WARNING: "#ffa500",
                AlertSeverity.ERROR: "#ff0000",
                AlertSeverity.CRITICAL: "#8b0000"
            }
            
            slack_message = {
                "channel": config["channel"],
                "username": config["username"],
                "icon_emoji": config["icon_emoji"],
                "attachments": [{
                    "color": color_map.get(alert.severity, "#ffa500"),
                    "title": f"🚨 {alert.severity.value.upper()}: {alert.message}",
                    "text": f"**Regra:** {alert.rule_id}\n**Valor:** {alert.metric_value:.2f}\n**Threshold:** {alert.threshold}\n**Timestamp:** {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    "fields": [
                        {
                            "title": "Severidade",
                            "value": alert.severity.value.upper(),
                            "short": True
                        },
                        {
                            "title": "Métrica",
                            "value": f"{alert.metric_value:.2f}",
                            "short": True
                        }
                    ],
                    "footer": "Load Test Alert System",
                    "ts": int(alert.timestamp.timestamp())
                }]
            }
            
            # Envia requisição
            response = requests.post(webhook_url, json=slack_message, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Alerta enviado para Slack: {alert.alert_id}")
                return True
            else:
                logger.error(f"Erro ao enviar para Slack: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar alerta para Slack: {e}")
            return False

    async def send_alert_to_pagerduty(self, alert: Alert) -> bool:
        """
        Envia alerta para PagerDuty.
        """
        try:
            config = self.channel_configs[AlertChannel.PAGERDUTY]
            api_key = config["api_key"]
            service_id = config["service_id"]
            
            if not api_key or not service_id:
                logger.warning("PagerDuty não configurado")
                return False
            
            # Prepara payload
            pagerduty_payload = {
                "routing_key": api_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"Load Test Alert: {alert.message}",
                    "severity": alert.severity.value,
                    "source": "load-test-system",
                    "custom_details": {
                        "rule_id": alert.rule_id,
                        "metric_value": alert.metric_value,
                        "threshold": alert.threshold,
                        "timestamp": alert.timestamp.isoformat()
                    }
                }
            }
            
            # Envia requisição
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/vnd.pagerduty+json;version=2"
            }
            
            response = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=pagerduty_payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code in [200, 202]:
                logger.info(f"Alerta enviado para PagerDuty: {alert.alert_id}")
                return True
            else:
                logger.error(f"Erro ao enviar para PagerDuty: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar alerta para PagerDuty: {e}")
            return False

    async def send_alert_to_email(self, alert: Alert) -> bool:
        """
        Envia alerta por email.
        """
        try:
            config = self.channel_configs[AlertChannel.EMAIL]
            
            if not config["username"] or not config["password"] or not config["to_emails"]:
                logger.warning("Email não configurado")
                return False
            
            # Prepara email
            msg = MIMEMultipart()
            msg['From'] = config["from_email"]
            msg['To'] = ", ".join(config["to_emails"])
            msg['Subject'] = f"[{alert.severity.value.upper()}] Load Test Alert: {alert.message}"
            
            # Corpo do email
            body = f"""
            <html>
            <body>
                <h2>🚨 Load Test Alert</h2>
                <p><strong>Severidade:</strong> {alert.severity.value.upper()}</p>
                <p><strong>Mensagem:</strong> {alert.message}</p>
                <p><strong>Regra:</strong> {alert.rule_id}</p>
                <p><strong>Valor da Métrica:</strong> {alert.metric_value:.2f}</p>
                <p><strong>Threshold:</strong> {alert.threshold}</p>
                <p><strong>Timestamp:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <p><em>Este alerta foi gerado automaticamente pelo sistema de load tests.</em></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Envia email
            server = smtplib.SMTP(config["smtp_server"], config["smtp_port"])
            server.starttls()
            server.login(config["username"], config["password"])
            
            text = msg.as_string()
            server.sendmail(config["from_email"], config["to_emails"], text)
            server.quit()
            
            logger.info(f"Alerta enviado por email: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar alerta por email: {e}")
            return False

    async def send_alert_to_webhook(self, alert: Alert) -> bool:
        """
        Envia alerta para webhook customizado.
        """
        try:
            config = self.channel_configs[AlertChannel.WEBHOOK]
            webhook_url = config["webhook_url"]
            
            if not webhook_url:
                logger.warning("Webhook URL não configurada")
                return False
            
            # Prepara payload
            webhook_payload = {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "severity": alert.severity.value,
                "message": alert.message,
                "metric_value": alert.metric_value,
                "threshold": alert.threshold,
                "timestamp": alert.timestamp.isoformat(),
                "source": "load-test-system"
            }
            
            # Envia requisição
            response = requests.post(
                webhook_url,
                json=webhook_payload,
                headers=config["headers"],
                timeout=10
            )
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Alerta enviado para webhook: {alert.alert_id}")
                return True
            else:
                logger.error(f"Erro ao enviar para webhook: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar alerta para webhook: {e}")
            return False

    async def broadcast_alert_websocket(self, alert: Alert) -> None:
        """
        Transmite alerta via WebSocket para clientes conectados.
        """
        if not self.websocket_clients:
            return
        
        try:
            alert_data = {
                "type": "alert",
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
                "metric_value": alert.metric_value,
                "threshold": alert.threshold
            }
            
            # Envia para todos os clientes conectados
            disconnected_clients = set()
            
            for client in self.websocket_clients:
                try:
                    await client.send(json.dumps(alert_data))
                except Exception as e:
                    logger.error(f"Erro ao enviar para cliente WebSocket: {e}")
                    disconnected_clients.add(client)
            
            # Remove clientes desconectados
            self.websocket_clients -= disconnected_clients
            
            if self.websocket_clients:
                logger.info(f"Alerta transmitido para {len(self.websocket_clients)} clientes WebSocket")
                
        except Exception as e:
            logger.error(f"Erro ao transmitir alerta WebSocket: {e}")

    async def send_alert_to_all_channels(self, alert: Alert) -> Dict[str, bool]:
        """
        Envia alerta para todos os canais configurados.
        """
        results = {}
        
        # Obtém regra para determinar canais
        rule = next((r for r in self.alert_rules if r.rule_id == alert.rule_id), None)
        if not rule:
            logger.error(f"Regra não encontrada: {alert.rule_id}")
            return results
        
        # Envia para cada canal configurado
        for channel in rule.channels:
            try:
                if channel == AlertChannel.SLACK:
                    results["slack"] = await self.send_alert_to_slack(alert)
                elif channel == AlertChannel.PAGERDUTY:
                    results["pagerduty"] = await self.send_alert_to_pagerduty(alert)
                elif channel == AlertChannel.EMAIL:
                    results["email"] = await self.send_alert_to_email(alert)
                elif channel == AlertChannel.WEBHOOK:
                    results["webhook"] = await self.send_alert_to_webhook(alert)
                elif channel == AlertChannel.WEBSOCKET:
                    await self.broadcast_alert_websocket(alert)
                    results["websocket"] = True
                elif channel == AlertChannel.CONSOLE:
                    logger.warning(f"ALERTA: {alert.message}")
                    results["console"] = True
                    
            except Exception as e:
                logger.error(f"Erro ao enviar para {channel.value}: {e}")
                results[channel.value] = False
        
        return results

    async def process_alerts(self, alerts: List[Alert]) -> None:
        """
        Processa lista de alertas.
        """
        for alert in alerts:
            try:
                # Adiciona ao histórico
                self.alert_history.append(alert)
                self.active_alerts[alert.alert_id] = alert
                
                # Envia para canais
                results = await self.send_alert_to_all_channels(alert)
                
                # Log de resultados
                successful_channels = [k for k, v in results.items() if v]
                logger.info(f"Alerta {alert.alert_id} enviado para: {successful_channels}")
                
                # Verifica escalação se necessário
                if self.alert_config["enable_escalation"] and alert.severity == AlertSeverity.CRITICAL:
                    await self._escalate_alert(alert)
                    
            except Exception as e:
                logger.error(f"Erro ao processar alerta {alert.alert_id}: {e}")

    async def _escalate_alert(self, alert: Alert) -> None:
        """
        Escala alerta crítico.
        """
        try:
            logger.warning(f"ESCALANDO ALERTA CRÍTICO: {alert.alert_id}")
            
            # Implementa lógica de escalação
            # Por exemplo, envia para gerentes, cria incidente, etc.
            
            escalation_message = f"🚨 ALERTA CRÍTICO ESCALADO: {alert.message}"
            
            # Envia para canais de escalação
            if AlertChannel.PAGERDUTY in self.channel_configs:
                await self.send_alert_to_pagerduty(alert)
            
            if AlertChannel.EMAIL in self.channel_configs:
                await self.send_alert_to_email(alert)
            
            logger.info(f"Alerta {alert.alert_id} escalado com sucesso")
            
        except Exception as e:
            logger.error(f"Erro ao escalar alerta {alert.alert_id}: {e}")

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """
        Reconhece um alerta.
        """
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.acknowledged = True
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
            
            logger.info(f"Alerta {alert_id} reconhecido por {acknowledged_by}")
            return True
        
        return False

    def get_active_alerts(self, severity: AlertSeverity = None) -> List[Alert]:
        """
        Obtém alertas ativos, opcionalmente filtrados por severidade.
        """
        alerts = list(self.active_alerts.values())
        
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        
        return alerts

    def get_alert_history(self, 
                         start_time: datetime = None, 
                         end_time: datetime = None,
                         severity: AlertSeverity = None) -> List[Alert]:
        """
        Obtém histórico de alertas com filtros opcionais.
        """
        alerts = self.alert_history.copy()
        
        if start_time:
            alerts = [alert for alert in alerts if alert.timestamp >= start_time]
        
        if end_time:
            alerts = [alert for alert in alerts if alert.timestamp <= end_time]
        
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        
        return alerts

    def generate_alert_report(self) -> str:
        """
        Gera relatório de alertas.
        """
        try:
            report_file = self.output_dir / f"alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Alertas - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Alertas ativos:** {len(self.active_alerts)}\n")
                f.write(f"- **Total de alertas (24h):** {len([a for a in self.alert_history if (datetime.now() - a.timestamp).total_seconds() < 86400])}\n")
                f.write(f"- **Regras ativas:** {len([r for r in self.alert_rules if r.active])}\n")
                f.write(f"- **Canais configurados:** {len(self.channel_configs)}\n\n")
                
                f.write("## Alertas Ativos\n\n")
                
                if self.active_alerts:
                    f.write("| ID | Severidade | Mensagem | Timestamp | Reconhecido |\n")
                    f.write("|----|------------|----------|-----------|-------------|\n")
                    
                    for alert in list(self.active_alerts.values())[:10]:  # Mostra apenas os primeiros 10
                        acknowledged = "Sim" if alert.acknowledged else "Não"
                        f.write(f"| {alert.alert_id} | {alert.severity.value} | {alert.message[:50]}... | {alert.timestamp.strftime('%H:%M:%S')} | {acknowledged} |\n")
                else:
                    f.write("Nenhum alerta ativo.\n")
                
                f.write("\n## Alertas por Severidade (24h)\n\n")
                
                # Agrupa por severidade
                recent_alerts = [a for a in self.alert_history if (datetime.now() - a.timestamp).total_seconds() < 86400]
                severity_counts = {}
                
                for alert in recent_alerts:
                    severity = alert.severity.value
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                for severity, count in severity_counts.items():
                    f.write(f"- **{severity.upper()}:** {count}\n")
                
                f.write("\n## Canais Configurados\n\n")
                
                for channel, config in self.channel_configs.items():
                    f.write(f"### {channel.value.title()}\n")
                    if channel == AlertChannel.SLACK:
                        f.write(f"- **Webhook:** {'Configurado' if config['webhook_url'] else 'Não configurado'}\n")
                        f.write(f"- **Canal:** {config['channel']}\n")
                    elif channel == AlertChannel.PAGERDUTY:
                        f.write(f"- **API Key:** {'Configurado' if config['api_key'] else 'Não configurado'}\n")
                        f.write(f"- **Service ID:** {config['service_id']}\n")
                    elif channel == AlertChannel.EMAIL:
                        f.write(f"- **SMTP:** {config['smtp_server']}:{config['smtp_port']}\n")
                        f.write(f"- **Destinatários:** {len(config['to_emails'])}\n")
                    f.write("\n")
                
                f.write("## Configurações\n\n")
                f.write(f"- **Tempo real:** {self.alert_config['enable_real_time']}\n")
                f.write(f"- **Escalação:** {self.alert_config['enable_escalation']}\n")
                f.write(f"- **Supressão:** {self.alert_config['suppression_enabled']}\n")
                f.write(f"- **Máximo por minuto:** {self.alert_config['max_alerts_per_minute']}\n")
                f.write(f"- **Retenção:** {self.alert_config['alert_retention_days']} dias\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return ""

    async def start_websocket_server(self, host: str = "localhost", port: int = 8765) -> None:
        """
        Inicia servidor WebSocket para alertas em tempo real.
        """
        try:
            async def websocket_handler(websocket, path):
                self.websocket_clients.add(websocket)
                logger.info(f"Cliente WebSocket conectado: {len(self.websocket_clients)} total")
                
                try:
                    async for message in websocket:
                        # Processa mensagens do cliente se necessário
                        pass
                except websockets.exceptions.ConnectionClosed:
                    pass
                finally:
                    self.websocket_clients.discard(websocket)
                    logger.info(f"Cliente WebSocket desconectado: {len(self.websocket_clients)} restantes")
            
            self.websocket_server = await websockets.serve(websocket_handler, host, port)
            logger.info(f"Servidor WebSocket iniciado em ws://{host}:{port}")
            
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor WebSocket: {e}")


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Enhanced Alert System...")
    
    alert_system = EnhancedAlertSystem()
    
    try:
        # Inicia servidor WebSocket
        await alert_system.start_websocket_server()
        
        # Simula métricas para teste
        test_metrics = {
            "response_time_avg": 1200,  # Acima do threshold
            "error_rate": 0.08,         # Acima do threshold
            "throughput": 5,            # Abaixo do threshold
            "cpu_usage": 95             # Acima do threshold
        }
        
        # Avalia regras
        alerts = alert_system.evaluate_alert_rules(test_metrics)
        
        # Processa alertas
        await alert_system.process_alerts(alerts)
        
        # Gera relatório
        report_file = alert_system.generate_alert_report()
        
        logger.info("Sistema de alertas testado com sucesso!")
        logger.info(f"Alertas gerados: {len(alerts)}")
        logger.info(f"Relatório: {report_file}")
        
        # Mantém servidor WebSocket ativo por um tempo
        await asyncio.sleep(30)
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 