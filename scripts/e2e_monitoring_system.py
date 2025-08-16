#!/usr/bin/env python3
"""
Sistema de Monitoramento E2E - Omni Writer
==========================================

Implementa monitoramento avançado para testes E2E:
- Alertas em tempo real para falhas
- Métricas de tempo de execução
- Logs estruturados para análise
- Dashboards de saúde dos testes
- Integração com Slack/Email
- Análise de tendências

📐 CoCoT: Baseado em padrões de monitoramento enterprise
🌲 ToT: Múltiplas estratégias de alerta implementadas
♻️ ReAct: Simulado para diferentes cenários de falha

**Prompt:** Sistema de Monitoramento E2E - Item 14
**Data/Hora:** 2025-01-28T12:00:00Z
**Tracing ID:** E2E_MONITORING_20250128_014
**Origem:** Necessidade de monitoramento em tempo real para testes E2E
"""

import os
import json
import time
import smtplib
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import logging
import threading
from collections import defaultdict, deque
import statistics

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/e2e_monitoring.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


@dataclass
class TestAlert:
    """Estrutura de alerta de teste"""
    alert_id: str
    test_name: str
    alert_type: str  # 'failure', 'performance', 'coverage', 'stability'
    severity: str    # 'critical', 'high', 'medium', 'low'
    message: str
    timestamp: str
    details: Dict[str, Any]
    resolved: bool = False
    resolution_time: Optional[str] = None


@dataclass
class TestMetrics:
    """Métricas de execução de teste"""
    test_name: str
    execution_time: float
    status: str
    browser: str
    shard: int
    timestamp: str
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    error_count: int = 0
    retry_count: int = 0


@dataclass
class HealthStatus:
    """Status de saúde dos testes"""
    overall_health: str  # 'healthy', 'warning', 'critical'
    success_rate: float
    avg_execution_time: float
    failure_rate: float
    active_alerts: int
    last_execution: str
    recommendations: List[str]


class E2EMonitoringSystem:
    """Sistema de monitoramento E2E"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alerts: List[TestAlert] = []
        self.metrics: List[TestMetrics] = []
        self.health_history: deque = deque(maxlen=100)
        
        # Configurações de alerta
        self.alert_thresholds = config.get('alert_thresholds', {
            'failure_rate': 0.1,      # 10% de falhas
            'execution_time': 300,    # 5 minutos
            'memory_usage': 1024,     # 1GB
            'cpu_usage': 80,          # 80%
            'consecutive_failures': 3  # 3 falhas consecutivas
        })
        
        # Configurações de notificação
        self.notification_config = config.get('notifications', {
            'slack_webhook': os.getenv('SLACK_WEBHOOK_URL'),
            'email_config': {
                'smtp_server': os.getenv('SMTP_SERVER'),
                'smtp_port': int(os.getenv('SMTP_PORT', '587')),
                'username': os.getenv('EMAIL_USERNAME'),
                'password': os.getenv('EMAIL_PASSWORD'),
                'recipients': os.getenv('EMAIL_RECIPIENTS', '').split(',')
            }
        })
        
        # Iniciar monitoramento em background
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"[{self.config.get('tracing_id', 'E2E_MONITORING')}] Sistema de monitoramento iniciado")
    
    def add_test_result(self, test_metrics: TestMetrics) -> None:
        """Adiciona resultado de teste ao sistema"""
        self.metrics.append(test_metrics)
        
        # Verificar se precisa gerar alerta
        self._check_for_alerts(test_metrics)
        
        # Atualizar saúde geral
        self._update_health_status()
        
        logger.info(f"[{self.config.get('tracing_id', 'E2E_MONITORING')}] Resultado adicionado: {test_metrics.test_name}")
    
    def _check_for_alerts(self, test_metrics: TestMetrics) -> None:
        """Verifica se precisa gerar alertas baseado nas métricas"""
        alerts_generated = []
        
        # Alerta de falha
        if test_metrics.status == 'failed':
            alert = TestAlert(
                alert_id=f"failure_{int(time.time())}",
                test_name=test_metrics.test_name,
                alert_type='failure',
                severity='high',
                message=f"Teste falhou: {test_metrics.test_name}",
                timestamp=datetime.now().isoformat(),
                details={
                    'execution_time': test_metrics.execution_time,
                    'browser': test_metrics.browser,
                    'shard': test_metrics.shard,
                    'error_count': test_metrics.error_count
                }
            )
            alerts_generated.append(alert)
        
        # Alerta de performance
        if test_metrics.execution_time > self.alert_thresholds['execution_time']:
            alert = TestAlert(
                alert_id=f"performance_{int(time.time())}",
                test_name=test_metrics.test_name,
                alert_type='performance',
                severity='medium',
                message=f"Teste lento: {test_metrics.test_name} ({test_metrics.execution_time:.1f}s)",
                timestamp=datetime.now().isoformat(),
                details={
                    'execution_time': test_metrics.execution_time,
                    'threshold': self.alert_thresholds['execution_time'],
                    'browser': test_metrics.browser
                }
            )
            alerts_generated.append(alert)
        
        # Alerta de uso de recursos
        if test_metrics.memory_usage and test_metrics.memory_usage > self.alert_thresholds['memory_usage']:
            alert = TestAlert(
                alert_id=f"memory_{int(time.time())}",
                test_name=test_metrics.test_name,
                alert_type='resource',
                severity='medium',
                message=f"Alto uso de memória: {test_metrics.test_name} ({test_metrics.memory_usage:.1f}MB)",
                timestamp=datetime.now().isoformat(),
                details={
                    'memory_usage': test_metrics.memory_usage,
                    'threshold': self.alert_thresholds['memory_usage']
                }
            )
            alerts_generated.append(alert)
        
        # Adicionar alertas ao sistema
        for alert in alerts_generated:
            self.alerts.append(alert)
            self._send_notification(alert)
    
    def _update_health_status(self) -> None:
        """Atualiza status de saúde geral"""
        if not self.metrics:
            return
        
        # Calcular métricas
        recent_metrics = [m for m in self.metrics 
                         if datetime.fromisoformat(m.timestamp) > datetime.now() - timedelta(hours=1)]
        
        if not recent_metrics:
            return
        
        total_tests = len(recent_metrics)
        passed_tests = len([m for m in recent_metrics if m.status == 'passed'])
        failed_tests = len([m for m in recent_metrics if m.status == 'failed'])
        
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        failure_rate = (failed_tests / total_tests) * 100 if total_tests > 0 else 0
        avg_execution_time = statistics.mean([m.execution_time for m in recent_metrics])
        
        # Determinar saúde geral
        if failure_rate > 20 or success_rate < 80:
            overall_health = 'critical'
        elif failure_rate > 10 or success_rate < 90:
            overall_health = 'warning'
        else:
            overall_health = 'healthy'
        
        # Gerar recomendações
        recommendations = []
        if failure_rate > 10:
            recommendations.append("Investigar causas das falhas frequentes")
        if avg_execution_time > 300:
            recommendations.append("Otimizar performance dos testes")
        if len([a for a in self.alerts if not a.resolved]) > 5:
            recommendations.append("Revisar alertas não resolvidos")
        
        health_status = HealthStatus(
            overall_health=overall_health,
            success_rate=success_rate,
            avg_execution_time=avg_execution_time,
            failure_rate=failure_rate,
            active_alerts=len([a for a in self.alerts if not a.resolved]),
            last_execution=recent_metrics[-1].timestamp,
            recommendations=recommendations
        )
        
        self.health_history.append(health_status)
        
        # Verificar se precisa gerar alerta de saúde
        if overall_health == 'critical':
            self._send_health_alert(health_status)
    
    def _send_notification(self, alert: TestAlert) -> None:
        """Envia notificação de alerta"""
        try:
            # Slack
            if self.notification_config.get('slack_webhook'):
                self._send_slack_notification(alert)
            
            # Email
            if self.notification_config.get('email_config', {}).get('smtp_server'):
                self._send_email_notification(alert)
                
        except Exception as e:
            logger.error(f"Erro ao enviar notificação: {e}")
    
    def _send_slack_notification(self, alert: TestAlert) -> None:
        """Envia notificação para Slack"""
        webhook_url = self.notification_config['slack_webhook']
        
        # Determinar cor baseada na severidade
        color_map = {
            'critical': '#ff0000',
            'high': '#ff6600',
            'medium': '#ffcc00',
            'low': '#00cc00'
        }
        
        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, '#cccccc'),
                    "title": f"🚨 Alerta E2E: {alert.alert_type.upper()}",
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Teste",
                            "value": alert.test_name,
                            "short": True
                        },
                        {
                            "title": "Severidade",
                            "value": alert.severity.upper(),
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": alert.timestamp,
                            "short": True
                        }
                    ],
                    "footer": "Omni Writer E2E Monitoring"
                }
            ]
        }
        
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            logger.error(f"Erro ao enviar para Slack: {response.status_code}")
    
    def _send_email_notification(self, alert: TestAlert) -> None:
        """Envia notificação por email"""
        email_config = self.notification_config['email_config']
        
        subject = f"[E2E ALERT] {alert.alert_type.upper()} - {alert.test_name}"
        body = f"""
        Alerta de Teste E2E
        
        Tipo: {alert.alert_type}
        Teste: {alert.test_name}
        Severidade: {alert.severity}
        Mensagem: {alert.message}
        Timestamp: {alert.timestamp}
        
        Detalhes: {json.dumps(alert.details, indent=2)}
        
        ---
        Omni Writer E2E Monitoring System
        """
        
        try:
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['username'], email_config['password'])
                
                for recipient in email_config['recipients']:
                    server.sendmail(
                        email_config['username'],
                        recipient.strip(),
                        f"Subject: {subject}\n\n{body}"
                    )
                    
        except Exception as e:
            logger.error(f"Erro ao enviar email: {e}")
    
    def _send_health_alert(self, health_status: HealthStatus) -> None:
        """Envia alerta de saúde geral"""
        alert = TestAlert(
            alert_id=f"health_{int(time.time())}",
            test_name="SYSTEM_HEALTH",
            alert_type='health',
            severity='critical',
            message=f"Saúde crítica dos testes E2E: {health_status.failure_rate:.1f}% de falhas",
            timestamp=datetime.now().isoformat(),
            details=asdict(health_status)
        )
        
        self.alerts.append(alert)
        self._send_notification(alert)
    
    def _monitoring_loop(self) -> None:
        """Loop principal de monitoramento"""
        while self.monitoring_active:
            try:
                # Verificar falhas consecutivas
                self._check_consecutive_failures()
                
                # Limpar alertas antigos
                self._cleanup_old_alerts()
                
                # Gerar relatório periódico
                if len(self.metrics) % 10 == 0:  # A cada 10 testes
                    self._generate_periodic_report()
                
                time.sleep(30)  # Verificar a cada 30 segundos
                
            except Exception as e:
                logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(60)
    
    def _check_consecutive_failures(self) -> None:
        """Verifica falhas consecutivas"""
        recent_tests = sorted(self.metrics, key=lambda x: x.timestamp, reverse=True)[:10]
        
        consecutive_failures = 0
        for test in recent_tests:
            if test.status == 'failed':
                consecutive_failures += 1
            else:
                break
        
        if consecutive_failures >= self.alert_thresholds['consecutive_failures']:
            alert = TestAlert(
                alert_id=f"consecutive_{int(time.time())}",
                test_name="CONSECUTIVE_FAILURES",
                alert_type='stability',
                severity='critical',
                message=f"{consecutive_failures} falhas consecutivas detectadas",
                timestamp=datetime.now().isoformat(),
                details={
                    'consecutive_failures': consecutive_failures,
                    'threshold': self.alert_thresholds['consecutive_failures'],
                    'recent_tests': [t.test_name for t in recent_tests[:consecutive_failures]]
                }
            )
            
            # Verificar se já existe alerta similar
            existing_alert = next((a for a in self.alerts 
                                 if a.alert_type == 'stability' and not a.resolved), None)
            
            if not existing_alert:
                self.alerts.append(alert)
                self._send_notification(alert)
    
    def _cleanup_old_alerts(self) -> None:
        """Remove alertas antigos"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        # Marcar alertas antigos como resolvidos
        for alert in self.alerts:
            if not alert.resolved and datetime.fromisoformat(alert.timestamp) < cutoff_time:
                alert.resolved = True
                alert.resolution_time = datetime.now().isoformat()
        
        # Remover alertas muito antigos (mais de 7 dias)
        cutoff_time_old = datetime.now() - timedelta(days=7)
        self.alerts = [a for a in self.alerts 
                      if datetime.fromisoformat(a.timestamp) > cutoff_time_old]
    
    def _generate_periodic_report(self) -> None:
        """Gera relatório periódico"""
        if not self.health_history:
            return
        
        current_health = self.health_history[-1]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'health_status': asdict(current_health),
            'total_tests': len(self.metrics),
            'active_alerts': len([a for a in self.alerts if not a.resolved]),
            'tracing_id': self.config.get('tracing_id', 'E2E_MONITORING')
        }
        
        # Salvar relatório
        reports_dir = Path('test-results/monitoring')
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = reports_dir / f"monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Relatório periódico gerado: {report_file}")
    
    def get_current_health(self) -> HealthStatus:
        """Retorna saúde atual do sistema"""
        if self.health_history:
            return self.health_history[-1]
        
        return HealthStatus(
            overall_health='unknown',
            success_rate=0.0,
            avg_execution_time=0.0,
            failure_rate=0.0,
            active_alerts=0,
            last_execution='',
            recommendations=[]
        )
    
    def get_active_alerts(self) -> List[TestAlert]:
        """Retorna alertas ativos"""
        return [a for a in self.alerts if not a.resolved]
    
    def resolve_alert(self, alert_id: str, resolution_notes: str = "") -> bool:
        """Marca alerta como resolvido"""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.resolution_time = datetime.now().isoformat()
                if resolution_notes:
                    alert.details['resolution_notes'] = resolution_notes
                return True
        return False
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Gera dados para dashboard"""
        current_health = self.get_current_health()
        active_alerts = self.get_active_alerts()
        
        # Métricas por browser
        browser_metrics = defaultdict(lambda: {'total': 0, 'passed': 0, 'failed': 0})
        for metric in self.metrics[-100:]:  # Últimos 100 testes
            browser_metrics[metric.browser]['total'] += 1
            if metric.status == 'passed':
                browser_metrics[metric.browser]['passed'] += 1
            else:
                browser_metrics[metric.browser]['failed'] += 1
        
        # Tendências de tempo de execução
        execution_times = [m.execution_time for m in self.metrics[-50:]]
        time_trend = {
            'current_avg': statistics.mean(execution_times) if execution_times else 0,
            'min': min(execution_times) if execution_times else 0,
            'max': max(execution_times) if execution_times else 0,
            'trend': 'stable'  # TODO: Implementar análise de tendência
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'health_status': asdict(current_health),
            'active_alerts': [asdict(a) for a in active_alerts],
            'browser_metrics': dict(browser_metrics),
            'execution_trends': time_trend,
            'total_tests': len(self.metrics),
            'tracing_id': self.config.get('tracing_id', 'E2E_MONITORING')
        }
    
    def shutdown(self) -> None:
        """Desliga o sistema de monitoramento"""
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("Sistema de monitoramento E2E desligado")


def create_monitoring_system(config: Dict[str, Any]) -> E2EMonitoringSystem:
    """Factory para criar sistema de monitoramento"""
    return E2EMonitoringSystem(config)


if __name__ == "__main__":
    # Configuração de exemplo
    config = {
        'tracing_id': 'E2E_MONITORING_DEMO',
        'alert_thresholds': {
            'failure_rate': 0.1,
            'execution_time': 300,
            'memory_usage': 1024,
            'cpu_usage': 80,
            'consecutive_failures': 3
        },
        'notifications': {
            'slack_webhook': os.getenv('SLACK_WEBHOOK_URL'),
            'email_config': {
                'smtp_server': os.getenv('SMTP_SERVER'),
                'smtp_port': int(os.getenv('SMTP_PORT', '587')),
                'username': os.getenv('EMAIL_USERNAME'),
                'password': os.getenv('EMAIL_PASSWORD'),
                'recipients': os.getenv('EMAIL_RECIPIENTS', '').split(',')
            }
        }
    }
    
    # Criar sistema
    monitoring = create_monitoring_system(config)
    
    try:
        print("🚀 Sistema de Monitoramento E2E iniciado")
        print("Pressione Ctrl+C para parar")
        
        # Simular alguns testes
        for i in range(10):
            test_metric = TestMetrics(
                test_name=f"test_{i}",
                execution_time=100 + (i * 10),
                status='passed' if i < 8 else 'failed',
                browser='chromium',
                shard=1,
                timestamp=datetime.now().isoformat(),
                memory_usage=512 + (i * 50)
            )
            
            monitoring.add_test_result(test_metric)
            time.sleep(2)
        
        # Manter rodando
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Parando sistema...")
        monitoring.shutdown()
        print("✅ Sistema parado com sucesso") 