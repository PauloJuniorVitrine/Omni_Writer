#!/usr/bin/env python3
"""
Sistema de Monitoramento Proativo - Omni Writer
===============================================

Implementa monitoramento proativo com:
- Alertas inteligentes
- Auto-healing de componentes
- Análise preditiva de falhas
- Relatórios automáticos

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import time
import json
import logging
import requests
import psutil
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import threading
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import redis
import prometheus_client
from prometheus_client import Counter, Gauge, Histogram, Summary

@dataclass
class MetricData:
    """Dados de métrica"""
    timestamp: datetime
    value: float
    labels: Dict[str, str]
    metric_type: str

@dataclass
class Alert:
    """Alerta do sistema"""
    id: str
    severity: str  # 'critical', 'warning', 'info'
    message: str
    metric: str
    value: float
    threshold: float
    timestamp: datetime
    resolved: bool = False
    auto_resolved: bool = False

@dataclass
class ComponentHealth:
    """Saúde de um componente"""
    name: str
    status: str  # 'healthy', 'degraded', 'unhealthy'
    last_check: datetime
    response_time: float
    error_count: int
    uptime: float
    memory_usage: float
    cpu_usage: float

class ProactiveMonitoring:
    """Sistema de monitoramento proativo"""
    
    def __init__(self, config_file: str = "monitoring_config.json"):
        self.config = self._load_config(config_file)
        self.redis_client = redis.Redis(
            host=self.config.get('redis_host', 'localhost'),
            port=self.config.get('redis_port', 6379),
            db=self.config.get('redis_db', 0)
        )
        
        # Métricas Prometheus
        self.metrics = {
            'http_requests_total': Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status']),
            'http_request_duration': Histogram('http_request_duration', 'HTTP request duration', ['method', 'endpoint']),
            'system_cpu_usage': Gauge('system_cpu_usage', 'CPU usage percentage'),
            'system_memory_usage': Gauge('system_memory_usage', 'Memory usage percentage'),
            'system_disk_usage': Gauge('system_disk_usage', 'Disk usage percentage'),
            'application_errors': Counter('application_errors', 'Application errors', ['component', 'error_type']),
            'database_connections': Gauge('database_connections', 'Database connections'),
            'queue_size': Gauge('queue_size', 'Queue size', ['queue_name']),
            'response_time_p95': Summary('response_time_p95', '95th percentile response time'),
            'error_rate': Gauge('error_rate', 'Error rate percentage'),
            'throughput': Gauge('throughput', 'Requests per second')
        }
        
        # Inicializa Prometheus
        prometheus_client.start_http_server(self.config.get('prometheus_port', 8000))
        
        # Filas para processamento assíncrono
        self.alert_queue = queue.Queue()
        self.metric_queue = queue.Queue()
        
        # Estado do sistema
        self.alerts: List[Alert] = []
        self.component_health: Dict[str, ComponentHealth] = {}
        self.predictive_models = {}
        
        # Configuração de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('monitoring.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Threads de monitoramento
        self.monitoring_threads = []
        self.running = False
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Carrega configuração do monitoramento"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Configuração padrão
            return {
                'components': {
                    'api': {
                        'url': 'http://localhost:5000/health',
                        'timeout': 5,
                        'interval': 30,
                        'thresholds': {
                            'response_time': 2000,
                            'error_rate': 5,
                            'cpu_usage': 80,
                            'memory_usage': 85
                        }
                    },
                    'database': {
                        'url': 'postgresql://localhost:5432/omni_writer',
                        'timeout': 10,
                        'interval': 60,
                        'thresholds': {
                            'connection_time': 1000,
                            'query_time': 5000
                        }
                    },
                    'redis': {
                        'url': 'redis://localhost:6379',
                        'timeout': 5,
                        'interval': 30,
                        'thresholds': {
                            'response_time': 100,
                            'memory_usage': 80
                        }
                    },
                    'celery': {
                        'url': 'http://localhost:5555',
                        'timeout': 10,
                        'interval': 60,
                        'thresholds': {
                            'queue_size': 100,
                            'worker_count': 2
                        }
                    }
                },
                'alerts': {
                    'email': {
                        'enabled': True,
                        'smtp_server': 'smtp.gmail.com',
                        'smtp_port': 587,
                        'username': 'alerts@omniwriter.com',
                        'password': 'your_password',
                        'recipients': ['admin@omniwriter.com']
                    },
                    'slack': {
                        'enabled': True,
                        'webhook_url': 'https://hooks.slack.com/services/...',
                        'channel': '#alerts'
                    }
                },
                'predictive_analysis': {
                    'enabled': True,
                    'window_size': 24,  # horas
                    'prediction_horizon': 1,  # hora
                    'confidence_threshold': 0.8
                }
            }
    
    def start_monitoring(self):
        """Inicia o monitoramento proativo"""
        self.logger.info("🚀 Iniciando monitoramento proativo...")
        self.running = True
        
        # Inicia threads de monitoramento
        self._start_component_monitoring()
        self._start_system_monitoring()
        self._start_predictive_analysis()
        self._start_alert_processor()
        self._start_auto_healing()
        
        self.logger.info("✅ Monitoramento proativo iniciado")
    
    def stop_monitoring(self):
        """Para o monitoramento"""
        self.logger.info("🛑 Parando monitoramento proativo...")
        self.running = False
        
        # Aguarda threads terminarem
        for thread in self.monitoring_threads:
            thread.join()
        
        self.logger.info("✅ Monitoramento proativo parado")
    
    def _start_component_monitoring(self):
        """Inicia monitoramento de componentes"""
        def monitor_components():
            while self.running:
                for component_name, config in self.config['components'].items():
                    try:
                        health = self._check_component_health(component_name, config)
                        self.component_health[component_name] = health
                        
                        # Atualiza métricas
                        self._update_component_metrics(component_name, health)
                        
                        # Verifica alertas
                        self._check_component_alerts(component_name, health, config)
                        
                    except Exception as e:
                        self.logger.error(f"Erro ao monitorar componente {component_name}: {e}")
                        self._create_alert(
                            f"monitoring_error_{component_name}",
                            "critical",
                            f"Erro no monitoramento de {component_name}: {e}",
                            "monitoring",
                            1,
                            0
                        )
                
                time.sleep(30)  # Intervalo de verificação
        
        thread = threading.Thread(target=monitor_components, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)
    
    def _check_component_health(self, component_name: str, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde de um componente"""
        start_time = time.time()
        
        try:
            if component_name == 'api':
                return self._check_api_health(config)
            elif component_name == 'database':
                return self._check_database_health(config)
            elif component_name == 'redis':
                return self._check_redis_health(config)
            elif component_name == 'celery':
                return self._check_celery_health(config)
            else:
                return self._check_generic_health(component_name, config)
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name=component_name,
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _check_api_health(self, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde da API"""
        start_time = time.time()
        
        try:
            response = requests.get(
                config['url'],
                timeout=config['timeout'],
                headers={'User-Agent': 'OmniWriter-Monitoring/1.0'}
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                data = response.json()
                status = 'healthy' if data.get('status') == 'healthy' else 'degraded'
                
                return ComponentHealth(
                    name='api',
                    status=status,
                    last_check=datetime.now(),
                    response_time=response_time,
                    error_count=0,
                    uptime=data.get('uptime', 0),
                    memory_usage=data.get('memory_usage', 0),
                    cpu_usage=data.get('cpu_usage', 0)
                )
            else:
                return ComponentHealth(
                    name='api',
                    status='unhealthy',
                    last_check=datetime.now(),
                    response_time=response_time,
                    error_count=1,
                    uptime=0,
                    memory_usage=0,
                    cpu_usage=0
                )
                
        except requests.exceptions.RequestException as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name='api',
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _check_database_health(self, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde do banco de dados"""
        start_time = time.time()
        
        try:
            # Simula verificação de banco de dados
            # Em produção, usar biblioteca específica do banco
            import psycopg2
            
            conn = psycopg2.connect(config['url'])
            cursor = conn.cursor()
            
            # Testa query simples
            cursor.execute("SELECT 1")
            cursor.fetchone()
            
            response_time = (time.time() - start_time) * 1000
            
            cursor.close()
            conn.close()
            
            return ComponentHealth(
                name='database',
                status='healthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=0,
                uptime=time.time(),
                memory_usage=0,
                cpu_usage=0
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name='database',
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _check_redis_health(self, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde do Redis"""
        start_time = time.time()
        
        try:
            # Testa conexão Redis
            self.redis_client.ping()
            
            # Obtém informações do Redis
            info = self.redis_client.info()
            
            response_time = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name='redis',
                status='healthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=0,
                uptime=info.get('uptime_in_seconds', 0),
                memory_usage=info.get('used_memory_human', '0B'),
                cpu_usage=0
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name='redis',
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _check_celery_health(self, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde do Celery"""
        start_time = time.time()
        
        try:
            # Verifica workers Celery
            result = subprocess.run(
                ['celery', '-A', 'app.celery', 'inspect', 'active'],
                capture_output=True,
                text=True,
                timeout=config['timeout']
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                # Conta workers ativos
                worker_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
                
                return ComponentHealth(
                    name='celery',
                    status='healthy' if worker_count > 0 else 'degraded',
                    last_check=datetime.now(),
                    response_time=response_time,
                    error_count=0,
                    uptime=time.time(),
                    memory_usage=0,
                    cpu_usage=0
                )
            else:
                return ComponentHealth(
                    name='celery',
                    status='unhealthy',
                    last_check=datetime.now(),
                    response_time=response_time,
                    error_count=1,
                    uptime=0,
                    memory_usage=0,
                    cpu_usage=0
                )
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name='celery',
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _check_generic_health(self, component_name: str, config: Dict[str, Any]) -> ComponentHealth:
        """Verifica saúde genérica de componente"""
        start_time = time.time()
        
        try:
            response = requests.get(
                config['url'],
                timeout=config['timeout']
            )
            
            response_time = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name=component_name,
                status='healthy' if response.status_code == 200 else 'degraded',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=0,
                uptime=time.time(),
                memory_usage=0,
                cpu_usage=0
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name=component_name,
                status='unhealthy',
                last_check=datetime.now(),
                response_time=response_time,
                error_count=1,
                uptime=0,
                memory_usage=0,
                cpu_usage=0
            )
    
    def _start_system_monitoring(self):
        """Inicia monitoramento do sistema"""
        def monitor_system():
            while self.running:
                try:
                    # CPU
                    cpu_percent = psutil.cpu_percent(interval=1)
                    self.metrics['system_cpu_usage'].set(cpu_percent)
                    
                    # Memória
                    memory = psutil.virtual_memory()
                    self.metrics['system_memory_usage'].set(memory.percent)
                    
                    # Disco
                    disk = psutil.disk_usage('/')
                    self.metrics['system_disk_usage'].set((disk.used / disk.total) * 100)
                    
                    # Verifica alertas do sistema
                    self._check_system_alerts(cpu_percent, memory.percent, (disk.used / disk.total) * 100)
                    
                except Exception as e:
                    self.logger.error(f"Erro no monitoramento do sistema: {e}")
                
                time.sleep(60)  # Verifica a cada minuto
        
        thread = threading.Thread(target=monitor_system, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)
    
    def _start_predictive_analysis(self):
        """Inicia análise preditiva"""
        if not self.config.get('predictive_analysis', {}).get('enabled', False):
            return
        
        def predictive_analysis():
            while self.running:
                try:
                    # Coleta dados históricos
                    historical_data = self._collect_historical_data()
                    
                    # Executa análise preditiva
                    predictions = self._run_predictive_analysis(historical_data)
                    
                    # Verifica predições
                    self._check_predictions(predictions)
                    
                except Exception as e:
                    self.logger.error(f"Erro na análise preditiva: {e}")
                
                time.sleep(300)  # Executa a cada 5 minutos
        
        thread = threading.Thread(target=predictive_analysis, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)
    
    def _collect_historical_data(self) -> List[Dict[str, Any]]:
        """Coleta dados históricos para análise preditiva"""
        # Em produção, coletar dados do Prometheus ou banco de dados
        # Aqui simulamos dados históricos
        return [
            {
                'timestamp': datetime.now() - timedelta(hours=i),
                'cpu_usage': 50 + (i % 20),
                'memory_usage': 60 + (i % 15),
                'error_rate': 2 + (i % 3),
                'response_time': 150 + (i % 50)
            }
            for i in range(24)
        ]
    
    def _run_predictive_analysis(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Executa análise preditiva"""
        # Implementação simplificada de análise preditiva
        # Em produção, usar modelos ML mais sofisticados
        
        predictions = {}
        
        # Análise de tendência simples
        for metric in ['cpu_usage', 'memory_usage', 'error_rate', 'response_time']:
            values = [d[metric] for d in historical_data]
            
            if len(values) >= 2:
                # Calcula tendência linear simples
                trend = (values[-1] - values[0]) / len(values)
                predicted_value = values[-1] + trend
                
                predictions[metric] = {
                    'current': values[-1],
                    'predicted': predicted_value,
                    'trend': trend,
                    'confidence': 0.8 if abs(trend) < 5 else 0.6
                }
        
        return predictions
    
    def _check_predictions(self, predictions: Dict[str, Any]):
        """Verifica predições e cria alertas se necessário"""
        thresholds = {
            'cpu_usage': 80,
            'memory_usage': 85,
            'error_rate': 10,
            'response_time': 1000
        }
        
        for metric, prediction in predictions.items():
            if metric in thresholds:
                threshold = thresholds[metric]
                predicted_value = prediction['predicted']
                confidence = prediction['confidence']
                
                if predicted_value > threshold and confidence > 0.7:
                    self._create_alert(
                        f"predictive_{metric}",
                        "warning",
                        f"Predição indica que {metric} pode exceder threshold em breve: {predicted_value:.2f} > {threshold}",
                        metric,
                        predicted_value,
                        threshold
                    )
    
    def _start_alert_processor(self):
        """Inicia processador de alertas"""
        def process_alerts():
            while self.running:
                try:
                    # Processa alertas da fila
                    while not self.alert_queue.empty():
                        alert = self.alert_queue.get_nowait()
                        self._process_alert(alert)
                    
                    # Verifica alertas existentes
                    self._check_existing_alerts()
                    
                except Exception as e:
                    self.logger.error(f"Erro no processamento de alertas: {e}")
                
                time.sleep(10)  # Processa a cada 10 segundos
        
        thread = threading.Thread(target=process_alerts, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)
    
    def _start_auto_healing(self):
        """Inicia auto-healing"""
        def auto_healing():
            while self.running:
                try:
                    # Verifica componentes que precisam de healing
                    for component_name, health in self.component_health.items():
                        if health.status == 'unhealthy':
                            self._attempt_auto_healing(component_name, health)
                    
                except Exception as e:
                    self.logger.error(f"Erro no auto-healing: {e}")
                
                time.sleep(60)  # Verifica a cada minuto
        
        thread = threading.Thread(target=auto_healing, daemon=True)
        thread.start()
        self.monitoring_threads.append(thread)
    
    def _attempt_auto_healing(self, component_name: str, health: ComponentHealth):
        """Tenta auto-healing de um componente"""
        self.logger.info(f"🔧 Tentando auto-healing para {component_name}")
        
        try:
            if component_name == 'api':
                self._heal_api()
            elif component_name == 'database':
                self._heal_database()
            elif component_name == 'redis':
                self._heal_redis()
            elif component_name == 'celery':
                self._heal_celery()
            else:
                self._heal_generic_component(component_name)
                
        except Exception as e:
            self.logger.error(f"Erro no auto-healing de {component_name}: {e}")
    
    def _heal_api(self):
        """Auto-healing da API"""
        try:
            # Reinicia workers se necessário
            subprocess.run(['systemctl', 'restart', 'omni-writer-api'], check=True)
            self.logger.info("✅ API reiniciada via auto-healing")
        except Exception as e:
            self.logger.error(f"Falha no auto-healing da API: {e}")
    
    def _heal_database(self):
        """Auto-healing do banco de dados"""
        try:
            # Limpa conexões órfãs
            subprocess.run(['pg_terminate_backend', '--all'], check=True)
            self.logger.info("✅ Conexões do banco limpas via auto-healing")
        except Exception as e:
            self.logger.error(f"Falha no auto-healing do banco: {e}")
    
    def _heal_redis(self):
        """Auto-healing do Redis"""
        try:
            # Limpa cache se necessário
            self.redis_client.flushdb()
            self.logger.info("✅ Cache Redis limpo via auto-healing")
        except Exception as e:
            self.logger.error(f"Falha no auto-healing do Redis: {e}")
    
    def _heal_celery(self):
        """Auto-healing do Celery"""
        try:
            # Reinicia workers Celery
            subprocess.run(['celery', '-A', 'app.celery', 'restart'], check=True)
            self.logger.info("✅ Workers Celery reiniciados via auto-healing")
        except Exception as e:
            self.logger.error(f"Falha no auto-healing do Celery: {e}")
    
    def _heal_generic_component(self, component_name: str):
        """Auto-healing genérico"""
        try:
            # Tenta reiniciar serviço
            subprocess.run(['systemctl', 'restart', f'omni-writer-{component_name}'], check=True)
            self.logger.info(f"✅ {component_name} reiniciado via auto-healing")
        except Exception as e:
            self.logger.error(f"Falha no auto-healing de {component_name}: {e}")
    
    def _create_alert(self, alert_id: str, severity: str, message: str, 
                     metric: str, value: float, threshold: float):
        """Cria um novo alerta"""
        alert = Alert(
            id=alert_id,
            severity=severity,
            message=message,
            metric=metric,
            value=value,
            threshold=threshold,
            timestamp=datetime.now()
        )
        
        # Adiciona à fila de alertas
        self.alert_queue.put(alert)
        
        # Adiciona à lista de alertas
        self.alerts.append(alert)
        
        self.logger.warning(f"🚨 Alerta criado: {message}")
    
    def _process_alert(self, alert: Alert):
        """Processa um alerta"""
        # Envia notificações
        if self.config.get('alerts', {}).get('email', {}).get('enabled', False):
            self._send_email_alert(alert)
        
        if self.config.get('alerts', {}).get('slack', {}).get('enabled', False):
            self._send_slack_alert(alert)
        
        # Salva alerta no Redis
        self.redis_client.setex(
            f"alert:{alert.id}",
            3600,  # Expira em 1 hora
            json.dumps(asdict(alert))
        )
    
    def _send_email_alert(self, alert: Alert):
        """Envia alerta por email"""
        try:
            email_config = self.config['alerts']['email']
            
            msg = MIMEMultipart()
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = f"[{alert.severity.upper()}] Alerta Omni Writer - {alert.metric}"
            
            body = f"""
            Alerta do Sistema Omni Writer
            
            Severidade: {alert.severity}
            Métrica: {alert.metric}
            Valor: {alert.value}
            Threshold: {alert.threshold}
            Mensagem: {alert.message}
            Timestamp: {alert.timestamp}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"📧 Alerta enviado por email: {alert.message}")
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar email: {e}")
    
    def _send_slack_alert(self, alert: Alert):
        """Envia alerta para Slack"""
        try:
            slack_config = self.config['alerts']['slack']
            
            color_map = {
                'critical': 'danger',
                'warning': 'warning',
                'info': 'good'
            }
            
            payload = {
                'channel': slack_config['channel'],
                'attachments': [{
                    'color': color_map.get(alert.severity, 'good'),
                    'title': f"🚨 Alerta Omni Writer - {alert.severity.upper()}",
                    'fields': [
                        {'title': 'Métrica', 'value': alert.metric, 'short': True},
                        {'title': 'Valor', 'value': str(alert.value), 'short': True},
                        {'title': 'Threshold', 'value': str(alert.threshold), 'short': True},
                        {'title': 'Mensagem', 'value': alert.message, 'short': False}
                    ],
                    'footer': f"Timestamp: {alert.timestamp}"
                }]
            }
            
            response = requests.post(slack_config['webhook_url'], json=payload)
            response.raise_for_status()
            
            self.logger.info(f"💬 Alerta enviado para Slack: {alert.message}")
            
        except Exception as e:
            self.logger.error(f"Erro ao enviar para Slack: {e}")
    
    def _check_component_alerts(self, component_name: str, health: ComponentHealth, config: Dict[str, Any]):
        """Verifica alertas de componente"""
        thresholds = config.get('thresholds', {})
        
        # Verifica response time
        if 'response_time' in thresholds and health.response_time > thresholds['response_time']:
            self._create_alert(
                f"{component_name}_response_time",
                "warning",
                f"Response time de {component_name} muito alto: {health.response_time}ms",
                f"{component_name}_response_time",
                health.response_time,
                thresholds['response_time']
            )
        
        # Verifica status
        if health.status == 'unhealthy':
            self._create_alert(
                f"{component_name}_unhealthy",
                "critical",
                f"Componente {component_name} está unhealthy",
                f"{component_name}_status",
                0,
                1
            )
    
    def _check_system_alerts(self, cpu_usage: float, memory_usage: float, disk_usage: float):
        """Verifica alertas do sistema"""
        # CPU
        if cpu_usage > 80:
            self._create_alert(
                "system_cpu_high",
                "warning",
                f"CPU usage muito alto: {cpu_usage}%",
                "cpu_usage",
                cpu_usage,
                80
            )
        
        # Memória
        if memory_usage > 85:
            self._create_alert(
                "system_memory_high",
                "warning",
                f"Memory usage muito alto: {memory_usage}%",
                "memory_usage",
                memory_usage,
                85
            )
        
        # Disco
        if disk_usage > 90:
            self._create_alert(
                "system_disk_high",
                "critical",
                f"Disk usage muito alto: {disk_usage}%",
                "disk_usage",
                disk_usage,
                90
            )
    
    def _update_component_metrics(self, component_name: str, health: ComponentHealth):
        """Atualiza métricas do componente"""
        # Response time
        self.metrics['http_request_duration'].observe(health.response_time / 1000)
        
        # Error count
        if health.error_count > 0:
            self.metrics['application_errors'].inc()
        
        # Status como métrica
        status_value = 1 if health.status == 'healthy' else 0
        self.metrics['system_cpu_usage'].set(status_value)
    
    def _check_existing_alerts(self):
        """Verifica alertas existentes para resolução"""
        current_time = datetime.now()
        
        for alert in self.alerts:
            if not alert.resolved:
                # Verifica se o alerta foi resolvido
                if self._is_alert_resolved(alert):
                    alert.resolved = True
                    alert.auto_resolved = True
                    self.logger.info(f"✅ Alerta resolvido automaticamente: {alert.message}")
    
    def _is_alert_resolved(self, alert: Alert) -> bool:
        """Verifica se um alerta foi resolvido"""
        # Verifica se a métrica voltou ao normal
        if alert.metric in self.component_health:
            health = self.component_health[alert.metric]
            
            if alert.metric.endswith('_response_time'):
                return health.response_time <= alert.threshold
            elif alert.metric.endswith('_status'):
                return health.status == 'healthy'
        
        return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Gera relatório de monitoramento"""
        return {
            'timestamp': datetime.now().isoformat(),
            'components': {
                name: asdict(health) for name, health in self.component_health.items()
            },
            'alerts': {
                'total': len(self.alerts),
                'active': len([a for a in self.alerts if not a.resolved]),
                'critical': len([a for a in self.alerts if a.severity == 'critical' and not a.resolved]),
                'warning': len([a for a in self.alerts if a.severity == 'warning' and not a.resolved])
            },
            'system': {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
            }
        }

def main():
    """Função principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sistema de Monitoramento Proativo")
    parser.add_argument("--config", default="monitoring_config.json", help="Arquivo de configuração")
    parser.add_argument("--daemon", action="store_true", help="Executa como daemon")
    
    args = parser.parse_args()
    
    monitor = ProactiveMonitoring(args.config)
    
    try:
        monitor.start_monitoring()
        
        if args.daemon:
            # Executa indefinidamente
            while True:
                time.sleep(1)
        else:
            # Executa por 1 hora
            time.sleep(3600)
            
    except KeyboardInterrupt:
        print("\n🛑 Interrompendo monitoramento...")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main() 