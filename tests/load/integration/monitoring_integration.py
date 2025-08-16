"""
Monitoring Integration - Omni Writer
====================================

Sistema de integração com monitoramento existente.
Integração com Grafana, Prometheus e sistema de logs.

Prompt: LOAD_TESTS_IMPLEMENTATION_CHECKLIST.md - Fase 3, Item 20
Ruleset: enterprise_control_layer.yaml
Data: 2025-01-27T16:40:00Z
"""

import os
import json
import time
import asyncio
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Union
from pathlib import Path
import logging
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway
import grafana_client
from grafana_client.grafana_apiclient import GrafanaClientError
import elasticsearch
from elasticsearch import Elasticsearch
import influxdb
from influxdb import InfluxDBClient

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] [%(name)s] %(message)s - %(asctime)s'
)
logger = logging.getLogger('monitoring_integration')

@dataclass
class MonitoringConfig:
    """Configuração de monitoramento."""
    grafana_url: str
    grafana_api_key: str
    prometheus_url: str
    prometheus_pushgateway: str
    elasticsearch_url: str
    elasticsearch_index: str
    influxdb_url: str
    influxdb_database: str
    influxdb_username: str
    influxdb_password: str

@dataclass
class CustomMetric:
    """Métrica customizada."""
    metric_name: str
    metric_type: str  # 'gauge', 'counter', 'histogram'
    description: str
    labels: List[str]
    value: float
    timestamp: datetime

@dataclass
class DashboardConfig:
    """Configuração de dashboard."""
    dashboard_id: str
    title: str
    description: str
    panels: List[Dict[str, Any]]
    tags: List[str]
    folder: str

@dataclass
class UnifiedAlert:
    """Alerta unificado."""
    alert_id: str
    source: str  # 'grafana', 'prometheus', 'custom'
    severity: str
    message: str
    metric_value: float
    threshold: float
    timestamp: datetime
    status: str  # 'firing', 'resolved'

class MonitoringIntegration:
    """
    Sistema de integração com monitoramento existente.
    """
    
    def __init__(self, 
                 config_file: str = "tests/load/integration/config.json"):
        """
        Inicializa o sistema de integração.
        
        Args:
            config_file: Arquivo de configuração
        """
        self.config_file = Path(config_file)
        self.output_dir = Path("tests/load/integration/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurações de monitoramento
        self.monitoring_config = MonitoringConfig(
            grafana_url=os.getenv("GRAFANA_URL", "http://localhost:3000"),
            grafana_api_key=os.getenv("GRAFANA_API_KEY", ""),
            prometheus_url=os.getenv("PROMETHEUS_URL", "http://localhost:9090"),
            prometheus_pushgateway=os.getenv("PROMETHEUS_PUSHGATEWAY", "http://localhost:9091"),
            elasticsearch_url=os.getenv("ELASTICSEARCH_URL", "http://localhost:9200"),
            elasticsearch_index=os.getenv("ELASTICSEARCH_INDEX", "load-tests"),
            influxdb_url=os.getenv("INFLUXDB_URL", "http://localhost:8086"),
            influxdb_database=os.getenv("INFLUXDB_DATABASE", "load_tests"),
            influxdb_username=os.getenv("INFLUXDB_USERNAME", ""),
            influxdb_password=os.getenv("INFLUXDB_PASSWORD", "")
        )
        
        # Clientes de monitoramento
        self.grafana_client = None
        self.prometheus_registry = None
        self.elasticsearch_client = None
        self.influxdb_client = None
        
        # Métricas customizadas
        self.custom_metrics: List[CustomMetric] = []
        self.metric_registry: Dict[str, Any] = {}
        
        # Dashboards
        self.dashboards: List[DashboardConfig] = []
        self.unified_dashboards: List[Dict[str, Any]] = []
        
        # Alertas unificados
        self.unified_alerts: List[UnifiedAlert] = []
        
        # Estado do sistema
        self.is_integrated = False
        self.integration_status = {}
        
        # Carrega configuração
        self.load_config()
        
        # Inicializa clientes
        self._initialize_clients()
        
        logger.info(f"Inicializado - {datetime.now().isoformat()}")

    def load_config(self) -> None:
        """
        Carrega configuração de integração.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Atualiza configurações
                for key, value in config.get('monitoring_config', {}).items():
                    if hasattr(self.monitoring_config, key):
                        setattr(self.monitoring_config, key, value)
                
                logger.info("Configuração carregada do arquivo")
            else:
                self.save_config()
                logger.info("Usando configuração padrão")
                
        except Exception as e:
            logger.error(f"Erro ao carregar configuração: {e}")

    def save_config(self) -> None:
        """
        Salva configuração atual.
        """
        try:
            config = {
                'monitoring_config': asdict(self.monitoring_config),
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, default=str)
                
            logger.info("Configuração salva")
            
        except Exception as e:
            logger.error(f"Erro ao salvar configuração: {e}")

    def _initialize_clients(self) -> None:
        """
        Inicializa clientes de monitoramento.
        """
        try:
            # Inicializa Grafana
            if self.monitoring_config.grafana_api_key:
                self.grafana_client = grafana_client.GrafanaApi(
                    auth=self.monitoring_config.grafana_api_key,
                    host=self.monitoring_config.grafana_url
                )
                logger.info("Cliente Grafana inicializado")
            
            # Inicializa Prometheus
            self.prometheus_registry = CollectorRegistry()
            logger.info("Registry Prometheus inicializado")
            
            # Inicializa Elasticsearch
            if self.monitoring_config.elasticsearch_url:
                self.elasticsearch_client = Elasticsearch([self.monitoring_config.elasticsearch_url])
                logger.info("Cliente Elasticsearch inicializado")
            
            # Inicializa InfluxDB
            if self.monitoring_config.influxdb_url:
                self.influxdb_client = InfluxDBClient(
                    host=self.monitoring_config.influxdb_url.replace('http://', ''),
                    database=self.monitoring_config.influxdb_database,
                    username=self.monitoring_config.influxdb_username,
                    password=self.monitoring_config.influxdb_password
                )
                logger.info("Cliente InfluxDB inicializado")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar clientes: {e}")

    def integrate_with_grafana(self) -> bool:
        """
        Integra com Grafana existente.
        """
        try:
            if not self.grafana_client:
                logger.warning("Cliente Grafana não configurado")
                return False
            
            # Testa conexão
            response = self.grafana_client.search.search_dashboards()
            
            if response.status_code == 200:
                logger.info("Integração com Grafana estabelecida")
                self.integration_status['grafana'] = True
                return True
            else:
                logger.error(f"Erro na conexão com Grafana: {response.status_code}")
                self.integration_status['grafana'] = False
                return False
                
        except Exception as e:
            logger.error(f"Erro na integração com Grafana: {e}")
            self.integration_status['grafana'] = False
            return False

    def integrate_with_prometheus(self) -> bool:
        """
        Integra com Prometheus existente.
        """
        try:
            # Testa conexão com Prometheus
            response = requests.get(f"{self.monitoring_config.prometheus_url}/api/v1/status/config")
            
            if response.status_code == 200:
                logger.info("Integração com Prometheus estabelecida")
                self.integration_status['prometheus'] = True
                return True
            else:
                logger.error(f"Erro na conexão com Prometheus: {response.status_code}")
                self.integration_status['prometheus'] = False
                return False
                
        except Exception as e:
            logger.error(f"Erro na integração com Prometheus: {e}")
            self.integration_status['prometheus'] = False
            return False

    def integrate_with_logs_system(self) -> bool:
        """
        Integra com sistema de logs existente.
        """
        try:
            # Testa Elasticsearch
            if self.elasticsearch_client:
                health = self.elasticsearch_client.cluster.health()
                if health['status'] in ['green', 'yellow']:
                    logger.info("Integração com Elasticsearch estabelecida")
                    self.integration_status['elasticsearch'] = True
                else:
                    logger.warning(f"Elasticsearch não saudável: {health['status']}")
                    self.integration_status['elasticsearch'] = False
            
            # Testa InfluxDB
            if self.influxdb_client:
                try:
                    self.influxdb_client.ping()
                    logger.info("Integração com InfluxDB estabelecida")
                    self.integration_status['influxdb'] = True
                except Exception as e:
                    logger.error(f"Erro na conexão com InfluxDB: {e}")
                    self.integration_status['influxdb'] = False
            
            return any(self.integration_status.get(k, False) for k in ['elasticsearch', 'influxdb'])
            
        except Exception as e:
            logger.error(f"Erro na integração com sistema de logs: {e}")
            return False

    def create_unified_dashboards(self) -> List[Dict[str, Any]]:
        """
        Cria dashboards unificados.
        """
        try:
            unified_dashboards = []
            
            # Dashboard principal de load tests
            main_dashboard = {
                "dashboard": {
                    "id": None,
                    "title": "Load Tests - Dashboard Unificado",
                    "description": "Dashboard unificado para monitoramento de load tests",
                    "tags": ["load-tests", "performance", "unified"],
                    "timezone": "browser",
                    "panels": [
                        {
                            "id": 1,
                            "title": "Throughput (req/s)",
                            "type": "graph",
                            "targets": [
                                {
                                    "expr": "rate(load_test_requests_total[5m])",
                                    "legendFormat": "{{test_name}}"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                        },
                        {
                            "id": 2,
                            "title": "Response Time (ms)",
                            "type": "graph",
                            "targets": [
                                {
                                    "expr": "histogram_quantile(0.95, rate(load_test_response_time_bucket[5m]))",
                                    "legendFormat": "95th percentile"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
                        },
                        {
                            "id": 3,
                            "title": "Error Rate (%)",
                            "type": "graph",
                            "targets": [
                                {
                                    "expr": "rate(load_test_errors_total[5m]) / rate(load_test_requests_total[5m]) * 100",
                                    "legendFormat": "Error Rate"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
                        },
                        {
                            "id": 4,
                            "title": "Active Users",
                            "type": "stat",
                            "targets": [
                                {
                                    "expr": "load_test_active_users",
                                    "legendFormat": "Active Users"
                                }
                            ],
                            "gridPos": {"h": 4, "w": 6, "x": 12, "y": 8}
                        },
                        {
                            "id": 5,
                            "title": "System Resources",
                            "type": "graph",
                            "targets": [
                                {
                                    "expr": "rate(process_cpu_seconds_total[5m]) * 100",
                                    "legendFormat": "CPU %"
                                },
                                {
                                    "expr": "process_resident_memory_bytes / 1024 / 1024",
                                    "legendFormat": "Memory MB"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
                        }
                    ],
                    "time": {
                        "from": "now-1h",
                        "to": "now"
                    },
                    "refresh": "5s"
                },
                "folderId": 0,
                "overwrite": True
            }
            
            unified_dashboards.append(main_dashboard)
            
            # Dashboard de alertas
            alerts_dashboard = {
                "dashboard": {
                    "id": None,
                    "title": "Load Tests - Alertas",
                    "description": "Dashboard de alertas de load tests",
                    "tags": ["load-tests", "alerts", "unified"],
                    "timezone": "browser",
                    "panels": [
                        {
                            "id": 1,
                            "title": "Alertas Ativos",
                            "type": "table",
                            "targets": [
                                {
                                    "expr": "ALERTS{alertstate=\"firing\"}",
                                    "legendFormat": "{{alertname}}"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0}
                        },
                        {
                            "id": 2,
                            "title": "Histórico de Alertas",
                            "type": "graph",
                            "targets": [
                                {
                                    "expr": "changes(ALERTS[1h])",
                                    "legendFormat": "Alert Changes"
                                }
                            ],
                            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
                        }
                    ],
                    "time": {
                        "from": "now-24h",
                        "to": "now"
                    },
                    "refresh": "30s"
                },
                "folderId": 0,
                "overwrite": True
            }
            
            unified_dashboards.append(alerts_dashboard)
            
            self.unified_dashboards = unified_dashboards
            logger.info(f"Dashboards unificados criados: {len(unified_dashboards)}")
            
            return unified_dashboards
            
        except Exception as e:
            logger.error(f"Erro ao criar dashboards unificados: {e}")
            return []

    def create_custom_metrics(self) -> Dict[str, Any]:
        """
        Cria métricas customizadas.
        """
        try:
            # Métricas de load test
            load_test_requests = Counter(
                'load_test_requests_total',
                'Total number of load test requests',
                ['test_name', 'endpoint', 'status'],
                registry=self.prometheus_registry
            )
            
            load_test_response_time = Histogram(
                'load_test_response_time_seconds',
                'Response time of load test requests',
                ['test_name', 'endpoint'],
                registry=self.prometheus_registry
            )
            
            load_test_errors = Counter(
                'load_test_errors_total',
                'Total number of load test errors',
                ['test_name', 'error_type'],
                registry=self.prometheus_registry
            )
            
            load_test_active_users = Gauge(
                'load_test_active_users',
                'Number of active users in load test',
                ['test_name'],
                registry=self.prometheus_registry
            )
            
            load_test_throughput = Gauge(
                'load_test_throughput_rps',
                'Current throughput in requests per second',
                ['test_name'],
                registry=self.prometheus_registry
            )
            
            # Métricas de sistema
            system_cpu_usage = Gauge(
                'load_test_system_cpu_percent',
                'CPU usage during load test',
                ['test_name'],
                registry=self.prometheus_registry
            )
            
            system_memory_usage = Gauge(
                'load_test_system_memory_mb',
                'Memory usage during load test in MB',
                ['test_name'],
                registry=self.prometheus_registry
            )
            
            # Armazena métricas
            self.metric_registry = {
                'load_test_requests': load_test_requests,
                'load_test_response_time': load_test_response_time,
                'load_test_errors': load_test_errors,
                'load_test_active_users': load_test_active_users,
                'load_test_throughput': load_test_throughput,
                'system_cpu_usage': system_cpu_usage,
                'system_memory_usage': system_memory_usage
            }
            
            logger.info(f"Métricas customizadas criadas: {len(self.metric_registry)}")
            return self.metric_registry
            
        except Exception as e:
            logger.error(f"Erro ao criar métricas customizadas: {e}")
            return {}

    def update_custom_metrics(self, 
                            test_name: str,
                            requests_count: int = 0,
                            response_time: float = 0.0,
                            errors_count: int = 0,
                            active_users: int = 0,
                            throughput: float = 0.0,
                            cpu_usage: float = 0.0,
                            memory_usage: float = 0.0) -> None:
        """
        Atualiza métricas customizadas.
        """
        try:
            # Atualiza métricas de load test
            if 'load_test_requests' in self.metric_registry:
                self.metric_registry['load_test_requests'].labels(
                    test_name=test_name,
                    endpoint='api',
                    status='success'
                ).inc(requests_count)
            
            if 'load_test_response_time' in self.metric_registry and response_time > 0:
                self.metric_registry['load_test_response_time'].labels(
                    test_name=test_name,
                    endpoint='api'
                ).observe(response_time)
            
            if 'load_test_errors' in self.metric_registry and errors_count > 0:
                self.metric_registry['load_test_errors'].labels(
                    test_name=test_name,
                    error_type='http_error'
                ).inc(errors_count)
            
            if 'load_test_active_users' in self.metric_registry:
                self.metric_registry['load_test_active_users'].labels(
                    test_name=test_name
                ).set(active_users)
            
            if 'load_test_throughput' in self.metric_registry:
                self.metric_registry['load_test_throughput'].labels(
                    test_name=test_name
                ).set(throughput)
            
            # Atualiza métricas de sistema
            if 'system_cpu_usage' in self.metric_registry:
                self.metric_registry['system_cpu_usage'].labels(
                    test_name=test_name
                ).set(cpu_usage)
            
            if 'system_memory_usage' in self.metric_registry:
                self.metric_registry['system_memory_usage'].labels(
                    test_name=test_name
                ).set(memory_usage)
            
            # Envia métricas para Prometheus
            if self.monitoring_config.prometheus_pushgateway:
                push_to_gateway(
                    self.monitoring_config.prometheus_pushgateway,
                    job='load_tests',
                    registry=self.prometheus_registry
                )
            
        except Exception as e:
            logger.error(f"Erro ao atualizar métricas customizadas: {e}")

    def create_unified_alerts(self) -> List[UnifiedAlert]:
        """
        Cria alertas unificados.
        """
        try:
            unified_alerts = []
            
            # Alerta de alta taxa de erro
            error_alert = UnifiedAlert(
                alert_id="high_error_rate",
                source="prometheus",
                severity="warning",
                message="Taxa de erro alta detectada",
                metric_value=0.0,
                threshold=0.05,
                timestamp=datetime.now(),
                status="pending"
            )
            
            # Alerta de tempo de resposta alto
            response_time_alert = UnifiedAlert(
                alert_id="high_response_time",
                source="prometheus",
                severity="warning",
                message="Tempo de resposta alto detectado",
                metric_value=0.0,
                threshold=1000.0,
                timestamp=datetime.now(),
                status="pending"
            )
            
            # Alerta de throughput baixo
            throughput_alert = UnifiedAlert(
                alert_id="low_throughput",
                source="prometheus",
                severity="info",
                message="Throughput baixo detectado",
                metric_value=0.0,
                threshold=10.0,
                timestamp=datetime.now(),
                status="pending"
            )
            
            # Alerta de uso de CPU alto
            cpu_alert = UnifiedAlert(
                alert_id="high_cpu_usage",
                source="prometheus",
                severity="warning",
                message="Uso de CPU alto detectado",
                metric_value=0.0,
                threshold=90.0,
                timestamp=datetime.now(),
                status="pending"
            )
            
            unified_alerts.extend([error_alert, response_time_alert, throughput_alert, cpu_alert])
            self.unified_alerts = unified_alerts
            
            logger.info(f"Alertas unificados criados: {len(unified_alerts)}")
            return unified_alerts
            
        except Exception as e:
            logger.error(f"Erro ao criar alertas unificados: {e}")
            return []

    def send_metrics_to_elasticsearch(self, metrics_data: Dict[str, Any]) -> bool:
        """
        Envia métricas para Elasticsearch.
        """
        try:
            if not self.elasticsearch_client:
                logger.warning("Cliente Elasticsearch não configurado")
                return False
            
            # Prepara documento
            document = {
                "timestamp": datetime.now().isoformat(),
                "test_name": metrics_data.get("test_name", "unknown"),
                "requests_count": metrics_data.get("requests_count", 0),
                "response_time_avg": metrics_data.get("response_time_avg", 0.0),
                "error_rate": metrics_data.get("error_rate", 0.0),
                "throughput": metrics_data.get("throughput", 0.0),
                "cpu_usage": metrics_data.get("cpu_usage", 0.0),
                "memory_usage": metrics_data.get("memory_usage", 0.0),
                "source": "load_test_integration"
            }
            
            # Envia para Elasticsearch
            response = self.elasticsearch_client.index(
                index=self.monitoring_config.elasticsearch_index,
                body=document
            )
            
            if response['result'] in ['created', 'updated']:
                logger.info(f"Métricas enviadas para Elasticsearch: {response['_id']}")
                return True
            else:
                logger.error(f"Erro ao enviar métricas para Elasticsearch: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao enviar métricas para Elasticsearch: {e}")
            return False

    def send_metrics_to_influxdb(self, metrics_data: Dict[str, Any]) -> bool:
        """
        Envia métricas para InfluxDB.
        """
        try:
            if not self.influxdb_client:
                logger.warning("Cliente InfluxDB não configurado")
                return False
            
            # Prepara pontos de dados
            points = [
                {
                    "measurement": "load_test_metrics",
                    "tags": {
                        "test_name": metrics_data.get("test_name", "unknown"),
                        "source": "load_test_integration"
                    },
                    "time": datetime.now().isoformat(),
                    "fields": {
                        "requests_count": metrics_data.get("requests_count", 0),
                        "response_time_avg": metrics_data.get("response_time_avg", 0.0),
                        "error_rate": metrics_data.get("error_rate", 0.0),
                        "throughput": metrics_data.get("throughput", 0.0),
                        "cpu_usage": metrics_data.get("cpu_usage", 0.0),
                        "memory_usage": metrics_data.get("memory_usage", 0.0)
                    }
                }
            ]
            
            # Envia para InfluxDB
            self.influxdb_client.write_points(points)
            
            logger.info("Métricas enviadas para InfluxDB")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao enviar métricas para InfluxDB: {e}")
            return False

    def create_consolidated_reports(self) -> Dict[str, Any]:
        """
        Cria relatórios consolidados.
        """
        try:
            consolidated_report = {
                "report_id": f"consolidated_{int(time.time())}",
                "timestamp": datetime.now().isoformat(),
                "integration_status": self.integration_status,
                "metrics_summary": {
                    "total_metrics": len(self.custom_metrics),
                    "active_dashboards": len(self.unified_dashboards),
                    "active_alerts": len([a for a in self.unified_alerts if a.status == "firing"])
                },
                "system_health": {
                    "grafana": self.integration_status.get('grafana', False),
                    "prometheus": self.integration_status.get('prometheus', False),
                    "elasticsearch": self.integration_status.get('elasticsearch', False),
                    "influxdb": self.integration_status.get('influxdb', False)
                },
                "performance_metrics": {
                    "avg_response_time": 0.0,
                    "total_requests": 0,
                    "error_rate": 0.0,
                    "throughput": 0.0
                },
                "recommendations": []
            }
            
            # Adiciona recomendações baseadas no status
            if not self.integration_status.get('grafana', False):
                consolidated_report["recommendations"].append("Configurar integração com Grafana")
            
            if not self.integration_status.get('prometheus', False):
                consolidated_report["recommendations"].append("Configurar integração com Prometheus")
            
            if not any([self.integration_status.get('elasticsearch', False), 
                       self.integration_status.get('influxdb', False)]):
                consolidated_report["recommendations"].append("Configurar sistema de logs")
            
            logger.info("Relatório consolidado criado")
            return consolidated_report
            
        except Exception as e:
            logger.error(f"Erro ao criar relatório consolidado: {e}")
            return {}

    def deploy_dashboards_to_grafana(self) -> bool:
        """
        Deploya dashboards para Grafana.
        """
        try:
            if not self.grafana_client:
                logger.warning("Cliente Grafana não configurado")
                return False
            
            success_count = 0
            
            for dashboard_config in self.unified_dashboards:
                try:
                    response = self.grafana_client.dashboard.update_dashboard(
                        dashboard=dashboard_config
                    )
                    
                    if response.status_code in [200, 201]:
                        logger.info(f"Dashboard deployado: {dashboard_config['dashboard']['title']}")
                        success_count += 1
                    else:
                        logger.error(f"Erro ao deployar dashboard: {response.status_code}")
                        
                except Exception as e:
                    logger.error(f"Erro ao deployar dashboard {dashboard_config['dashboard']['title']}: {e}")
            
            logger.info(f"Dashboards deployados: {success_count}/{len(self.unified_dashboards)}")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Erro ao deployar dashboards: {e}")
            return False

    def run_full_integration(self) -> Dict[str, Any]:
        """
        Executa integração completa.
        """
        logger.info("Iniciando integração completa com sistemas de monitoramento...")
        
        integration_results = {
            "timestamp": datetime.now().isoformat(),
            "success": True,
            "integrations": {},
            "dashboards_created": 0,
            "metrics_created": 0,
            "alerts_created": 0
        }
        
        try:
            # Integra com Grafana
            grafana_success = self.integrate_with_grafana()
            integration_results["integrations"]["grafana"] = grafana_success
            
            # Integra com Prometheus
            prometheus_success = self.integrate_with_prometheus()
            integration_results["integrations"]["prometheus"] = prometheus_success
            
            # Integra com sistema de logs
            logs_success = self.integrate_with_logs_system()
            integration_results["integrations"]["logs"] = logs_success
            
            # Cria dashboards unificados
            dashboards = self.create_unified_dashboards()
            integration_results["dashboards_created"] = len(dashboards)
            
            # Cria métricas customizadas
            metrics = self.create_custom_metrics()
            integration_results["metrics_created"] = len(metrics)
            
            # Cria alertas unificados
            alerts = self.create_unified_alerts()
            integration_results["alerts_created"] = len(alerts)
            
            # Deploya dashboards se Grafana estiver disponível
            if grafana_success:
                self.deploy_dashboards_to_grafana()
            
            # Cria relatório consolidado
            consolidated_report = self.create_consolidated_reports()
            
            # Salva relatório
            report_file = self.output_dir / f"integration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(consolidated_report, f, indent=2, default=str)
            
            integration_results["report_file"] = str(report_file)
            
            logger.info("Integração completa finalizada com sucesso!")
            return integration_results
            
        except Exception as e:
            logger.error(f"Erro na integração completa: {e}")
            integration_results["success"] = False
            integration_results["error"] = str(e)
            return integration_results

    def generate_integration_report(self) -> str:
        """
        Gera relatório de integração.
        """
        try:
            report_file = self.output_dir / f"monitoring_integration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"# Relatório de Integração com Monitoramento - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("## Resumo Executivo\n\n")
                f.write(f"- **Integração Grafana:** {'✅' if self.integration_status.get('grafana', False) else '❌'}\n")
                f.write(f"- **Integração Prometheus:** {'✅' if self.integration_status.get('prometheus', False) else '❌'}\n")
                f.write(f"- **Integração Logs:** {'✅' if any([self.integration_status.get('elasticsearch', False), self.integration_status.get('influxdb', False)]) else '❌'}\n")
                f.write(f"- **Dashboards criados:** {len(self.unified_dashboards)}\n")
                f.write(f"- **Métricas customizadas:** {len(self.metric_registry)}\n")
                f.write(f"- **Alertas unificados:** {len(self.unified_alerts)}\n\n")
                
                f.write("## Status das Integrações\n\n")
                
                for system, status in self.integration_status.items():
                    status_icon = "✅" if status else "❌"
                    f.write(f"- **{system.title()}:** {status_icon}\n")
                
                f.write("\n## Dashboards Unificados\n\n")
                
                for i, dashboard in enumerate(self.unified_dashboards, 1):
                    f.write(f"### {i}. {dashboard['dashboard']['title']}\n")
                    f.write(f"- **Descrição:** {dashboard['dashboard']['description']}\n")
                    f.write(f"- **Tags:** {', '.join(dashboard['dashboard']['tags'])}\n")
                    f.write(f"- **Painéis:** {len(dashboard['dashboard']['panels'])}\n\n")
                
                f.write("## Métricas Customizadas\n\n")
                
                for metric_name, metric_obj in self.metric_registry.items():
                    f.write(f"- **{metric_name}:** {type(metric_obj).__name__}\n")
                
                f.write("\n## Alertas Unificados\n\n")
                
                for alert in self.unified_alerts:
                    f.write(f"- **{alert.alert_id}:** {alert.message} (Severidade: {alert.severity})\n")
                
                f.write("\n## Configurações\n\n")
                f.write(f"- **Grafana URL:** {self.monitoring_config.grafana_url}\n")
                f.write(f"- **Prometheus URL:** {self.monitoring_config.prometheus_url}\n")
                f.write(f"- **Elasticsearch URL:** {self.monitoring_config.elasticsearch_url}\n")
                f.write(f"- **InfluxDB URL:** {self.monitoring_config.influxdb_url}\n")
                f.write(f"- **InfluxDB Database:** {self.monitoring_config.influxdb_database}\n\n")
                
                f.write("---\n")
                f.write(f"*Relatório gerado automaticamente em {datetime.now().isoformat()}*\n")
            
            logger.info(f"Relatório de integração gerado: {report_file}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório de integração: {e}")
            return ""


async def main():
    """
    Função principal para execução direta.
    """
    logger.info("Iniciando Monitoring Integration...")
    
    integration = MonitoringIntegration()
    
    try:
        # Executa integração completa
        results = integration.run_full_integration()
        
        # Gera relatório
        report_file = integration.generate_integration_report()
        
        # Simula envio de métricas
        test_metrics = {
            "test_name": "integration_test",
            "requests_count": 1000,
            "response_time_avg": 150.5,
            "error_rate": 0.02,
            "throughput": 50.0,
            "cpu_usage": 75.0,
            "memory_usage": 512.0
        }
        
        # Atualiza métricas customizadas
        integration.update_custom_metrics(**test_metrics)
        
        # Envia para sistemas de logs
        integration.send_metrics_to_elasticsearch(test_metrics)
        integration.send_metrics_to_influxdb(test_metrics)
        
        logger.info("Monitoring Integration testado com sucesso!")
        logger.info(f"Resultados: {results}")
        logger.info(f"Relatório: {report_file}")
        
    except Exception as e:
        logger.error(f"Erro no teste: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 