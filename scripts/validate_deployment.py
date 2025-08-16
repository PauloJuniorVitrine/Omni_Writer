#!/usr/bin/env python3
"""
Script de Validação de Deploy - Omni Writer
===========================================

Executa validações rigorosas após deploy:
- Health checks de todos os componentes
- Verificação de métricas críticas
- Testes de funcionalidade
- Validação de performance
- Verificação de segurança

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import time
import json
import requests
import subprocess
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import psutil
import redis
import prometheus_client
from prometheus_client import CollectorRegistry, generate_latest
import os

@dataclass
class ValidationResult:
    """Resultado de uma validação"""
    component: str
    status: str  # 'passed', 'failed', 'warning'
    message: str
    duration: float
    timestamp: datetime
    details: Dict[str, Any]

@dataclass
class DeploymentValidation:
    """Validação completa do deploy"""
    deployment_id: str
    environment: str
    version: str
    start_time: datetime
    end_time: Optional[datetime] = None
    results: List[ValidationResult] = None
    overall_status: str = 'pending'
    
    def __post_init__(self):
        if self.results is None:
            self.results = []

class DeploymentValidator:
    """Validador de deploy"""
    
    def __init__(self, config_file: str = "deployment_config.json"):
        self.config = self._load_config(config_file)
        self.registry = CollectorRegistry()
        
        # Configuração de logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('deployment_validation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Resultados da validação
        self.validation_results: List[ValidationResult] = []
        self.deployment_validation: Optional[DeploymentValidation] = None
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Carrega configuração de validação"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Configuração padrão
            return {
                'environments': {
                    'staging': {
                        'base_url': 'http://staging.omniwriter.com',
                        'timeout': 30,
                        'retries': 3,
                        'thresholds': {
                            'response_time': 2000,
                            'error_rate': 5,
                            'cpu_usage': 80,
                            'memory_usage': 85
                        }
                    },
                    'production': {
                        'base_url': 'https://api.omniwriter.com',
                        'timeout': 60,
                        'retries': 5,
                        'thresholds': {
                            'response_time': 1500,
                            'error_rate': 2,
                            'cpu_usage': 70,
                            'memory_usage': 80
                        }
                    }
                },
                'components': {
                    'api': {
                        'health_endpoint': '/health',
                        'metrics_endpoint': '/metrics',
                        'critical_endpoints': [
                            '/api/v1/generate',
                            '/api/v1/status',
                            '/api/v1/export'
                        ]
                    },
                    'database': {
                        'connection_string': 'postgresql://localhost:5432/omni_writer',
                        'test_queries': [
                            'SELECT 1',
                            'SELECT COUNT(*) FROM articles',
                            'SELECT COUNT(*) FROM users'
                        ]
                    },
                    'redis': {
                        'connection_string': 'redis://localhost:6379',
                        'test_operations': ['ping', 'set', 'get', 'del']
                    },
                    'celery': {
                        'flower_url': 'http://localhost:5555',
                        'test_tasks': ['health_check', 'status_check']
                    }
                },
                'security': {
                    'headers_to_check': [
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'X-XSS-Protection',
                        'Strict-Transport-Security',
                        'Content-Security-Policy'
                    ],
                    'ssl_verification': True,
                    'rate_limit_check': True
                },
                'performance': {
                    'load_test_duration': 60,
                    'concurrent_users': 10,
                    'target_rps': 100
                }
            }
    
    def validate_deployment(self, environment: str, version: str, 
                          deployment_id: str = None) -> DeploymentValidation:
        """Executa validação completa do deploy"""
        if deployment_id is None:
            deployment_id = f"deploy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.logger.info(f"🚀 Iniciando validação de deploy: {deployment_id}")
        self.logger.info(f"Environment: {environment}")
        self.logger.info(f"Version: {version}")
        
        # Inicializa validação
        self.deployment_validation = DeploymentValidation(
            deployment_id=deployment_id,
            environment=environment,
            version=version,
            start_time=datetime.now()
        )
        
        try:
            # Executa validações
            self._validate_environment_config(environment)
            self._validate_health_checks(environment)
            self._validate_critical_endpoints(environment)
            self._validate_database(environment)
            self._validate_redis(environment)
            self._validate_celery(environment)
            self._validate_security(environment)
            self._validate_performance(environment)
            self._validate_metrics(environment)
            self._validate_logs(environment)
            
            # Finaliza validação
            self.deployment_validation.end_time = datetime.now()
            self.deployment_validation.overall_status = self._determine_overall_status()
            
            # Gera relatório
            self._generate_validation_report()
            
            self.logger.info(f"✅ Validação concluída: {self.deployment_validation.overall_status}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro durante validação: {e}")
            self.deployment_validation.overall_status = 'failed'
            self.deployment_validation.end_time = datetime.now()
        
        return self.deployment_validation
    
    def _validate_environment_config(self, environment: str):
        """Valida configuração do ambiente"""
        self.logger.info(f"🔧 Validando configuração do ambiente: {environment}")
        
        start_time = time.time()
        
        try:
            env_config = self.config['environments'].get(environment)
            if not env_config:
                raise ValueError(f"Configuração não encontrada para ambiente: {environment}")
            
            # Verifica se base_url está acessível
            response = requests.get(
                f"{env_config['base_url']}/health",
                timeout=env_config['timeout'],
                headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
            )
            
            duration = time.time() - start_time
            
            if response.status_code == 200:
                self._add_validation_result(
                    'environment_config',
                    'passed',
                    f"Ambiente {environment} configurado corretamente",
                    duration,
                    {'base_url': env_config['base_url'], 'status_code': response.status_code}
                )
            else:
                self._add_validation_result(
                    'environment_config',
                    'failed',
                    f"Ambiente {environment} não responde corretamente: {response.status_code}",
                    duration,
                    {'base_url': env_config['base_url'], 'status_code': response.status_code}
                )
                
        except Exception as e:
            duration = time.time() - start_time
            self._add_validation_result(
                'environment_config',
                'failed',
                f"Erro ao validar ambiente {environment}: {e}",
                duration,
                {'error': str(e)}
            )
    
    def _validate_health_checks(self, environment: str):
        """Valida health checks de todos os componentes"""
        self.logger.info(f"🏥 Validando health checks: {environment}")
        
        env_config = self.config['environments'][environment]
        components = self.config['components']
        
        for component_name, component_config in components.items():
            start_time = time.time()
            
            try:
                if component_name == 'api':
                    self._validate_api_health(env_config, component_config)
                elif component_name == 'database':
                    self._validate_database_health(component_config)
                elif component_name == 'redis':
                    self._validate_redis_health(component_config)
                elif component_name == 'celery':
                    self._validate_celery_health(component_config)
                
                duration = time.time() - start_time
                
            except Exception as e:
                duration = time.time() - start_time
                self._add_validation_result(
                    f'{component_name}_health',
                    'failed',
                    f"Health check falhou para {component_name}: {e}",
                    duration,
                    {'error': str(e)}
                )
    
    def _validate_api_health(self, env_config: Dict[str, Any], component_config: Dict[str, Any]):
        """Valida health da API"""
        health_url = f"{env_config['base_url']}{component_config['health_endpoint']}"
        
        response = requests.get(
            health_url,
            timeout=env_config['timeout'],
            headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
        )
        
        if response.status_code == 200:
            health_data = response.json()
            
            # Verifica status geral
            if health_data.get('status') == 'healthy':
                self._add_validation_result(
                    'api_health',
                    'passed',
                    "API está saudável",
                    0,
                    health_data
                )
            else:
                self._add_validation_result(
                    'api_health',
                    'warning',
                    f"API com status: {health_data.get('status')}",
                    0,
                    health_data
                )
        else:
            self._add_validation_result(
                'api_health',
                'failed',
                f"Health check da API falhou: {response.status_code}",
                0,
                {'status_code': response.status_code}
            )
    
    def _validate_database_health(self, component_config: Dict[str, Any]):
        """Valida health do banco de dados"""
        try:
            import psycopg2
            
            conn = psycopg2.connect(component_config['connection_string'])
            cursor = conn.cursor()
            
            # Executa queries de teste
            for query in component_config['test_queries']:
                cursor.execute(query)
                result = cursor.fetchone()
                
                if not result:
                    raise Exception(f"Query falhou: {query}")
            
            cursor.close()
            conn.close()
            
            self._add_validation_result(
                'database_health',
                'passed',
                "Banco de dados está saudável",
                0,
                {'queries_tested': len(component_config['test_queries'])}
            )
            
        except Exception as e:
            self._add_validation_result(
                'database_health',
                'failed',
                f"Health check do banco falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_redis_health(self, component_config: Dict[str, Any]):
        """Valida health do Redis"""
        try:
            redis_client = redis.from_url(component_config['connection_string'])
            
            # Testa operações básicas
            for operation in component_config['test_operations']:
                if operation == 'ping':
                    redis_client.ping()
                elif operation == 'set':
                    redis_client.set('test_key', 'test_value')
                elif operation == 'get':
                    value = redis_client.get('test_key')
                    if value != b'test_value':
                        raise Exception("Valor incorreto no Redis")
                elif operation == 'del':
                    redis_client.delete('test_key')
            
            self._add_validation_result(
                'redis_health',
                'passed',
                "Redis está saudável",
                0,
                {'operations_tested': len(component_config['test_operations'])}
            )
            
        except Exception as e:
            self._add_validation_result(
                'redis_health',
                'failed',
                f"Health check do Redis falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_celery_health(self, component_config: Dict[str, Any]):
        """Valida health do Celery"""
        try:
            # Verifica Flower (interface web do Celery)
            flower_url = component_config['flower_url']
            response = requests.get(f"{flower_url}/api/workers", timeout=10)
            
            if response.status_code == 200:
                workers_data = response.json()
                active_workers = len(workers_data)
                
                if active_workers > 0:
                    self._add_validation_result(
                        'celery_health',
                        'passed',
                        f"Celery está saudável com {active_workers} workers",
                        0,
                        {'active_workers': active_workers}
                    )
                else:
                    self._add_validation_result(
                        'celery_health',
                        'warning',
                        "Celery sem workers ativos",
                        0,
                        {'active_workers': 0}
                    )
            else:
                self._add_validation_result(
                    'celery_health',
                    'failed',
                    f"Flower não responde: {response.status_code}",
                    0,
                    {'status_code': response.status_code}
                )
                
        except Exception as e:
            self._add_validation_result(
                'celery_health',
                'failed',
                f"Health check do Celery falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_critical_endpoints(self, environment: str):
        """Valida endpoints críticos"""
        self.logger.info(f"🎯 Validando endpoints críticos: {environment}")
        
        env_config = self.config['environments'][environment]
        component_config = self.config['components']['api']
        
        for endpoint in component_config['critical_endpoints']:
            start_time = time.time()
            
            try:
                url = f"{env_config['base_url']}{endpoint}"
                
                # Testa com diferentes métodos HTTP
                for method in ['GET', 'POST']:
                    if method == 'GET':
                        response = requests.get(
                            url,
                            timeout=env_config['timeout'],
                            headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
                        )
                    else:
                        response = requests.post(
                            url,
                            json={'test': 'data'},
                            timeout=env_config['timeout'],
                            headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
                        )
                    
                    duration = time.time() - start_time
                    
                    # Verifica se endpoint responde (não necessariamente 200)
                    if response.status_code < 500:  # Não é erro de servidor
                        self._add_validation_result(
                            f'endpoint_{endpoint}_{method}',
                            'passed',
                            f"Endpoint {endpoint} ({method}) responde corretamente",
                            duration,
                            {'status_code': response.status_code, 'method': method}
                        )
                    else:
                        self._add_validation_result(
                            f'endpoint_{endpoint}_{method}',
                            'failed',
                            f"Endpoint {endpoint} ({method}) com erro: {response.status_code}",
                            duration,
                            {'status_code': response.status_code, 'method': method}
                        )
                        
            except Exception as e:
                duration = time.time() - start_time
                self._add_validation_result(
                    f'endpoint_{endpoint}',
                    'failed',
                    f"Erro ao testar endpoint {endpoint}: {e}",
                    duration,
                    {'error': str(e)}
                )
    
    def _validate_database(self, environment: str):
        """Validações específicas do banco de dados"""
        self.logger.info(f"🗄️ Validando banco de dados: {environment}")
        
        component_config = self.config['components']['database']
        
        try:
            import psycopg2
            
            conn = psycopg2.connect(component_config['connection_string'])
            cursor = conn.cursor()
            
            # Verifica conexões ativas
            cursor.execute("SELECT count(*) FROM pg_stat_activity")
            active_connections = cursor.fetchone()[0]
            
            # Verifica tamanho do banco
            cursor.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
            db_size = cursor.fetchone()[0]
            
            # Verifica tabelas críticas
            cursor.execute("""
                SELECT table_name, pg_size_pretty(pg_total_relation_size(table_name))
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY pg_total_relation_size(table_name) DESC
                LIMIT 5
            """)
            table_sizes = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            self._add_validation_result(
                'database_validation',
                'passed',
                "Banco de dados validado com sucesso",
                0,
                {
                    'active_connections': active_connections,
                    'database_size': db_size,
                    'table_sizes': table_sizes
                }
            )
            
        except Exception as e:
            self._add_validation_result(
                'database_validation',
                'failed',
                f"Validação do banco falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_redis(self, environment: str):
        """Validações específicas do Redis"""
        self.logger.info(f"🔴 Validando Redis: {environment}")
        
        component_config = self.config['components']['redis']
        
        try:
            redis_client = redis.from_url(component_config['connection_string'])
            
            # Obtém informações do Redis
            info = redis_client.info()
            
            # Verifica uso de memória
            used_memory = info.get('used_memory_human', '0B')
            max_memory = info.get('maxmemory_human', '0B')
            
            # Verifica número de chaves
            db_info = redis_client.info('keyspace')
            total_keys = sum(int(db.split(',')[1].split('=')[1]) for db in db_info.values() if 'keys=' in db)
            
            self._add_validation_result(
                'redis_validation',
                'passed',
                "Redis validado com sucesso",
                0,
                {
                    'used_memory': used_memory,
                    'max_memory': max_memory,
                    'total_keys': total_keys,
                    'uptime': info.get('uptime_in_seconds', 0)
                }
            )
            
        except Exception as e:
            self._add_validation_result(
                'redis_validation',
                'failed',
                f"Validação do Redis falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_celery(self, environment: str):
        """Validações específicas do Celery"""
        self.logger.info(f"🌿 Validando Celery: {environment}")
        
        component_config = self.config['components']['celery']
        
        try:
            flower_url = component_config['flower_url']
            
            # Obtém informações dos workers
            workers_response = requests.get(f"{flower_url}/api/workers", timeout=10)
            workers_data = workers_response.json()
            
            # Obtém informações das tasks
            tasks_response = requests.get(f"{flower_url}/api/tasks", timeout=10)
            tasks_data = tasks_response.json()
            
            # Calcula métricas
            active_workers = len(workers_data)
            total_tasks = len(tasks_data)
            completed_tasks = len([t for t in tasks_data.values() if t.get('state') == 'SUCCESS'])
            failed_tasks = len([t for t in tasks_data.values() if t.get('state') == 'FAILURE'])
            
            self._add_validation_result(
                'celery_validation',
                'passed',
                "Celery validado com sucesso",
                0,
                {
                    'active_workers': active_workers,
                    'total_tasks': total_tasks,
                    'completed_tasks': completed_tasks,
                    'failed_tasks': failed_tasks,
                    'success_rate': (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
                }
            )
            
        except Exception as e:
            self._add_validation_result(
                'celery_validation',
                'failed',
                f"Validação do Celery falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_security(self, environment: str):
        """Validações de segurança"""
        self.logger.info(f"🔒 Validando segurança: {environment}")
        
        env_config = self.config['environments'][environment]
        security_config = self.config['security']
        
        try:
            # Verifica headers de segurança
            response = requests.get(
                f"{env_config['base_url']}/health",
                timeout=env_config['timeout'],
                headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
            )
            
            headers = response.headers
            missing_headers = []
            
            for header in security_config['headers_to_check']:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self._add_validation_result(
                    'security_headers',
                    'warning',
                    f"Headers de segurança ausentes: {missing_headers}",
                    0,
                    {'missing_headers': missing_headers, 'present_headers': list(headers.keys())}
                )
            else:
                self._add_validation_result(
                    'security_headers',
                    'passed',
                    "Todos os headers de segurança estão presentes",
                    0,
                    {'headers_checked': security_config['headers_to_check']}
                )
            
            # Verifica SSL se aplicável
            if env_config['base_url'].startswith('https://') and security_config['ssl_verification']:
                self._validate_ssl_certificate(env_config['base_url'])
                
        except Exception as e:
            self._add_validation_result(
                'security_validation',
                'failed',
                f"Validação de segurança falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_ssl_certificate(self, url: str):
        """Valida certificado SSL"""
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verifica data de expiração
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        self._add_validation_result(
                            'ssl_certificate',
                            'passed',
                            f"Certificado SSL válido por {days_until_expiry} dias",
                            0,
                            {'days_until_expiry': days_until_expiry, 'issuer': cert.get('issuer')}
                        )
                    else:
                        self._add_validation_result(
                            'ssl_certificate',
                            'warning',
                            f"Certificado SSL expira em {days_until_expiry} dias",
                            0,
                            {'days_until_expiry': days_until_expiry, 'issuer': cert.get('issuer')}
                        )
                        
        except Exception as e:
            self._add_validation_result(
                'ssl_certificate',
                'failed',
                f"Validação de certificado SSL falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_performance(self, environment: str):
        """Validações de performance"""
        self.logger.info(f"⚡ Validando performance: {environment}")
        
        env_config = self.config['environments'][environment]
        performance_config = self.config['performance']
        
        try:
            # Teste de carga simples
            import threading
            import concurrent.futures
            
            def make_request():
                start_time = time.time()
                response = requests.get(
                    f"{env_config['base_url']}/health",
                    timeout=env_config['timeout'],
                    headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
                )
                duration = time.time() - start_time
                return response.status_code, duration
            
            # Executa requests concorrentes
            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=performance_config['concurrent_users']) as executor:
                futures = [executor.submit(make_request) for _ in range(performance_config['concurrent_users'] * 10)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            total_duration = time.time() - start_time
            total_requests = len(results)
            
            # Calcula métricas
            successful_requests = len([r for r in results if r[0] == 200])
            response_times = [r[1] for r in results]
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            max_response_time = max(response_times) if response_times else 0
            min_response_time = min(response_times) if response_times else 0
            
            rps = total_requests / total_duration
            success_rate = (successful_requests / total_requests) * 100 if total_requests > 0 else 0
            
            # Verifica thresholds
            thresholds = env_config['thresholds']
            performance_status = 'passed'
            performance_message = "Performance dentro dos limites"
            
            if avg_response_time > thresholds['response_time']:
                performance_status = 'warning'
                performance_message = f"Response time médio alto: {avg_response_time:.2f}ms"
            
            if success_rate < (100 - thresholds['error_rate']):
                performance_status = 'failed'
                performance_message = f"Taxa de sucesso baixa: {success_rate:.2f}%"
            
            self._add_validation_result(
                'performance_validation',
                performance_status,
                performance_message,
                total_duration,
                {
                    'total_requests': total_requests,
                    'successful_requests': successful_requests,
                    'success_rate': success_rate,
                    'avg_response_time': avg_response_time,
                    'max_response_time': max_response_time,
                    'min_response_time': min_response_time,
                    'requests_per_second': rps
                }
            )
            
        except Exception as e:
            self._add_validation_result(
                'performance_validation',
                'failed',
                f"Validação de performance falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_metrics(self, environment: str):
        """Valida métricas do sistema"""
        self.logger.info(f"📊 Validando métricas: {environment}")
        
        env_config = self.config['environments'][environment]
        component_config = self.config['components']['api']
        
        try:
            # Obtém métricas da aplicação
            metrics_url = f"{env_config['base_url']}{component_config['metrics_endpoint']}"
            response = requests.get(
                metrics_url,
                timeout=env_config['timeout'],
                headers={'User-Agent': 'OmniWriter-DeploymentValidator/1.0'}
            )
            
            if response.status_code == 200:
                metrics_data = response.text
                
                # Verifica métricas críticas
                critical_metrics = [
                    'http_requests_total',
                    'http_request_duration_seconds',
                    'application_errors_total',
                    'system_cpu_usage',
                    'system_memory_usage'
                ]
                
                missing_metrics = []
                for metric in critical_metrics:
                    if metric not in metrics_data:
                        missing_metrics.append(metric)
                
                if missing_metrics:
                    self._add_validation_result(
                        'metrics_validation',
                        'warning',
                        f"Métricas ausentes: {missing_metrics}",
                        0,
                        {'missing_metrics': missing_metrics}
                    )
                else:
                    self._add_validation_result(
                        'metrics_validation',
                        'passed',
                        "Todas as métricas críticas estão disponíveis",
                        0,
                        {'metrics_checked': critical_metrics}
                    )
            else:
                self._add_validation_result(
                    'metrics_validation',
                    'failed',
                    f"Endpoint de métricas não responde: {response.status_code}",
                    0,
                    {'status_code': response.status_code}
                )
                
        except Exception as e:
            self._add_validation_result(
                'metrics_validation',
                'failed',
                f"Validação de métricas falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _validate_logs(self, environment: str):
        """Valida logs do sistema"""
        self.logger.info(f"📝 Validando logs: {environment}")
        
        try:
            # Verifica se logs estão sendo gerados
            log_files = [
                'logs/application.log',
                'logs/error.log',
                'logs/access.log'
            ]
            
            existing_logs = []
            for log_file in log_files:
                if os.path.exists(log_file):
                    # Verifica se arquivo tem conteúdo recente
                    stat = os.stat(log_file)
                    if time.time() - stat.st_mtime < 3600:  # Modificado na última hora
                        existing_logs.append(log_file)
            
            if existing_logs:
                self._add_validation_result(
                    'logs_validation',
                    'passed',
                    f"Logs estão sendo gerados: {len(existing_logs)} arquivos ativos",
                    0,
                    {'active_logs': existing_logs}
                )
            else:
                self._add_validation_result(
                    'logs_validation',
                    'warning',
                    "Nenhum log ativo encontrado",
                    0,
                    {'checked_files': log_files}
                )
                
        except Exception as e:
            self._add_validation_result(
                'logs_validation',
                'failed',
                f"Validação de logs falhou: {e}",
                0,
                {'error': str(e)}
            )
    
    def _add_validation_result(self, component: str, status: str, message: str, 
                             duration: float, details: Dict[str, Any]):
        """Adiciona resultado de validação"""
        result = ValidationResult(
            component=component,
            status=status,
            message=message,
            duration=duration,
            timestamp=datetime.now(),
            details=details
        )
        
        self.validation_results.append(result)
        
        if self.deployment_validation:
            self.deployment_validation.results.append(result)
        
        # Log do resultado
        status_emoji = {'passed': '✅', 'failed': '❌', 'warning': '⚠️'}
        self.logger.info(f"{status_emoji.get(status, '❓')} {component}: {message}")
    
    def _determine_overall_status(self) -> str:
        """Determina status geral da validação"""
        if not self.validation_results:
            return 'unknown'
        
        failed_count = len([r for r in self.validation_results if r.status == 'failed'])
        warning_count = len([r for r in self.validation_results if r.status == 'warning'])
        
        if failed_count > 0:
            return 'failed'
        elif warning_count > 0:
            return 'warning'
        else:
            return 'passed'
    
    def _generate_validation_report(self):
        """Gera relatório de validação"""
        if not self.deployment_validation:
            return
        
        report = {
            'deployment_id': self.deployment_validation.deployment_id,
            'environment': self.deployment_validation.environment,
            'version': self.deployment_validation.version,
            'start_time': self.deployment_validation.start_time.isoformat(),
            'end_time': self.deployment_validation.end_time.isoformat() if self.deployment_validation.end_time else None,
            'overall_status': self.deployment_validation.overall_status,
            'total_duration': (self.deployment_validation.end_time - self.deployment_validation.start_time).total_seconds() if self.deployment_validation.end_time else 0,
            'results_summary': {
                'total': len(self.validation_results),
                'passed': len([r for r in self.validation_results if r.status == 'passed']),
                'failed': len([r for r in self.validation_results if r.status == 'failed']),
                'warning': len([r for r in self.validation_results if r.status == 'warning'])
            },
            'results': [
                {
                    'component': r.component,
                    'status': r.status,
                    'message': r.message,
                    'duration': r.duration,
                    'timestamp': r.timestamp.isoformat(),
                    'details': r.details
                }
                for r in self.validation_results
            ]
        }
        
        # Salva relatório
        report_file = f"deployment_validation_{self.deployment_validation.deployment_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"📄 Relatório salvo: {report_file}")
        
        # Exibe resumo
        self._display_summary()
    
    def _display_summary(self):
        """Exibe resumo da validação"""
        if not self.deployment_validation:
            return
        
        print("\n" + "="*60)
        print("📋 RESUMO DA VALIDAÇÃO DE DEPLOY")
        print("="*60)
        print(f"Deployment ID: {self.deployment_validation.deployment_id}")
        print(f"Environment: {self.deployment_validation.environment}")
        print(f"Version: {self.deployment_validation.version}")
        print(f"Status: {self.deployment_validation.overall_status.upper()}")
        
        if self.deployment_validation.end_time:
            duration = (self.deployment_validation.end_time - self.deployment_validation.start_time).total_seconds()
            print(f"Duration: {duration:.2f}s")
        
        print(f"\nResults: {len(self.validation_results)} total")
        passed = len([r for r in self.validation_results if r.status == 'passed'])
        failed = len([r for r in self.validation_results if r.status == 'failed'])
        warning = len([r for r in self.validation_results if r.status == 'warning'])
        
        print(f"  ✅ Passed: {passed}")
        print(f"  ❌ Failed: {failed}")
        print(f"  ⚠️ Warning: {warning}")
        
        if failed > 0:
            print(f"\n❌ FAILED VALIDATIONS:")
            for result in self.validation_results:
                if result.status == 'failed':
                    print(f"  - {result.component}: {result.message}")
        
        if warning > 0:
            print(f"\n⚠️ WARNINGS:")
            for result in self.validation_results:
                if result.status == 'warning':
                    print(f"  - {result.component}: {result.message}")
        
        print("="*60)

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Validador de Deploy - Omni Writer")
    parser.add_argument("--environment", required=True, choices=['staging', 'production'], 
                       help="Ambiente para validar")
    parser.add_argument("--version", required=True, help="Versão do deploy")
    parser.add_argument("--deployment-id", help="ID do deploy (opcional)")
    parser.add_argument("--config", default="deployment_config.json", 
                       help="Arquivo de configuração")
    
    args = parser.parse_args()
    
    validator = DeploymentValidator(args.config)
    validation = validator.validate_deployment(
        environment=args.environment,
        version=args.version,
        deployment_id=args.deployment_id
    )
    
    # Retorna código de saída baseado no status
    if validation.overall_status == 'failed':
        exit(1)
    elif validation.overall_status == 'warning':
        exit(2)
    else:
        exit(0)

if __name__ == "__main__":
    main() 