"""
Teste Unitário - Sistema de DevOps e Automação
=============================================

Testa funcionalidades do sistema de DevOps:
- CI/CD pipeline
- Monitoramento proativo
- Auto-healing
- Alertas inteligentes

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
import sys
from datetime import datetime, timedelta

# Adiciona o diretório scripts ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from proactive_monitoring import (
    ProactiveMonitoring, 
    MetricData, 
    Alert, 
    ComponentHealth
)

class TestProactiveMonitoring:
    """Testes para o sistema de monitoramento proativo"""
    
    @pytest.fixture
    def temp_config(self):
        """Cria configuração temporária para testes"""
        config = {
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
                }
            },
            'alerts': {
                'email': {
                    'enabled': True,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': 'test@example.com',
                    'password': 'test_password',
                    'recipients': ['admin@example.com']
                },
                'slack': {
                    'enabled': True,
                    'webhook_url': 'https://hooks.slack.com/services/test',
                    'channel': '#alerts'
                }
            },
            'predictive_analysis': {
                'enabled': True,
                'window_size': 24,
                'prediction_horizon': 1,
                'confidence_threshold': 0.8
            },
            'redis_host': 'localhost',
            'redis_port': 6379,
            'redis_db': 0,
            'prometheus_port': 8000
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            temp_config_file = f.name
        
        yield temp_config_file
        
        # Limpa arquivo temporário
        os.unlink(temp_config_file)
    
    @pytest.fixture
    def monitor(self, temp_config):
        """Cria instância do monitoramento para testes"""
        with patch('redis.Redis'):
            with patch('prometheus_client.start_http_server'):
                return ProactiveMonitoring(temp_config)
    
    def test_load_config(self, temp_config):
        """Testa carregamento de configuração"""
        with patch('redis.Redis'):
            with patch('prometheus_client.start_http_server'):
                monitor = ProactiveMonitoring(temp_config)
                
                assert 'components' in monitor.config
                assert 'api' in monitor.config['components']
                assert 'alerts' in monitor.config
                assert 'predictive_analysis' in monitor.config
    
    def test_load_default_config(self):
        """Testa carregamento de configuração padrão"""
        with patch('redis.Redis'):
            with patch('prometheus_client.start_http_server'):
                monitor = ProactiveMonitoring('nonexistent_config.json')
                
                assert 'components' in monitor.config
                assert 'api' in monitor.config['components']
                assert 'alerts' in monitor.config
    
    @patch('requests.get')
    def test_check_api_health_success(self, mock_get, monitor):
        """Testa verificação de saúde da API com sucesso"""
        # Mock de resposta bem-sucedida
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'healthy',
            'uptime': 3600,
            'memory_usage': 50.0,
            'cpu_usage': 30.0
        }
        mock_get.return_value = mock_response
        
        config = monitor.config['components']['api']
        health = monitor._check_api_health(config)
        
        assert health.name == 'api'
        assert health.status == 'healthy'
        assert health.error_count == 0
        assert health.uptime == 3600
        assert health.memory_usage == 50.0
        assert health.cpu_usage == 30.0
    
    @patch('requests.get')
    def test_check_api_health_failure(self, mock_get, monitor):
        """Testa verificação de saúde da API com falha"""
        # Mock de exceção
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")
        
        config = monitor.config['components']['api']
        health = monitor._check_api_health(config)
        
        assert health.name == 'api'
        assert health.status == 'unhealthy'
        assert health.error_count == 1
        assert health.uptime == 0
    
    @patch('requests.get')
    def test_check_api_health_degraded(self, mock_get, monitor):
        """Testa verificação de saúde da API degradada"""
        # Mock de resposta com status degradado
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'degraded',
            'uptime': 3600,
            'memory_usage': 80.0,
            'cpu_usage': 70.0
        }
        mock_get.return_value = mock_response
        
        config = monitor.config['components']['api']
        health = monitor._check_api_health(config)
        
        assert health.name == 'api'
        assert health.status == 'degraded'
        assert health.error_count == 0
    
    @patch('psycopg2.connect')
    def test_check_database_health_success(self, mock_connect, monitor):
        """Testa verificação de saúde do banco de dados com sucesso"""
        # Mock de conexão bem-sucedida
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        config = monitor.config['components']['database']
        health = monitor._check_database_health(config)
        
        assert health.name == 'database'
        assert health.status == 'healthy'
        assert health.error_count == 0
        assert health.uptime > 0
        
        # Verifica se cursor foi fechado
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()
    
    @patch('psycopg2.connect')
    def test_check_database_health_failure(self, mock_connect, monitor):
        """Testa verificação de saúde do banco de dados com falha"""
        # Mock de exceção
        mock_connect.side_effect = Exception("Database connection failed")
        
        config = monitor.config['components']['database']
        health = monitor._check_database_health(config)
        
        assert health.name == 'database'
        assert health.status == 'unhealthy'
        assert health.error_count == 1
        assert health.uptime == 0
    
    @patch.object(ProactiveMonitoring, 'redis_client')
    def test_check_redis_health_success(self, mock_redis, monitor):
        """Testa verificação de saúde do Redis com sucesso"""
        # Mock de Redis bem-sucedido
        mock_redis.ping.return_value = True
        mock_redis.info.return_value = {
            'uptime_in_seconds': 7200,
            'used_memory_human': '100M'
        }
        
        config = monitor.config['components']['redis']
        health = monitor._check_redis_health(config)
        
        assert health.name == 'redis'
        assert health.status == 'healthy'
        assert health.error_count == 0
        assert health.uptime == 7200
        assert health.memory_usage == '100M'
    
    @patch.object(ProactiveMonitoring, 'redis_client')
    def test_check_redis_health_failure(self, mock_redis, monitor):
        """Testa verificação de saúde do Redis com falha"""
        # Mock de exceção
        mock_redis.ping.side_effect = Exception("Redis connection failed")
        
        config = monitor.config['components']['redis']
        health = monitor._check_redis_health(config)
        
        assert health.name == 'redis'
        assert health.status == 'unhealthy'
        assert health.error_count == 1
        assert health.uptime == 0
    
    @patch('subprocess.run')
    def test_check_celery_health_success(self, mock_run, monitor):
        """Testa verificação de saúde do Celery com sucesso"""
        # Mock de comando bem-sucedido
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "worker1\nworker2\n"
        mock_run.return_value = mock_result
        
        config = monitor.config['components']['celery']
        health = monitor._check_celery_health(config)
        
        assert health.name == 'celery'
        assert health.status == 'healthy'
        assert health.error_count == 0
        assert health.uptime > 0
    
    @patch('subprocess.run')
    def test_check_celery_health_failure(self, mock_run, monitor):
        """Testa verificação de saúde do Celery com falha"""
        # Mock de comando com falha
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        config = monitor.config['components']['celery']
        health = monitor._check_celery_health(config)
        
        assert health.name == 'celery'
        assert health.status == 'unhealthy'
        assert health.error_count == 1
        assert health.uptime == 0
    
    def test_create_alert(self, monitor):
        """Testa criação de alerta"""
        alert_id = "test_alert"
        severity = "warning"
        message = "Test alert message"
        metric = "test_metric"
        value = 85.0
        threshold = 80.0
        
        monitor._create_alert(alert_id, severity, message, metric, value, threshold)
        
        # Verifica se alerta foi criado
        assert len(monitor.alerts) == 1
        
        alert = monitor.alerts[0]
        assert alert.id == alert_id
        assert alert.severity == severity
        assert alert.message == message
        assert alert.metric == metric
        assert alert.value == value
        assert alert.threshold == threshold
        assert not alert.resolved
    
    def test_check_component_alerts(self, monitor):
        """Testa verificação de alertas de componente"""
        # Cria componente com health problemático
        health = ComponentHealth(
            name='api',
            status='healthy',
            last_check=datetime.now(),
            response_time=2500,  # Acima do threshold
            error_count=0,
            uptime=3600,
            memory_usage=50.0,
            cpu_usage=30.0
        )
        
        config = monitor.config['components']['api']
        
        # Verifica se alerta é criado
        initial_alert_count = len(monitor.alerts)
        monitor._check_component_alerts('api', health, config)
        
        assert len(monitor.alerts) > initial_alert_count
        
        # Verifica se alerta correto foi criado
        response_time_alert = next(
            (a for a in monitor.alerts if a.metric == 'api_response_time'), 
            None
        )
        assert response_time_alert is not None
        assert response_time_alert.value == 2500
        assert response_time_alert.threshold == 2000
    
    def test_check_system_alerts(self, monitor):
        """Testa verificação de alertas do sistema"""
        # CPU alto
        cpu_usage = 85.0
        memory_usage = 70.0
        disk_usage = 75.0
        
        initial_alert_count = len(monitor.alerts)
        monitor._check_system_alerts(cpu_usage, memory_usage, disk_usage)
        
        assert len(monitor.alerts) > initial_alert_count
        
        # Verifica se alerta de CPU foi criado
        cpu_alert = next(
            (a for a in monitor.alerts if a.metric == 'cpu_usage'), 
            None
        )
        assert cpu_alert is not None
        assert cpu_alert.value == 85.0
        assert cpu_alert.threshold == 80
    
    def test_collect_historical_data(self, monitor):
        """Testa coleta de dados históricos"""
        data = monitor._collect_historical_data()
        
        assert len(data) == 24  # 24 horas
        assert all('timestamp' in d for d in data)
        assert all('cpu_usage' in d for d in data)
        assert all('memory_usage' in d for d in data)
        assert all('error_rate' in d for d in data)
        assert all('response_time' in d for d in data)
    
    def test_run_predictive_analysis(self, monitor):
        """Testa análise preditiva"""
        historical_data = monitor._collect_historical_data()
        predictions = monitor._run_predictive_analysis(historical_data)
        
        assert 'cpu_usage' in predictions
        assert 'memory_usage' in predictions
        assert 'error_rate' in predictions
        assert 'response_time' in predictions
        
        # Verifica estrutura das predições
        for metric, prediction in predictions.items():
            assert 'current' in prediction
            assert 'predicted' in prediction
            assert 'trend' in prediction
            assert 'confidence' in prediction
    
    def test_check_predictions(self, monitor):
        """Testa verificação de predições"""
        # Cria predições que excedem thresholds
        predictions = {
            'cpu_usage': {
                'current': 75,
                'predicted': 85,
                'trend': 2.5,
                'confidence': 0.9
            },
            'memory_usage': {
                'current': 80,
                'predicted': 90,
                'trend': 3.0,
                'confidence': 0.8
            }
        }
        
        initial_alert_count = len(monitor.alerts)
        monitor._check_predictions(predictions)
        
        # Verifica se alertas foram criados
        assert len(monitor.alerts) > initial_alert_count
        
        # Verifica se alertas preditivos foram criados
        predictive_alerts = [
            a for a in monitor.alerts 
            if a.id.startswith('predictive_')
        ]
        assert len(predictive_alerts) > 0
    
    @patch('smtplib.SMTP')
    def test_send_email_alert(self, mock_smtp, monitor):
        """Testa envio de alerta por email"""
        alert = Alert(
            id="test_alert",
            severity="warning",
            message="Test alert",
            metric="test_metric",
            value=85.0,
            threshold=80.0,
            timestamp=datetime.now()
        )
        
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        monitor._send_email_alert(alert)
        
        # Verifica se SMTP foi chamado
        mock_smtp.assert_called_once()
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()
    
    @patch('requests.post')
    def test_send_slack_alert(self, mock_post, monitor):
        """Testa envio de alerta para Slack"""
        alert = Alert(
            id="test_alert",
            severity="warning",
            message="Test alert",
            metric="test_metric",
            value=85.0,
            threshold=80.0,
            timestamp=datetime.now()
        )
        
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        monitor._send_slack_alert(alert)
        
        # Verifica se request foi feito
        mock_post.assert_called_once()
        
        # Verifica payload
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        
        assert payload['channel'] == '#alerts'
        assert len(payload['attachments']) == 1
        assert payload['attachments'][0]['color'] == 'warning'
    
    def test_is_alert_resolved(self, monitor):
        """Testa verificação de resolução de alerta"""
        # Cria alerta
        alert = Alert(
            id="test_alert",
            severity="warning",
            message="Test alert",
            metric="api_response_time",
            value=2500,
            threshold=2000,
            timestamp=datetime.now()
        )
        
        # Cria componente com problema
        health = ComponentHealth(
            name='api',
            status='healthy',
            last_check=datetime.now(),
            response_time=2500,  # Ainda acima do threshold
            error_count=0,
            uptime=3600,
            memory_usage=50.0,
            cpu_usage=30.0
        )
        
        monitor.component_health['api_response_time'] = health
        
        # Alerta não deve estar resolvido
        assert not monitor._is_alert_resolved(alert)
        
        # Corrige o problema
        health.response_time = 1500  # Abaixo do threshold
        monitor.component_health['api_response_time'] = health
        
        # Alerta deve estar resolvido
        assert monitor._is_alert_resolved(alert)
    
    def test_generate_report(self, monitor):
        """Testa geração de relatório"""
        # Adiciona dados de exemplo
        monitor.component_health['api'] = ComponentHealth(
            name='api',
            status='healthy',
            last_check=datetime.now(),
            response_time=150,
            error_count=0,
            uptime=3600,
            memory_usage=50.0,
            cpu_usage=30.0
        )
        
        monitor.alerts.append(Alert(
            id="test_alert",
            severity="warning",
            message="Test alert",
            metric="test_metric",
            value=85.0,
            threshold=80.0,
            timestamp=datetime.now()
        ))
        
        report = monitor.generate_report()
        
        assert 'timestamp' in report
        assert 'components' in report
        assert 'alerts' in report
        assert 'system' in report
        
        # Verifica estrutura do relatório
        assert 'api' in report['components']
        assert report['alerts']['total'] == 1
        assert 'cpu_usage' in report['system']
        assert 'memory_usage' in report['system']
        assert 'disk_usage' in report['system']

class TestMetricData:
    """Testes para a classe MetricData"""
    
    def test_metric_data_creation(self):
        """Testa criação de MetricData"""
        timestamp = datetime.now()
        value = 85.5
        labels = {'component': 'api', 'metric': 'response_time'}
        metric_type = 'gauge'
        
        metric = MetricData(
            timestamp=timestamp,
            value=value,
            labels=labels,
            metric_type=metric_type
        )
        
        assert metric.timestamp == timestamp
        assert metric.value == value
        assert metric.labels == labels
        assert metric.metric_type == metric_type

class TestAlert:
    """Testes para a classe Alert"""
    
    def test_alert_creation(self):
        """Testa criação de Alert"""
        alert_id = "test_alert"
        severity = "warning"
        message = "Test alert message"
        metric = "test_metric"
        value = 85.0
        threshold = 80.0
        timestamp = datetime.now()
        
        alert = Alert(
            id=alert_id,
            severity=severity,
            message=message,
            metric=metric,
            value=value,
            threshold=threshold,
            timestamp=timestamp
        )
        
        assert alert.id == alert_id
        assert alert.severity == severity
        assert alert.message == message
        assert alert.metric == metric
        assert alert.value == value
        assert alert.threshold == threshold
        assert alert.timestamp == timestamp
        assert not alert.resolved
        assert not alert.auto_resolved

class TestComponentHealth:
    """Testes para a classe ComponentHealth"""
    
    def test_component_health_creation(self):
        """Testa criação de ComponentHealth"""
        name = "api"
        status = "healthy"
        last_check = datetime.now()
        response_time = 150.0
        error_count = 0
        uptime = 3600.0
        memory_usage = 50.0
        cpu_usage = 30.0
        
        health = ComponentHealth(
            name=name,
            status=status,
            last_check=last_check,
            response_time=response_time,
            error_count=error_count,
            uptime=uptime,
            memory_usage=memory_usage,
            cpu_usage=cpu_usage
        )
        
        assert health.name == name
        assert health.status == status
        assert health.last_check == last_check
        assert health.response_time == response_time
        assert health.error_count == error_count
        assert health.uptime == uptime
        assert health.memory_usage == memory_usage
        assert health.cpu_usage == cpu_usage

if __name__ == "__main__":
    pytest.main([__file__]) 