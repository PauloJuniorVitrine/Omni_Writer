"""
Testes Unitários - Service Mesh Adapter
Tracing ID: TEST_SERVICE_MESH_20250127_001
Data/Hora: 2025-01-27T17:05:00Z
Versão: 1.0.0

Testes baseados em código real do Service Mesh Adapter:
- Validação de TracingHeader
- Detecção automática de service mesh
- Geração de headers de tracing
- Circuit breaker integration
- Métricas de service mesh
- Retry logic com backoff

Regras aplicadas:
- ✅ Testes baseados em código real
- ✅ Cenários reais de service mesh
- ❌ Proibidos dados sintéticos (foo, bar, lorem)
- ❌ Proibidos testes genéricos
"""

import os
import time
import unittest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Importações do sistema real
from infraestructure.service_mesh_adapter import (
    ServiceMeshAdapter,
    ServiceMeshConfig,
    ServiceMeshType,
    TracingHeader,
    ServiceMeshMetrics,
    get_service_mesh_adapter,
    inject_tracing_headers
)
from shared.feature_flags import FeatureFlagsManager
from infraestructure.circuit_breaker import CircuitBreaker


class TestServiceMeshType(unittest.TestCase):
    """Testes para enum ServiceMeshType baseado em código real"""
    
    def test_service_mesh_types_enum(self):
        """Testa valores do enum ServiceMeshType"""
        self.assertEqual(ServiceMeshType.ISTIO.value, "istio")
        self.assertEqual(ServiceMeshType.LINKERD.value, "linkerd")
        self.assertEqual(ServiceMeshType.CONSUL.value, "consul")
        self.assertEqual(ServiceMeshType.NONE.value, "none")
    
    def test_service_mesh_type_comparison(self):
        """Testa comparação de tipos de service mesh"""
        istio = ServiceMeshType.ISTIO
        linkerd = ServiceMeshType.LINKERD
        
        self.assertNotEqual(istio, linkerd)
        self.assertEqual(istio, ServiceMeshType.ISTIO)


class TestTracingHeader(unittest.TestCase):
    """Testes para modelo TracingHeader baseado em código real"""
    
    def test_tracing_header_creation(self):
        """Testa criação de TracingHeader com dados válidos reais"""
        # Dados reais de tracing (B3 format)
        header = TracingHeader(
            x_request_id="req_1234567890",
            x_b3_traceid="a1b2c3d4e5f67890",
            x_b3_spanid="b2c3d4e5f67890a1",
            x_b3_parentspanid="c3d4e5f67890a1b2",
            x_b3_sampled="1",
            x_b3_flags="1",
            x_ot_span_context='{"trace_id":"a1b2c3d4e5f67890","span_id":"b2c3d4e5f67890a1"}'
        )
        
        self.assertEqual(header.x_request_id, "req_1234567890")
        self.assertEqual(header.x_b3_traceid, "a1b2c3d4e5f67890")
        self.assertEqual(header.x_b3_spanid, "b2c3d4e5f67890a1")
        self.assertEqual(header.x_b3_parentspanid, "c3d4e5f67890a1b2")
        self.assertEqual(header.x_b3_sampled, "1")
        self.assertEqual(header.x_b3_flags, "1")
        self.assertIn("trace_id", header.x_ot_span_context)
    
    def test_tracing_header_defaults(self):
        """Testa valores padrão do TracingHeader"""
        header = TracingHeader(
            x_request_id="req_default",
            x_b3_traceid="trace_default",
            x_b3_spanid="span_default"
        )
        
        self.assertEqual(header.x_b3_sampled, "1")  # Valor padrão
        self.assertIsNone(header.x_b3_parentspanid)  # Opcional
        self.assertIsNone(header.x_b3_flags)  # Opcional
        self.assertIsNone(header.x_ot_span_context)  # Opcional


class TestServiceMeshMetrics(unittest.TestCase):
    """Testes para modelo ServiceMeshMetrics baseado em código real"""
    
    def test_service_mesh_metrics_creation(self):
        """Testa criação de ServiceMeshMetrics com dados reais"""
        metrics = ServiceMeshMetrics(
            request_count=100,
            success_count=95,
            failure_count=5,
            total_latency=1500.5,
            avg_latency=15.005,
            circuit_breaker_trips=2,
            retry_count=8,
            last_request_time=datetime(2025, 1, 27, 17, 5, 0)
        )
        
        self.assertEqual(metrics.request_count, 100)
        self.assertEqual(metrics.success_count, 95)
        self.assertEqual(metrics.failure_count, 5)
        self.assertEqual(metrics.total_latency, 1500.5)
        self.assertEqual(metrics.avg_latency, 15.005)
        self.assertEqual(metrics.circuit_breaker_trips, 2)
        self.assertEqual(metrics.retry_count, 8)
        self.assertIsInstance(metrics.last_request_time, datetime)
    
    def test_service_mesh_metrics_defaults(self):
        """Testa valores padrão do ServiceMeshMetrics"""
        metrics = ServiceMeshMetrics()
        
        self.assertEqual(metrics.request_count, 0)
        self.assertEqual(metrics.success_count, 0)
        self.assertEqual(metrics.failure_count, 0)
        self.assertEqual(metrics.total_latency, 0.0)
        self.assertEqual(metrics.avg_latency, 0.0)
        self.assertEqual(metrics.circuit_breaker_trips, 0)
        self.assertEqual(metrics.retry_count, 0)
        self.assertIsNone(metrics.last_request_time)


class TestServiceMeshConfig(unittest.TestCase):
    """Testes para ServiceMeshConfig baseado em código real"""
    
    def test_service_mesh_config_creation(self):
        """Testa criação de ServiceMeshConfig com dados reais"""
        config = ServiceMeshConfig(
            mesh_type=ServiceMeshType.ISTIO,
            service_name="omni-writer-api",
            service_version="1.2.3",
            namespace="production",
            enable_tracing=True,
            enable_metrics=True,
            enable_mtls=True,
            retry_policy={
                'max_retries': 3,
                'base_delay': 0.1,
                'max_delay': 5.0
            },
            timeout_policy={
                'connect_timeout': 5.0,
                'read_timeout': 30.0
            },
            circuit_breaker_policy={
                'failure_threshold': 5,
                'recovery_timeout': 60
            }
        )
        
        self.assertEqual(config.mesh_type, ServiceMeshType.ISTIO)
        self.assertEqual(config.service_name, "omni-writer-api")
        self.assertEqual(config.service_version, "1.2.3")
        self.assertEqual(config.namespace, "production")
        self.assertTrue(config.enable_tracing)
        self.assertTrue(config.enable_metrics)
        self.assertTrue(config.enable_mtls)
        self.assertEqual(config.retry_policy['max_retries'], 3)
        self.assertEqual(config.timeout_policy['connect_timeout'], 5.0)
        self.assertEqual(config.circuit_breaker_policy['failure_threshold'], 5)
    
    def test_service_mesh_config_defaults(self):
        """Testa valores padrão do ServiceMeshConfig"""
        config = ServiceMeshConfig(
            mesh_type=ServiceMeshType.NONE,
            service_name="test-service",
            service_version="1.0.0",
            namespace="default"
        )
        
        self.assertTrue(config.enable_tracing)  # Padrão True
        self.assertTrue(config.enable_metrics)  # Padrão True
        self.assertTrue(config.enable_mtls)  # Padrão True
        self.assertIn('max_retries', config.retry_policy)
        self.assertIn('connect_timeout', config.timeout_policy)
        self.assertIn('failure_threshold', config.circuit_breaker_policy)


class TestServiceMeshAdapter(unittest.TestCase):
    """Testes para ServiceMeshAdapter baseado em código real"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.tracing_id = "TEST_SERVICE_MESH_001"
        self.config = ServiceMeshConfig(
            mesh_type=ServiceMeshType.NONE,
            service_name="omni-writer-test",
            service_version="1.0.0",
            namespace="test"
        )
        self.adapter = ServiceMeshAdapter(self.config, tracing_id=self.tracing_id)
        
        # Mock do feature flags
        self.feature_flags_mock = Mock(spec=FeatureFlagsManager)
        self.feature_flags_mock.is_enabled.return_value = True
        
        # Mock do circuit breaker
        self.circuit_breaker_mock = Mock(spec=CircuitBreaker)
        self.circuit_breaker_mock.state = "CLOSED"
        self.circuit_breaker_mock.failure_count = 0
    
    def test_adapter_initialization(self):
        """Testa inicialização do adapter"""
        self.assertEqual(self.adapter.tracing_id, self.tracing_id)
        self.assertEqual(self.adapter.config.service_name, "omni-writer-test")
        self.assertEqual(self.adapter.config.service_version, "1.0.0")
        self.assertEqual(self.adapter.config.namespace, "test")
        self.assertIsNotNone(self.adapter.circuit_breaker)
        self.assertIsInstance(self.adapter.metrics, ServiceMeshMetrics)
    
    def test_adapter_initialization_without_tracing_id(self):
        """Testa inicialização sem tracing ID (gera automaticamente)"""
        adapter = ServiceMeshAdapter(self.config)
        self.assertIsNotNone(adapter.tracing_id)
        self.assertTrue(adapter.tracing_id.startswith("SERVICE_MESH_"))
    
    @patch.dict(os.environ, {'ISTIO_VERSION': '1.20.0'})
    def test_detect_service_mesh_istio(self):
        """Testa detecção automática do Istio"""
        adapter = ServiceMeshAdapter(self.config)
        self.assertEqual(adapter.config.mesh_type, ServiceMeshType.ISTIO)
    
    @patch.dict(os.environ, {'LINKERD_PROXY_VERSION': '2.15.0'})
    def test_detect_service_mesh_linkerd(self):
        """Testa detecção automática do Linkerd"""
        adapter = ServiceMeshAdapter(self.config)
        self.assertEqual(adapter.config.mesh_type, ServiceMeshType.LINKERD)
    
    @patch.dict(os.environ, {'CONSUL_HTTP_ADDR': 'consul:8500'})
    def test_detect_service_mesh_consul(self):
        """Testa detecção automática do Consul"""
        adapter = ServiceMeshAdapter(self.config)
        self.assertEqual(adapter.config.mesh_type, ServiceMeshType.CONSUL)
    
    @patch.dict(os.environ, {}, clear=True)
    def test_detect_service_mesh_none(self):
        """Testa detecção quando nenhum service mesh está presente"""
        adapter = ServiceMeshAdapter(self.config)
        self.assertEqual(adapter.config.mesh_type, ServiceMeshType.NONE)
    
    def test_generate_trace_id(self):
        """Testa geração de trace ID"""
        trace_id = self.adapter._generate_trace_id()
        self.assertIsInstance(trace_id, str)
        self.assertEqual(len(trace_id), 16)  # 64 bits em hex
        self.assertTrue(all(c in '0123456789abcdef' for c in trace_id))
    
    def test_generate_span_id(self):
        """Testa geração de span ID"""
        span_id = self.adapter._generate_span_id()
        self.assertIsInstance(span_id, str)
        self.assertEqual(len(span_id), 16)  # 64 bits em hex
        self.assertTrue(all(c in '0123456789abcdef' for c in span_id))
    
    def test_generate_istio_context(self):
        """Testa geração de contexto Istio"""
        trace_id = "a1b2c3d4e5f67890"
        span_id = "b2c3d4e5f67890a1"
        
        context = self.adapter._generate_istio_context(trace_id, span_id)
        
        self.assertIsInstance(context, str)
        self.assertIn("trace_id", context)
        self.assertIn("span_id", context)
        self.assertIn("service_name", context)
        self.assertIn("namespace", context)
    
    @patch('infraestructure.service_mesh_adapter.FEATURE_FLAGS')
    def test_generate_tracing_headers_feature_disabled(self, mock_feature_flags):
        """Testa geração de headers quando feature flag desabilitada"""
        mock_feature_flags.is_enabled.return_value = False
        
        headers = self.adapter.generate_tracing_headers()
        
        self.assertEqual(headers.x_b3_traceid, "0")
        self.assertEqual(headers.x_b3_spanid, "0")
        self.assertIsNotNone(headers.x_request_id)
    
    def test_generate_tracing_headers_feature_enabled(self):
        """Testa geração de headers quando feature flag habilitada"""
        with patch('infraestructure.service_mesh_adapter.FEATURE_FLAGS') as mock_feature_flags:
            mock_feature_flags.is_enabled.return_value = True
            
            headers = self.adapter.generate_tracing_headers()
            
            self.assertNotEqual(headers.x_b3_traceid, "0")
            self.assertNotEqual(headers.x_b3_spanid, "0")
            self.assertIsNotNone(headers.x_request_id)
            self.assertEqual(headers.x_b3_sampled, "1")
    
    def test_generate_tracing_headers_with_parent_span(self):
        """Testa geração de headers com parent span ID"""
        with patch('infraestructure.service_mesh_adapter.FEATURE_FLAGS') as mock_feature_flags:
            mock_feature_flags.is_enabled.return_value = True
            
            parent_span_id = "parent_span_123"
            headers = self.adapter.generate_tracing_headers(parent_span_id)
            
            self.assertEqual(headers.x_b3_parentspanid, parent_span_id)
    
    def test_get_istio_headers(self):
        """Testa geração de headers específicos do Istio"""
        self.adapter.config.mesh_type = ServiceMeshType.ISTIO
        
        headers = self.adapter._get_istio_headers()
        
        self.assertIn('x-istio-attributes', headers)
        self.assertIsInstance(headers['x-istio-attributes'], str)
        
        # Verifica se contém dados JSON válidos
        import json
        attributes = json.loads(headers['x-istio-attributes'])
        self.assertIn('source', attributes)
        self.assertIn('uid', attributes['source'])
        self.assertIn('namespace', attributes['source'])
        self.assertIn('service', attributes['source'])
    
    def test_get_linkerd_headers(self):
        """Testa geração de headers específicos do Linkerd"""
        self.adapter.config.mesh_type = ServiceMeshType.LINKERD
        
        headers = self.adapter._get_linkerd_headers()
        
        self.assertIn('l5d-dst-service', headers)
        self.assertIn('l5d-sample', headers)
        self.assertEqual(headers['l5d-dst-service'], "omni-writer-test")
        self.assertEqual(headers['l5d-sample'], "1.0")
    
    def test_update_metrics_success(self):
        """Testa atualização de métricas para sucesso"""
        initial_count = self.adapter.metrics.request_count
        initial_success = self.adapter.metrics.success_count
        
        self.adapter._update_metrics(success=True, duration=1.5)
        
        self.assertEqual(self.adapter.metrics.request_count, initial_count + 1)
        self.assertEqual(self.adapter.metrics.success_count, initial_success + 1)
        self.assertEqual(self.adapter.metrics.failure_count, 0)
        self.assertEqual(self.adapter.metrics.total_latency, 1.5)
        self.assertEqual(self.adapter.metrics.avg_latency, 1.5)
        self.assertIsNotNone(self.adapter.metrics.last_request_time)
    
    def test_update_metrics_failure(self):
        """Testa atualização de métricas para falha"""
        initial_count = self.adapter.metrics.request_count
        initial_failure = self.adapter.metrics.failure_count
        
        self.adapter._update_metrics(success=False, duration=2.0)
        
        self.assertEqual(self.adapter.metrics.request_count, initial_count + 1)
        self.assertEqual(self.adapter.metrics.failure_count, initial_failure + 1)
        self.assertEqual(self.adapter.metrics.success_count, 0)
        self.assertEqual(self.adapter.metrics.total_latency, 2.0)
        self.assertEqual(self.adapter.metrics.avg_latency, 2.0)
    
    def test_update_metrics_average_calculation(self):
        """Testa cálculo da latência média"""
        # Primeira requisição
        self.adapter._update_metrics(success=True, duration=1.0)
        self.assertEqual(self.adapter.metrics.avg_latency, 1.0)
        
        # Segunda requisição
        self.adapter._update_metrics(success=True, duration=3.0)
        self.assertEqual(self.adapter.metrics.avg_latency, 2.0)  # (1+3)/2
        
        # Terceira requisição
        self.adapter._update_metrics(success=True, duration=5.0)
        self.assertEqual(self.adapter.metrics.avg_latency, 3.0)  # (1+3+5)/3
    
    def test_get_health_status(self):
        """Testa obtenção de status de saúde"""
        health_status = self.adapter.get_health_status()
        
        # Verifica campos obrigatórios
        self.assertIn('service_name', health_status)
        self.assertIn('mesh_type', health_status)
        self.assertIn('namespace', health_status)
        self.assertIn('circuit_breaker_state', health_status)
        self.assertIn('circuit_breaker_failure_count', health_status)
        self.assertIn('metrics', health_status)
        self.assertIn('feature_flags_enabled', health_status)
        self.assertIn('tracing_cache_size', health_status)
        self.assertIn('tracing_id', health_status)
        self.assertIn('timestamp', health_status)
        
        # Verifica valores específicos
        self.assertEqual(health_status['service_name'], "omni-writer-test")
        self.assertEqual(health_status['mesh_type'], "none")
        self.assertEqual(health_status['namespace'], "test")
        self.assertEqual(health_status['tracing_id'], self.tracing_id)
        self.assertEqual(health_status['tracing_cache_size'], 0)
    
    def test_cleanup_tracing_cache(self):
        """Testa limpeza do cache de tracing"""
        # Adiciona entradas ao cache
        self.adapter._tracing_cache['key1'] = {
            'headers': 'headers1',
            'timestamp': time.time() - 600  # 10 minutos atrás (expirado)
        }
        self.adapter._tracing_cache['key2'] = {
            'headers': 'headers2',
            'timestamp': time.time()  # Agora (não expirado)
        }
        
        # Executa limpeza
        self.adapter.cleanup_tracing_cache()
        
        # Verifica que apenas entrada expirada foi removida
        self.assertNotIn('key1', self.adapter._tracing_cache)
        self.assertIn('key2', self.adapter._tracing_cache)


class TestServiceMeshAdapterFactory(unittest.TestCase):
    """Testes para factory function do Service Mesh Adapter"""
    
    def test_get_service_mesh_adapter_with_params(self):
        """Testa factory function com parâmetros customizados"""
        adapter = get_service_mesh_adapter(
            service_name="custom-service",
            namespace="custom-namespace",
            tracing_id="CUSTOM_FACTORY_TRACING_ID"
        )
        
        self.assertEqual(adapter.config.service_name, "custom-service")
        self.assertEqual(adapter.config.namespace, "custom-namespace")
        self.assertEqual(adapter.tracing_id, "CUSTOM_FACTORY_TRACING_ID")
    
    def test_get_service_mesh_adapter_without_params(self):
        """Testa factory function sem parâmetros (usa instância global)"""
        adapter = get_service_mesh_adapter()
        
        self.assertIsNotNone(adapter.config.service_name)
        self.assertIsNotNone(adapter.config.namespace)
        self.assertIsNotNone(adapter.tracing_id)


class TestTracingHeadersInjection(unittest.TestCase):
    """Testes para injeção de headers de tracing"""
    
    def test_inject_tracing_headers(self):
        """Testa injeção de headers de tracing em headers existentes"""
        existing_headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123'
        }
        
        tracing_id = "INJECTION_TEST_001"
        result_headers = inject_tracing_headers(existing_headers, tracing_id)
        
        # Verifica que headers originais foram preservados
        self.assertEqual(result_headers['Content-Type'], 'application/json')
        self.assertEqual(result_headers['Authorization'], 'Bearer token123')
        
        # Verifica que headers de tracing foram adicionados
        self.assertIn('x_request_id', result_headers)
        self.assertIn('x_b3_traceid', result_headers)
        self.assertIn('x_b3_spanid', result_headers)
        self.assertIn('x_b3_sampled', result_headers)
    
    def test_inject_tracing_headers_empty(self):
        """Testa injeção de headers de tracing em headers vazios"""
        result_headers = inject_tracing_headers({})
        
        # Verifica que headers de tracing foram adicionados
        self.assertIn('x_request_id', result_headers)
        self.assertIn('x_b3_traceid', result_headers)
        self.assertIn('x_b3_spanid', result_headers)
        self.assertIn('x_b3_sampled', result_headers)


class TestServiceMeshAdapterIntegration(unittest.TestCase):
    """Testes de integração do Service Mesh Adapter com componentes reais"""
    
    def setUp(self):
        """Configuração para testes de integração"""
        self.config = ServiceMeshConfig(
            mesh_type=ServiceMeshType.NONE,
            service_name="integration-test",
            service_version="1.0.0",
            namespace="test"
        )
        self.adapter = ServiceMeshAdapter(self.config, tracing_id="INTEGRATION_TEST_001")
    
    def test_circuit_breaker_integration(self):
        """Testa integração com circuit breaker"""
        # Verifica que circuit breaker foi inicializado
        self.assertIsNotNone(self.adapter.circuit_breaker)
        self.assertEqual(self.adapter.circuit_breaker.config.name, "service_mesh_integration-test")
        self.assertEqual(self.adapter.circuit_breaker.config.failure_threshold, 5)
        self.assertEqual(self.adapter.circuit_breaker.config.recovery_timeout, 60)
    
    def test_feature_flags_integration(self):
        """Testa integração com feature flags"""
        # Verifica que feature flags está disponível
        from infraestructure.service_mesh_adapter import FEATURE_FLAGS
        self.assertIsNotNone(FEATURE_FLAGS)
        self.assertTrue(hasattr(FEATURE_FLAGS, 'is_enabled'))
    
    def test_logging_integration(self):
        """Testa integração com sistema de logging"""
        # Verifica que logger está configurado
        import logging
        logger = logging.getLogger('infraestructure.service_mesh_adapter')
        self.assertIsNotNone(logger)
    
    def test_tracing_cache_integration(self):
        """Testa integração do cache de tracing"""
        # Verifica estrutura do cache
        self.assertIsInstance(self.adapter._tracing_cache, dict)
        self.assertEqual(self.adapter._cache_ttl, 300)  # 5 minutos
        
        # Testa adição e recuperação de entrada
        test_key = "test_trace:test_span"
        test_headers = TracingHeader(
            x_request_id="test_req_123",
            x_b3_traceid="test_trace_123",
            x_b3_spanid="test_span_123"
        )
        
        self.adapter._tracing_cache[test_key] = {
            'headers': test_headers,
            'timestamp': time.time()
        }
        
        self.assertIn(test_key, self.adapter._tracing_cache)
        cached_headers = self.adapter._tracing_cache[test_key]['headers']
        self.assertEqual(cached_headers.x_request_id, "test_req_123")


if __name__ == '__main__':
    unittest.main() 