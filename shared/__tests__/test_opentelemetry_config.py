"""
Testes Unitários - OpenTelemetry Configuration
=============================================

Testes para o sistema de configuração do OpenTelemetry.

Prompt: Testes OpenTelemetry - ETAPA 8
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T22:30:00Z
Tracing ID: TEST_OPENTELEMETRY_20250127_001
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import logging
import os
from typing import Dict, Any

# Importar módulos a serem testados
from shared.opentelemetry_config import OpenTelemetryConfig, initialize_opentelemetry, get_tracer, get_meter
from shared.telemetry_hooks import TelemetryHooks, trace_function, trace_api_endpoint

class TestOpenTelemetryConfig(unittest.TestCase):
    """Testes para a classe OpenTelemetryConfig."""
    
    def setUp(self):
        """Configuração inicial para cada teste."""
        self.config = OpenTelemetryConfig("test-service", "1.0.0")
        self.logger = logging.getLogger(__name__)
    
    def test_initialization_with_default_values(self):
        """Testa inicialização com valores padrão."""
        # Arrange
        config = OpenTelemetryConfig()
        
        # Assert
        self.assertEqual(config.service_name, "omni-writer")
        self.assertEqual(config.service_version, "1.0.0")
        self.assertFalse(config._initialized)
    
    def test_initialization_with_custom_values(self):
        """Testa inicialização com valores customizados."""
        # Arrange & Act
        config = OpenTelemetryConfig("custom-service", "2.0.0")
        
        # Assert
        self.assertEqual(config.service_name, "custom-service")
        self.assertEqual(config.service_version, "2.0.0")
    
    @patch('shared.opentelemetry_config.Resource.create')
    @patch('shared.opentelemetry_config.TracerProvider')
    @patch('shared.opentelemetry_config.MeterProvider')
    def test_initialize_success(self, mock_meter_provider, mock_tracer_provider, mock_resource):
        """Testa inicialização bem-sucedida."""
        # Arrange
        mock_resource.return_value = Mock()
        mock_tracer_provider.return_value = Mock()
        mock_meter_provider.return_value = Mock()
        
        # Act
        self.config.initialize()
        
        # Assert
        self.assertTrue(self.config._initialized)
        mock_resource.assert_called_once()
        mock_tracer_provider.assert_called_once()
        mock_meter_provider.assert_called_once()
    
    @patch('shared.opentelemetry_config.Resource.create')
    def test_initialize_with_jaeger_endpoint(self, mock_resource):
        """Testa inicialização com endpoint do Jaeger."""
        # Arrange
        mock_resource.return_value = Mock()
        jaeger_endpoint = "http://localhost:14268/api/traces"
        
        # Act
        with patch.object(self.config, '_setup_tracing') as mock_setup:
            self.config.initialize(jaeger_endpoint=jaeger_endpoint)
            
        # Assert
        mock_setup.assert_called_once()
    
    @patch('shared.opentelemetry_config.Resource.create')
    def test_initialize_with_otlp_endpoint(self, mock_resource):
        """Testa inicialização com endpoint OTLP."""
        # Arrange
        mock_resource.return_value = Mock()
        otlp_endpoint = "http://localhost:4317"
        
        # Act
        with patch.object(self.config, '_setup_tracing') as mock_setup_tracing, \
             patch.object(self.config, '_setup_metrics') as mock_setup_metrics:
            self.config.initialize(otlp_endpoint=otlp_endpoint)
            
        # Assert
        mock_setup_tracing.assert_called_once()
        mock_setup_metrics.assert_called_once()
    
    def test_fallback_to_existing_system(self):
        """Testa fallback para sistema existente."""
        # Arrange
        with patch('shared.opentelemetry_config.logging.getLogger') as mock_logger:
            mock_logger.return_value = Mock()
            
        # Act
        with patch('shared.opentelemetry_config.Resource.create', side_effect=Exception("Test error")):
            self.config.initialize()
            
        # Assert
        self.assertFalse(self.config._initialized)
    
    def test_get_tracer_when_initialized(self):
        """Testa obtenção do tracer quando inicializado."""
        # Arrange
        mock_tracer = Mock()
        self.config.tracer = mock_tracer
        self.config._initialized = True
        
        # Act
        result = self.config.get_tracer()
        
        # Assert
        self.assertEqual(result, mock_tracer)
    
    def test_get_tracer_fallback(self):
        """Testa fallback do tracer."""
        # Arrange
        self.config._initialized = False
        
        # Act
        with patch('shared.opentelemetry_config.trace.get_tracer') as mock_get_tracer:
            mock_get_tracer.return_value = Mock()
            result = self.config.get_tracer()
            
        # Assert
        mock_get_tracer.assert_called_once_with("dummy")
    
    def test_get_meter_when_initialized(self):
        """Testa obtenção do meter quando inicializado."""
        # Arrange
        mock_meter = Mock()
        self.config.meter = mock_meter
        self.config._initialized = True
        
        # Act
        result = self.config.get_meter()
        
        # Assert
        self.assertEqual(result, mock_meter)
    
    def test_cleanup(self):
        """Testa limpeza de recursos."""
        # Arrange
        mock_tracer_provider = Mock()
        mock_meter_provider = Mock()
        self.config.tracer_provider = mock_tracer_provider
        self.config.meter_provider = mock_meter_provider
        
        # Act
        self.config.cleanup()
        
        # Assert
        mock_tracer_provider.force_flush.assert_called_once()
        mock_tracer_provider.shutdown.assert_called_once()
        mock_meter_provider.force_flush.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()


class TestTelemetryHooks(unittest.TestCase):
    """Testes para a classe TelemetryHooks."""
    
    def setUp(self):
        """Configuração inicial para cada teste."""
        self.hooks = TelemetryHooks()
        self.logger = logging.getLogger(__name__)
    
    def test_trace_function_decorator(self):
        """Testa decorator de tracing de função."""
        # Arrange
        @trace_function("test.function")
        def test_function():
            return "success"
        
        # Act
        with patch.object(self.hooks.tracer, 'start_as_current_span') as mock_span:
            mock_span.return_value.__enter__.return_value = Mock()
            result = test_function()
            
        # Assert
        self.assertEqual(result, "success")
    
    def test_trace_api_endpoint_decorator(self):
        """Testa decorator de tracing de endpoint."""
        # Arrange
        @trace_api_endpoint("/api/test", "GET")
        def test_endpoint():
            return {"status": "ok"}
        
        # Act
        with patch.object(self.hooks.tracer, 'start_as_current_span') as mock_span:
            mock_span.return_value.__enter__.return_value = Mock()
            result = test_endpoint()
            
        # Assert
        self.assertEqual(result, {"status": "ok"})
    
    def test_database_span_context_manager(self):
        """Testa context manager para operações de banco."""
        # Arrange
        with patch.object(self.hooks.tracer, 'start_as_current_span') as mock_span:
            mock_span.return_value.__enter__.return_value = Mock()
            
            # Act
            with database_span("SELECT", "users") as span:
                result = "database_result"
                
        # Assert
        self.assertEqual(result, "database_result")
    
    def test_external_service_span_context_manager(self):
        """Testa context manager para serviços externos."""
        # Arrange
        with patch.object(self.hooks.tracer, 'start_as_current_span') as mock_span:
            mock_span.return_value.__enter__.return_value = Mock()
            
            # Act
            with external_service_span("external-api", "get_data") as span:
                result = "external_result"
                
        # Assert
        self.assertEqual(result, "external_result")
    
    def test_log_with_trace(self):
        """Testa logging com contexto de trace."""
        # Arrange
        mock_logger = Mock()
        message = "Test log message"
        
        # Act
        with patch('shared.telemetry_hooks.trace.get_current_span') as mock_get_span:
            mock_span = Mock()
            mock_span.get_span_context.return_value.trace_id = 12345
            mock_span.get_span_context.return_value.span_id = 67890
            mock_get_span.return_value = mock_span
            
            log_with_trace(mock_logger, "INFO", message)
            
        # Assert
        mock_logger.info.assert_called_once()


class TestOpenTelemetryIntegration(unittest.TestCase):
    """Testes de integração do OpenTelemetry."""
    
    def setUp(self):
        """Configuração inicial para cada teste."""
        self.config = OpenTelemetryConfig("integration-test", "1.0.0")
    
    def test_environment_variables_integration(self):
        """Testa integração com variáveis de ambiente."""
        # Arrange
        os.environ["ENVIRONMENT"] = "test"
        os.environ["HOSTNAME"] = "test-host"
        
        # Act
        with patch.object(self.config, '_setup_tracing'), \
             patch.object(self.config, '_setup_metrics'), \
             patch.object(self.config, '_setup_logging'), \
             patch.object(self.config, '_instrument_frameworks'):
            self.config.initialize()
            
        # Assert
        self.assertTrue(self.config._initialized)
        
        # Cleanup
        del os.environ["ENVIRONMENT"]
        del os.environ["HOSTNAME"]
    
    def test_metric_recording(self):
        """Testa registro de métricas."""
        # Arrange
        mock_meter = Mock()
        mock_counter = Mock()
        mock_meter.create_counter.return_value = mock_counter
        self.config.meter = mock_meter
        self.config._initialized = True
        
        # Act
        self.config.record_metric("test.metric", 1.0, {"status": "success"})
        
        # Assert
        mock_meter.create_counter.assert_called_once_with("test.metric")
        mock_counter.add.assert_called_once_with(1.0, {"status": "success"})


class TestOpenTelemetryFunctions(unittest.TestCase):
    """Testes para funções de conveniência."""
    
    def test_initialize_opentelemetry_function(self):
        """Testa função de conveniência para inicialização."""
        # Arrange
        with patch('shared.opentelemetry_config.opentelemetry_config') as mock_config:
            
            # Act
            initialize_opentelemetry(enable_tracing=True)
            
            # Assert
            mock_config.initialize.assert_called_once_with(enable_tracing=True)
    
    def test_get_tracer_function(self):
        """Testa função de conveniência para obter tracer."""
        # Arrange
        mock_tracer = Mock()
        with patch('shared.opentelemetry_config.opentelemetry_config') as mock_config:
            mock_config.get_tracer.return_value = mock_tracer
            
            # Act
            result = get_tracer()
            
            # Assert
            self.assertEqual(result, mock_tracer)
    
    def test_get_meter_function(self):
        """Testa função de conveniência para obter meter."""
        # Arrange
        mock_meter = Mock()
        with patch('shared.opentelemetry_config.opentelemetry_config') as mock_config:
            mock_config.get_meter.return_value = mock_meter
            
            # Act
            result = get_meter()
            
            # Assert
            self.assertEqual(result, mock_meter)


if __name__ == '__main__':
    # Configurar logging para testes
    logging.basicConfig(level=logging.INFO)
    
    # Executar testes
    unittest.main(verbosity=2) 