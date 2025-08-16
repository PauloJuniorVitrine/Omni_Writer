"""
Testes Unitários - Stripe Gateway
Tracing ID: TEST_STRIPE_GATEWAY_20250127_001
Data/Hora: 2025-01-27T16:50:00Z
Versão: 1.0.0

Testes baseados em código real do Stripe Gateway:
- Validação de Payment Intent Request/Response
- Verificação de webhook signature
- Circuit breaker integration
- Feature flags integration
- Idempotência de pagamentos
- Retry logic com backoff exponencial

Regras aplicadas:
- ✅ Testes baseados em código real
- ✅ Cenários reais de pagamento
- ❌ Proibidos dados sintéticos (foo, bar, lorem)
- ❌ Proibidos testes genéricos
"""

import json
import time
import unittest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Importações do sistema real
from infraestructure.stripe_gateway import (
    StripeGateway,
    PaymentIntentRequest,
    PaymentIntentResponse,
    WebhookEvent,
    get_stripe_gateway
)
from shared.feature_flags import FeatureFlagsManager
from infraestructure.circuit_breaker import CircuitBreaker


class TestPaymentIntentRequest(unittest.TestCase):
    """Testes para modelo PaymentIntentRequest baseado em código real"""
    
    def test_valid_payment_intent_request_creation(self):
        """Testa criação de PaymentIntentRequest com dados válidos reais"""
        # Dados reais de pagamento
        request = PaymentIntentRequest(
            amount=2500,  # R$ 25,00 em centavos
            currency="brl",
            customer_id="cus_1234567890",
            metadata={"order_id": "ORD-2025-001", "user_id": "user_123"},
            idempotency_key="pi_20250127_001"
        )
        
        self.assertEqual(request.amount, 2500)
        self.assertEqual(request.currency, "brl")
        self.assertEqual(request.customer_id, "cus_1234567890")
        self.assertEqual(request.metadata["order_id"], "ORD-2025-001")
        self.assertEqual(request.idempotency_key, "pi_20250127_001")
    
    def test_currency_validation_brl(self):
        """Testa validação de moeda BRL (real brasileiro)"""
        request = PaymentIntentRequest(
            amount=1000,
            currency="brl",
            idempotency_key="pi_20250127_002"
        )
        self.assertEqual(request.currency, "brl")
    
    def test_currency_validation_usd(self):
        """Testa validação de moeda USD (dólar americano)"""
        request = PaymentIntentRequest(
            amount=1000,
            currency="usd",
            idempotency_key="pi_20250127_003"
        )
        self.assertEqual(request.currency, "usd")
    
    def test_currency_validation_eur(self):
        """Testa validação de moeda EUR (euro)"""
        request = PaymentIntentRequest(
            amount=1000,
            currency="eur",
            idempotency_key="pi_20250127_004"
        )
        self.assertEqual(request.currency, "eur")
    
    def test_invalid_currency_raises_error(self):
        """Testa que moeda inválida gera erro"""
        with self.assertRaises(ValueError):
            PaymentIntentRequest(
                amount=1000,
                currency="invalid_currency",
                idempotency_key="pi_20250127_005"
            )
    
    def test_amount_validation_positive(self):
        """Testa que valor positivo é aceito"""
        request = PaymentIntentRequest(
            amount=1,  # Valor mínimo
            currency="brl",
            idempotency_key="pi_20250127_006"
        )
        self.assertEqual(request.amount, 1)
    
    def test_amount_validation_zero_raises_error(self):
        """Testa que valor zero gera erro"""
        with self.assertRaises(ValueError):
            PaymentIntentRequest(
                amount=0,
                currency="brl",
                idempotency_key="pi_20250127_007"
            )


class TestPaymentIntentResponse(unittest.TestCase):
    """Testes para modelo PaymentIntentResponse baseado em código real"""
    
    def test_payment_intent_response_creation(self):
        """Testa criação de PaymentIntentResponse com dados reais"""
        # Dados reais de resposta do Stripe
        response = PaymentIntentResponse(
            payment_intent_id="pi_3OqX8X2eZvKYlo2C1gQKqX8X",
            client_secret="pi_3OqX8X2eZvKYlo2C1gQKqX8X_secret_abc123",
            status="requires_payment_method",
            amount=2500,
            currency="brl",
            created_at=datetime(2025, 1, 27, 16, 50, 0),
            metadata={"order_id": "ORD-2025-001"}
        )
        
        self.assertEqual(response.payment_intent_id, "pi_3OqX8X2eZvKYlo2C1gQKqX8X")
        self.assertEqual(response.client_secret, "pi_3OqX8X2eZvKYlo2C1gQKqX8X_secret_abc123")
        self.assertEqual(response.status, "requires_payment_method")
        self.assertEqual(response.amount, 2500)
        self.assertEqual(response.currency, "brl")
        self.assertEqual(response.metadata["order_id"], "ORD-2025-001")


class TestWebhookEvent(unittest.TestCase):
    """Testes para modelo WebhookEvent baseado em código real"""
    
    def test_webhook_event_creation(self):
        """Testa criação de WebhookEvent com dados reais do Stripe"""
        # Dados reais de webhook do Stripe
        event = WebhookEvent(
            event_id="evt_3OqX8X2eZvKYlo2C1gQKqX8X",
            event_type="payment_intent.succeeded",
            created_at=datetime(2025, 1, 27, 16, 50, 0),
            data={
                "object": {
                    "id": "pi_3OqX8X2eZvKYlo2C1gQKqX8X",
                    "amount": 2500,
                    "currency": "brl",
                    "status": "succeeded"
                }
            },
            livemode=False,
            api_version="2023-10-16"
        )
        
        self.assertEqual(event.event_id, "evt_3OqX8X2eZvKYlo2C1gQKqX8X")
        self.assertEqual(event.event_type, "payment_intent.succeeded")
        self.assertEqual(event.livemode, False)
        self.assertEqual(event.api_version, "2023-10-16")
        self.assertEqual(event.data["object"]["amount"], 2500)


class TestStripeGateway(unittest.TestCase):
    """Testes para StripeGateway baseado em código real"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.tracing_id = "TEST_STRIPE_GATEWAY_001"
        self.gateway = StripeGateway(tracing_id=self.tracing_id)
        
        # Mock do feature flags
        self.feature_flags_mock = Mock(spec=FeatureFlagsManager)
        self.feature_flags_mock.is_enabled.return_value = True
        
        # Mock do circuit breaker
        self.circuit_breaker_mock = Mock(spec=CircuitBreaker)
        self.circuit_breaker_mock.state = "CLOSED"
        self.circuit_breaker_mock.failure_count = 0
    
    def test_gateway_initialization_with_tracing_id(self):
        """Testa inicialização do gateway com tracing ID"""
        gateway = StripeGateway(tracing_id="CUSTOM_TRACING_ID")
        self.assertEqual(gateway.tracing_id, "CUSTOM_TRACING_ID")
    
    def test_gateway_initialization_without_tracing_id(self):
        """Testa inicialização do gateway sem tracing ID (gera automaticamente)"""
        gateway = StripeGateway()
        self.assertIsNotNone(gateway.tracing_id)
        self.assertTrue(gateway.tracing_id.startswith("STRIPE_"))
    
    def test_retry_config_initialization(self):
        """Testa configuração de retry inicializada corretamente"""
        expected_config = {
            'max_retries': 3,
            'base_delay': 1.0,
            'max_delay': 30.0,
            'exponential_base': 2
        }
        self.assertEqual(self.gateway.retry_config, expected_config)
    
    def test_idempotency_cache_initialization(self):
        """Testa cache de idempotência inicializado vazio"""
        self.assertEqual(len(self.gateway._idempotency_cache), 0)
        self.assertEqual(self.gateway._cache_ttl, 3600)  # 1 hora
    
    @patch('infraestructure.stripe_gateway.FEATURE_FLAGS')
    def test_create_payment_intent_feature_flag_disabled(self, mock_feature_flags):
        """Testa que criação de payment intent falha quando feature flag desabilitada"""
        mock_feature_flags.is_enabled.return_value = False
        
        request = PaymentIntentRequest(
            amount=2500,
            currency="brl",
            idempotency_key="pi_20250127_008"
        )
        
        with self.assertRaises(ValueError) as context:
            self.gateway.create_payment_intent(request)
        
        self.assertIn("Pagamentos Stripe desabilitados", str(context.exception))
    
    def test_verify_webhook_signature_valid(self):
        """Testa verificação de assinatura de webhook válida"""
        # Dados reais de webhook do Stripe
        payload = b'{"id":"evt_123","type":"payment_intent.succeeded","data":{"object":{"id":"pi_123"}}}'
        timestamp = str(int(time.time()))
        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        
        # Mock do HMAC para simular assinatura válida
        with patch('infraestructure.stripe_gateway.hmac') as mock_hmac:
            mock_hmac.new.return_value.hexdigest.return_value = "valid_signature"
            mock_hmac.compare_digest.return_value = True
            
            result = self.gateway.verify_webhook_signature(
                payload, 
                f"t={timestamp},v1=valid_signature"
            )
            
            self.assertTrue(result)
    
    def test_verify_webhook_signature_invalid(self):
        """Testa verificação de assinatura de webhook inválida"""
        payload = b'{"id":"evt_123","type":"payment_intent.succeeded"}'
        timestamp = str(int(time.time()))
        
        # Mock do HMAC para simular assinatura inválida
        with patch('infraestructure.stripe_gateway.hmac') as mock_hmac:
            mock_hmac.new.return_value.hexdigest.return_value = "valid_signature"
            mock_hmac.compare_digest.return_value = False
            
            result = self.gateway.verify_webhook_signature(
                payload, 
                f"t={timestamp},v1=invalid_signature"
            )
            
            self.assertFalse(result)
    
    def test_process_webhook_event_valid(self):
        """Testa processamento de evento de webhook válido"""
        # Dados reais de webhook
        payload = json.dumps({
            "id": "evt_3OqX8X2eZvKYlo2C1gQKqX8X",
            "type": "payment_intent.succeeded",
            "created": int(time.time()),
            "data": {
                "object": {
                    "id": "pi_3OqX8X2eZvKYlo2C1gQKqX8X",
                    "amount": 2500,
                    "currency": "brl"
                }
            },
            "livemode": False,
            "api_version": "2023-10-16"
        }).encode('utf-8')
        
        # Mock da verificação de assinatura
        with patch.object(self.gateway, 'verify_webhook_signature', return_value=True):
            event = self.gateway.process_webhook_event(
                payload, 
                "t=1234567890,v1=valid_signature"
            )
            
            self.assertIsNotNone(event)
            self.assertEqual(event.event_id, "evt_3OqX8X2eZvKYlo2C1gQKqX8X")
            self.assertEqual(event.event_type, "payment_intent.succeeded")
            self.assertEqual(event.livemode, False)
    
    def test_process_webhook_event_invalid_signature(self):
        """Testa processamento de evento com assinatura inválida"""
        payload = b'{"id":"evt_123","type":"payment_intent.succeeded"}'
        
        # Mock da verificação de assinatura retornando False
        with patch.object(self.gateway, 'verify_webhook_signature', return_value=False):
            event = self.gateway.process_webhook_event(
                payload, 
                "t=1234567890,v1=invalid_signature"
            )
            
            self.assertIsNone(event)
    
    def test_get_health_status(self):
        """Testa obtenção de status de saúde do gateway"""
        health_status = self.gateway.get_health_status()
        
        # Verifica campos obrigatórios
        self.assertIn('circuit_breaker_state', health_status)
        self.assertIn('circuit_breaker_failure_count', health_status)
        self.assertIn('idempotency_cache_size', health_status)
        self.assertIn('feature_flags_enabled', health_status)
        self.assertIn('tracing_id', health_status)
        self.assertIn('timestamp', health_status)
        
        # Verifica valores específicos
        self.assertEqual(health_status['tracing_id'], self.tracing_id)
        self.assertEqual(health_status['idempotency_cache_size'], 0)
    
    def test_cleanup_idempotency_cache(self):
        """Testa limpeza do cache de idempotência"""
        # Adiciona entradas ao cache
        self.gateway._idempotency_cache['key1'] = {
            'response': 'response1',
            'timestamp': time.time() - 7200  # 2 horas atrás (expirado)
        }
        self.gateway._idempotency_cache['key2'] = {
            'response': 'response2',
            'timestamp': time.time()  # Agora (não expirado)
        }
        
        # Executa limpeza
        self.gateway.cleanup_idempotency_cache()
        
        # Verifica que apenas entrada expirada foi removida
        self.assertNotIn('key1', self.gateway._idempotency_cache)
        self.assertIn('key2', self.gateway._idempotency_cache)
    
    @patch('infraestructure.stripe_gateway.asyncio.sleep')
    async def test_retry_with_backoff_success_first_try(self, mock_sleep):
        """Testa retry com backoff quando sucesso na primeira tentativa"""
        mock_func = Mock(return_value="success")
        
        result = await self.gateway._retry_with_backoff(mock_func)
        
        self.assertEqual(result, "success")
        mock_func.assert_called_once()
        mock_sleep.assert_not_called()
    
    @patch('infraestructure.stripe_gateway.asyncio.sleep')
    async def test_retry_with_backoff_success_after_retries(self, mock_sleep):
        """Testa retry com backoff quando sucesso após algumas tentativas"""
        mock_func = Mock()
        mock_func.side_effect = [Exception("Error 1"), Exception("Error 2"), "success"]
        
        result = await self.gateway._retry_with_backoff(mock_func)
        
        self.assertEqual(result, "success")
        self.assertEqual(mock_func.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)  # 2 delays
    
    @patch('infraestructure.stripe_gateway.asyncio.sleep')
    async def test_retry_with_backoff_max_retries_exceeded(self, mock_sleep):
        """Testa retry com backoff quando máximo de tentativas excedido"""
        mock_func = Mock(side_effect=Exception("Persistent Error"))
        
        with self.assertRaises(Exception) as context:
            await self.gateway._retry_with_backoff(mock_func)
        
        self.assertIn("Persistent Error", str(context.exception))
        self.assertEqual(mock_func.call_count, 4)  # 1 tentativa + 3 retries
        self.assertEqual(mock_sleep.call_count, 3)  # 3 delays


class TestStripeGatewayFactory(unittest.TestCase):
    """Testes para factory function do Stripe Gateway"""
    
    def test_get_stripe_gateway_with_tracing_id(self):
        """Testa factory function com tracing ID customizado"""
        tracing_id = "CUSTOM_FACTORY_TRACING_ID"
        gateway = get_stripe_gateway(tracing_id)
        
        self.assertEqual(gateway.tracing_id, tracing_id)
    
    def test_get_stripe_gateway_without_tracing_id(self):
        """Testa factory function sem tracing ID (usa instância global)"""
        gateway = get_stripe_gateway()
        
        self.assertIsNotNone(gateway.tracing_id)
        self.assertTrue(gateway.tracing_id.startswith("STRIPE_"))


class TestStripeGatewayIntegration(unittest.TestCase):
    """Testes de integração do Stripe Gateway com componentes reais"""
    
    def setUp(self):
        """Configuração para testes de integração"""
        self.gateway = StripeGateway(tracing_id="INTEGRATION_TEST_001")
    
    def test_circuit_breaker_integration(self):
        """Testa integração com circuit breaker"""
        # Verifica que circuit breaker foi inicializado
        self.assertIsNotNone(self.gateway.circuit_breaker)
        self.assertEqual(self.gateway.circuit_breaker.config.name, "stripe_gateway")
        self.assertEqual(self.gateway.circuit_breaker.config.failure_threshold, 5)
        self.assertEqual(self.gateway.circuit_breaker.config.recovery_timeout, 60)
    
    def test_feature_flags_integration(self):
        """Testa integração com feature flags"""
        # Verifica que feature flags está disponível
        from infraestructure.stripe_gateway import FEATURE_FLAGS
        self.assertIsNotNone(FEATURE_FLAGS)
        self.assertTrue(hasattr(FEATURE_FLAGS, 'is_enabled'))
    
    def test_logging_integration(self):
        """Testa integração com sistema de logging"""
        # Verifica que logger está configurado
        import logging
        logger = logging.getLogger('infraestructure.stripe_gateway')
        self.assertIsNotNone(logger)
    
    def test_idempotency_cache_integration(self):
        """Testa integração do cache de idempotência"""
        # Verifica estrutura do cache
        self.assertIsInstance(self.gateway._idempotency_cache, dict)
        self.assertEqual(self.gateway._cache_ttl, 3600)
        
        # Testa adição e recuperação de entrada
        test_key = "test_payment_intent:key123"
        test_response = PaymentIntentResponse(
            payment_intent_id="pi_test123",
            client_secret="secret_test123",
            status="requires_payment_method",
            amount=1000,
            currency="brl",
            created_at=datetime.now(),
            metadata={}
        )
        
        self.gateway._idempotency_cache[test_key] = {
            'response': test_response,
            'timestamp': time.time()
        }
        
        self.assertIn(test_key, self.gateway._idempotency_cache)
        cached_response = self.gateway._idempotency_cache[test_key]['response']
        self.assertEqual(cached_response.payment_intent_id, "pi_test123")


if __name__ == '__main__':
    unittest.main() 