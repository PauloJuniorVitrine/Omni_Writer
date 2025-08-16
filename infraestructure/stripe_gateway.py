"""
Gateway de Pagamento Stripe - Omni Writer
Tracing ID: STRIPE_GATEWAY_20250127_001
Data/Hora: 2025-01-27T16:45:00Z
Versão: 1.0.0

Implementação baseada em:
- PCI-DSS 4.0 compliance
- Stripe Security Best Practices
- OWASP ASVS 1.2
- Circuit Breaker Pattern
- Idempotência e Retry Logic
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urlencode

# Importações condicionais para evitar erros se dependências não estiverem instaladas
try:
    import stripe
except ImportError:
    stripe = None
    logging.warning("Stripe não instalado - funcionalidades de pagamento desabilitadas")

try:
    from pydantic import BaseModel, Field, validator
except ImportError:
    # Fallback para dataclasses se pydantic não estiver disponível
    from dataclasses import dataclass, field
    from typing import Any
    
    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    
    def Field(*args, **kwargs):
        return field(*args, **kwargs)
    
    def validator(field_name):
        def decorator(func):
            return func
        return decorator

from shared.feature_flags import FeatureFlagsManager
from infraestructure.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from infraestructure.resilience_config import CircuitBreakerState

# Configuração de logging estruturado
logger = logging.getLogger(__name__)

# Configuração do Stripe
if stripe:
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")

# Feature flags para controle granular
FEATURE_FLAGS = FeatureFlagsManager()


class PaymentIntentRequest(BaseModel):
    """Modelo para requisição de Payment Intent"""
    amount: int = Field(..., gt=0, description="Valor em centavos")
    currency: str = Field(default="brl", description="Moeda (ISO 4217)")
    customer_id: Optional[str] = Field(None, description="ID do cliente Stripe")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Metadados customizados")
    idempotency_key: str = Field(..., description="Chave de idempotência única")
    
    @validator('currency')
    def validate_currency(cls, v):
        """Valida moeda suportada"""
        supported_currencies = ['brl', 'usd', 'eur']
        if v.lower() not in supported_currencies:
            raise ValueError(f"Moeda não suportada: {v}")
        return v.lower()


class PaymentIntentResponse(BaseModel):
    """Modelo para resposta de Payment Intent"""
    payment_intent_id: str
    client_secret: str
    status: str
    amount: int
    currency: str
    created_at: datetime
    metadata: Dict[str, str]


class WebhookEvent(BaseModel):
    """Modelo para eventos de webhook"""
    event_id: str
    event_type: str
    created_at: datetime
    data: Dict
    livemode: bool
    api_version: str


class StripeGateway:
    """
    Gateway de pagamento Stripe com circuit breaker e retry logic
    
    Implementa:
    - Circuit breaker pattern para resiliência
    - Retry automático com backoff exponencial
    - Validação de webhooks com HMAC
    - Idempotência para evitar duplicação
    - Logging estruturado com tracing
    - Feature flags para controle granular
    """
    
    def __init__(self, tracing_id: str = None):
        self.tracing_id = tracing_id or f"STRIPE_{int(time.time())}"
        
        # Configuração do circuit breaker
        circuit_config = CircuitBreakerConfig(
            name="stripe_gateway",
            failure_threshold=5,
            recovery_timeout=60,
            expected_exceptions=[stripe.error.StripeError] if stripe else []
        )
        self.circuit_breaker = CircuitBreaker(config=circuit_config)
        self.retry_config = {
            'max_retries': 3,
            'base_delay': 1.0,
            'max_delay': 30.0,
            'exponential_base': 2
        }
        
        # Cache para idempotência
        self._idempotency_cache = {}
        self._cache_ttl = 3600  # 1 hora
        
        logger.info(f"[{self.tracing_id}] Stripe Gateway inicializado")
    
    async def create_payment_intent(
        self, 
        request: PaymentIntentRequest
    ) -> PaymentIntentResponse:
        """
        Cria Payment Intent no Stripe com idempotência
        
        Args:
            request: Dados da requisição de pagamento
            
        Returns:
            PaymentIntentResponse com dados do pagamento
            
        Raises:
            stripe.error.StripeError: Erro da API Stripe
            ValueError: Dados inválidos
        """
        if not FEATURE_FLAGS.is_enabled("stripe_payments"):
            raise ValueError("Pagamentos Stripe desabilitados via feature flag")
        
        # Validação de idempotência
        cache_key = f"payment_intent:{request.idempotency_key}"
        if cache_key in self._idempotency_cache:
            cached_response = self._idempotency_cache[cache_key]
            if time.time() - cached_response['timestamp'] < self._cache_ttl:
                logger.info(f"[{self.tracing_id}] Retornando resposta cacheada para idempotência")
                return cached_response['response']
        
        try:
            # Circuit breaker wrapper
            @self.circuit_breaker
            def _create_payment_intent():
                return stripe.PaymentIntent.create(
                    amount=request.amount,
                    currency=request.currency,
                    customer=request.customer_id,
                    metadata=request.metadata,
                    idempotency_key=request.idempotency_key
                )
            
            # Retry logic com backoff exponencial
            payment_intent = await self._retry_with_backoff(_create_payment_intent)
            
            response = PaymentIntentResponse(
                payment_intent_id=payment_intent.id,
                client_secret=payment_intent.client_secret,
                status=payment_intent.status,
                amount=payment_intent.amount,
                currency=payment_intent.currency,
                created_at=datetime.fromtimestamp(payment_intent.created),
                metadata=payment_intent.metadata
            )
            
            # Cache para idempotência
            self._idempotency_cache[cache_key] = {
                'response': response,
                'timestamp': time.time()
            }
            
            logger.info(
                f"[{self.tracing_id}] Payment Intent criado: {payment_intent.id}",
                extra={
                    'payment_intent_id': payment_intent.id,
                    'amount': request.amount,
                    'currency': request.currency,
                    'status': payment_intent.status
                }
            )
            
            return response
            
        except stripe.error.StripeError as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao criar Payment Intent: {str(e)}",
                extra={
                    'error_code': e.code,
                    'error_type': e.type,
                    'amount': request.amount,
                    'currency': request.currency
                }
            )
            raise
    
    async def confirm_payment_intent(
        self, 
        payment_intent_id: str,
        payment_method_id: str
    ) -> Dict:
        """
        Confirma Payment Intent com método de pagamento
        
        Args:
            payment_intent_id: ID do Payment Intent
            payment_method_id: ID do método de pagamento
            
        Returns:
            Dados da confirmação
        """
        try:
            @self.circuit_breaker
            def _confirm_payment_intent():
                return stripe.PaymentIntent.confirm(
                    payment_intent_id,
                    payment_method=payment_method_id
                )
            
            payment_intent = await self._retry_with_backoff(_confirm_payment_intent)
            
            logger.info(
                f"[{self.tracing_id}] Payment Intent confirmado: {payment_intent_id}",
                extra={
                    'payment_intent_id': payment_intent_id,
                    'status': payment_intent.status,
                    'payment_method_id': payment_method_id
                }
            )
            
            return {
                'id': payment_intent.id,
                'status': payment_intent.status,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency,
                'last_payment_error': payment_intent.last_payment_error
            }
            
        except stripe.error.StripeError as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao confirmar Payment Intent: {str(e)}",
                extra={
                    'payment_intent_id': payment_intent_id,
                    'error_code': e.code,
                    'error_type': e.type
                }
            )
            raise
    
    def verify_webhook_signature(
        self, 
        payload: bytes, 
        signature: str
    ) -> bool:
        """
        Verifica assinatura do webhook usando HMAC
        
        Args:
            payload: Corpo da requisição
            signature: Header Stripe-Signature
            
        Returns:
            True se assinatura válida, False caso contrário
        """
        try:
            # Extrai timestamp e assinatura do header
            timestamp, sig = signature.split(',')
            timestamp = timestamp.split('=')[1]
            sig = sig.split('=')[1]
            
            # Constrói string para verificação
            signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
            
            # Calcula HMAC
            expected_signature = hmac.new(
                STRIPE_WEBHOOK_SECRET.encode('utf-8'),
                signed_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Compara assinaturas
            is_valid = hmac.compare_digest(expected_signature, sig)
            
            if not is_valid:
                logger.warning(
                    f"[{self.tracing_id}] Assinatura de webhook inválida",
                    extra={'timestamp': timestamp}
                )
            
            return is_valid
            
        except Exception as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao verificar assinatura: {str(e)}"
            )
            return False
    
    def process_webhook_event(
        self, 
        payload: bytes, 
        signature: str
    ) -> Optional[WebhookEvent]:
        """
        Processa evento de webhook com validação
        
        Args:
            payload: Corpo da requisição
            signature: Header Stripe-Signature
            
        Returns:
            WebhookEvent se válido, None caso contrário
        """
        if not self.verify_webhook_signature(payload, signature):
            return None
        
        try:
            event_data = json.loads(payload.decode('utf-8'))
            
            event = WebhookEvent(
                event_id=event_data['id'],
                event_type=event_data['type'],
                created_at=datetime.fromtimestamp(event_data['created']),
                data=event_data['data'],
                livemode=event_data['livemode'],
                api_version=event_data['api_version']
            )
            
            logger.info(
                f"[{self.tracing_id}] Webhook processado: {event.event_type}",
                extra={
                    'event_id': event.event_id,
                    'event_type': event.event_type,
                    'livemode': event.livemode
                }
            )
            
            return event
            
        except Exception as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao processar webhook: {str(e)}"
            )
            return None
    
    async def _retry_with_backoff(self, func, *args, **kwargs):
        """
        Executa função com retry e backoff exponencial
        
        Args:
            func: Função a executar
            *args, **kwargs: Argumentos da função
            
        Returns:
            Resultado da função
            
        Raises:
            Exception: Se todas as tentativas falharem
        """
        last_exception = None
        
        for attempt in range(self.retry_config['max_retries'] + 1):
            try:
                return func(*args, **kwargs)
                
            except Exception as e:
                last_exception = e
                
                if attempt == self.retry_config['max_retries']:
                    break
                
                # Calcula delay com backoff exponencial
                delay = min(
                    self.retry_config['base_delay'] * 
                    (self.retry_config['exponential_base'] ** attempt),
                    self.retry_config['max_delay']
                )
                
                logger.warning(
                    f"[{self.tracing_id}] Tentativa {attempt + 1} falhou, "
                    f"tentando novamente em {delay}s: {str(e)}"
                )
                
                await asyncio.sleep(delay)
        
        raise last_exception
    
    def get_payment_intent(self, payment_intent_id: str) -> Dict:
        """
        Recupera Payment Intent do Stripe
        
        Args:
            payment_intent_id: ID do Payment Intent
            
        Returns:
            Dados do Payment Intent
        """
        try:
            @self.circuit_breaker
            def _get_payment_intent():
                return stripe.PaymentIntent.retrieve(payment_intent_id)
            
            payment_intent = _get_payment_intent()
            
            return {
                'id': payment_intent.id,
                'status': payment_intent.status,
                'amount': payment_intent.amount,
                'currency': payment_intent.currency,
                'created': payment_intent.created,
                'metadata': payment_intent.metadata
            }
            
        except stripe.error.StripeError as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao recuperar Payment Intent: {str(e)}",
                extra={
                    'payment_intent_id': payment_intent_id,
                    'error_code': e.code,
                    'error_type': e.type
                }
            )
            raise
    
    def create_customer(
        self, 
        email: str, 
        name: str = None,
        metadata: Dict[str, str] = None
    ) -> str:
        """
        Cria cliente no Stripe
        
        Args:
            email: Email do cliente
            name: Nome do cliente
            metadata: Metadados customizados
            
        Returns:
            ID do cliente criado
        """
        try:
            @self.circuit_breaker
            def _create_customer():
                return stripe.Customer.create(
                    email=email,
                    name=name,
                    metadata=metadata or {}
                )
            
            customer = _create_customer()
            
            logger.info(
                f"[{self.tracing_id}] Cliente criado: {customer.id}",
                extra={
                    'customer_id': customer.id,
                    'email': email
                }
            )
            
            return customer.id
            
        except stripe.error.StripeError as e:
            logger.error(
                f"[{self.tracing_id}] Erro ao criar cliente: {str(e)}",
                extra={
                    'email': email,
                    'error_code': e.code,
                    'error_type': e.type
                }
            )
            raise
    
    def get_health_status(self) -> Dict:
        """
        Retorna status de saúde do gateway
        
        Returns:
            Dicionário com métricas de saúde
        """
        return {
            'circuit_breaker_state': self.circuit_breaker.state,
            'circuit_breaker_failure_count': self.circuit_breaker.failure_count,
            'idempotency_cache_size': len(self._idempotency_cache),
            'feature_flags_enabled': {
                'stripe_payments': FEATURE_FLAGS.is_enabled("stripe_payments")
            },
            'tracing_id': self.tracing_id,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def cleanup_idempotency_cache(self):
        """Remove entradas expiradas do cache de idempotência"""
        current_time = time.time()
        expired_keys = [
            key for key, value in self._idempotency_cache.items()
            if current_time - value['timestamp'] > self._cache_ttl
        ]
        
        for key in expired_keys:
            del self._idempotency_cache[key]
        
        if expired_keys:
            logger.info(
                f"[{self.tracing_id}] Removidas {len(expired_keys)} entradas expiradas do cache"
            )


# Instância global do gateway
stripe_gateway = StripeGateway()


def get_stripe_gateway(tracing_id: str = None) -> StripeGateway:
    """
    Factory function para obter instância do gateway
    
    Args:
        tracing_id: ID de rastreamento opcional
        
    Returns:
        Instância do StripeGateway
    """
    if tracing_id:
        return StripeGateway(tracing_id)
    return stripe_gateway 