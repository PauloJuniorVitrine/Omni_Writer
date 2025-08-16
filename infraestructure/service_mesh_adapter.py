"""
Service Mesh Adapter - Omni Writer
Tracing ID: SERVICE_MESH_20250127_001
Data/Hora: 2025-01-27T17:00:00Z
Versão: 1.0.0

Implementação baseada em:
- Service Mesh Patterns (Istio/Linkerd)
- CNCF Observability Standards
- Distributed Tracing (OpenTelemetry)
- mTLS e Security Headers
- Circuit Breaker Integration
"""

import os
import time
import uuid
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager

import requests
from pydantic import BaseModel, Field, validator
from shared.feature_flags import FeatureFlagsManager
from infraestructure.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

# Configuração de logging estruturado
logger = logging.getLogger(__name__)

# Feature flags para controle granular
FEATURE_FLAGS = FeatureFlagsManager()


class ServiceMeshType(Enum):
    """Tipos de service mesh suportados"""
    ISTIO = "istio"
    LINKERD = "linkerd"
    CONSUL = "consul"
    NONE = "none"


class TracingHeader(BaseModel):
    """Headers de tracing para service mesh"""
    x_request_id: str = Field(..., description="ID único da requisição")
    x_b3_traceid: str = Field(..., description="Trace ID (B3 format)")
    x_b3_spanid: str = Field(..., description="Span ID (B3 format)")
    x_b3_parentspanid: Optional[str] = Field(None, description="Parent Span ID")
    x_b3_sampled: str = Field(default="1", description="Sampling decision")
    x_b3_flags: Optional[str] = Field(None, description="B3 flags")
    x_ot_span_context: Optional[str] = Field(None, description="OpenTelemetry context")


class ServiceMeshMetrics(BaseModel):
    """Métricas de service mesh"""
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_latency: float = 0.0
    avg_latency: float = 0.0
    circuit_breaker_trips: int = 0
    retry_count: int = 0
    last_request_time: Optional[datetime] = None


@dataclass
class ServiceMeshConfig:
    """Configuração do service mesh"""
    mesh_type: ServiceMeshType
    service_name: str
    service_version: str
    namespace: str
    enable_tracing: bool = True
    enable_metrics: bool = True
    enable_mtls: bool = True
    retry_policy: Dict[str, Any] = field(default_factory=lambda: {
        'max_retries': 3,
        'base_delay': 0.1,
        'max_delay': 5.0
    })
    timeout_policy: Dict[str, Any] = field(default_factory=lambda: {
        'connect_timeout': 5.0,
        'read_timeout': 30.0
    })
    circuit_breaker_policy: Dict[str, Any] = field(default_factory=lambda: {
        'failure_threshold': 5,
        'recovery_timeout': 60
    })


class ServiceMeshAdapter:
    """
    Adapter para service mesh (Istio/Linkerd)
    
    Funcionalidades:
    - Headers de tracing automáticos
    - Métricas de latência e throughput
    - Circuit breaker por serviço
    - Retry policies configuráveis
    - mTLS awareness
    - Observabilidade distribuída
    """
    
    def __init__(self, config: ServiceMeshConfig, tracing_id: str = None):
        self.config = config
        self.tracing_id = tracing_id or f"SERVICE_MESH_{int(time.time())}"
        
        # Circuit breaker por serviço
        circuit_config = CircuitBreakerConfig(
            name=f"service_mesh_{config.service_name}",
            failure_threshold=config.circuit_breaker_policy['failure_threshold'],
            recovery_timeout=config.circuit_breaker_policy['recovery_timeout'],
            expected_exceptions=[requests.RequestException]
        )
        self.circuit_breaker = CircuitBreaker(config=circuit_config)
        
        # Métricas
        self.metrics = ServiceMeshMetrics()
        
        # Cache de headers de tracing
        self._tracing_cache = {}
        self._cache_ttl = 300  # 5 minutos
        
        # Detecção automática do service mesh
        self._detect_service_mesh()
        
        logger.info(
            f"[{self.tracing_id}] Service Mesh Adapter inicializado",
            extra={
                'service_name': config.service_name,
                'mesh_type': config.mesh_type.value,
                'namespace': config.namespace
            }
        )
    
    def _detect_service_mesh(self):
        """Detecta automaticamente o service mesh em uso"""
        # Verifica variáveis de ambiente do Istio
        if os.getenv('ISTIO_VERSION') or os.getenv('POD_NAME', '').startswith('istio'):
            self.config.mesh_type = ServiceMeshType.ISTIO
            logger.info(f"[{self.tracing_id}] Istio detectado automaticamente")
        
        # Verifica variáveis de ambiente do Linkerd
        elif os.getenv('LINKERD_PROXY_VERSION') or os.getenv('LINKERD2_PROXY_VERSION'):
            self.config.mesh_type = ServiceMeshType.LINKERD
            logger.info(f"[{self.tracing_id}] Linkerd detectado automaticamente")
        
        # Verifica variáveis de ambiente do Consul
        elif os.getenv('CONSUL_HTTP_ADDR') or os.getenv('CONSUL_SERVICE'):
            self.config.mesh_type = ServiceMeshType.CONSUL
            logger.info(f"[{self.tracing_id}] Consul detectado automaticamente")
        
        else:
            self.config.mesh_type = ServiceMeshType.NONE
            logger.info(f"[{self.tracing_id}] Nenhum service mesh detectado")
    
    def generate_tracing_headers(self, parent_span_id: Optional[str] = None) -> TracingHeader:
        """
        Gera headers de tracing para service mesh
        
        Args:
            parent_span_id: ID do span pai (opcional)
            
        Returns:
            Headers de tracing configurados
        """
        if not FEATURE_FLAGS.is_enabled("service_mesh_enabled"):
            return TracingHeader(
                x_request_id=str(uuid.uuid4()),
                x_b3_traceid="0",
                x_b3_spanid="0"
            )
        
        # Gera IDs únicos
        trace_id = self._generate_trace_id()
        span_id = self._generate_span_id()
        
        # Cache para reutilização
        cache_key = f"{trace_id}:{span_id}"
        if cache_key in self._tracing_cache:
            cached_headers = self._tracing_cache[cache_key]
            if time.time() - cached_headers['timestamp'] < self._cache_ttl:
                return cached_headers['headers']
        
        # Cria headers baseados no tipo de service mesh
        headers = TracingHeader(
            x_request_id=str(uuid.uuid4()),
            x_b3_traceid=trace_id,
            x_b3_spanid=span_id,
            x_b3_parentspanid=parent_span_id,
            x_b3_sampled="1"
        )
        
        # Headers específicos por service mesh
        if self.config.mesh_type == ServiceMeshType.ISTIO:
            headers.x_ot_span_context = self._generate_istio_context(trace_id, span_id)
        elif self.config.mesh_type == ServiceMeshType.LINKERD:
            headers.x_b3_flags = "1"  # Linkerd usa flags B3
        
        # Cache dos headers
        self._tracing_cache[cache_key] = {
            'headers': headers,
            'timestamp': time.time()
        }
        
        return headers
    
    def _generate_trace_id(self) -> str:
        """Gera trace ID único"""
        return format(uuid.uuid4().int & (1 << 64) - 1, '016x')
    
    def _generate_span_id(self) -> str:
        """Gera span ID único"""
        return format(uuid.uuid4().int & (1 << 64) - 1, '016x')
    
    def _generate_istio_context(self, trace_id: str, span_id: str) -> str:
        """Gera contexto OpenTelemetry para Istio"""
        context = {
            "trace_id": trace_id,
            "span_id": span_id,
            "service_name": self.config.service_name,
            "namespace": self.config.namespace
        }
        return json.dumps(context)
    
    @contextmanager
    def service_call(self, target_service: str, operation: str = "request"):
        """
        Context manager para chamadas de serviço com observabilidade
        
        Args:
            target_service: Nome do serviço de destino
            operation: Nome da operação
            
        Yields:
            Headers de tracing para usar na requisição
        """
        start_time = time.time()
        headers = self.generate_tracing_headers()
        
        try:
            # Log do início da chamada
            logger.info(
                f"[{self.tracing_id}] Iniciando chamada de serviço",
                extra={
                    'target_service': target_service,
                    'operation': operation,
                    'trace_id': headers.x_b3_traceid,
                    'span_id': headers.x_b3_spanid
                }
            )
            
            yield headers
            
            # Log de sucesso
            duration = time.time() - start_time
            self._update_metrics(success=True, duration=duration)
            
            logger.info(
                f"[{self.tracing_id}] Chamada de serviço concluída",
                extra={
                    'target_service': target_service,
                    'operation': operation,
                    'duration_ms': duration * 1000,
                    'trace_id': headers.x_b3_traceid
                }
            )
            
        except Exception as e:
            # Log de falha
            duration = time.time() - start_time
            self._update_metrics(success=False, duration=duration)
            
            logger.error(
                f"[{self.tracing_id}] Falha na chamada de serviço",
                extra={
                    'target_service': target_service,
                    'operation': operation,
                    'error': str(e),
                    'duration_ms': duration * 1000,
                    'trace_id': headers.x_b3_traceid
                }
            )
            raise
    
    def make_request(
        self, 
        target_service: str,
        method: str = "GET",
        url: str = "",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None
    ) -> requests.Response:
        """
        Faz requisição HTTP com observabilidade de service mesh
        
        Args:
            target_service: Nome do serviço de destino
            method: Método HTTP
            url: URL da requisição
            headers: Headers adicionais
            data: Dados da requisição
            timeout: Timeout em segundos
            
        Returns:
            Response da requisição
            
        Raises:
            requests.RequestException: Se a requisição falhar
        """
        if not FEATURE_FLAGS.is_enabled("service_mesh_enabled"):
            # Fallback para requisição normal
            return requests.request(method, url, headers=headers, data=data, timeout=timeout)
        
        # Configura timeout
        timeout = timeout or self.config.timeout_policy['read_timeout']
        
        # Headers de tracing
        tracing_headers = self.generate_tracing_headers()
        
        # Headers completos
        full_headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'{self.config.service_name}/{self.config.service_version}',
            **tracing_headers.dict(exclude_none=True),
            **(headers or {})
        }
        
        # Adiciona headers específicos do service mesh
        if self.config.mesh_type == ServiceMeshType.ISTIO:
            full_headers.update(self._get_istio_headers())
        elif self.config.mesh_type == ServiceMeshType.LINKERD:
            full_headers.update(self._get_linkerd_headers())
        
        try:
            # Circuit breaker wrapper
            @self.circuit_breaker
            def _make_request():
                return requests.request(
                    method=method,
                    url=url,
                    headers=full_headers,
                    data=data,
                    timeout=timeout
                )
            
            # Retry logic
            response = self._retry_with_backoff(_make_request)
            
            # Log da resposta
            logger.info(
                f"[{self.tracing_id}] Requisição HTTP concluída",
                extra={
                    'target_service': target_service,
                    'method': method,
                    'url': url,
                    'status_code': response.status_code,
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'trace_id': tracing_headers.x_b3_traceid
                }
            )
            
            return response
            
        except requests.RequestException as e:
            logger.error(
                f"[{self.tracing_id}] Falha na requisição HTTP",
                extra={
                    'target_service': target_service,
                    'method': method,
                    'url': url,
                    'error': str(e),
                    'trace_id': tracing_headers.x_b3_traceid
                }
            )
            raise
    
    def _get_istio_headers(self) -> Dict[str, str]:
        """Retorna headers específicos do Istio"""
        return {
            'x-istio-attributes': json.dumps({
                'source': {
                    'uid': f'kubernetes://{self.config.namespace}/{self.config.service_name}',
                    'namespace': self.config.namespace,
                    'service': self.config.service_name
                }
            })
        }
    
    def _get_linkerd_headers(self) -> Dict[str, str]:
        """Retorna headers específicos do Linkerd"""
        return {
            'l5d-dst-service': self.config.service_name,
            'l5d-sample': '1.0'
        }
    
    def _retry_with_backoff(self, func, *args, **kwargs):
        """
        Executa função com retry e backoff exponencial
        
        Args:
            func: Função a executar
            *args, **kwargs: Argumentos da função
            
        Returns:
            Resultado da função
        """
        last_exception = None
        retry_config = self.config.retry_policy
        
        for attempt in range(retry_config['max_retries'] + 1):
            try:
                return func(*args, **kwargs)
                
            except Exception as e:
                last_exception = e
                
                if attempt == retry_config['max_retries']:
                    break
                
                # Calcula delay com backoff exponencial
                delay = min(
                    retry_config['base_delay'] * (2 ** attempt),
                    retry_config['max_delay']
                )
                
                logger.warning(
                    f"[{self.tracing_id}] Tentativa {attempt + 1} falhou, "
                    f"tentando novamente em {delay}s: {str(e)}"
                )
                
                time.sleep(delay)
        
        raise last_exception
    
    def _update_metrics(self, success: bool, duration: float):
        """Atualiza métricas de service mesh"""
        self.metrics.request_count += 1
        self.metrics.total_latency += duration
        
        if success:
            self.metrics.success_count += 1
        else:
            self.metrics.failure_count += 1
        
        # Calcula latência média
        if self.metrics.request_count > 0:
            self.metrics.avg_latency = self.metrics.total_latency / self.metrics.request_count
        
        self.metrics.last_request_time = datetime.utcnow()
    
    def get_health_status(self) -> Dict[str, Any]:
        """
        Retorna status de saúde do service mesh adapter
        
        Returns:
            Dicionário com métricas de saúde
        """
        return {
            'service_name': self.config.service_name,
            'mesh_type': self.config.mesh_type.value,
            'namespace': self.config.namespace,
            'circuit_breaker_state': self.circuit_breaker.state,
            'circuit_breaker_failure_count': self.circuit_breaker.failure_count,
            'metrics': self.metrics.dict(),
            'feature_flags_enabled': {
                'service_mesh_enabled': FEATURE_FLAGS.is_enabled("service_mesh_enabled")
            },
            'tracing_cache_size': len(self._tracing_cache),
            'tracing_id': self.tracing_id,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def cleanup_tracing_cache(self):
        """Remove entradas expiradas do cache de tracing"""
        current_time = time.time()
        expired_keys = [
            key for key, value in self._tracing_cache.items()
            if current_time - value['timestamp'] > self._cache_ttl
        ]
        
        for key in expired_keys:
            del self._tracing_cache[key]
        
        if expired_keys:
            logger.info(
                f"[{self.tracing_id}] Removidas {len(expired_keys)} entradas expiradas do cache de tracing"
            )


# Instância global do adapter
service_mesh_adapter = ServiceMeshAdapter(
    config=ServiceMeshConfig(
        mesh_type=ServiceMeshType.NONE,
        service_name=os.getenv('SERVICE_NAME', 'omni-writer'),
        service_version=os.getenv('SERVICE_VERSION', '1.0.0'),
        namespace=os.getenv('NAMESPACE', 'default')
    )
)


def get_service_mesh_adapter(
    service_name: str = None,
    namespace: str = None,
    tracing_id: str = None
) -> ServiceMeshAdapter:
    """
    Factory function para obter instância do service mesh adapter
    
    Args:
        service_name: Nome do serviço
        namespace: Namespace do serviço
        tracing_id: ID de rastreamento opcional
        
    Returns:
        Instância do ServiceMeshAdapter
    """
    if service_name or namespace:
        config = ServiceMeshConfig(
            mesh_type=ServiceMeshType.NONE,
            service_name=service_name or os.getenv('SERVICE_NAME', 'omni-writer'),
            service_version=os.getenv('SERVICE_VERSION', '1.0.0'),
            namespace=namespace or os.getenv('NAMESPACE', 'default')
        )
        return ServiceMeshAdapter(config, tracing_id)
    
    return service_mesh_adapter


def inject_tracing_headers(headers: Dict[str, str], tracing_id: str = None) -> Dict[str, str]:
    """
    Função de conveniência para injetar headers de tracing
    
    Args:
        headers: Headers existentes
        tracing_id: ID de rastreamento opcional
        
    Returns:
        Headers com tracing injetado
    """
    adapter = get_service_mesh_adapter(tracing_id=tracing_id)
    tracing_headers = adapter.generate_tracing_headers()
    
    return {
        **headers,
        **tracing_headers.dict(exclude_none=True)
    } 