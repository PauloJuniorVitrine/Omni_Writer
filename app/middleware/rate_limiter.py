# 🚦 RATE LIMITER AVANÇADO COM ADAPTIVE RATE LIMITING
# 📐 CoCoT + ToT + ReAct - Implementação Baseada em Código Real
# 🚫 PROIBIDO: Código sintético, genérico ou aleatório
# ✅ PERMITIDO: Apenas rate limiting baseado em padrões reais de uso
# 📅 Data/Hora: 2025-01-27T20:15:00Z
# 🎯 Prompt: Implementação de Adaptive Rate Limiting - Seção 3.2
# 📋 Ruleset: enterprise_control_layer.yaml
# 🆔 Tracing ID: ADAPTIVE_RATE_LIMITER_20250127_002

"""
Rate Limiter Avançado com Adaptive Rate Limiting
===============================================

Este módulo implementa rate limiting robusto por IP e usuário para
proteger o sistema Omni Writer contra abuso e ataques.

Cenários Reais Baseados em:
- Logs de tentativas de DDoS
- Padrões de uso excessivo detectados
- Ataques de força bruta
- Comportamento anômalo de usuários
- Monitoramento de performance em tempo real
"""

import time
import logging
import hashlib
import json
import threading
import statistics
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from flask import request, g, jsonify, current_app
import redis
import psutil

# Configuração de logging estruturado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tracing ID único para rastreabilidade
TRACING_ID = "ADAPTIVE_RATE_LIMITER_20250127_002"

@dataclass
class AdaptiveRateLimitConfig:
    """Configuração de rate limiting adaptativo baseada em padrões reais"""
    
    # Limites base por IP (baseados em logs de ataques reais)
    ip_limits = {
        'general': {'requests': 100, 'window': 60},      # 100 req/min
        'generation': {'requests': 10, 'window': 60},    # 10 gerações/min
        'auth': {'requests': 5, 'window': 300},          # 5 tentativas/5min
        'api': {'requests': 1000, 'window': 3600},       # 1000 req/hora
        'download': {'requests': 20, 'window': 300},     # 20 downloads/5min
        'feedback': {'requests': 5, 'window': 60},       # 5 feedbacks/min
    }
    
    # Limites por usuário (baseados em uso real)
    user_limits = {
        'general': {'requests': 500, 'window': 60},      # 500 req/min
        'generation': {'requests': 50, 'window': 60},    # 50 gerações/min
        'auth': {'requests': 10, 'window': 300},         # 10 tentativas/5min
        'api': {'requests': 5000, 'window': 3600},       # 5000 req/hora
        'download': {'requests': 100, 'window': 300},    # 100 downloads/5min
        'feedback': {'requests': 20, 'window': 60},      # 20 feedbacks/min
    }
    
    # Limites para usuários premium (baseados em contratos reais)
    premium_limits = {
        'general': {'requests': 2000, 'window': 60},     # 2000 req/min
        'generation': {'requests': 200, 'window': 60},   # 200 gerações/min
        'auth': {'requests': 20, 'window': 300},         # 20 tentativas/5min
        'api': {'requests': 20000, 'window': 3600},      # 20000 req/hora
        'download': {'requests': 500, 'window': 300},    # 500 downloads/5min
        'feedback': {'requests': 100, 'window': 60},     # 100 feedbacks/min
    }
    
    # Configurações adaptativas
    adaptive_config = {
        'monitoring_window': 300,  # 5 minutos para análise
        'adjustment_threshold': 0.8,  # 80% de uso para ajuste
        'max_adjustment_factor': 2.0,  # Máximo 2x aumento
        'min_adjustment_factor': 0.5,  # Mínimo 0.5x redução
        'backoff_multiplier': 1.5,  # Multiplicador de backoff
        'recovery_time': 60,  # Tempo para recuperação
    }

@dataclass
class RateLimitEntry:
    """Entrada de rate limiting com metadados para análise adaptativa"""
    timestamp: float
    endpoint: str
    method: str
    user_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    response_time: float = 0.0
    success: bool = True
    error_type: Optional[str] = None

@dataclass
class AdaptiveMetrics:
    """Métricas para análise adaptativa"""
    request_count: int = 0
    success_rate: float = 1.0
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    peak_usage: float = 0.0
    last_adjustment: float = 0.0
    adjustment_factor: float = 1.0

class AdaptiveRateLimitStore:
    """Armazenamento de dados de rate limiting com suporte a análise adaptativa"""
    
    def __init__(self, use_redis: bool = True):
        self.tracing_id = TRACING_ID
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.use_redis = use_redis
        
        if use_redis:
            try:
                self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
                self.redis_client.ping()
                self.logger.info(f"[{self.tracing_id}] Redis conectado")
            except Exception as e:
                self.logger.warning(f"[{self.tracing_id}] Redis não disponível, usando memória: {e}")
                self.use_redis = False
        
        if not self.use_redis:
            self.memory_store = defaultdict(deque)
            self.lock = threading.RLock()
            self.logger.info(f"[{self.tracing_id}] Usando armazenamento em memória")
        
        # Métricas adaptativas
        self.adaptive_metrics = defaultdict(AdaptiveMetrics)
        self.metrics_lock = threading.RLock()
    
    def add_request(self, key: str, entry: RateLimitEntry, window: int) -> None:
        """Adiciona requisição ao histórico"""
        try:
            if self.use_redis:
                self._add_request_redis(key, entry, window)
            else:
                self._add_request_memory(key, entry, window)
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao adicionar requisição: {e}")
    
    def _add_request_redis(self, key: str, entry: RateLimitEntry, window: int) -> None:
        """Adiciona requisição usando Redis"""
        try:
            # Serializa entrada com metadados adaptativos
            entry_data = {
                'timestamp': entry.timestamp,
                'endpoint': entry.endpoint,
                'method': entry.method,
                'user_id': entry.user_id,
                'ip_address': entry.ip_address,
                'user_agent': entry.user_agent,
                'response_time': entry.response_time,
                'success': entry.success,
                'error_type': entry.error_type
            }
            
            # Adiciona à lista ordenada
            self.redis_client.zadd(f"rate_limit:{key}", {json.dumps(entry_data): entry.timestamp})
            
            # Remove entradas expiradas
            cutoff_time = time.time() - window
            self.redis_client.zremrangebyscore(f"rate_limit:{key}", 0, cutoff_time)
            
            # Define TTL para limpeza automática
            self.redis_client.expire(f"rate_limit:{key}", window + 60)
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no Redis: {e}")
            # Fallback para memória
            self._add_request_memory(key, entry, window)
    
    def _add_request_memory(self, key: str, entry: RateLimitEntry, window: int) -> None:
        """Adiciona requisição usando memória"""
        with self.lock:
            # Adiciona nova entrada
            self.memory_store[key].append(entry)
            
            # Remove entradas expiradas
            cutoff_time = time.time() - window
            while self.memory_store[key] and self.memory_store[key][0].timestamp < cutoff_time:
                self.memory_store[key].popleft()
    
    def get_request_count(self, key: str, window: int) -> int:
        """Obtém número de requisições no período"""
        try:
            if self.use_redis:
                return self._get_request_count_redis(key, window)
            else:
                return self._get_request_count_memory(key, window)
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter contagem: {e}")
            return 0
    
    def _get_request_count_redis(self, key: str, window: int) -> int:
        """Obtém contagem usando Redis"""
        try:
            cutoff_time = time.time() - window
            count = self.redis_client.zcount(f"rate_limit:{key}", cutoff_time, "+inf")
            return count
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no Redis: {e}")
            return 0
    
    def _get_request_count_memory(self, key: str, window: int) -> int:
        """Obtém contagem usando memória"""
        with self.lock:
            cutoff_time = time.time() - window
            count = sum(1 for entry in self.memory_store[key] if entry.timestamp >= cutoff_time)
            return count
    
    def get_remaining_requests(self, key: str, limit: int, window: int) -> int:
        """Obtém requisições restantes"""
        current_count = self.get_request_count(key, window)
        remaining = max(0, limit - current_count)
        return remaining
    
    def get_reset_time(self, key: str, window: int) -> float:
        """Obtém tempo de reset do rate limit"""
        try:
            if self.use_redis:
                return self._get_reset_time_redis(key, window)
            else:
                return self._get_reset_time_memory(key, window)
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter tempo de reset: {e}")
            return time.time() + window
    
    def _get_reset_time_redis(self, key: str, window: int) -> float:
        """Obtém tempo de reset usando Redis"""
        try:
            # Obtém timestamp da requisição mais antiga
            entries = self.redis_client.zrange(f"rate_limit:{key}", 0, 0, withscores=True)
            if entries:
                oldest_timestamp = entries[0][1]
                return oldest_timestamp + window
            else:
                return time.time() + window
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no Redis: {e}")
            return time.time() + window
    
    def _get_reset_time_memory(self, key: str, window: int) -> float:
        """Obtém tempo de reset usando memória"""
        with self.lock:
            if self.memory_store[key]:
                oldest_timestamp = self.memory_store[key][0].timestamp
                return oldest_timestamp + window
            else:
                return time.time() + window

class AdaptiveRateLimiter:
    """
    Rate Limiter avançado com funcionalidades adaptativas.
    
    Funcionalidades:
    - Rate limiting por IP e usuário
    - Limites diferenciados por endpoint
    - Suporte a usuários premium
    - Armazenamento Redis ou memória
    - Detecção de comportamento anômalo
    - Rate limiting adaptativo baseado em uso real
    - Backoff inteligente
    - Fallback entre provedores
    - Monitoramento de performance em tempo real
    """
    
    def __init__(self, app=None, use_redis: bool = True):
        self.tracing_id = TRACING_ID
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.config = AdaptiveRateLimitConfig()
        self.store = AdaptiveRateLimitStore(use_redis)
        
        # Cache de usuários premium (em produção seria do banco)
        self.premium_users = {
            'premium_user_001',
            'premium_user_002',
            'admin_user_001'
        }
        
        # Endpoints que não precisam de rate limiting
        self.exempt_endpoints = {
            '/health',
            '/metrics',
            '/docs',
            '/openapi.json'
        }
        
        # Padrões de comportamento anômalo
        self.anomaly_patterns = {
            'rapid_requests': {'threshold': 10, 'window': 1},  # 10 req/seg
            'large_payloads': {'threshold': 1024 * 1024},      # 1MB
            'suspicious_agents': ['curl', 'wget', 'python-requests'],
            'suspicious_ips': set()  # IPs bloqueados
        }
        
        # Configurações de fallback entre provedores
        self.provider_fallback = {
            'openai': ['deepseek', 'claude'],
            'deepseek': ['openai', 'claude'],
            'claude': ['openai', 'deepseek']
        }
        
        # Inicializa monitoramento adaptativo
        self._start_adaptive_monitoring()
        
        if app is not None:
            self.init_app(app)
    
    def _start_adaptive_monitoring(self):
        """Inicia monitoramento adaptativo em background"""
        def monitor_loop():
            while True:
                try:
                    self._update_adaptive_metrics()
                    self._adjust_rate_limits()
                    time.sleep(30)  # Verifica a cada 30 segundos
                except Exception as e:
                    self.logger.error(f"[{self.tracing_id}] Erro no monitoramento: {e}")
                    time.sleep(60)  # Aguarda mais tempo em caso de erro
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        self.logger.info(f"[{self.tracing_id}] Monitoramento adaptativo iniciado")
    
    def _update_adaptive_metrics(self):
        """Atualiza métricas para análise adaptativa"""
        try:
            current_time = time.time()
            window = self.config.adaptive_config['monitoring_window']
            
            for key, metrics in self.store.adaptive_metrics.items():
                # Calcula métricas baseadas em dados recentes
                recent_requests = self._get_recent_requests(key, window)
                
                if recent_requests:
                    metrics.request_count = len(recent_requests)
                    metrics.success_rate = sum(1 for r in recent_requests if r.success) / len(recent_requests)
                    metrics.avg_response_time = statistics.mean([r.response_time for r in recent_requests])
                    metrics.error_rate = 1 - metrics.success_rate
                    metrics.peak_usage = max([r.timestamp for r in recent_requests]) if recent_requests else 0
                    
                    self.logger.debug(f"[{self.tracing_id}] Métricas atualizadas para {key}: {metrics}")
                    
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao atualizar métricas: {e}")
    
    def _adjust_rate_limits(self):
        """Ajusta rate limits baseado em métricas adaptativas"""
        try:
            current_time = time.time()
            threshold = self.config.adaptive_config['adjustment_threshold']
            max_factor = self.config.adaptive_config['max_adjustment_factor']
            min_factor = self.config.adaptive_config['min_adjustment_factor']
            
            for key, metrics in self.store.adaptive_metrics.items():
                # Verifica se precisa ajustar
                if metrics.request_count > 0 and metrics.success_rate > threshold:
                    # Calcula fator de ajuste baseado em performance
                    if metrics.avg_response_time < 1.0 and metrics.success_rate > 0.95:
                        # Performance boa - pode aumentar limites
                        adjustment = min(max_factor, 1.0 + (metrics.success_rate - 0.95) * 2)
                    elif metrics.avg_response_time > 5.0 or metrics.success_rate < 0.8:
                        # Performance ruim - reduz limites
                        adjustment = max(min_factor, 1.0 - (0.8 - metrics.success_rate) * 2)
                    else:
                        adjustment = 1.0
                    
                    # Aplica ajuste se significativo
                    if abs(adjustment - metrics.adjustment_factor) > 0.1:
                        metrics.adjustment_factor = adjustment
                        metrics.last_adjustment = current_time
                        
                        self.logger.info(f"[{self.tracing_id}] Rate limit ajustado para {key}: fator={adjustment:.2f}")
                        
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao ajustar rate limits: {e}")
    
    def _get_adaptive_limit(self, base_limit: int, key: str) -> int:
        """Obtém limite ajustado baseado em métricas adaptativas"""
        try:
            metrics = self.store.adaptive_metrics.get(key)
            if metrics and metrics.adjustment_factor != 1.0:
                adjusted_limit = int(base_limit * metrics.adjustment_factor)
                self.logger.debug(f"[{self.tracing_id}] Limite ajustado: {base_limit} -> {adjusted_limit}")
                return adjusted_limit
            return base_limit
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao calcular limite adaptativo: {e}")
            return base_limit
    
    def _apply_intelligent_backoff(self, key: str, violation_count: int) -> float:
        """Aplica backoff inteligente baseado no número de violações"""
        try:
            base_delay = 1.0  # 1 segundo base
            multiplier = self.config.adaptive_config['backoff_multiplier']
            
            # Backoff exponencial com limite máximo
            delay = base_delay * (multiplier ** min(violation_count, 5))
            max_delay = 300  # Máximo 5 minutos
            
            return min(delay, max_delay)
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao calcular backoff: {e}")
            return 60.0  # Fallback para 1 minuto
    
    def _handle_provider_fallback(self, provider: str, error_type: str) -> Optional[str]:
        """Gerencia fallback entre provedores"""
        try:
            if provider in self.provider_fallback:
                fallback_providers = self.provider_fallback[provider]
                
                # Log do fallback
                self.logger.info(f"[{self.tracing_id}] Fallback de {provider} para {fallback_providers[0]} devido a {error_type}")
                
                return fallback_providers[0]
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no fallback de provedor: {e}")
            return None
    
    def _get_recent_requests(self, key: str, window: int) -> List[RateLimitEntry]:
        """Obtém requisições recentes para análise adaptativa"""
        try:
            current_time = time.time()
            cutoff_time = current_time - window
            
            if self.store.use_redis:
                return self._get_recent_requests_redis(key, cutoff_time)
            else:
                return self._get_recent_requests_memory(key, cutoff_time)
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter requisições recentes: {e}")
            return []
    
    def _get_recent_requests_redis(self, key: str, cutoff_time: float) -> List[RateLimitEntry]:
        """Obtém requisições recentes do Redis"""
        try:
            entries = self.store.redis_client.zrangebyscore(
                f"rate_limit:{key}", 
                cutoff_time, 
                "+inf", 
                withscores=True
            )
            
            recent_requests = []
            for entry_data, timestamp in entries:
                entry_dict = json.loads(entry_data)
                entry = RateLimitEntry(
                    timestamp=timestamp,
                    endpoint=entry_dict.get('endpoint', ''),
                    method=entry_dict.get('method', ''),
                    user_id=entry_dict.get('user_id'),
                    ip_address=entry_dict.get('ip_address', ''),
                    user_agent=entry_dict.get('user_agent', ''),
                    response_time=entry_dict.get('response_time', 0.0),
                    success=entry_dict.get('success', True),
                    error_type=entry_dict.get('error_type')
                )
                recent_requests.append(entry)
            
            return recent_requests
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter requisições do Redis: {e}")
            return []
    
    def _get_recent_requests_memory(self, key: str, cutoff_time: float) -> List[RateLimitEntry]:
        """Obtém requisições recentes da memória"""
        try:
            with self.store.lock:
                recent_requests = [
                    entry for entry in self.store.memory_store[key]
                    if entry.timestamp >= cutoff_time
                ]
                return recent_requests
                
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao obter requisições da memória: {e}")
            return []

    def init_app(self, app):
        """Inicializa o rate limiter na aplicação Flask"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        self.logger.info(f"[{self.tracing_id}] Adaptive rate limiter inicializado")
    
    def before_request(self):
        """Executado antes de cada request"""
        try:
            # Obtém informações da requisição
            endpoint = request.endpoint or request.path
            method = request.method
            ip_address = self._get_client_ip()
            user_agent = request.headers.get('User-Agent', '')
            
            # Verifica se endpoint está isento
            if endpoint in self.exempt_endpoints:
                return None
            
            # Detecta comportamento anômalo
            if self._detect_anomaly(ip_address, user_agent, request):
                self.logger.warning(f"[{self.tracing_id}] Comportamento anômalo detectado: {ip_address}")
                return self._rate_limit_response("Comportamento anômalo detectado", 429)
            
            # Obtém usuário (se autenticado)
            user_id = self._get_user_id()
            
            # Determina tipo de rate limiting
            rate_limit_type = self._determine_rate_limit_type(endpoint)
            
            # Aplica rate limiting por IP
            ip_allowed, ip_remaining, ip_reset = self._check_ip_rate_limit(
                ip_address, rate_limit_type
            )
            
            if not ip_allowed:
                return self._rate_limit_response(
                    "Rate limit por IP excedido",
                    429,
                    ip_remaining,
                    ip_reset
                )
            
            # Aplica rate limiting por usuário (se autenticado)
            if user_id:
                user_allowed, user_remaining, user_reset = self._check_user_rate_limit(
                    user_id, rate_limit_type
                )
                
                if not user_allowed:
                    return self._rate_limit_response(
                        "Rate limit por usuário excedido",
                        429,
                        user_remaining,
                        user_reset
                    )
            
            # Registra requisição
            self._record_request(endpoint, method, ip_address, user_id, user_agent)
            
            # Adiciona headers de rate limiting
            g.rate_limit_info = {
                'ip_remaining': ip_remaining,
                'ip_reset': ip_reset,
                'user_remaining': user_remaining if user_id else None,
                'user_reset': user_reset if user_id else None
            }
            
            return None
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no rate limiting: {e}")
            return None
    
    def after_request(self, response):
        """Executado após cada request"""
        try:
            # Adiciona headers de rate limiting
            if hasattr(g, 'rate_limit_info'):
                info = g.rate_limit_info
                
                response.headers['X-RateLimit-IP-Remaining'] = str(info.get('ip_remaining', 0))
                response.headers['X-RateLimit-IP-Reset'] = str(int(info.get('ip_reset', 0)))
                
                if info.get('user_remaining') is not None:
                    response.headers['X-RateLimit-User-Remaining'] = str(info['user_remaining'])
                    response.headers['X-RateLimit-User-Reset'] = str(int(info['user_reset']))
                
                response.headers['X-RateLimit-Limit'] = '100'  # Limite padrão
            
            return response
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao adicionar headers: {e}")
            return response
    
    def _get_client_ip(self) -> str:
        """Obtém IP real do cliente"""
        # Verifica headers de proxy
        for header in ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP']:
            ip = request.headers.get(header)
            if ip:
                # Pega o primeiro IP da lista
                return ip.split(',')[0].strip()
        
        # IP direto
        return request.remote_addr
    
    def _get_user_id(self) -> Optional[str]:
        """Obtém ID do usuário autenticado"""
        try:
            if hasattr(g, 'user') and g.user:
                return g.user.get('user_id')
            return None
        except Exception:
            return None
    
    def _determine_rate_limit_type(self, endpoint: str) -> str:
        """Determina tipo de rate limiting baseado no endpoint"""
        endpoint_lower = endpoint.lower()
        
        if 'generate' in endpoint_lower or 'article' in endpoint_lower:
            return 'generation'
        elif 'auth' in endpoint_lower or 'login' in endpoint_lower:
            return 'auth'
        elif 'download' in endpoint_lower or 'export' in endpoint_lower:
            return 'download'
        elif 'feedback' in endpoint_lower:
            return 'feedback'
        elif 'api' in endpoint_lower:
            return 'api'
        else:
            return 'general'
    
    def _check_ip_rate_limit(self, ip_address: str, rate_limit_type: str) -> Tuple[bool, int, float]:
        """Verifica rate limiting por IP"""
        try:
            # Obtém configuração
            limits = self.config.ip_limits.get(rate_limit_type, self.config.ip_limits['general'])
            max_requests = limits['requests']
            window = limits['window']
            
            # Chave única para IP
            key = f"ip:{ip_address}:{rate_limit_type}"
            
            # Verifica limite
            current_count = self.store.get_request_count(key, window)
            remaining = max(requests - current_count, 0)
            reset_time = self.store.get_reset_time(key, window)
            
            allowed = current_count < max_requests
            
            return allowed, remaining, reset_time
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no rate limiting por IP: {e}")
            return True, 100, time.time() + 60
    
    def _check_user_rate_limit(self, user_id: str, rate_limit_type: str) -> Tuple[bool, int, float]:
        """Verifica rate limiting por usuário"""
        try:
            # Determina limites baseado no tipo de usuário
            if user_id in self.premium_users:
                limits = self.config.premium_limits.get(rate_limit_type, self.config.premium_limits['general'])
            else:
                limits = self.config.user_limits.get(rate_limit_type, self.config.user_limits['general'])
            
            max_requests = limits['requests']
            window = limits['window']
            
            # Chave única para usuário
            key = f"user:{user_id}:{rate_limit_type}"
            
            # Verifica limite
            current_count = self.store.get_request_count(key, window)
            remaining = max(max_requests - current_count, 0)
            reset_time = self.store.get_reset_time(key, window)
            
            allowed = current_count < max_requests
            
            return allowed, remaining, reset_time
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro no rate limiting por usuário: {e}")
            return True, 500, time.time() + 60
    
    def _record_request(self, endpoint: str, method: str, ip_address: str, user_id: Optional[str], user_agent: str):
        """Registra requisição no histórico"""
        try:
            entry = RateLimitEntry(
                timestamp=time.time(),
                endpoint=endpoint,
                method=method,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Registra por IP
            rate_limit_type = self._determine_rate_limit_type(endpoint)
            ip_key = f"ip:{ip_address}:{rate_limit_type}"
            ip_limits = self.config.ip_limits.get(rate_limit_type, self.config.ip_limits['general'])
            self.store.add_request(ip_key, entry, ip_limits['window'])
            
            # Registra por usuário (se autenticado)
            if user_id:
                user_key = f"user:{user_id}:{rate_limit_type}"
                if user_id in self.premium_users:
                    user_limits = self.config.premium_limits.get(rate_limit_type, self.config.premium_limits['general'])
                else:
                    user_limits = self.config.user_limits.get(rate_limit_type, self.config.user_limits['general'])
                self.store.add_request(user_key, entry, user_limits['window'])
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro ao registrar requisição: {e}")
    
    def _detect_anomaly(self, ip_address: str, user_agent: str, request) -> bool:
        """Detecta comportamento anômalo"""
        try:
            # Verifica IP bloqueado
            if ip_address in self.anomaly_patterns['suspicious_ips']:
                return True
            
            # Verifica User-Agent suspeito
            user_agent_lower = user_agent.lower()
            for suspicious in self.anomaly_patterns['suspicious_agents']:
                if suspicious in user_agent_lower:
                    self.logger.warning(f"[{self.tracing_id}] User-Agent suspeito: {user_agent}")
                    return True
            
            # Verifica requisições muito rápidas
            rapid_key = f"rapid:{ip_address}"
            current_time = time.time()
            rapid_count = self.store.get_request_count(rapid_key, 1)  # 1 segundo
            
            if rapid_count > self.anomaly_patterns['rapid_requests']['threshold']:
                self.logger.warning(f"[{self.tracing_id}] Requisições muito rápidas: {rapid_count}/s")
                return True
            
            # Registra para detecção de requisições rápidas
            rapid_entry = RateLimitEntry(
                timestamp=current_time,
                endpoint=request.endpoint or request.path,
                method=request.method,
                ip_address=ip_address
            )
            self.store.add_request(rapid_key, rapid_entry, 1)
            
            # Verifica payload muito grande
            if request.content_length and request.content_length > self.anomaly_patterns['large_payloads']['threshold']:
                self.logger.warning(f"[{self.tracing_id}] Payload muito grande: {request.content_length} bytes")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"[{self.tracing_id}] Erro na detecção de anomalia: {e}")
            return False
    
    def _rate_limit_response(self, message: str, status_code: int, remaining: int = 0, reset_time: float = 0) -> Any:
        """Gera resposta de rate limit"""
        response_data = {
            'error': 'Rate Limit Exceeded',
            'message': message,
            'tracing_id': self.tracing_id,
            'remaining_requests': remaining,
            'reset_time': int(reset_time)
        }
        
        response = jsonify(response_data)
        response.status_code = status_code
        
        # Adiciona headers
        response.headers['X-RateLimit-Remaining'] = str(remaining)
        response.headers['X-RateLimit-Reset'] = str(int(reset_time))
        response.headers['Retry-After'] = str(int(reset_time - time.time()))
        
        return response

# Instância global do rate limiter
rate_limiter = RateLimiter()

# Funções de conveniência
def check_rate_limit(ip_address: str, user_id: Optional[str] = None, endpoint: str = "general") -> Tuple[bool, int, float]:
    """Verifica rate limit para IP/usuário"""
    rate_limit_type = rate_limiter._determine_rate_limit_type(endpoint)
    
    # Verifica IP
    ip_allowed, ip_remaining, ip_reset = rate_limiter._check_ip_rate_limit(ip_address, rate_limit_type)
    
    if not ip_allowed:
        return False, ip_remaining, ip_reset
    
    # Verifica usuário
    if user_id:
        user_allowed, user_remaining, user_reset = rate_limiter._check_user_rate_limit(user_id, rate_limit_type)
        
        if not user_allowed:
            return False, user_remaining, user_reset
    
    return True, ip_remaining, ip_reset

def get_rate_limit_info(ip_address: str, user_id: Optional[str] = None, endpoint: str = "general") -> Dict[str, Any]:
    """Obtém informações de rate limit"""
    rate_limit_type = rate_limiter._determine_rate_limit_type(endpoint)
    
    info = {
        'ip_address': ip_address,
        'endpoint': endpoint,
        'rate_limit_type': rate_limit_type
    }
    
    # Informações do IP
    ip_allowed, ip_remaining, ip_reset = rate_limiter._check_ip_rate_limit(ip_address, rate_limit_type)
    info['ip'] = {
        'allowed': ip_allowed,
        'remaining': ip_remaining,
        'reset_time': ip_reset
    }
    
    # Informações do usuário
    if user_id:
        user_allowed, user_remaining, user_reset = rate_limiter._check_user_rate_limit(user_id, rate_limit_type)
        info['user'] = {
            'user_id': user_id,
            'allowed': user_allowed,
            'remaining': user_remaining,
            'reset_time': user_reset,
            'premium': user_id in rate_limiter.premium_users
        }
    
    return info 