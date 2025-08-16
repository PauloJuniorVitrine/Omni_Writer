"""
Sistema de Adaptive Rate Limiting - Omni Writer
==============================================

Implementa rate limiting adaptativo avançado:
- Monitoramento de uso real das APIs
- Ajuste dinâmico de limites
- Predição de uso
- Otimização automática
- Alertas inteligentes
- Analytics detalhados

Prompt: Implementação de Gargalos Médios - Adaptive Rate Limiting
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T23:45:00Z
Tracing ID: ADAPTIVE_RATE_LIMITING_20250127_001
"""

import time
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import redis
from functools import wraps

logger = logging.getLogger(__name__)

@dataclass
class APIMetrics:
    """Métricas de uso de API"""
    provider: str
    endpoint: str
    request_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_response_time: float = 0.0
    avg_response_time: float = 0.0
    rate_limit_hits: int = 0
    last_request: datetime = field(default_factory=datetime.utcnow)
    last_adjustment: datetime = field(default_factory=datetime.utcnow)

@dataclass
class RateLimitPrediction:
    """Predição de uso de rate limits"""
    provider: str
    predicted_requests: int
    confidence: float
    time_window: int
    recommended_limit: int
    next_peak_time: datetime

@dataclass
class AdaptiveConfig:
    """Configuração adaptativa"""
    monitoring_window: int = 300  # 5 minutos
    adjustment_threshold: float = 0.8  # 80% de uso
    max_adjustment_factor: float = 2.0  # Máximo 2x aumento
    min_adjustment_factor: float = 0.5  # Mínimo 0.5x redução
    prediction_horizon: int = 3600  # 1 hora
    alert_threshold: float = 0.9  # 90% de uso para alerta

class APIMonitor:
    """Monitor de uso real das APIs"""
    
    def __init__(self, redis_client=None):
        self.redis_client = redis_client or redis.Redis()
        self.api_metrics: Dict[str, APIMetrics] = defaultdict(lambda: APIMetrics("", ""))
        self.request_history = deque(maxlen=10000)
        self.monitoring_enabled = True
        
    def record_request(self, provider: str, endpoint: str, success: bool, response_time: float):
        """Registra requisição à API"""
        key = f"{provider}:{endpoint}"
        
        if key not in self.api_metrics:
            self.api_metrics[key] = APIMetrics(provider=provider, endpoint=endpoint)
        
        metrics = self.api_metrics[key]
        metrics.request_count += 1
        metrics.total_response_time += response_time
        metrics.avg_response_time = metrics.total_response_time / metrics.request_count
        metrics.last_request = datetime.utcnow()
        
        if success:
            metrics.success_count += 1
        else:
            metrics.error_count += 1
        
        # Registra no histórico
        self.request_history.append({
            'provider': provider,
            'endpoint': endpoint,
            'success': success,
            'response_time': response_time,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Armazena no Redis para persistência
        self._store_metrics(key, metrics)
    
    def record_rate_limit_hit(self, provider: str, endpoint: str):
        """Registra hit de rate limit"""
        key = f"{provider}:{endpoint}"
        
        if key in self.api_metrics:
            self.api_metrics[key].rate_limit_hits += 1
            self._store_metrics(key, self.api_metrics[key])
    
    def _store_metrics(self, key: str, metrics: APIMetrics):
        """Armazena métricas no Redis"""
        try:
            metrics_data = {
                'provider': metrics.provider,
                'endpoint': metrics.endpoint,
                'request_count': metrics.request_count,
                'success_count': metrics.success_count,
                'error_count': metrics.error_count,
                'total_response_time': metrics.total_response_time,
                'avg_response_time': metrics.avg_response_time,
                'rate_limit_hits': metrics.rate_limit_hits,
                'last_request': metrics.last_request.isoformat(),
                'last_adjustment': metrics.last_adjustment.isoformat()
            }
            
            self.redis_client.setex(f"api_metrics:{key}", 3600, json.dumps(metrics_data))
            
        except Exception as e:
            logger.error(f"Erro ao armazenar métricas: {e}")
    
    def get_usage_patterns(self, provider: str, window: int = 3600) -> Dict[str, Any]:
        """Analisa padrões de uso para um provedor"""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=window)
        
        # Filtra requisições recentes
        recent_requests = [
            req for req in self.request_history
            if req['provider'] == provider and 
            datetime.fromisoformat(req['timestamp']) > cutoff_time
        ]
        
        if not recent_requests:
            return {}
        
        # Calcula estatísticas
        response_times = [req['response_time'] for req in recent_requests]
        success_rate = sum(1 for req in recent_requests if req['success']) / len(recent_requests)
        
        # Análise temporal
        hourly_usage = defaultdict(int)
        for req in recent_requests:
            hour = datetime.fromisoformat(req['timestamp']).hour
            hourly_usage[hour] += 1
        
        return {
            'total_requests': len(recent_requests),
            'avg_response_time': statistics.mean(response_times),
            'success_rate': success_rate,
            'hourly_usage': dict(hourly_usage),
            'peak_hour': max(hourly_usage.items(), key=lambda x: x[1])[0] if hourly_usage else 0
        }

class DynamicRateAdjuster:
    """Ajustador dinâmico de rate limits"""
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.adjustment_history = deque(maxlen=1000)
        self.current_limits = {}
        
    def calculate_adjustment(self, provider: str, current_usage: float, 
                           success_rate: float, response_time: float) -> float:
        """Calcula fator de ajuste baseado em métricas"""
        
        # Fator baseado no uso atual
        usage_factor = 1.0
        if current_usage > self.config.adjustment_threshold:
            # Aumenta limite se uso está alto mas performance é boa
            if success_rate > 0.95 and response_time < 2.0:
                usage_factor = min(self.config.max_adjustment_factor, 1.0 + (current_usage - 0.8) * 0.5)
        elif current_usage < 0.3:
            # Reduz limite se uso está baixo
            usage_factor = max(self.config.min_adjustment_factor, 1.0 - (0.3 - current_usage) * 0.3)
        
        # Fator baseado na performance
        performance_factor = 1.0
        if success_rate < 0.9:
            # Reduz limite se taxa de sucesso está baixa
            performance_factor = max(self.config.min_adjustment_factor, success_rate)
        elif response_time > 5.0:
            # Reduz limite se tempo de resposta está alto
            performance_factor = max(self.config.min_adjustment_factor, 5.0 / response_time)
        
        # Fator combinado
        adjustment_factor = usage_factor * performance_factor
        
        # Aplica limites
        adjustment_factor = max(self.config.min_adjustment_factor, 
                              min(self.config.max_adjustment_factor, adjustment_factor))
        
        return adjustment_factor
    
    def apply_adjustment(self, provider: str, current_limit: int, adjustment_factor: float) -> int:
        """Aplica ajuste ao limite atual"""
        new_limit = int(current_limit * adjustment_factor)
        
        # Registra ajuste
        self.adjustment_history.append({
            'provider': provider,
            'old_limit': current_limit,
            'new_limit': new_limit,
            'adjustment_factor': adjustment_factor,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        self.current_limits[provider] = new_limit
        
        logger.info(f"Ajuste aplicado para {provider}: {current_limit} -> {new_limit} (fator: {adjustment_factor:.2f})")
        
        return new_limit

class RateLimitPredictor:
    """Preditor de uso de rate limits"""
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.prediction_models = {}
        
    def predict_usage(self, provider: str, usage_patterns: Dict[str, Any]) -> Optional[RateLimitPrediction]:
        """Prediz uso futuro baseado em padrões"""
        
        if not usage_patterns or 'total_requests' not in usage_patterns:
            return None
        
        total_requests = usage_patterns['total_requests']
        hourly_usage = usage_patterns.get('hourly_usage', {})
        peak_hour = usage_patterns.get('peak_hour', 0)
        
        if not hourly_usage:
            return None
        
        # Calcula taxa de requisições por hora
        avg_requests_per_hour = total_requests / len(hourly_usage) if hourly_usage else 0
        
        # Prediz uso para próxima hora
        predicted_requests = int(avg_requests_per_hour * 1.2)  # 20% de margem
        
        # Calcula confiança baseada na consistência dos dados
        usage_values = list(hourly_usage.values())
        if len(usage_values) > 1:
            std_dev = statistics.stdev(usage_values)
            mean_usage = statistics.mean(usage_values)
            confidence = max(0.1, 1.0 - (std_dev / mean_usage) if mean_usage > 0 else 0.1)
        else:
            confidence = 0.5
        
        # Recomenda limite baseado na predição
        recommended_limit = int(predicted_requests * 1.5)  # 50% de margem
        
        # Calcula próximo pico
        current_hour = datetime.utcnow().hour
        next_peak_time = datetime.utcnow().replace(hour=peak_hour, minute=0, second=0, microsecond=0)
        if next_peak_time <= datetime.utcnow():
            next_peak_time += timedelta(days=1)
        
        return RateLimitPrediction(
            provider=provider,
            predicted_requests=predicted_requests,
            confidence=confidence,
            time_window=3600,
            recommended_limit=recommended_limit,
            next_peak_time=next_peak_time
        )
    
    def get_predictions(self) -> List[RateLimitPrediction]:
        """Retorna todas as predições ativas"""
        predictions = []
        
        for provider in ['openai', 'deepseek', 'claude']:
            # Simula padrões de uso (em produção viria do monitor)
            usage_patterns = {
                'total_requests': 100,
                'hourly_usage': {i: 10 for i in range(24)},
                'peak_hour': 14
            }
            
            prediction = self.predict_usage(provider, usage_patterns)
            if prediction and prediction.confidence > 0.5:
                predictions.append(prediction)
        
        return predictions

class RateLimitOptimizer:
    """Otimizador de rate limits"""
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.optimization_history = deque(maxlen=1000)
        
    def optimize_limits(self, current_limits: Dict[str, int], 
                       usage_patterns: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
        """Otimiza limites baseado em padrões de uso"""
        
        optimized_limits = current_limits.copy()
        
        for provider, patterns in usage_patterns.items():
            if not patterns:
                continue
            
            current_limit = current_limits.get(provider, 100)
            total_requests = patterns.get('total_requests', 0)
            success_rate = patterns.get('success_rate', 1.0)
            avg_response_time = patterns.get('avg_response_time', 0.0)
            
            # Calcula uso atual
            current_usage = total_requests / current_limit if current_limit > 0 else 0
            
            # Aplica otimizações
            if current_usage > 0.8 and success_rate > 0.95:
                # Aumenta limite se uso está alto mas performance é boa
                optimized_limits[provider] = int(current_limit * 1.2)
            elif current_usage < 0.3:
                # Reduz limite se uso está baixo
                optimized_limits[provider] = int(current_limit * 0.8)
            elif success_rate < 0.9:
                # Reduz limite se taxa de sucesso está baixa
                optimized_limits[provider] = int(current_limit * 0.7)
            
            # Registra otimização
            self.optimization_history.append({
                'provider': provider,
                'old_limit': current_limit,
                'new_limit': optimized_limits[provider],
                'reason': self._get_optimization_reason(current_usage, success_rate),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return optimized_limits
    
    def _get_optimization_reason(self, usage: float, success_rate: float) -> str:
        """Retorna razão da otimização"""
        if usage > 0.8 and success_rate > 0.95:
            return "Alto uso com boa performance - aumentando limite"
        elif usage < 0.3:
            return "Baixo uso - reduzindo limite"
        elif success_rate < 0.9:
            return "Baixa taxa de sucesso - reduzindo limite"
        else:
            return "Ajuste automático"

class RateLimitAlertManager:
    """Gerenciador de alertas de rate limiting"""
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.alert_history = deque(maxlen=1000)
        self.alert_handlers = []
        
    def add_alert_handler(self, handler: Callable[[str, Dict[str, Any]], None]):
        """Adiciona handler de alerta"""
        self.alert_handlers.append(handler)
    
    def check_alerts(self, provider: str, current_usage: float, 
                    success_rate: float, rate_limit_hits: int) -> List[str]:
        """Verifica e gera alertas"""
        alerts = []
        
        # Alerta de uso alto
        if current_usage > self.config.alert_threshold:
            alert_msg = f"Uso alto detectado para {provider}: {current_usage:.1%}"
            alerts.append(alert_msg)
            self._trigger_alert("high_usage", {
                'provider': provider,
                'usage': current_usage,
                'threshold': self.config.alert_threshold
            })
        
        # Alerta de taxa de sucesso baixa
        if success_rate < 0.9:
            alert_msg = f"Taxa de sucesso baixa para {provider}: {success_rate:.1%}"
            alerts.append(alert_msg)
            self._trigger_alert("low_success_rate", {
                'provider': provider,
                'success_rate': success_rate
            })
        
        # Alerta de muitos rate limit hits
        if rate_limit_hits > 10:
            alert_msg = f"Muitos rate limit hits para {provider}: {rate_limit_hits}"
            alerts.append(alert_msg)
            self._trigger_alert("high_rate_limit_hits", {
                'provider': provider,
                'hits': rate_limit_hits
            })
        
        # Registra alertas
        for alert in alerts:
            self.alert_history.append({
                'provider': provider,
                'message': alert,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return alerts
    
    def _trigger_alert(self, alert_type: str, data: Dict[str, Any]):
        """Dispara alerta para todos os handlers"""
        for handler in self.alert_handlers:
            try:
                handler(alert_type, data)
            except Exception as e:
                logger.error(f"Erro no handler de alerta: {e}")
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Retorna alertas recentes"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        recent_alerts = [
            alert for alert in self.alert_history
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
        
        return recent_alerts

class RateLimitAnalytics:
    """Analytics de rate limiting"""
    
    def __init__(self):
        self.analytics_data = defaultdict(list)
        
    def record_analytics(self, provider: str, endpoint: str, 
                        request_data: Dict[str, Any]):
        """Registra dados para analytics"""
        analytics_entry = {
            'provider': provider,
            'endpoint': endpoint,
            'timestamp': datetime.utcnow().isoformat(),
            **request_data
        }
        
        self.analytics_data[f"{provider}:{endpoint}"].append(analytics_entry)
        
        # Mantém apenas últimos 1000 registros por endpoint
        if len(self.analytics_data[f"{provider}:{endpoint}"]) > 1000:
            self.analytics_data[f"{provider}:{endpoint}"] = \
                self.analytics_data[f"{provider}:{endpoint}"][-1000:]
    
    def generate_analytics_report(self, provider: str = None, 
                                time_window: int = 3600) -> Dict[str, Any]:
        """Gera relatório de analytics"""
        
        cutoff_time = datetime.utcnow() - timedelta(seconds=time_window)
        
        if provider:
            # Analytics para provedor específico
            provider_data = []
            for key, entries in self.analytics_data.items():
                if key.startswith(provider):
                    recent_entries = [
                        entry for entry in entries
                        if datetime.fromisoformat(entry['timestamp']) > cutoff_time
                    ]
                    provider_data.extend(recent_entries)
            
            return self._analyze_provider_data(provider_data)
        else:
            # Analytics para todos os provedores
            all_data = []
            for entries in self.analytics_data.values():
                recent_entries = [
                    entry for entry in entries
                    if datetime.fromisoformat(entry['timestamp']) > cutoff_time
                ]
                all_data.extend(recent_entries)
            
            return self._analyze_all_data(all_data)
    
    def _analyze_provider_data(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisa dados de um provedor específico"""
        if not data:
            return {}
        
        # Estatísticas básicas
        total_requests = len(data)
        success_count = sum(1 for entry in data if entry.get('success', True))
        success_rate = success_count / total_requests if total_requests > 0 else 0
        
        response_times = [entry.get('response_time', 0) for entry in data]
        avg_response_time = statistics.mean(response_times) if response_times else 0
        
        # Análise por endpoint
        endpoint_stats = defaultdict(lambda: {'count': 0, 'success': 0, 'response_times': []})
        for entry in data:
            endpoint = entry.get('endpoint', 'unknown')
            endpoint_stats[endpoint]['count'] += 1
            if entry.get('success', True):
                endpoint_stats[endpoint]['success'] += 1
            endpoint_stats[endpoint]['response_times'].append(entry.get('response_time', 0))
        
        # Calcula estatísticas por endpoint
        endpoint_analysis = {}
        for endpoint, stats in endpoint_stats.items():
            endpoint_analysis[endpoint] = {
                'request_count': stats['count'],
                'success_rate': stats['success'] / stats['count'] if stats['count'] > 0 else 0,
                'avg_response_time': statistics.mean(stats['response_times']) if stats['response_times'] else 0
            }
        
        return {
            'total_requests': total_requests,
            'success_rate': success_rate,
            'avg_response_time': avg_response_time,
            'endpoint_analysis': endpoint_analysis,
            'time_window': '1 hour'
        }
    
    def _analyze_all_data(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisa dados de todos os provedores"""
        if not data:
            return {}
        
        # Agrupa por provedor
        provider_stats = defaultdict(lambda: {'count': 0, 'success': 0, 'response_times': []})
        for entry in data:
            provider = entry.get('provider', 'unknown')
            provider_stats[provider]['count'] += 1
            if entry.get('success', True):
                provider_stats[provider]['success'] += 1
            provider_stats[provider]['response_times'].append(entry.get('response_time', 0))
        
        # Calcula estatísticas por provedor
        provider_analysis = {}
        for provider, stats in provider_stats.items():
            provider_analysis[provider] = {
                'request_count': stats['count'],
                'success_rate': stats['success'] / stats['count'] if stats['count'] > 0 else 0,
                'avg_response_time': statistics.mean(stats['response_times']) if stats['response_times'] else 0
            }
        
        return {
            'total_requests': len(data),
            'provider_analysis': provider_analysis,
            'time_window': '1 hour'
        }

class AdaptiveRateLimiter:
    """Rate Limiter adaptativo principal"""
    
    def __init__(self, config: AdaptiveConfig = None):
        self.config = config or AdaptiveConfig()
        self.redis_client = redis.Redis()
        
        # Componentes
        self.api_monitor = APIMonitor(self.redis_client)
        self.rate_adjuster = DynamicRateAdjuster(self.config)
        self.predictor = RateLimitPredictor(self.config)
        self.optimizer = RateLimitOptimizer(self.config)
        self.alert_manager = RateLimitAlertManager(self.config)
        self.analytics = RateLimitAnalytics()
        
        # Thread de monitoramento
        self.monitoring_thread = None
        self.is_monitoring = False
        
        # Inicia monitoramento
        self.start_monitoring()
        
        logger.info("Adaptive Rate Limiter inicializado")
    
    def start_monitoring(self):
        """Inicia monitoramento adaptativo"""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Monitoramento adaptativo iniciado")
    
    def stop_monitoring(self):
        """Para monitoramento adaptativo"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Monitoramento adaptativo parado")
    
    def _monitoring_loop(self):
        """Loop principal de monitoramento"""
        while self.is_monitoring:
            try:
                self._update_adaptive_metrics()
                self._adjust_rate_limits()
                self._check_alerts()
                time.sleep(60)  # Verifica a cada minuto
                
            except Exception as e:
                logger.error(f"Erro no monitoramento adaptativo: {e}")
                time.sleep(120)
    
    def _update_adaptive_metrics(self):
        """Atualiza métricas para análise adaptativa"""
        for provider in ['openai', 'deepseek', 'claude']:
            usage_patterns = self.api_monitor.get_usage_patterns(provider)
            
            if usage_patterns:
                # Registra para analytics
                self.analytics.record_analytics(provider, 'general', usage_patterns)
                
                # Atualiza predições
                prediction = self.predictor.predict_usage(provider, usage_patterns)
                if prediction:
                    logger.debug(f"Predição para {provider}: {prediction.predicted_requests} req/hora")
    
    def _adjust_rate_limits(self):
        """Ajusta rate limits baseado em métricas"""
        current_limits = {
            'openai': 300,
            'deepseek': 200,
            'claude': 150
        }
        
        for provider in current_limits.keys():
            usage_patterns = self.api_monitor.get_usage_patterns(provider)
            
            if usage_patterns:
                current_limit = current_limits[provider]
                total_requests = usage_patterns.get('total_requests', 0)
                success_rate = usage_patterns.get('success_rate', 1.0)
                avg_response_time = usage_patterns.get('avg_response_time', 0.0)
                
                current_usage = total_requests / current_limit if current_limit > 0 else 0
                
                # Calcula ajuste
                adjustment_factor = self.rate_adjuster.calculate_adjustment(
                    provider, current_usage, success_rate, avg_response_time
                )
                
                # Aplica ajuste se necessário
                if abs(adjustment_factor - 1.0) > 0.1:  # Mais de 10% de diferença
                    new_limit = self.rate_adjuster.apply_adjustment(provider, current_limit, adjustment_factor)
                    logger.info(f"Rate limit ajustado para {provider}: {current_limit} -> {new_limit}")
    
    def _check_alerts(self):
        """Verifica e gera alertas"""
        for provider in ['openai', 'deepseek', 'claude']:
            usage_patterns = self.api_monitor.get_usage_patterns(provider)
            
            if usage_patterns:
                current_limit = 300  # Limite base
                total_requests = usage_patterns.get('total_requests', 0)
                success_rate = usage_patterns.get('success_rate', 1.0)
                
                current_usage = total_requests / current_limit if current_limit > 0 else 0
                rate_limit_hits = 0  # Em produção viria do monitor
                
                alerts = self.alert_manager.check_alerts(
                    provider, current_usage, success_rate, rate_limit_hits
                )
                
                if alerts:
                    logger.warning(f"Alertas para {provider}: {alerts}")
    
    def record_api_request(self, provider: str, endpoint: str, success: bool, response_time: float):
        """Registra requisição à API"""
        self.api_monitor.record_request(provider, endpoint, success, response_time)
    
    def record_rate_limit_hit(self, provider: str, endpoint: str):
        """Registra hit de rate limit"""
        self.api_monitor.record_rate_limit_hit(provider, endpoint)
    
    def get_adaptive_report(self) -> Dict[str, Any]:
        """Gera relatório completo de rate limiting adaptativo"""
        predictions = self.predictor.get_predictions()
        analytics_report = self.analytics.generate_analytics_report()
        recent_alerts = self.alert_manager.get_recent_alerts()
        
        return {
            'predictions': [
                {
                    'provider': p.provider,
                    'predicted_requests': p.predicted_requests,
                    'confidence': p.confidence,
                    'recommended_limit': p.recommended_limit,
                    'next_peak_time': p.next_peak_time.isoformat()
                }
                for p in predictions
            ],
            'analytics': analytics_report,
            'recent_alerts': recent_alerts,
            'current_limits': self.rate_adjuster.current_limits,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def shutdown(self):
        """Finaliza o rate limiter adaptativo"""
        self.stop_monitoring()
        logger.info("Adaptive Rate Limiter finalizado")

# Decorator para rate limiting adaptativo
def adaptive_rate_limit(provider: str, endpoint: str = "general"):
    """Decorator para rate limiting adaptativo"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                response_time = time.time() - start_time
                
                # Registra requisição bem-sucedida
                adaptive_limiter.record_api_request(provider, endpoint, True, response_time)
                
                return result
                
            except Exception as e:
                response_time = time.time() - start_time
                
                # Registra requisição falhada
                adaptive_limiter.record_api_request(provider, endpoint, False, response_time)
                
                raise
        
        return wrapper
    return decorator

# Instância global
adaptive_limiter = AdaptiveRateLimiter() 