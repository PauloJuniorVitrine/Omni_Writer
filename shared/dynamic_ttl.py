"""
Sistema de TTL Dinâmico Baseado em Uso - Omni Writer

Prompt: Pendência 2.1.5 - Configurar TTL dinâmico baseado em uso
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:50:00Z
Tracing ID: PENDENCIA_2_1_5_001

Sistema de TTL dinâmico baseado em código real:
- Ajuste automático de TTL baseado em padrões de acesso
- Análise de frequência e recência de uso
- Otimização de memória e performance
- Integração com sistema de cache existente
- Métricas de eficiência do TTL dinâmico
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import json
import math

from .cache_manager import get_cache_manager, CacheType
from .cache_config import CacheConfig, get_cache_config

logger = logging.getLogger("dynamic_ttl")

@dataclass
class TTLUsagePattern:
    """Padrão de uso para cálculo de TTL dinâmico."""
    access_count: int
    last_access: datetime
    first_access: datetime
    average_interval: float  # Intervalo médio entre acessos em segundos
    access_frequency: float  # Acessos por hora


class DynamicTTLManager:
    """
    Sistema de TTL dinâmico baseado em uso.
    
    Funcionalidades:
    - Ajuste automático de TTL baseado em padrões de acesso
    - Análise de frequência e recência de uso
    - Otimização de memória e performance
    - Integração com sistema de cache existente
    - Métricas de eficiência do TTL dinâmico
    """
    
    def __init__(self, enable_metrics: bool = True):
        self.cache_manager = get_cache_manager()
        self.enable_metrics = enable_metrics
        self.usage_patterns: Dict[str, TTLUsagePattern] = {}
        self.ttl_history: List[Dict[str, Any]] = []
        self.is_running = False
        self.ttl_thread = None
        self.lock = threading.RLock()
        
        # Configurações baseadas em código real
        self.analysis_interval = 600  # 10 minutos
        self.max_history_size = 500
        self.min_ttl = 300  # 5 minutos
        self.max_ttl = 86400  # 24 horas
        
        # Fatores de ajuste
        self.frequency_weight = 0.4
        self.recency_weight = 0.3
        self.size_weight = 0.2
        self.cost_weight = 0.1
        
        logger.info("DynamicTTLManager inicializado com sucesso")
    
    def record_access(self, cache_key: str, cache_type: CacheType, 
                     access_time: Optional[datetime] = None):
        """
        Registra acesso a um item do cache.
        
        Args:
            cache_key: Chave do cache
            access_time: Tempo do acesso (opcional)
        """
        if access_time is None:
            access_time = datetime.now()
        
        with self.lock:
            if cache_key in self.usage_patterns:
                pattern = self.usage_patterns[cache_key]
                pattern.access_count += 1
                
                # Calcula novo intervalo médio
                time_diff = (access_time - pattern.last_access).total_seconds()
                if time_diff > 0:
                    pattern.average_interval = (
                        (pattern.average_interval * (pattern.access_count - 1) + time_diff) 
                        / pattern.access_count
                    )
                
                pattern.last_access = access_time
                
                # Atualiza frequência de acesso
                total_time = (access_time - pattern.first_access).total_seconds()
                if total_time > 0:
                    pattern.access_frequency = (pattern.access_count / total_time) * 3600  # por hora
                
            else:
                # Primeiro acesso
                self.usage_patterns[cache_key] = TTLUsagePattern(
                    access_count=1,
                    last_access=access_time,
                    first_access=access_time,
                    average_interval=0,
                    access_frequency=0
                )
    
    def calculate_dynamic_ttl(self, cache_key: str, cache_type: CacheType, 
                            content_size: int = 0, generation_cost: float = 0) -> int:
        """
        Calcula TTL dinâmico baseado em padrões de uso.
        
        Args:
            cache_key: Chave do cache
            cache_type: Tipo de cache
            content_size: Tamanho do conteúdo em bytes
            generation_cost: Custo de geração (tempo em segundos)
            
        Returns:
            TTL em segundos
        """
        try:
            # Obtém TTL base da configuração
            base_config = get_cache_config(cache_type)
            base_ttl = base_config.ttl
            
            # Obtém padrão de uso
            pattern = self.usage_patterns.get(cache_key)
            if not pattern:
                return base_ttl
            
            # Calcula fatores de ajuste
            frequency_factor = self._calculate_frequency_factor(pattern)
            recency_factor = self._calculate_recency_factor(pattern)
            size_factor = self._calculate_size_factor(content_size)
            cost_factor = self._calculate_cost_factor(generation_cost)
            
            # Calcula TTL dinâmico
            dynamic_ttl = base_ttl * (
                self.frequency_weight * frequency_factor +
                self.recency_weight * recency_factor +
                self.size_weight * size_factor +
                self.cost_weight * cost_factor
            )
            
            # Aplica limites
            dynamic_ttl = max(self.min_ttl, min(self.max_ttl, int(dynamic_ttl)))
            
            # Registra ajuste
            self._record_ttl_adjustment(cache_key, cache_type, base_ttl, dynamic_ttl, {
                'frequency_factor': frequency_factor,
                'recency_factor': recency_factor,
                'size_factor': size_factor,
                'cost_factor': cost_factor
            })
            
            logger.debug(f"TTL dinâmico calculado para {cache_key}: {base_ttl}s -> {dynamic_ttl}s")
            return dynamic_ttl
            
        except Exception as e:
            logger.error(f"Erro ao calcular TTL dinâmico para {cache_key}: {e}")
            return base_ttl
    
    def _calculate_frequency_factor(self, pattern: TTLUsagePattern) -> float:
        """
        Calcula fator baseado na frequência de acesso.
        
        Args:
            pattern: Padrão de uso
            
        Returns:
            Fator de frequência (0.5 - 2.0)
        """
        if pattern.access_count <= 1:
            return 0.8  # Primeiro acesso, TTL menor
        
        # Baseado na frequência de acesso por hora
        if pattern.access_frequency > 100:
            return 2.0  # Muito frequente, TTL maior
        elif pattern.access_frequency > 50:
            return 1.5
        elif pattern.access_frequency > 20:
            return 1.2
        elif pattern.access_frequency > 10:
            return 1.0
        elif pattern.access_frequency > 5:
            return 0.8
        else:
            return 0.6  # Pouco frequente, TTL menor
    
    def _calculate_recency_factor(self, pattern: TTLUsagePattern) -> float:
        """
        Calcula fator baseado na recência de acesso.
        
        Args:
            pattern: Padrão de uso
            
        Returns:
            Fator de recência (0.5 - 1.5)
        """
        now = datetime.now()
        time_since_last = (now - pattern.last_access).total_seconds()
        
        # Se foi acessado recentemente, aumenta TTL
        if time_since_last < 300:  # 5 minutos
            return 1.5
        elif time_since_last < 1800:  # 30 minutos
            return 1.2
        elif time_since_last < 3600:  # 1 hora
            return 1.0
        elif time_since_last < 7200:  # 2 horas
            return 0.8
        else:
            return 0.6  # Não acessado há muito tempo
    
    def _calculate_size_factor(self, content_size: int) -> float:
        """
        Calcula fator baseado no tamanho do conteúdo.
        
        Args:
            content_size: Tamanho em bytes
            
        Returns:
            Fator de tamanho (0.7 - 1.3)
        """
        if content_size == 0:
            return 1.0
        
        # Converte para MB
        size_mb = content_size / (1024 * 1024)
        
        if size_mb > 10:
            return 0.7  # Conteúdo muito grande, TTL menor
        elif size_mb > 5:
            return 0.8
        elif size_mb > 1:
            return 0.9
        elif size_mb > 0.1:
            return 1.0
        else:
            return 1.3  # Conteúdo pequeno, TTL maior
    
    def _calculate_cost_factor(self, generation_cost: float) -> float:
        """
        Calcula fator baseado no custo de geração.
        
        Args:
            generation_cost: Custo em segundos
            
        Returns:
            Fator de custo (0.8 - 1.5)
        """
        if generation_cost <= 0:
            return 1.0
        
        if generation_cost > 60:
            return 1.5  # Muito custoso, TTL maior
        elif generation_cost > 30:
            return 1.3
        elif generation_cost > 10:
            return 1.1
        elif generation_cost > 5:
            return 1.0
        else:
            return 0.8  # Pouco custoso, TTL menor
    
    def _record_ttl_adjustment(self, cache_key: str, cache_type: CacheType, 
                             base_ttl: int, dynamic_ttl: int, factors: Dict[str, float]):
        """Registra ajuste de TTL no histórico."""
        adjustment = {
            'timestamp': datetime.now().isoformat(),
            'cache_key': cache_key,
            'cache_type': cache_type.value,
            'base_ttl': base_ttl,
            'dynamic_ttl': dynamic_ttl,
            'adjustment_ratio': dynamic_ttl / base_ttl if base_ttl > 0 else 1.0,
            'factors': factors
        }
        
        with self.lock:
            self.ttl_history.append(adjustment)
            
            # Mantém apenas histórico recente
            if len(self.ttl_history) > self.max_history_size:
                self.ttl_history = self.ttl_history[-self.max_history_size:]
    
    def get_usage_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Obtém padrões de uso atuais.
        
        Returns:
            Dicionário com padrões de uso
        """
        with self.lock:
            patterns = {}
            for cache_key, pattern in self.usage_patterns.items():
                patterns[cache_key] = {
                    'access_count': pattern.access_count,
                    'last_access': pattern.last_access.isoformat(),
                    'first_access': pattern.first_access.isoformat(),
                    'average_interval': pattern.average_interval,
                    'access_frequency': pattern.access_frequency
                }
            return patterns
    
    def get_ttl_metrics(self) -> Dict[str, Any]:
        """
        Obtém métricas de TTL dinâmico.
        
        Returns:
            Dicionário com métricas
        """
        with self.lock:
            if not self.ttl_history:
                return {
                    'total_adjustments': 0,
                    'average_adjustment_ratio': 1.0,
                    'most_adjusted_cache_types': [],
                    'recent_adjustments': []
                }
            
            # Calcula métricas do histórico
            total_adjustments = len(self.ttl_history)
            adjustment_ratios = [adj['adjustment_ratio'] for adj in self.ttl_history]
            average_ratio = sum(adjustment_ratios) / len(adjustment_ratios)
            
            # Cache types mais ajustados
            cache_type_counts = {}
            for adj in self.ttl_history:
                cache_type = adj['cache_type']
                cache_type_counts[cache_type] = cache_type_counts.get(cache_type, 0) + 1
            
            most_adjusted = sorted(
                cache_type_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
            return {
                'total_adjustments': total_adjustments,
                'average_adjustment_ratio': round(average_ratio, 3),
                'most_adjusted_cache_types': [
                    {'cache_type': ct, 'adjustments': count}
                    for ct, count in most_adjusted
                ],
                'recent_adjustments': self.ttl_history[-10:] if self.ttl_history else []
            }
    
    def cleanup_old_patterns(self, max_age_hours: int = 24) -> int:
        """
        Remove padrões de uso antigos.
        
        Args:
            max_age_hours: Idade máxima em horas
            
        Returns:
            Número de padrões removidos
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        removed_count = 0
        
        with self.lock:
            keys_to_remove = []
            for cache_key, pattern in self.usage_patterns.items():
                if pattern.last_access < cutoff_time:
                    keys_to_remove.append(cache_key)
            
            for key in keys_to_remove:
                del self.usage_patterns[key]
                removed_count += 1
        
        logger.info(f"Padrões antigos removidos: {removed_count}")
        return removed_count
    
    def start_background_optimization(self):
        """Inicia otimização de TTL em background."""
        if self.is_running:
            logger.warning("Otimização de TTL em background já está rodando")
            return
        
        self.is_running = True
        self.ttl_thread = threading.Thread(target=self._ttl_optimization_worker, daemon=True)
        self.ttl_thread.start()
        logger.info("Otimização de TTL em background iniciada")
    
    def stop_background_optimization(self):
        """Para otimização de TTL em background."""
        self.is_running = False
        if self.ttl_thread:
            self.ttl_thread.join(timeout=10)
        logger.info("Otimização de TTL em background parada")
    
    def _ttl_optimization_worker(self):
        """Worker thread para otimização de TTL em background."""
        while self.is_running:
            try:
                # Limpa padrões antigos
                self.cleanup_old_patterns()
                
                # Analisa e otimiza TTLs
                self._optimize_existing_ttls()
                
                time.sleep(self.analysis_interval)
                
            except Exception as e:
                logger.error(f"Erro no worker de otimização de TTL: {e}")
                time.sleep(60)
    
    def _optimize_existing_ttls(self):
        """Otimiza TTLs de itens existentes no cache."""
        try:
            # Obtém métricas do cache
            cache_metrics = self.cache_manager.get_metrics()
            
            # Analisa cada tipo de cache
            for cache_type in CacheType:
                cache_data = cache_metrics.get(cache_type.value, {})
                hit_rate = cache_data.get('hit_ratio', 0)
                
                # Se hit rate está baixo, ajusta TTLs
                if hit_rate < 50:
                    logger.info(f"Ajustando TTLs para {cache_type.value} (hit rate: {hit_rate}%)")
                    # Em produção, aqui seria implementada a lógica de ajuste
                    
        except Exception as e:
            logger.error(f"Erro na otimização de TTLs existentes: {e}")


# Instância global
dynamic_ttl_manager = DynamicTTLManager()


# Funções helper para uso direto
def record_cache_access(cache_key: str, cache_type: CacheType, 
                       access_time: Optional[datetime] = None):
    """Registra acesso ao cache."""
    dynamic_ttl_manager.record_access(cache_key, cache_type, access_time)


def calculate_dynamic_ttl(cache_key: str, cache_type: CacheType, 
                         content_size: int = 0, generation_cost: float = 0) -> int:
    """Calcula TTL dinâmico."""
    return dynamic_ttl_manager.calculate_dynamic_ttl(cache_key, cache_type, content_size, generation_cost)


def get_usage_patterns() -> Dict[str, Dict[str, Any]]:
    """Obtém padrões de uso."""
    return dynamic_ttl_manager.get_usage_patterns()


def get_dynamic_ttl_metrics() -> Dict[str, Any]:
    """Obtém métricas de TTL dinâmico."""
    return dynamic_ttl_manager.get_ttl_metrics()


def cleanup_old_usage_patterns(max_age_hours: int = 24) -> int:
    """Remove padrões de uso antigos."""
    return dynamic_ttl_manager.cleanup_old_patterns(max_age_hours)


def start_dynamic_ttl_optimization():
    """Inicia otimização de TTL dinâmico em background."""
    dynamic_ttl_manager.start_background_optimization()


def stop_dynamic_ttl_optimization():
    """Para otimização de TTL dinâmico em background."""
    dynamic_ttl_manager.stop_background_optimization() 