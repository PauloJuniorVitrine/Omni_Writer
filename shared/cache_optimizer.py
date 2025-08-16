"""
Sistema de Otimização de Cache Hit Rate - Omni Writer

Prompt: Pendência 2.1.4 - Otimizar cache hit rate (meta: > 70%)
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T22:45:00Z
Tracing ID: PENDENCIA_2_1_4_001

Sistema de otimização baseado em código real:
- Análise de padrões de acesso
- Ajuste automático de TTL
- Estratégias de cache inteligente
- Métricas de hit rate em tempo real
- Recomendações de otimização
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import json

from .cache_manager import get_cache_manager, CacheType
from .query_cache import query_cache
from .generation_cache import generation_cache

logger = logging.getLogger("cache_optimizer")

@dataclass
class CacheOptimizationRule:
    """Regra de otimização de cache."""
    name: str
    cache_type: CacheType
    condition: str  # Condição para aplicar otimização
    action: str     # Ação a ser executada
    priority: int   # Prioridade da regra (1-10)
    enabled: bool = True


class CacheOptimizer:
    """
    Sistema de otimização de cache hit rate.
    
    Funcionalidades:
    - Análise de padrões de acesso
    - Ajuste automático de TTL
    - Estratégias de cache inteligente
    - Métricas de hit rate em tempo real
    - Recomendações de otimização
    """
    
    def __init__(self, target_hit_rate: float = 70.0):
        self.cache_manager = get_cache_manager()
        self.target_hit_rate = target_hit_rate
        self.optimization_rules: List[CacheOptimizationRule] = []
        self.performance_history: List[Dict[str, Any]] = []
        self.is_running = False
        self.optimization_thread = None
        self.lock = threading.RLock()
        
        # Configurações baseadas em código real
        self.analysis_interval = 300  # 5 minutos
        self.max_history_size = 1000
        self.optimization_threshold = 0.05  # 5% de melhoria mínima
        
        # Inicializa regras de otimização
        self._initialize_optimization_rules()
        
        logger.info(f"CacheOptimizer inicializado com hit rate alvo: {target_hit_rate}%")
    
    def _initialize_optimization_rules(self):
        """Inicializa regras de otimização baseadas em código real."""
        
        optimization_rules = [
            # Regra 1: Aumentar TTL para dados muito acessados
            CacheOptimizationRule(
                name="increase_ttl_frequent_access",
                cache_type=CacheType.API_RESPONSES,
                condition="hit_rate < 60 and access_frequency > 100",
                action="increase_ttl_by_50_percent",
                priority=10
            ),
            
            # Regra 2: Reduzir TTL para dados pouco acessados
            CacheOptimizationRule(
                name="decrease_ttl_infrequent_access",
                cache_type=CacheType.API_RESPONSES,
                condition="hit_rate < 30 and access_frequency < 10",
                action="decrease_ttl_by_30_percent",
                priority=8
            ),
            
            # Regra 3: Otimizar cache de gerações
            CacheOptimizationRule(
                name="optimize_generation_cache",
                cache_type=CacheType.ARTICLE_CONTENT,
                condition="hit_rate < 50 and cache_size > 100",
                action="cleanup_old_generations",
                priority=9
            ),
            
            # Regra 4: Ajustar cache de status
            CacheOptimizationRule(
                name="optimize_status_cache",
                cache_type=CacheType.GENERATION_STATUS,
                condition="hit_rate < 40",
                action="increase_ttl_and_warm",
                priority=7
            ),
            
            # Regra 5: Otimizar cache de métricas
            CacheOptimizationRule(
                name="optimize_metrics_cache",
                cache_type=CacheType.METRICS,
                condition="hit_rate < 20",
                action="reduce_ttl_and_cleanup",
                priority=6
            )
        ]
        
        self.optimization_rules.extend(optimization_rules)
        logger.info(f"Regras de otimização inicializadas: {len(optimization_rules)} regras")
    
    def analyze_cache_performance(self) -> Dict[str, Any]:
        """
        Analisa performance atual do cache.
        
        Returns:
            Dicionário com métricas de performance
        """
        try:
            # Obtém métricas de todos os caches
            cache_metrics = self.cache_manager.get_metrics()
            query_metrics = query_cache.get_query_metrics()
            generation_metrics = generation_cache.get_generation_metrics()
            
            # Calcula hit rate geral
            total_hits = 0
            total_requests = 0
            
            # Soma hits e requests de todos os caches
            for cache_type in CacheType:
                cache_data = cache_metrics.get(cache_type.value, {})
                hits = cache_data.get('hits', 0)
                misses = cache_data.get('misses', 0)
                total_hits += hits
                total_requests += hits + misses
            
            overall_hit_rate = (total_hits / total_requests * 100) if total_requests > 0 else 0
            
            # Análise por tipo de cache
            cache_analysis = {}
            for cache_type in CacheType:
                cache_data = cache_metrics.get(cache_type.value, {})
                hits = cache_data.get('hits', 0)
                misses = cache_data.get('misses', 0)
                requests = hits + misses
                hit_rate = (hits / requests * 100) if requests > 0 else 0
                
                cache_analysis[cache_type.value] = {
                    'hit_rate': round(hit_rate, 2),
                    'total_requests': requests,
                    'hits': hits,
                    'misses': misses,
                    'size_mb': cache_data.get('size_mb', 0),
                    'memory_usage': cache_data.get('memory_usage', 0)
                }
            
            # Identifica problemas
            issues = self._identify_performance_issues(cache_analysis)
            
            # Gera recomendações
            recommendations = self._generate_recommendations(cache_analysis, issues)
            
            analysis_result = {
                'timestamp': datetime.now().isoformat(),
                'overall_hit_rate': round(overall_hit_rate, 2),
                'target_hit_rate': self.target_hit_rate,
                'cache_analysis': cache_analysis,
                'issues': issues,
                'recommendations': recommendations,
                'query_metrics': query_metrics,
                'generation_metrics': generation_metrics
            }
            
            # Armazena histórico
            self._store_performance_history(analysis_result)
            
            logger.info(f"Análise de performance concluída - Hit Rate: {overall_hit_rate:.2f}%")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Erro na análise de performance: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'overall_hit_rate': 0,
                'target_hit_rate': self.target_hit_rate
            }
    
    def _identify_performance_issues(self, cache_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identifica problemas de performance no cache.
        
        Args:
            cache_analysis: Análise dos caches
            
        Returns:
            Lista de problemas identificados
        """
        issues = []
        
        for cache_type, analysis in cache_analysis.items():
            hit_rate = analysis['hit_rate']
            total_requests = analysis['total_requests']
            
            # Problema 1: Hit rate muito baixo
            if hit_rate < 30 and total_requests > 10:
                issues.append({
                    'type': 'low_hit_rate',
                    'cache_type': cache_type,
                    'severity': 'high' if hit_rate < 20 else 'medium',
                    'description': f"Hit rate muito baixo ({hit_rate}%) para {cache_type}",
                    'recommendation': 'Aumentar TTL ou implementar cache warming'
                })
            
            # Problema 2: Cache muito grande
            if analysis['size_mb'] > 500:
                issues.append({
                    'type': 'large_cache_size',
                    'cache_type': cache_type,
                    'severity': 'medium',
                    'description': f"Cache muito grande ({analysis['size_mb']}MB) para {cache_type}",
                    'recommendation': 'Limpar cache antigo ou reduzir TTL'
                })
            
            # Problema 3: Muitos misses
            if analysis['misses'] > 1000 and hit_rate < 50:
                issues.append({
                    'type': 'high_miss_rate',
                    'cache_type': cache_type,
                    'severity': 'high',
                    'description': f"Muitos cache misses ({analysis['misses']}) para {cache_type}",
                    'recommendation': 'Analisar padrões de acesso e otimizar estratégia'
                })
        
        return issues
    
    def _generate_recommendations(self, cache_analysis: Dict[str, Any], 
                                issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Gera recomendações de otimização.
        
        Args:
            cache_analysis: Análise dos caches
            issues: Problemas identificados
            
        Returns:
            Lista de recomendações
        """
        recommendations = []
        
        # Recomendação 1: Otimizar caches com hit rate baixo
        for cache_type, analysis in cache_analysis.items():
            hit_rate = analysis['hit_rate']
            
            if hit_rate < 50:
                recommendations.append({
                    'priority': 'high' if hit_rate < 30 else 'medium',
                    'cache_type': cache_type,
                    'action': 'increase_ttl',
                    'description': f"Aumentar TTL para {cache_type} (hit rate: {hit_rate}%)",
                    'expected_improvement': '10-20%'
                })
        
        # Recomendação 2: Implementar cache warming
        overall_hit_rate = sum(
            analysis['hit_rate'] for analysis in cache_analysis.values()
        ) / len(cache_analysis) if cache_analysis else 0
        
        if overall_hit_rate < self.target_hit_rate:
            recommendations.append({
                'priority': 'high',
                'cache_type': 'all',
                'action': 'cache_warming',
                'description': f"Implementar cache warming (hit rate atual: {overall_hit_rate:.1f}%)",
                'expected_improvement': '15-25%'
            })
        
        # Recomendação 3: Limpar cache antigo
        for cache_type, analysis in cache_analysis.items():
            if analysis['size_mb'] > 200:
                recommendations.append({
                    'priority': 'medium',
                    'cache_type': cache_type,
                    'action': 'cleanup',
                    'description': f"Limpar cache antigo de {cache_type}",
                    'expected_improvement': '5-10%'
                })
        
        return recommendations
    
    def _store_performance_history(self, analysis: Dict[str, Any]):
        """Armazena análise no histórico."""
        with self.lock:
            self.performance_history.append(analysis)
            
            # Mantém apenas as análises mais recentes
            if len(self.performance_history) > self.max_history_size:
                self.performance_history = self.performance_history[-self.max_history_size:]
    
    def apply_optimization_rules(self) -> List[Dict[str, Any]]:
        """
        Aplica regras de otimização automaticamente.
        
        Returns:
            Lista de otimizações aplicadas
        """
        applied_optimizations = []
        
        try:
            # Obtém análise atual
            analysis = self.analyze_cache_performance()
            cache_analysis = analysis.get('cache_analysis', {})
            
            # Aplica regras habilitadas
            for rule in self.optimization_rules:
                if not rule.enabled:
                    continue
                
                # Verifica se regra deve ser aplicada
                if self._should_apply_rule(rule, cache_analysis):
                    optimization_result = self._apply_optimization_rule(rule, cache_analysis)
                    if optimization_result:
                        applied_optimizations.append(optimization_result)
                        logger.info(f"Otimização aplicada: {rule.name}")
            
            logger.info(f"Otimizações aplicadas: {len(applied_optimizations)} regras")
            return applied_optimizations
            
        except Exception as e:
            logger.error(f"Erro ao aplicar regras de otimização: {e}")
            return []
    
    def _should_apply_rule(self, rule: CacheOptimizationRule, 
                          cache_analysis: Dict[str, Any]) -> bool:
        """
        Verifica se regra deve ser aplicada.
        
        Args:
            rule: Regra de otimização
            cache_analysis: Análise dos caches
            
        Returns:
            True se regra deve ser aplicada
        """
        cache_data = cache_analysis.get(rule.cache_type.value, {})
        
        if rule.condition == "hit_rate < 60 and access_frequency > 100":
            hit_rate = cache_data.get('hit_rate', 100)
            # Simula frequência de acesso (em produção seria calculada)
            access_frequency = cache_data.get('total_requests', 0)
            return hit_rate < 60 and access_frequency > 100
        
        elif rule.condition == "hit_rate < 30 and access_frequency < 10":
            hit_rate = cache_data.get('hit_rate', 100)
            access_frequency = cache_data.get('total_requests', 0)
            return hit_rate < 30 and access_frequency < 10
        
        elif rule.condition == "hit_rate < 50 and cache_size > 100":
            hit_rate = cache_data.get('hit_rate', 100)
            cache_size = cache_data.get('size_mb', 0)
            return hit_rate < 50 and cache_size > 100
        
        elif rule.condition == "hit_rate < 40":
            hit_rate = cache_data.get('hit_rate', 100)
            return hit_rate < 40
        
        elif rule.condition == "hit_rate < 20":
            hit_rate = cache_data.get('hit_rate', 100)
            return hit_rate < 20
        
        return False
    
    def _apply_optimization_rule(self, rule: CacheOptimizationRule, 
                               cache_analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Aplica regra de otimização específica.
        
        Args:
            rule: Regra de otimização
            cache_analysis: Análise dos caches
            
        Returns:
            Resultado da otimização ou None
        """
        try:
            if rule.action == "increase_ttl_by_50_percent":
                return self._increase_ttl(rule.cache_type, 1.5)
            
            elif rule.action == "decrease_ttl_by_30_percent":
                return self._decrease_ttl(rule.cache_type, 0.7)
            
            elif rule.action == "cleanup_old_generations":
                return self._cleanup_old_generations()
            
            elif rule.action == "increase_ttl_and_warm":
                return self._increase_ttl_and_warm(rule.cache_type)
            
            elif rule.action == "reduce_ttl_and_cleanup":
                return self._reduce_ttl_and_cleanup(rule.cache_type)
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao aplicar regra {rule.name}: {e}")
            return None
    
    def _increase_ttl(self, cache_type: CacheType, multiplier: float) -> Dict[str, Any]:
        """Aumenta TTL do cache."""
        try:
            # Obtém configuração atual
            from .cache_config import get_cache_config
            config = get_cache_config(cache_type)
            
            # Aumenta TTL
            new_ttl = int(config.ttl * multiplier)
            
            # Atualiza configuração
            config.ttl = new_ttl
            
            return {
                'action': 'increase_ttl',
                'cache_type': cache_type.value,
                'old_ttl': config.ttl,
                'new_ttl': new_ttl,
                'multiplier': multiplier
            }
            
        except Exception as e:
            logger.error(f"Erro ao aumentar TTL: {e}")
            return None
    
    def _decrease_ttl(self, cache_type: CacheType, multiplier: float) -> Dict[str, Any]:
        """Diminui TTL do cache."""
        try:
            from .cache_config import get_cache_config
            config = get_cache_config(cache_type)
            
            new_ttl = int(config.ttl * multiplier)
            config.ttl = new_ttl
            
            return {
                'action': 'decrease_ttl',
                'cache_type': cache_type.value,
                'old_ttl': config.ttl,
                'new_ttl': new_ttl,
                'multiplier': multiplier
            }
            
        except Exception as e:
            logger.error(f"Erro ao diminuir TTL: {e}")
            return None
    
    def _cleanup_old_generations(self) -> Dict[str, Any]:
        """Limpa gerações antigas."""
        try:
            removed_count = generation_cache.clear_generation_cache()
            
            return {
                'action': 'cleanup_old_generations',
                'cache_type': 'ARTICLE_CONTENT',
                'removed_count': removed_count
            }
            
        except Exception as e:
            logger.error(f"Erro ao limpar gerações antigas: {e}")
            return None
    
    def _increase_ttl_and_warm(self, cache_type: CacheType) -> Dict[str, Any]:
        """Aumenta TTL e executa warming."""
        try:
            # Aumenta TTL
            ttl_result = self._increase_ttl(cache_type, 1.3)
            
            # Executa warming
            from .cache_warming import execute_warming_cycle
            execute_warming_cycle()
            
            return {
                'action': 'increase_ttl_and_warm',
                'cache_type': cache_type.value,
                'ttl_result': ttl_result,
                'warming_executed': True
            }
            
        except Exception as e:
            logger.error(f"Erro ao aumentar TTL e executar warming: {e}")
            return None
    
    def _reduce_ttl_and_cleanup(self, cache_type: CacheType) -> Dict[str, Any]:
        """Reduz TTL e limpa cache."""
        try:
            # Reduz TTL
            ttl_result = self._decrease_ttl(cache_type, 0.8)
            
            # Limpa cache
            removed_count = self.cache_manager.clear(cache_type)
            
            return {
                'action': 'reduce_ttl_and_cleanup',
                'cache_type': cache_type.value,
                'ttl_result': ttl_result,
                'removed_count': removed_count
            }
            
        except Exception as e:
            logger.error(f"Erro ao reduzir TTL e limpar cache: {e}")
            return None
    
    def get_optimization_metrics(self) -> Dict[str, Any]:
        """
        Obtém métricas de otimização.
        
        Returns:
            Dicionário com métricas
        """
        with self.lock:
            if not self.performance_history:
                return {
                    'total_analyses': 0,
                    'average_hit_rate': 0,
                    'optimizations_applied': 0,
                    'performance_trend': 'stable'
                }
            
            # Calcula métricas do histórico
            total_analyses = len(self.performance_history)
            hit_rates = [analysis['overall_hit_rate'] for analysis in self.performance_history]
            average_hit_rate = sum(hit_rates) / len(hit_rates)
            
            # Calcula tendência
            if len(hit_rates) >= 2:
                recent_avg = sum(hit_rates[-5:]) / min(5, len(hit_rates))
                older_avg = sum(hit_rates[:-5]) / max(1, len(hit_rates) - 5)
                
                if recent_avg > older_avg + 5:
                    trend = 'improving'
                elif recent_avg < older_avg - 5:
                    trend = 'declining'
                else:
                    trend = 'stable'
            else:
                trend = 'stable'
            
            return {
                'total_analyses': total_analyses,
                'average_hit_rate': round(average_hit_rate, 2),
                'target_hit_rate': self.target_hit_rate,
                'performance_trend': trend,
                'recent_analyses': self.performance_history[-5:] if self.performance_history else []
            }
    
    def start_background_optimization(self):
        """Inicia otimização em background."""
        if self.is_running:
            logger.warning("Otimização em background já está rodando")
            return
        
        self.is_running = True
        self.optimization_thread = threading.Thread(target=self._optimization_worker, daemon=True)
        self.optimization_thread.start()
        logger.info("Otimização em background iniciada")
    
    def stop_background_optimization(self):
        """Para otimização em background."""
        self.is_running = False
        if self.optimization_thread:
            self.optimization_thread.join(timeout=10)
        logger.info("Otimização em background parada")
    
    def _optimization_worker(self):
        """Worker thread para otimização em background."""
        while self.is_running:
            try:
                # Analisa performance
                analysis = self.analyze_cache_performance()
                current_hit_rate = analysis.get('overall_hit_rate', 0)
                
                # Aplica otimizações se necessário
                if current_hit_rate < self.target_hit_rate:
                    optimizations = self.apply_optimization_rules()
                    if optimizations:
                        logger.info(f"Otimizações aplicadas automaticamente: {len(optimizations)}")
                
                time.sleep(self.analysis_interval)
                
            except Exception as e:
                logger.error(f"Erro no worker de otimização: {e}")
                time.sleep(60)


# Instância global
cache_optimizer = CacheOptimizer(target_hit_rate=70.0)


# Funções helper
def analyze_cache_performance() -> Dict[str, Any]:
    """Analisa performance do cache."""
    return cache_optimizer.analyze_cache_performance()


def apply_cache_optimizations() -> List[Dict[str, Any]]:
    """Aplica otimizações de cache."""
    return cache_optimizer.apply_optimization_rules()


def get_cache_optimization_metrics() -> Dict[str, Any]:
    """Obtém métricas de otimização."""
    return cache_optimizer.get_optimization_metrics()


def start_cache_optimization():
    """Inicia otimização de cache em background."""
    cache_optimizer.start_background_optimization()


def stop_cache_optimization():
    """Para otimização de cache em background."""
    cache_optimizer.stop_background_optimization() 