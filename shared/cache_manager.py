"""
Gerenciador de Cache Inteligente - Enterprise+ Implementation

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import time
import json
import logging
from typing import Any, Dict, Optional, List, Union
from dataclasses import dataclass
from contextlib import contextmanager

from .cache_config import CacheType, CacheConfig, get_cache_config, get_redis_config
from .cache_strategies import (
    CacheStrategyBase, create_strategy, CacheCompressor, CacheEncryptor
)
from .intelligent_cache import IntelligentCache

logger = logging.getLogger(__name__)


@dataclass
class CacheOperation:
    """Operação de cache com metadados"""
    operation_type: str  # 'get', 'set', 'delete', 'clear'
    cache_type: CacheType
    key: str
    success: bool
    duration_ms: float
    timestamp: float
    error_message: Optional[str] = None


class CacheManager:
    """
    Gerenciador central de cache que integra todas as estratégias.
    
    Funcionalidades:
    - Gerenciamento unificado de diferentes tipos de cache
    - Estratégias adaptativas baseadas no tipo de dados
    - Compressão e criptografia automática
    - Métricas detalhadas por operação
    - Fallback inteligente entre Redis e local
    - Cache warming e invalidação automática
    """
    
    def __init__(self, enable_metrics: bool = True, enable_compression: bool = True):
        self.enable_metrics = enable_metrics
        self.enable_compression = enable_compression
        
        # Componentes principais
        self.intelligent_cache = IntelligentCache(enable_metrics=enable_metrics)
        self.compressor = CacheCompressor()
        self.encryptor = CacheEncryptor()
        
        # Estratégias por tipo de cache
        self.strategies: Dict[CacheType, CacheStrategyBase] = {}
        self._initialize_strategies()
        
        # Métricas e operações
        self.operations: List[CacheOperation] = []
        self.max_operations_history = 1000
        
        # Configurações
        self.redis_config = get_redis_config()
        self.stats_config = get_cache_stats_config()
        
        logger.info("CacheManager inicializado com sucesso")
    
    def _initialize_strategies(self):
        """Inicializa estratégias para cada tipo de cache"""
        for cache_type in CacheType:
            config = get_cache_config(cache_type)
            self.strategies[cache_type] = create_strategy(
                strategy=config.strategy,
                max_size=config.max_size,
                default_ttl=config.ttl if config.strategy.value == 'ttl' else None
            )
    
    def get(self, cache_type: CacheType, key: str, default: Any = None) -> Any:
        """
        Obtém valor do cache com estratégia específica.
        
        Args:
            cache_type: Tipo de cache
            key: Chave do cache
            default: Valor padrão se não encontrado
            
        Returns:
            Valor do cache ou default
        """
        start_time = time.time()
        operation = CacheOperation(
            operation_type='get',
            cache_type=cache_type,
            key=key,
            success=False,
            duration_ms=0,
            timestamp=start_time
        )
        
        try:
            # Tenta cache inteligente primeiro
            result = self._get_from_intelligent_cache(cache_type, key)
            if result is not None:
                operation.success = True
                self._log_operation(operation, start_time)
                return result
            
            # Tenta estratégia específica
            strategy = self.strategies.get(cache_type)
            if strategy:
                result = strategy.get_entry(key)
                if result is not None:
                    operation.success = True
                    self._log_operation(operation, start_time)
                    return result
            
            # Cache miss
            self._log_operation(operation, start_time)
            return default
            
        except Exception as e:
            operation.error_message = str(e)
            self._log_operation(operation, start_time)
            logger.error(f"Erro ao obter cache {cache_type.value}:{key}: {e}")
            return default
    
    def set(self, cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Armazena valor no cache com estratégia específica.
        
        Args:
            cache_type: Tipo de cache
            key: Chave do cache
            value: Valor a armazenar
            ttl: TTL em segundos (opcional)
            
        Returns:
            True se armazenado com sucesso
        """
        start_time = time.time()
        operation = CacheOperation(
            operation_type='set',
            cache_type=cache_type,
            key=key,
            success=False,
            duration_ms=0,
            timestamp=start_time
        )
        
        try:
            config = get_cache_config(cache_type)
            
            # Processa valor (compressão/criptografia)
            processed_value, compression_info = self._process_value_for_storage(
                value, config
            )
            
            # Armazena no cache inteligente
            success = self._set_in_intelligent_cache(cache_type, key, processed_value, ttl)
            
            # Armazena na estratégia específica
            strategy = self.strategies.get(cache_type)
            if strategy:
                strategy_success = strategy.add_entry(
                    key, processed_value,
                    compressed=compression_info.get('compressed', False),
                    encrypted=compression_info.get('encrypted', False),
                    ttl=ttl if hasattr(strategy, 'ttl_map') else None
                )
                success = success and strategy_success
            
            operation.success = success
            self._log_operation(operation, start_time)
            return success
            
        except Exception as e:
            operation.error_message = str(e)
            self._log_operation(operation, start_time)
            logger.error(f"Erro ao armazenar cache {cache_type.value}:{key}: {e}")
            return False
    
    def delete(self, cache_type: CacheType, key: str) -> bool:
        """
        Remove valor do cache.
        
        Args:
            cache_type: Tipo de cache
            key: Chave do cache
            
        Returns:
            True se removido com sucesso
        """
        start_time = time.time()
        operation = CacheOperation(
            operation_type='delete',
            cache_type=cache_type,
            key=key,
            success=False,
            duration_ms=0,
            timestamp=start_time
        )
        
        try:
            # Remove do cache inteligente
            success = self._delete_from_intelligent_cache(cache_type, key)
            
            # Remove da estratégia específica
            strategy = self.strategies.get(cache_type)
            if strategy:
                strategy_success = strategy.remove_entry(key)
                success = success and strategy_success
            
            operation.success = success
            self._log_operation(operation, start_time)
            return success
            
        except Exception as e:
            operation.error_message = str(e)
            self._log_operation(operation, start_time)
            logger.error(f"Erro ao remover cache {cache_type.value}:{key}: {e}")
            return False
    
    def clear(self, cache_type: CacheType) -> int:
        """
        Limpa todos os valores de um tipo de cache.
        
        Args:
            cache_type: Tipo de cache
            
        Returns:
            Número de chaves removidas
        """
        start_time = time.time()
        operation = CacheOperation(
            operation_type='clear',
            cache_type=cache_type,
            key='*',
            success=False,
            duration_ms=0,
            timestamp=start_time
        )
        
        try:
            # Limpa cache inteligente
            removed_count = self._clear_intelligent_cache(cache_type)
            
            # Limpa estratégia específica
            strategy = self.strategies.get(cache_type)
            if strategy:
                strategy.entries.clear()
                strategy.current_size = 0
                removed_count += len(strategy.entries)
            
            operation.success = True
            self._log_operation(operation, start_time)
            return removed_count
            
        except Exception as e:
            operation.error_message = str(e)
            self._log_operation(operation, start_time)
            logger.error(f"Erro ao limpar cache {cache_type.value}: {e}")
            return 0
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Obtém métricas consolidadas do cache.
        
        Returns:
            Dicionário com métricas
        """
        # Métricas do cache inteligente
        intelligent_metrics = self.intelligent_cache.get_metrics()
        
        # Métricas das estratégias
        strategy_metrics = {}
        total_entries = 0
        total_size_mb = 0
        
        for cache_type, strategy in self.strategies.items():
            stats = strategy.get_stats()
            strategy_metrics[cache_type.value] = stats
            total_entries += stats['total_entries']
            total_size_mb += stats['current_size_mb']
        
        # Métricas de operações
        operation_metrics = self._calculate_operation_metrics()
        
        return {
            'intelligent_cache': intelligent_metrics,
            'strategies': strategy_metrics,
            'operations': operation_metrics,
            'total_entries': total_entries,
            'total_size_mb': total_size_mb,
            'cache_types': len(self.strategies),
            'redis_available': self.intelligent_cache.redis_client is not None
        }
    
    def warm_cache(self, cache_type: CacheType, data: Dict[str, Any]):
        """
        Aquecimento de cache com dados frequentes.
        
        Args:
            cache_type: Tipo de cache
            data: Dados para aquecer
        """
        try:
            # Aquecimento no cache inteligente
            self.intelligent_cache.warm_cache(cache_type.value, data)
            
            # Aquecimento na estratégia específica
            strategy = self.strategies.get(cache_type)
            if strategy:
                for key, value in data.items():
                    strategy.add_entry(key, value)
            
            logger.info(f"Cache {cache_type.value} aquecido com {len(data)} itens")
            
        except Exception as e:
            logger.error(f"Erro ao aquecer cache {cache_type.value}: {e}")
    
    def cleanup_expired(self) -> Dict[CacheType, int]:
        """
        Remove entradas expiradas de todos os caches.
        
        Returns:
            Dicionário com número de entradas removidas por tipo
        """
        cleanup_results = {}
        
        for cache_type, strategy in self.strategies.items():
            try:
                if hasattr(strategy, 'cleanup_expired'):
                    removed_count = strategy.cleanup_expired()
                else:
                    # Limpeza manual para estratégias sem TTL
                    removed_count = 0
                    expired_keys = []
                    
                    for key, entry in strategy.entries.items():
                        if hasattr(entry, 'created_at'):
                            ttl = getattr(entry, 'ttl', 3600)
                            if time.time() - entry.created_at > ttl:
                                expired_keys.append(key)
                    
                    for key in expired_keys:
                        if strategy.remove_entry(key):
                            removed_count += 1
                
                cleanup_results[cache_type] = removed_count
                
            except Exception as e:
                logger.error(f"Erro ao limpar cache {cache_type.value}: {e}")
                cleanup_results[cache_type] = 0
        
        return cleanup_results
    
    @contextmanager
    def transaction(self, cache_type: CacheType):
        """
        Context manager para operações transacionais.
        
        Args:
            cache_type: Tipo de cache para a transação
        """
        # Implementação básica - em produção usar locks distribuídos
        try:
            yield self
        except Exception as e:
            logger.error(f"Erro na transação de cache {cache_type.value}: {e}")
            raise
    
    def _get_from_intelligent_cache(self, cache_type: CacheType, key: str) -> Any:
        """Obtém valor do cache inteligente"""
        return self.intelligent_cache.get(cache_type.value, key)
    
    def _set_in_intelligent_cache(self, cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Armazena valor no cache inteligente"""
        return self.intelligent_cache.set(cache_type.value, key, value, ttl)
    
    def _delete_from_intelligent_cache(self, cache_type: CacheType, key: str) -> bool:
        """Remove valor do cache inteligente"""
        return self.intelligent_cache.delete(cache_type.value, key)
    
    def _clear_intelligent_cache(self, cache_type: CacheType) -> int:
        """Limpa cache inteligente"""
        return self.intelligent_cache.clear_prefix(cache_type.value)
    
    def _process_value_for_storage(self, value: Any, config: CacheConfig) -> tuple:
        """
        Processa valor para armazenamento (compressão/criptografia).
        
        Returns:
            Tuple[Any, Dict]: (valor_processado, info_compressão)
        """
        compression_info = {'compressed': False, 'encrypted': False}
        processed_value = value
        
        try:
            # Compressão
            if config.compression and self.enable_compression:
                compressed_data, was_compressed = self.compressor.compress(value)
                if was_compressed:
                    processed_value = compressed_data
                    compression_info['compressed'] = True
            
            # Criptografia
            if config.encryption:
                encrypted_data, was_encrypted = self.encryptor.encrypt(processed_value)
                if was_encrypted:
                    processed_value = encrypted_data
                    compression_info['encrypted'] = True
            
            return processed_value, compression_info
            
        except Exception as e:
            logger.error(f"Erro ao processar valor para armazenamento: {e}")
            return value, compression_info
    
    def _log_operation(self, operation: CacheOperation, start_time: float):
        """Registra operação de cache"""
        operation.duration_ms = (time.time() - start_time) * 1000
        
        self.operations.append(operation)
        
        # Limita histórico de operações
        if len(self.operations) > self.max_operations_history:
            self.operations = self.operations[-self.max_operations_history:]
        
        # Log da operação
        if operation.success:
            logger.debug(f"Cache {operation.operation_type} {operation.cache_type.value}:{operation.key} "
                        f"sucesso em {operation.duration_ms:.2f}ms")
        else:
            logger.warning(f"Cache {operation.operation_type} {operation.cache_type.value}:{operation.key} "
                          f"falhou em {operation.duration_ms:.2f}ms: {operation.error_message}")
    
    def _calculate_operation_metrics(self) -> Dict[str, Any]:
        """Calcula métricas das operações"""
        if not self.operations:
            return {
                'total_operations': 0,
                'success_rate': 0.0,
                'avg_duration_ms': 0.0,
                'operations_by_type': {},
                'operations_by_cache_type': {}
            }
        
        total_ops = len(self.operations)
        successful_ops = sum(1 for op in self.operations if op.success)
        avg_duration = sum(op.duration_ms for op in self.operations) / total_ops
        
        # Operações por tipo
        ops_by_type = {}
        for op in self.operations:
            ops_by_type[op.operation_type] = ops_by_type.get(op.operation_type, 0) + 1
        
        # Operações por tipo de cache
        ops_by_cache_type = {}
        for op in self.operations:
            cache_type_str = op.cache_type.value
            ops_by_cache_type[cache_type_str] = ops_by_cache_type.get(cache_type_str, 0) + 1
        
        return {
            'total_operations': total_ops,
            'success_rate': (successful_ops / total_ops) * 100,
            'avg_duration_ms': avg_duration,
            'operations_by_type': ops_by_type,
            'operations_by_cache_type': ops_by_cache_type
        }


# Instância global do gerenciador de cache
cache_manager = CacheManager()


def get_cache_manager() -> CacheManager:
    """
    Obtém instância global do gerenciador de cache.
    
    Returns:
        CacheManager: Instância do gerenciador
    """
    return cache_manager


# Funções helper para uso direto
def cache_get(cache_type: CacheType, key: str, default: Any = None) -> Any:
    """Helper para obter valor do cache"""
    return cache_manager.get(cache_type, key, default)


def cache_set(cache_type: CacheType, key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """Helper para armazenar valor no cache"""
    return cache_manager.set(cache_type, key, value, ttl)


def cache_delete(cache_type: CacheType, key: str) -> bool:
    """Helper para remover valor do cache"""
    return cache_manager.delete(cache_type, key)


def cache_clear(cache_type: CacheType) -> int:
    """Helper para limpar cache"""
    return cache_manager.clear(cache_type)


def get_cache_metrics() -> Dict[str, Any]:
    """Helper para obter métricas do cache"""
    return cache_manager.get_metrics() 