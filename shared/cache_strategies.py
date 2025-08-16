"""
Estratégias de Cache Inteligente - Enterprise+ Implementation

Prompt: Refatoração Enterprise+ - IMP-002
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T15:50:00Z
Tracing ID: ENTERPRISE_20250127_001
"""

import time
import json
import gzip
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging

from .cache_config import CacheStrategy, CacheType, CacheConfig

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Entrada de cache com metadados"""
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    size_bytes: int
    compressed: bool = False
    encrypted: bool = False


class CacheStrategyBase(ABC):
    """Classe base para estratégias de cache"""
    
    def __init__(self, max_size: int):
        self.max_size = max_size * 1024 * 1024  # Converte MB para bytes
        self.current_size = 0
        self.entries: Dict[str, CacheEntry] = {}
    
    @abstractmethod
    def should_evict(self, key: str) -> bool:
        """Determina se uma chave deve ser removida"""
        pass
    
    @abstractmethod
    def on_access(self, key: str):
        """Chamado quando uma chave é acessada"""
        pass
    
    def add_entry(self, key: str, value: Any, compressed: bool = False, encrypted: bool = False) -> bool:
        """
        Adiciona entrada ao cache.
        
        Args:
            key: Chave do cache
            value: Valor a armazenar
            compressed: Se o valor está comprimido
            encrypted: Se o valor está criptografado
            
        Returns:
            True se adicionado com sucesso
        """
        try:
            # Calcula tamanho do valor
            value_bytes = self._calculate_size(value)
            
            # Verifica se há espaço
            if value_bytes > self.max_size:
                logger.warning(f"Valor muito grande para cache: {value_bytes} bytes")
                return False
            
            # Remove entradas se necessário
            while self.current_size + value_bytes > self.max_size and self.entries:
                self._evict_oldest()
            
            # Adiciona nova entrada
            self.entries[key] = CacheEntry(
                value=value,
                created_at=time.time(),
                last_accessed=time.time(),
                access_count=0,
                size_bytes=value_bytes,
                compressed=compressed,
                encrypted=encrypted
            )
            
            self.current_size += value_bytes
            return True
            
        except Exception as e:
            logger.error(f"Erro ao adicionar entrada ao cache: {e}")
            return False
    
    def get_entry(self, key: str) -> Optional[Any]:
        """
        Obtém entrada do cache.
        
        Args:
            key: Chave do cache
            
        Returns:
            Valor da entrada ou None
        """
        if key not in self.entries:
            return None
        
        entry = self.entries[key]
        entry.last_accessed = time.time()
        entry.access_count += 1
        
        self.on_access(key)
        return entry.value
    
    def remove_entry(self, key: str) -> bool:
        """
        Remove entrada do cache.
        
        Args:
            key: Chave do cache
            
        Returns:
            True se removido com sucesso
        """
        if key not in self.entries:
            return False
        
        entry = self.entries[key]
        self.current_size -= entry.size_bytes
        del self.entries[key]
        return True
    
    def _evict_oldest(self):
        """Remove a entrada mais antiga"""
        if not self.entries:
            return
        
        oldest_key = min(self.entries.keys(), key=lambda k: self.entries[k].created_at)
        self.remove_entry(oldest_key)
    
    def _calculate_size(self, value: Any) -> int:
        """Calcula tamanho aproximado do valor em bytes"""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (int, float)):
                return 8
            elif isinstance(value, (list, tuple)):
                return sum(self._calculate_size(item) for item in value)
            elif isinstance(value, dict):
                return sum(self._calculate_size(k) + self._calculate_size(v) for k, v in value.items())
            else:
                return len(json.dumps(value, default=str).encode('utf-8'))
        except Exception:
            return 1024  # Tamanho padrão se não conseguir calcular
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtém estatísticas da estratégia"""
        return {
            'total_entries': len(self.entries),
            'current_size_mb': self.current_size / (1024 * 1024),
            'max_size_mb': self.max_size / (1024 * 1024),
            'utilization_percent': (self.current_size / self.max_size) * 100
        }


class LRUStrategy(CacheStrategyBase):
    """Estratégia Least Recently Used"""
    
    def __init__(self, max_size: int):
        super().__init__(max_size)
        self.access_order = OrderedDict()
    
    def should_evict(self, key: str) -> bool:
        """LRU: remove o menos recentemente usado"""
        return key == next(iter(self.access_order), None)
    
    def on_access(self, key: str):
        """Atualiza ordem de acesso"""
        if key in self.access_order:
            self.access_order.move_to_end(key)
        else:
            self.access_order[key] = time.time()
    
    def add_entry(self, key: str, value: Any, compressed: bool = False, encrypted: bool = False) -> bool:
        """Adiciona entrada e atualiza ordem de acesso"""
        success = super().add_entry(key, value, compressed, encrypted)
        if success:
            self.access_order[key] = time.time()
        return success
    
    def remove_entry(self, key: str) -> bool:
        """Remove entrada e atualiza ordem de acesso"""
        success = super().remove_entry(key)
        if success:
            self.access_order.pop(key, None)
        return success


class LFUStrategy(CacheStrategyBase):
    """Estratégia Least Frequently Used"""
    
    def __init__(self, max_size: int):
        super().__init__(max_size)
        self.frequency_map = defaultdict(int)
    
    def should_evict(self, key: str) -> bool:
        """LFU: remove o menos frequentemente usado"""
        if not self.entries:
            return False
        
        min_freq = min(self.frequency_map.values())
        candidates = [k for k, v in self.frequency_map.items() if v == min_freq]
        
        # Se múltiplos candidatos, remove o mais antigo
        if len(candidates) > 1:
            return min(candidates, key=lambda k: self.entries[k].created_at)
        
        return candidates[0] if candidates else False
    
    def on_access(self, key: str):
        """Incrementa contador de frequência"""
        self.frequency_map[key] += 1
    
    def remove_entry(self, key: str) -> bool:
        """Remove entrada e contador de frequência"""
        success = super().remove_entry(key)
        if success:
            self.frequency_map.pop(key, None)
        return success


class FIFOStrategy(CacheStrategyBase):
    """Estratégia First In, First Out"""
    
    def __init__(self, max_size: int):
        super().__init__(max_size)
        self.insertion_order = []
    
    def should_evict(self, key: str) -> bool:
        """FIFO: remove o primeiro a entrar"""
        return self.insertion_order and key == self.insertion_order[0]
    
    def on_access(self, key: str):
        """FIFO não altera ordem de acesso"""
        pass
    
    def add_entry(self, key: str, value: Any, compressed: bool = False, encrypted: bool = False) -> bool:
        """Adiciona entrada e atualiza ordem de inserção"""
        success = super().add_entry(key, value, compressed, encrypted)
        if success:
            self.insertion_order.append(key)
        return success
    
    def remove_entry(self, key: str) -> bool:
        """Remove entrada e atualiza ordem de inserção"""
        success = super().remove_entry(key)
        if success and key in self.insertion_order:
            self.insertion_order.remove(key)
        return success


class TTLStrategy(CacheStrategyBase):
    """Estratégia Time To Live"""
    
    def __init__(self, max_size: int, default_ttl: int = 3600):
        super().__init__(max_size)
        self.default_ttl = default_ttl
        self.ttl_map = {}
    
    def should_evict(self, key: str) -> bool:
        """TTL: remove se expirado"""
        if key not in self.ttl_map:
            return False
        
        ttl, created_at = self.ttl_map[key]
        return time.time() - created_at > ttl
    
    def on_access(self, key: str):
        """TTL não altera expiração no acesso"""
        pass
    
    def add_entry(self, key: str, value: Any, compressed: bool = False, encrypted: bool = False, ttl: Optional[int] = None) -> bool:
        """Adiciona entrada com TTL"""
        success = super().add_entry(key, value, compressed, encrypted)
        if success:
            self.ttl_map[key] = (ttl or self.default_ttl, time.time())
        return success
    
    def remove_entry(self, key: str) -> bool:
        """Remove entrada e TTL"""
        success = super().remove_entry(key)
        if success:
            self.ttl_map.pop(key, None)
        return success
    
    def cleanup_expired(self) -> int:
        """Remove entradas expiradas"""
        expired_keys = [key for key in self.entries.keys() if self.should_evict(key)]
        for key in expired_keys:
            self.remove_entry(key)
        return len(expired_keys)


class CacheCompressor:
    """Utilitário para compressão de dados"""
    
    @staticmethod
    def compress(data: Any) -> Tuple[bytes, bool]:
        """
        Comprime dados se benéfico.
        
        Args:
            data: Dados a comprimir
            
        Returns:
            Tuple[bytes, bool]: (dados comprimidos, se foi comprimido)
        """
        try:
            data_str = json.dumps(data, default=str)
            data_bytes = data_str.encode('utf-8')
            
            # Só comprime se for maior que 1KB
            if len(data_bytes) < 1024:
                return data_bytes, False
            
            compressed = gzip.compress(data_bytes)
            
            # Só retorna comprimido se for menor que o original
            if len(compressed) < len(data_bytes):
                return compressed, True
            
            return data_bytes, False
            
        except Exception as e:
            logger.error(f"Erro na compressão: {e}")
            return json.dumps(data, default=str).encode('utf-8'), False
    
    @staticmethod
    def decompress(data: bytes, was_compressed: bool) -> Any:
        """
        Descomprime dados.
        
        Args:
            data: Dados comprimidos
            was_compressed: Se os dados foram comprimidos
            
        Returns:
            Dados descomprimidos
        """
        try:
            if not was_compressed:
                return json.loads(data.decode('utf-8'))
            
            decompressed = gzip.decompress(data)
            return json.loads(decompressed.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Erro na descompressão: {e}")
            return None


class CacheEncryptor:
    """Utilitário para criptografia de dados"""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or "default-secret-key"
    
    def encrypt(self, data: Any) -> Tuple[bytes, bool]:
        """
        Criptografa dados.
        
        Args:
            data: Dados a criptografar
            
        Returns:
            Tuple[bytes, bool]: (dados criptografados, se foi criptografado)
        """
        try:
            # Implementação básica - em produção usar biblioteca de criptografia
            data_str = json.dumps(data, default=str)
            data_bytes = data_str.encode('utf-8')
            
            # XOR simples com a chave (apenas para demonstração)
            key_bytes = self.secret_key.encode('utf-8')
            encrypted = bytes(a ^ b for a, b in zip(data_bytes, key_bytes * (len(data_bytes) // len(key_bytes) + 1)))
            
            return encrypted, True
            
        except Exception as e:
            logger.error(f"Erro na criptografia: {e}")
            return json.dumps(data, default=str).encode('utf-8'), False
    
    def decrypt(self, data: bytes, was_encrypted: bool) -> Any:
        """
        Descriptografa dados.
        
        Args:
            data: Dados criptografados
            was_encrypted: Se os dados foram criptografados
            
        Returns:
            Dados descriptografados
        """
        try:
            if not was_encrypted:
                return json.loads(data.decode('utf-8'))
            
            # XOR simples com a chave (apenas para demonstração)
            key_bytes = self.secret_key.encode('utf-8')
            decrypted = bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // len(key_bytes) + 1)))
            
            return json.loads(decrypted.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Erro na descriptografia: {e}")
            return None


def create_strategy(strategy: CacheStrategy, max_size: int, **kwargs) -> CacheStrategyBase:
    """
    Factory para criar estratégias de cache.
    
    Args:
        strategy: Tipo de estratégia
        max_size: Tamanho máximo em MB
        **kwargs: Parâmetros adicionais
        
    Returns:
        CacheStrategyBase: Instância da estratégia
    """
    if strategy == CacheStrategy.LRU:
        return LRUStrategy(max_size)
    elif strategy == CacheStrategy.LFU:
        return LFUStrategy(max_size)
    elif strategy == CacheStrategy.FIFO:
        return FIFOStrategy(max_size)
    elif strategy == CacheStrategy.TTL:
        default_ttl = kwargs.get('default_ttl', 3600)
        return TTLStrategy(max_size, default_ttl)
    else:
        raise ValueError(f"Estratégia não suportada: {strategy}") 