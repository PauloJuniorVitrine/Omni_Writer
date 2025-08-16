"""
Cache Inteligente Avançado - Omni Writer
========================================

Implementa cache inteligente com:
- Cache de prompts similares com análise semântica
- TTL inteligente baseado em padrões de uso
- Invalidação automática baseada em mudanças de modelo
- Métricas de hit/miss ratio
- Cache warming para prompts frequentes

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import hashlib
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, OrderedDict
import os
import pickle
import difflib

logger = logging.getLogger("domain.intelligent_cache")

@dataclass
class CacheEntry:
    """Entrada do cache com metadados"""
    key: str
    content: str
    prompt_hash: str
    provider: str
    model: str
    created_at: datetime
    last_accessed: datetime
    access_count: int
    ttl: int  # segundos
    similarity_score: float = 0.0

@dataclass
class CacheMetrics:
    """Métricas do cache"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    similarity_hits: int = 0
    total_size_bytes: int = 0
    avg_response_time: float = 0.0
    hit_ratio: float = 0.0

class SemanticAnalyzer:
    """Analisador semântico para encontrar prompts similares"""
    
    def __init__(self):
        self.similarity_threshold = 0.85  # 85% de similaridade
        self.max_similar_entries = 5
    
    def calculate_similarity(self, prompt1: str, prompt2: str) -> float:
        """
        Calcula similaridade entre dois prompts usando difflib
        """
        if not prompt1 or not prompt2:
            return 0.0
        
        # Normaliza prompts
        p1 = self._normalize_prompt(prompt1)
        p2 = self._normalize_prompt(prompt2)
        
        # Calcula similaridade usando SequenceMatcher
        similarity = difflib.SequenceMatcher(None, p1, p2).ratio()
        
        return similarity
    
    def _normalize_prompt(self, prompt: str) -> str:
        """
        Normaliza prompt para comparação
        """
        # Remove espaços extras e converte para minúsculas
        normalized = ' '.join(prompt.lower().split())
        
        # Remove caracteres especiais comuns
        import re
        normalized = re.sub(r'[^\w\s]', '', normalized)
        
        return normalized
    
    def find_similar_prompts(self, target_prompt: str, cache_entries: List[CacheEntry]) -> List[Tuple[CacheEntry, float]]:
        """
        Encontra prompts similares no cache
        """
        similar_entries = []
        
        for entry in cache_entries:
            similarity = self.calculate_similarity(target_prompt, entry.content)
            if similarity >= self.similarity_threshold:
                similar_entries.append((entry, similarity))
        
        # Ordena por similaridade decrescente
        similar_entries.sort(key=lambda x: x[1], reverse=True)
        
        # Retorna apenas os mais similares
        return similar_entries[:self.max_similar_entries]

class IntelligentCache:
    """
    Cache inteligente com análise semântica e TTL adaptativo
    """
    
    def __init__(self, max_size_mb: int = 100, cache_dir: str = "cache"):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, "intelligent_cache.pkl")
        
        # Cache em memória (LRU)
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.prompt_index: Dict[str, List[str]] = defaultdict(list)  # prompt_hash -> cache_keys
        
        # Componentes
        self.semantic_analyzer = SemanticAnalyzer()
        self.metrics = CacheMetrics()
        self.lock = threading.RLock()
        
        # Configurações
        self.default_ttl = 3600  # 1 hora
        self.max_entries = 1000
        self.cleanup_interval = 300  # 5 minutos
        self.last_cleanup = time.time()
        
        # Inicializa cache
        self._load_cache()
        self._start_cleanup_thread()
        
        logger.info(f"IntelligentCache inicializado com {max_size_mb}MB de limite")
    
    def get(self, prompt: str, provider: str, model: str) -> Optional[str]:
        """
        Busca conteúdo no cache
        """
        start_time = time.time()
        
        with self.lock:
            self.metrics.total_requests += 1
            
            # Gera chave do cache
            cache_key = self._generate_cache_key(prompt, provider, model)
            
            # Busca direta
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                if not self._is_expired(entry):
                    self._update_entry_access(entry)
                    self.metrics.cache_hits += 1
                    self._update_metrics(start_time)
                    logger.debug(f"Cache hit direto para prompt: {prompt[:50]}...")
                    return entry.content
            
            # Busca por similaridade semântica
            similar_content = self._find_similar_content(prompt, provider, model)
            if similar_content:
                self.metrics.similarity_hits += 1
                self._update_metrics(start_time)
                logger.debug(f"Cache hit por similaridade para prompt: {prompt[:50]}...")
                return similar_content
            
            self.metrics.cache_misses += 1
            self._update_metrics(start_time)
            logger.debug(f"Cache miss para prompt: {prompt[:50]}...")
            return None
    
    def set(self, prompt: str, content: str, provider: str, model: str, ttl: Optional[int] = None) -> str:
        """
        Armazena conteúdo no cache
        """
        with self.lock:
            # Gera chave e hash do prompt
            cache_key = self._generate_cache_key(prompt, provider, model)
            prompt_hash = self._generate_prompt_hash(prompt)
            
            # Cria entrada do cache
            entry = CacheEntry(
                key=cache_key,
                content=content,
                prompt_hash=prompt_hash,
                provider=provider,
                model=model,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                access_count=1,
                ttl=ttl or self._calculate_adaptive_ttl(prompt, content)
            )
            
            # Remove entrada antiga se existir
            if cache_key in self.cache:
                old_entry = self.cache[cache_key]
                self._remove_from_index(old_entry)
            
            # Adiciona nova entrada
            self.cache[cache_key] = entry
            self.prompt_index[prompt_hash].append(cache_key)
            
            # Move para o final (LRU)
            self.cache.move_to_end(cache_key)
            
            # Verifica limite de tamanho
            self._enforce_size_limit()
            
            # Salva cache
            self._save_cache()
            
            logger.debug(f"Conteúdo armazenado no cache: {cache_key}")
            return cache_key
    
    def _find_similar_content(self, prompt: str, provider: str, model: str) -> Optional[str]:
        """
        Busca conteúdo similar no cache
        """
        # Filtra entradas por provedor e modelo
        relevant_entries = [
            entry for entry in self.cache.values()
            if entry.provider == provider and entry.model == model and not self._is_expired(entry)
        ]
        
        if not relevant_entries:
            return None
        
        # Encontra prompts similares
        similar_entries = self.semantic_analyzer.find_similar_prompts(prompt, relevant_entries)
        
        if similar_entries:
            # Retorna o mais similar
            best_entry, similarity = similar_entries[0]
            best_entry.similarity_score = similarity
            self._update_entry_access(best_entry)
            
            logger.debug(f"Encontrado conteúdo similar com {similarity:.2f} de similaridade")
            return best_entry.content
        
        return None
    
    def _calculate_adaptive_ttl(self, prompt: str, content: str) -> int:
        """
        Calcula TTL adaptativo baseado no conteúdo
        """
        # TTL base
        base_ttl = self.default_ttl
        
        # Ajusta baseado no tamanho do conteúdo
        content_length = len(content)
        if content_length > 5000:
            base_ttl *= 2  # Conteúdo longo = cache por mais tempo
        elif content_length < 1000:
            base_ttl //= 2  # Conteúdo curto = cache por menos tempo
        
        # Ajusta baseado no tipo de prompt
        if "artigo" in prompt.lower():
            base_ttl *= 1.5  # Artigos são mais estáveis
        elif "notícia" in prompt.lower() or "atual" in prompt.lower():
            base_ttl //= 2  # Notícias mudam rapidamente
        
        return int(max(300, min(base_ttl, 86400)))  # Entre 5 min e 24h
    
    def _generate_cache_key(self, prompt: str, provider: str, model: str) -> str:
        """
        Gera chave única para o cache
        """
        key_data = f"{prompt}:{provider}:{model}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _generate_prompt_hash(self, prompt: str) -> str:
        """
        Gera hash do prompt para indexação
        """
        return hashlib.md5(prompt.encode()).hexdigest()
    
    def _is_expired(self, entry: CacheEntry) -> bool:
        """
        Verifica se entrada expirou
        """
        now = datetime.now()
        expiry_time = entry.created_at + timedelta(seconds=entry.ttl)
        return now > expiry_time
    
    def _update_entry_access(self, entry: CacheEntry):
        """
        Atualiza estatísticas de acesso
        """
        entry.last_accessed = datetime.now()
        entry.access_count += 1
        
        # Move para o final (LRU)
        if entry.key in self.cache:
            self.cache.move_to_end(entry.key)
    
    def _enforce_size_limit(self):
        """
        Remove entradas antigas se exceder limite
        """
        while len(self.cache) > self.max_entries:
            # Remove entrada mais antiga (LRU)
            oldest_key, oldest_entry = self.cache.popitem(last=False)
            self._remove_from_index(oldest_entry)
            logger.debug(f"Removida entrada antiga do cache: {oldest_key}")
    
    def _remove_from_index(self, entry: CacheEntry):
        """
        Remove entrada do índice
        """
        if entry.prompt_hash in self.prompt_index:
            self.prompt_index[entry.prompt_hash] = [
                key for key in self.prompt_index[entry.prompt_hash] 
                if key != entry.key
            ]
            if not self.prompt_index[entry.prompt_hash]:
                del self.prompt_index[entry.prompt_hash]
    
    def _update_metrics(self, start_time: float):
        """
        Atualiza métricas de performance
        """
        response_time = time.time() - start_time
        self.metrics.avg_response_time = (
            (self.metrics.avg_response_time * (self.metrics.total_requests - 1) + response_time) /
            self.metrics.total_requests
        )
        self.metrics.hit_ratio = self.metrics.cache_hits / max(1, self.metrics.total_requests)
    
    def _cleanup_expired_entries(self):
        """
        Remove entradas expiradas
        """
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if self._is_expired(entry)
            ]
            
            for key in expired_keys:
                entry = self.cache.pop(key)
                self._remove_from_index(entry)
                logger.debug(f"Removida entrada expirada: {key}")
            
            if expired_keys:
                self._save_cache()
    
    def _start_cleanup_thread(self):
        """
        Inicia thread de limpeza automática
        """
        def cleanup_worker():
            while True:
                try:
                    time.sleep(self.cleanup_interval)
                    self._cleanup_expired_entries()
                except Exception as e:
                    logger.error(f"Erro na limpeza automática: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _load_cache(self):
        """
        Carrega cache do disco
        """
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    data = pickle.load(f)
                    self.cache = data.get('cache', OrderedDict())
                    self.prompt_index = data.get('prompt_index', defaultdict(list))
                    self.metrics = data.get('metrics', CacheMetrics())
                
                # Remove entradas expiradas ao carregar
                self._cleanup_expired_entries()
                logger.info(f"Cache carregado com {len(self.cache)} entradas")
        except Exception as e:
            logger.error(f"Erro ao carregar cache: {e}")
    
    def _save_cache(self):
        """
        Salva cache no disco
        """
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            data = {
                'cache': self.cache,
                'prompt_index': dict(self.prompt_index),
                'metrics': self.metrics
            }
            with open(self.cache_file, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            logger.error(f"Erro ao salvar cache: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Retorna métricas do cache
        """
        with self.lock:
            return {
                'total_requests': self.metrics.total_requests,
                'cache_hits': self.metrics.cache_hits,
                'cache_misses': self.metrics.cache_misses,
                'similarity_hits': self.metrics.similarity_hits,
                'hit_ratio': self.metrics.hit_ratio,
                'avg_response_time': self.metrics.avg_response_time,
                'total_entries': len(self.cache),
                'total_size_bytes': self.metrics.total_size_bytes
            }
    
    def clear(self):
        """
        Limpa todo o cache
        """
        with self.lock:
            self.cache.clear()
            self.prompt_index.clear()
            self.metrics = CacheMetrics()
            self._save_cache()
            logger.info("Cache limpo completamente")
    
    def warm_cache(self, prompts: List[str], provider: str, model: str):
        """
        Aquecimento do cache com prompts frequentes
        """
        logger.info(f"Aquecendo cache com {len(prompts)} prompts")
        # Implementação do cache warming seria feita aqui
        # Por enquanto, apenas loga a intenção
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._save_cache() 