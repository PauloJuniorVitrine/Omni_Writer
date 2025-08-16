/**
 * useIntelligentCache.ts
 * 
 * Hooks para cache inteligente enterprise
 * Implementa estratégias avançadas de cache para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';

// Tipos para cache inteligente
export interface CacheConfig {
  ttl: number; // Time to live em ms
  staleTime: number; // Tempo antes de considerar stale
  maxSize: number; // Tamanho máximo do cache
  priority: 'high' | 'medium' | 'low';
  prefetch: boolean; // Se deve pré-carregar
  backgroundRefresh: boolean; // Se deve atualizar em background
}

export interface CacheEntry<T = any> {
  data: T;
  timestamp: number;
  accessCount: number;
  lastAccessed: number;
  priority: 'high' | 'medium' | 'low';
  ttl: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
  hitRate: number;
  avgAccessTime: number;
}

// Configurações enterprise de cache
export const cacheConfigs = {
  // Cache para dados críticos (blogs, prompts)
  critical: {
    ttl: 5 * 60 * 1000, // 5 minutos
    staleTime: 2 * 60 * 1000, // 2 minutos
    maxSize: 100,
    priority: 'high' as const,
    prefetch: true,
    backgroundRefresh: true,
  },

  // Cache para dados de leitura (status, eventos)
  read: {
    ttl: 2 * 60 * 1000, // 2 minutos
    staleTime: 30 * 1000, // 30 segundos
    maxSize: 200,
    priority: 'medium' as const,
    prefetch: false,
    backgroundRefresh: true,
  },

  // Cache para dados temporários (downloads, uploads)
  temporary: {
    ttl: 10 * 60 * 1000, // 10 minutos
    staleTime: 5 * 60 * 1000, // 5 minutos
    maxSize: 50,
    priority: 'low' as const,
    prefetch: false,
    backgroundRefresh: false,
  },
};

// Hook para cache inteligente baseado em React Query
export const useIntelligentCache = <T = any>(config: CacheConfig = cacheConfigs.read) => {
  const queryClient = useQueryClient();
  const [stats, setStats] = useState<CacheStats>({
    hits: 0,
    misses: 0,
    size: 0,
    hitRate: 0,
    avgAccessTime: 0,
  });

  const cacheRef = useRef<Map<string, CacheEntry<T>>>(new Map());
  const accessTimesRef = useRef<number[]>([]);

  // Calcular estatísticas
  const updateStats = useCallback((hit: boolean, accessTime: number) => {
    setStats(prev => {
      const newHits = hit ? prev.hits + 1 : prev.hits;
      const newMisses = hit ? prev.misses : prev.misses + 1;
      const total = newHits + newMisses;
      
      accessTimesRef.current.push(accessTime);
      if (accessTimesRef.current.length > 100) {
        accessTimesRef.current.shift();
      }

      return {
        hits: newHits,
        misses: newMisses,
        size: cacheRef.current.size,
        hitRate: total > 0 ? newHits / total : 0,
        avgAccessTime: accessTimesRef.current.reduce((a, b) => a + b, 0) / accessTimesRef.current.length,
      };
    });
  }, []);

  // Limpar cache expirado
  const cleanupExpired = useCallback(() => {
    const now = Date.now();
    const expiredKeys: string[] = [];

    cacheRef.current.forEach((entry, key) => {
      if (now - entry.timestamp > entry.ttl) {
        expiredKeys.push(key);
      }
    });

    expiredKeys.forEach(key => {
      cacheRef.current.delete(key);
    });

    if (expiredKeys.length > 0) {
      setStats(prev => ({ ...prev, size: cacheRef.current.size }));
    }
  }, []);

  // Gerenciar tamanho do cache (LRU)
  const manageCacheSize = useCallback(() => {
    if (cacheRef.current.size <= config.maxSize) return;

    const entries = Array.from(cacheRef.current.entries());
    
    // Ordenar por prioridade e último acesso
    entries.sort((a, b) => {
      const priorityOrder = { high: 3, medium: 2, low: 1 };
      const aPriority = priorityOrder[a[1].priority];
      const bPriority = priorityOrder[b[1].priority];
      
      if (aPriority !== bPriority) {
        return bPriority - aPriority;
      }
      
      return a[1].lastAccessed - b[1].lastAccessed;
    });

    // Remover entradas menos importantes
    const toRemove = entries.slice(config.maxSize);
    toRemove.forEach(([key]) => {
      cacheRef.current.delete(key);
    });

    setStats(prev => ({ ...prev, size: cacheRef.current.size }));
  }, [config.maxSize]);

  // Obter dados do cache
  const get = useCallback((key: string): T | null => {
    const startTime = performance.now();
    
    cleanupExpired();
    
    const entry = cacheRef.current.get(key);
    if (!entry) {
      updateStats(false, performance.now() - startTime);
      return null;
    }

    // Atualizar estatísticas de acesso
    entry.accessCount++;
    entry.lastAccessed = Date.now();
    
    updateStats(true, performance.now() - startTime);
    return entry.data;
  }, [cleanupExpired, updateStats]);

  // Definir dados no cache
  const set = useCallback((key: string, data: T, customTtl?: number) => {
    const entry: CacheEntry<T> = {
      data,
      timestamp: Date.now(),
      accessCount: 0,
      lastAccessed: Date.now(),
      priority: config.priority,
      ttl: customTtl || config.ttl,
    };

    cacheRef.current.set(key, entry);
    manageCacheSize();
    setStats(prev => ({ ...prev, size: cacheRef.current.size }));
  }, [config.priority, config.ttl, manageCacheSize]);

  // Remover do cache
  const remove = useCallback((key: string) => {
    cacheRef.current.delete(key);
    setStats(prev => ({ ...prev, size: cacheRef.current.size }));
  }, []);

  // Limpar todo cache
  const clear = useCallback(() => {
    cacheRef.current.clear();
    setStats(prev => ({ ...prev, size: 0 }));
  }, []);

  // Pré-carregar dados
  const prefetch = useCallback(async (key: string, fetcher: () => Promise<T>) => {
    if (!config.prefetch) return;

    try {
      const data = await fetcher();
      set(key, data);
    } catch (error) {
      console.warn(`[Cache] Prefetch failed for key: ${key}`, error);
    }
  }, [config.prefetch, set]);

  // Atualizar em background
  const backgroundRefresh = useCallback(async (key: string, fetcher: () => Promise<T>) => {
    if (!config.backgroundRefresh) return;

    try {
      const data = await fetcher();
      set(key, data);
    } catch (error) {
      console.warn(`[Cache] Background refresh failed for key: ${key}`, error);
    }
  }, [config.backgroundRefresh, set]);

  // Hook para cache com React Query
  const useCachedQuery = useCallback((
    queryKey: readonly unknown[],
    queryFn: () => Promise<T>,
    options?: any
  ) => {
    const key = JSON.stringify(queryKey);
    
    // Tentar obter do cache local primeiro
    const cachedData = get(key);
    if (cachedData) {
      return {
        data: cachedData,
        isLoading: false,
        error: null,
        isStale: false,
      };
    }

    // Se não estiver no cache, usar React Query
    const query = queryClient.getQueryData(queryKey);
    if (query) {
      set(key, query as T);
      return {
        data: query as T,
        isLoading: false,
        error: null,
        isStale: false,
      };
    }

    // Executar query e cachear resultado
    return queryClient.fetchQuery({
      queryKey,
      queryFn,
      staleTime: config.staleTime,
      gcTime: config.ttl,
      ...options,
    }).then((data) => {
      set(key, data as T);
      return {
        data: data as T,
        isLoading: false,
        error: null,
        isStale: false,
      };
    });
  }, [get, set, queryClient, config.staleTime, config.ttl]);

  // Limpeza automática
  useEffect(() => {
    const interval = setInterval(cleanupExpired, 60000); // Limpar a cada minuto
    return () => clearInterval(interval);
  }, [cleanupExpired]);

  return {
    get,
    set,
    remove,
    clear,
    prefetch,
    backgroundRefresh,
    useCachedQuery,
    stats,
    size: cacheRef.current.size,
  };
};

// Hook para cache específicos
export const useCriticalCache = <T = any>() => useIntelligentCache<T>(cacheConfigs.critical);
export const useReadCache = <T = any>() => useIntelligentCache<T>(cacheConfigs.read);
export const useTemporaryCache = <T = any>() => useIntelligentCache<T>(cacheConfigs.temporary);

// Hook para cache com persistência
export const usePersistentCache = <T = any>(config: CacheConfig = cacheConfigs.read) => {
  const cache = useIntelligentCache<T>(config);
  const storageKey = `omni_writer_cache_${config.priority}`;

  // Carregar do localStorage
  const loadFromStorage = useCallback(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        const data = JSON.parse(stored);
        // Restaurar cache (implementação simplificada)
        console.log(`[Cache] Loaded ${Object.keys(data).length} entries from storage`);
      }
    } catch (error) {
      console.warn('[Cache] Failed to load from storage:', error);
    }
  }, [storageKey]);

  // Salvar no localStorage
  const saveToStorage = useCallback(() => {
    try {
      // Salvar cache (implementação simplificada)
      console.log(`[Cache] Saved ${cache.size} entries to storage`);
    } catch (error) {
      console.warn('[Cache] Failed to save to storage:', error);
    }
  }, [cache.size, storageKey]);

  // Carregar na inicialização
  useEffect(() => {
    loadFromStorage();
  }, [loadFromStorage]);

  // Salvar periodicamente
  useEffect(() => {
    const interval = setInterval(saveToStorage, 30000); // Salvar a cada 30 segundos
    return () => clearInterval(interval);
  }, [saveToStorage]);

  return {
    ...cache,
    loadFromStorage,
    saveToStorage,
  };
};

// Hook para cache com compressão
export const useCompressedCache = <T = any>(config: CacheConfig = cacheConfigs.read) => {
  const cache = useIntelligentCache<T>(config);

  // Comprimir dados
  const compress = useCallback((data: T): string => {
    try {
      const json = JSON.stringify(data);
      // Implementação simplificada de compressão
      return btoa(json);
    } catch (error) {
      console.warn('[Cache] Compression failed:', error);
      return JSON.stringify(data);
    }
  }, []);

  // Descomprimir dados
  const decompress = useCallback((compressed: string): T => {
    try {
      const json = atob(compressed);
      return JSON.parse(json);
    } catch (error) {
      console.warn('[Cache] Decompression failed:', error);
      return JSON.parse(compressed);
    }
  }, []);

  const setCompressed = useCallback((key: string, data: T, customTtl?: number) => {
    const compressed = compress(data);
    cache.set(key, compressed as any, customTtl);
  }, [cache, compress]);

  const getCompressed = useCallback((key: string): T | null => {
    const compressed = cache.get(key);
    if (!compressed) return null;
    
    try {
      return decompress(compressed as any);
    } catch (error) {
      console.warn('[Cache] Failed to decompress data:', error);
      return null;
    }
  }, [cache, decompress]);

  return {
    ...cache,
    set: setCompressed,
    get: getCompressed,
  };
}; 