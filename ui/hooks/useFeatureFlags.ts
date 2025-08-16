import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { FeatureFlagsResponse, FeatureFlagResponse } from '../../shared/types/api_types';

/**
 * Hook para gerenciamento de feature flags no frontend.
 * 
 * Tracing ID: FEATURE_FLAGS_FRONTEND_20250127_001
 * Data/Hora: 2025-01-27T22:30:00Z
 * Prompt: Implementar features flags de API pendentes
 * Ruleset: Enterprise+ Standards
 * 
 * Funcionalidades:
 * - Cache inteligente com TTL configurável
 * - Fallback para flags padrão em caso de erro
 * - Integração com sistema de autenticação
 * - Retry automático em caso de falha
 * - Suporte a contexto de usuário e sessão
 */

interface FeatureFlagsConfig {
  cacheTTL: number; // TTL do cache em ms
  retryAttempts: number; // Número de tentativas
  retryDelay: number; // Delay entre tentativas em ms
  fallbackFlags: Record<string, boolean>; // Flags padrão
}

const DEFAULT_CONFIG: FeatureFlagsConfig = {
  cacheTTL: 5 * 60 * 1000, // 5 minutos
  retryAttempts: 3,
  retryDelay: 1000,
  fallbackFlags: {
    enable_streaming: true,
    enable_webhooks: true,
    enable_analytics: true,
    enable_premium_features: false,
    advanced_generation_enabled: true,
    feedback_system_enabled: true,
    api_generation_enabled: true,
    stripe_payment_enabled: false,
    service_mesh_enabled: false,
    proactive_intelligence_enabled: false,
    contract_drift_prediction_enabled: false,
    multi_region_enabled: false,
    advanced_caching_enabled: true,
    parallel_processing_enabled: true,
    enhanced_security_enabled: true
  }
};

interface CacheEntry {
  data: Record<string, FeatureFlagResponse>;
  timestamp: number;
  expiresAt: number;
}

export function useFeatureFlags(config: Partial<FeatureFlagsConfig> = {}) {
  const [flags, setFlags] = useState<Record<string, FeatureFlagResponse>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  
  const { token, user } = useAuth();
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  
  // Cache em memória
  const cacheRef = useRef<CacheEntry | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  /**
   * Verifica se o cache é válido.
   */
  const isCacheValid = useCallback((): boolean => {
    if (!cacheRef.current) return false;
    return Date.now() < cacheRef.current.expiresAt;
  }, []);

  /**
   * Obtém flags do cache se válido.
   */
  const getFromCache = useCallback((): Record<string, FeatureFlagResponse> | null => {
    if (isCacheValid() && cacheRef.current) {
      return cacheRef.current.data;
    }
    return null;
  }, [isCacheValid]);

  /**
   * Salva flags no cache.
   */
  const saveToCache = useCallback((data: Record<string, FeatureFlagResponse>) => {
    const now = Date.now();
    cacheRef.current = {
      data,
      timestamp: now,
      expiresAt: now + finalConfig.cacheTTL
    };
  }, [finalConfig.cacheTTL]);

  /**
   * Obtém feature flags da API.
   */
  const fetchFeatureFlags = useCallback(async (): Promise<Record<string, FeatureFlagResponse>> => {
    try {
      // Cancela requisição anterior se existir
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      
      abortControllerRef.current = new AbortController();
      
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      };
      
      // Adiciona token de autenticação se disponível
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      // Adiciona contexto de usuário se disponível
      if (user?.id) {
        headers['X-User-ID'] = user.id;
      }
      
      // Adiciona session ID se disponível
      const sessionId = sessionStorage.getItem('session_id');
      if (sessionId) {
        headers['X-Session-ID'] = sessionId;
      }
      
      const response = await fetch('/api/feature-flags', {
        method: 'GET',
        headers,
        signal: abortControllerRef.current.signal
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result: FeatureFlagsResponse = await response.json();
      
      if (!result.success) {
        throw new Error(result.error || 'Erro ao obter feature flags');
      }
      
      return result.data;
      
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw error; // Re-throw abort errors
      }
      
      console.error('Erro ao obter feature flags:', error);
      throw error;
    }
  }, [token, user]);

  /**
   * Carrega feature flags com retry logic.
   */
  const loadFeatureFlags = useCallback(async (attempt: number = 0): Promise<void> => {
    try {
      setLoading(true);
      setError(null);
      
      // Tenta obter do cache primeiro
      const cachedFlags = getFromCache();
      if (cachedFlags) {
        setFlags(cachedFlags);
        setLastUpdated(new Date());
        setLoading(false);
        return;
      }
      
      // Obtém da API
      const apiFlags = await fetchFeatureFlags();
      
      // Salva no cache
      saveToCache(apiFlags);
      
      // Atualiza estado
      setFlags(apiFlags);
      setLastUpdated(new Date());
      setLoading(false);
      
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        return; // Ignora erros de abort
      }
      
      // Retry logic
      if (attempt < finalConfig.retryAttempts) {
        console.warn(`Tentativa ${attempt + 1} falhou, tentando novamente...`);
        setTimeout(() => {
          loadFeatureFlags(attempt + 1);
        }, finalConfig.retryDelay * (attempt + 1));
        return;
      }
      
      // Usa fallback após todas as tentativas
      console.warn('Usando feature flags padrão devido a erro na API');
      const fallbackFlags: Record<string, FeatureFlagResponse> = {};
      
      Object.entries(finalConfig.fallbackFlags).forEach(([flagName, enabled]) => {
        fallbackFlags[flagName] = {
          enabled,
          config: {
            name: flagName,
            status: enabled ? 'ENABLED' : 'DISABLED',
            type: 'RELEASE',
            description: `Fallback flag for ${flagName}`,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          },
          metadata: {
            checked_at: new Date().toISOString(),
            user_id: user?.id
          }
        };
      });
      
      setFlags(fallbackFlags);
      setError('Erro ao carregar feature flags, usando configuração padrão');
      setLoading(false);
    }
  }, [getFromCache, fetchFeatureFlags, saveToCache, finalConfig, user]);

  /**
   * Verifica se uma feature flag está habilitada.
   */
  const isEnabled = useCallback((flagName: string): boolean => {
    const flag = flags[flagName];
    return flag?.enabled ?? finalConfig.fallbackFlags[flagName] ?? false;
  }, [flags, finalConfig.fallbackFlags]);

  /**
   * Obtém configuração de uma feature flag.
   */
  const getFlagConfig = useCallback((flagName: string) => {
    return flags[flagName]?.config;
  }, [flags]);

  /**
   * Força recarregamento das flags.
   */
  const refresh = useCallback(() => {
    cacheRef.current = null; // Invalida cache
    loadFeatureFlags();
  }, [loadFeatureFlags]);

  /**
   * Carrega flags na inicialização.
   */
  useEffect(() => {
    loadFeatureFlags();
    
    // Cleanup function
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [loadFeatureFlags]);

  /**
   * Recarrega flags quando token ou usuário muda.
   */
  useEffect(() => {
    if (token || user) {
      refresh();
    }
  }, [token, user, refresh]);

  return {
    flags,
    loading,
    error,
    lastUpdated,
    isEnabled,
    getFlagConfig,
    refresh,
    // Utilitários para flags específicas
    enableStreaming: isEnabled('enable_streaming'),
    enableWebhooks: isEnabled('enable_webhooks'),
    enableAnalytics: isEnabled('enable_analytics'),
    enablePremiumFeatures: isEnabled('enable_premium_features'),
    advancedGenerationEnabled: isEnabled('advanced_generation_enabled'),
    feedbackSystemEnabled: isEnabled('feedback_system_enabled'),
    apiGenerationEnabled: isEnabled('api_generation_enabled'),
    stripePaymentEnabled: isEnabled('stripe_payment_enabled'),
    serviceMeshEnabled: isEnabled('service_mesh_enabled'),
    proactiveIntelligenceEnabled: isEnabled('proactive_intelligence_enabled'),
    contractDriftPredictionEnabled: isEnabled('contract_drift_prediction_enabled'),
    multiRegionEnabled: isEnabled('multi_region_enabled'),
    advancedCachingEnabled: isEnabled('advanced_caching_enabled'),
    parallelProcessingEnabled: isEnabled('parallel_processing_enabled'),
    enhancedSecurityEnabled: isEnabled('enhanced_security_enabled')
  };
} 