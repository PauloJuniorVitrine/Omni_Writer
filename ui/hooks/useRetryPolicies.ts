/**
 * useRetryPolicies.ts
 * 
 * Hooks para retry policies enterprise
 * Implementa estratégias avançadas de retry para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import { useState, useCallback, useRef } from 'react';
import { apiUtils } from '../services/apiClient';

// Tipos para retry policies
export interface RetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  jitter: boolean;
  retryCondition: (error: any, retryCount: number) => boolean;
}

export interface RetryState {
  retryCount: number;
  isRetrying: boolean;
  lastError: any;
  nextRetryDelay: number;
}

// Configurações enterprise de retry
export const retryConfigs = {
  // Retry para operações críticas (criação, geração)
  critical: {
    maxRetries: 5,
    baseDelay: 1000,
    maxDelay: 30000,
    backoffMultiplier: 2,
    jitter: true,
    retryCondition: (error: any, retryCount: number) => {
      // Retry para erros 5xx e de rede
      if (error?.response?.status >= 500) return true;
      if (error?.code === 'NETWORK_ERROR') return true;
      if (error?.code === 'ECONNABORTED') return true;
      
      // Retry limitado para rate limits
      if (error?.response?.status === 429 && retryCount < 3) return true;
      if (error?.response?.status === 408 && retryCount < 2) return true;
      
      return false;
    },
  },

  // Retry para operações de leitura
  read: {
    maxRetries: 3,
    baseDelay: 500,
    maxDelay: 10000,
    backoffMultiplier: 1.5,
    jitter: true,
    retryCondition: (error: any, retryCount: number) => {
      // Retry apenas para erros 5xx e de rede
      if (error?.response?.status >= 500) return true;
      if (error?.code === 'NETWORK_ERROR') return true;
      
      return false;
    },
  },

  // Retry para operações de atualização
  update: {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 15000,
    backoffMultiplier: 2,
    jitter: true,
    retryCondition: (error: any, retryCount: number) => {
      // Retry para erros 5xx e conflitos
      if (error?.response?.status >= 500) return true;
      if (error?.response?.status === 409 && retryCount < 2) return true; // Conflict
      if (error?.code === 'NETWORK_ERROR') return true;
      
      return false;
    },
  },

  // Retry para operações de exclusão
  delete: {
    maxRetries: 2,
    baseDelay: 2000,
    maxDelay: 10000,
    backoffMultiplier: 2,
    jitter: false,
    retryCondition: (error: any, retryCount: number) => {
      // Retry apenas para erros 5xx
      if (error?.response?.status >= 500) return true;
      
      return false;
    },
  },
};

// Hook para calcular delay de retry com jitter
export const useRetryDelay = (config: RetryConfig) => {
  return useCallback((retryCount: number): number => {
    const delay = Math.min(
      config.baseDelay * Math.pow(config.backoffMultiplier, retryCount),
      config.maxDelay
    );

    if (config.jitter) {
      // Adicionar jitter para evitar thundering herd
      const jitter = Math.random() * 0.1 * delay;
      return delay + jitter;
    }

    return delay;
  }, [config]);
};

// Hook principal para retry policies
export const useRetryPolicy = (config: RetryConfig = retryConfigs.read) => {
  const [retryState, setRetryState] = useState<RetryState>({
    retryCount: 0,
    isRetrying: false,
    lastError: null,
    nextRetryDelay: 0,
  });

  const timeoutRef = useRef<NodeJS.Timeout>();
  const calculateDelay = useRetryDelay(config);

  const resetRetry = useCallback(() => {
    setRetryState({
      retryCount: 0,
      isRetrying: false,
      lastError: null,
      nextRetryDelay: 0,
    });
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
  }, []);

  const executeWithRetry = useCallback(
    async <T>(
      operation: () => Promise<T>,
      onRetry?: (error: any, retryCount: number, delay: number) => void,
      onMaxRetriesExceeded?: (error: any) => void
    ): Promise<T> => {
      let currentRetryCount = 0;

      while (true) {
        try {
          setRetryState(prev => ({
            ...prev,
            isRetrying: false,
            lastError: null,
          }));

          return await operation();
        } catch (error) {
          currentRetryCount++;
          const shouldRetry = config.retryCondition(error, currentRetryCount);
          const delay = calculateDelay(currentRetryCount);

          setRetryState(prev => ({
            ...prev,
            retryCount: currentRetryCount,
            lastError: error,
            nextRetryDelay: delay,
          }));

          if (!shouldRetry || currentRetryCount >= config.maxRetries) {
            setRetryState(prev => ({
              ...prev,
              isRetrying: false,
            }));

            if (onMaxRetriesExceeded) {
              onMaxRetriesExceeded(error);
            }

            throw error;
          }

          setRetryState(prev => ({
            ...prev,
            isRetrying: true,
          }));

          if (onRetry) {
            onRetry(error, currentRetryCount, delay);
          }

          // Aguardar antes do próximo retry
          await new Promise(resolve => {
            timeoutRef.current = setTimeout(resolve, delay);
          });
        }
      }
    },
    [config, calculateDelay]
  );

  return {
    executeWithRetry,
    resetRetry,
    retryState,
  };
};

// Hook para retry policies específicas
export const useCriticalRetry = () => useRetryPolicy(retryConfigs.critical);
export const useReadRetry = () => useRetryPolicy(retryConfigs.read);
export const useUpdateRetry = () => useRetryPolicy(retryConfigs.update);
export const useDeleteRetry = () => useRetryPolicy(retryConfigs.delete);

// Hook para retry com circuit breaker
export const useCircuitBreakerRetry = (failureThreshold: number = 5, timeout: number = 60000) => {
  const [failureCount, setFailureCount] = useState(0);
  const [lastFailureTime, setLastFailureTime] = useState<number | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const resetCircuitBreaker = useCallback(() => {
    setFailureCount(0);
    setLastFailureTime(null);
    setIsOpen(false);
  }, []);

  const executeWithCircuitBreaker = useCallback(
    async <T>(operation: () => Promise<T>): Promise<T> => {
      // Verificar se circuit breaker está aberto
      if (isOpen) {
        const timeSinceLastFailure = Date.now() - (lastFailureTime || 0);
        if (timeSinceLastFailure < timeout) {
          throw new Error('Circuit breaker is open');
        }
        // Timeout expirado, tentar fechar
        resetCircuitBreaker();
      }

      try {
        const result = await operation();
        // Sucesso, resetar contadores
        resetCircuitBreaker();
        return result;
      } catch (error) {
        // Incrementar contador de falhas
        const newFailureCount = failureCount + 1;
        setFailureCount(newFailureCount);
        setLastFailureTime(Date.now());

        // Verificar se deve abrir circuit breaker
        if (newFailureCount >= failureThreshold) {
          setIsOpen(true);
        }

        throw error;
      }
    },
    [isOpen, lastFailureTime, timeout, failureCount, resetCircuitBreaker]
  );

  return {
    executeWithCircuitBreaker,
    resetCircuitBreaker,
    isOpen,
    failureCount,
  };
};

// Hook para retry com exponential backoff e jitter
export const useExponentialBackoffRetry = (
  maxRetries: number = 3,
  baseDelay: number = 1000,
  maxDelay: number = 10000
) => {
  const calculateDelay = useCallback((retryCount: number): number => {
    const delay = Math.min(baseDelay * Math.pow(2, retryCount), maxDelay);
    const jitter = Math.random() * 0.1 * delay;
    return delay + jitter;
  }, [baseDelay, maxDelay]);

  const executeWithBackoff = useCallback(
    async <T>(
      operation: () => Promise<T>,
      shouldRetry: (error: any, retryCount: number) => boolean = () => true
    ): Promise<T> => {
      let lastError: any;

      for (let retryCount = 0; retryCount <= maxRetries; retryCount++) {
        try {
          return await operation();
        } catch (error) {
          lastError = error;

          if (retryCount === maxRetries || !shouldRetry(error, retryCount)) {
            throw error;
          }

          const delay = calculateDelay(retryCount);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }

      throw lastError;
    },
    [maxRetries, calculateDelay]
  );

  return { executeWithBackoff };
}; 