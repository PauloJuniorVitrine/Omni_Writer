import { useState, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';

/**
 * Configurações de timeout e retry para requisições API.
 * 
 * Tracing ID: COMM_IMPL_20250128_001
 * Data/Hora: 2025-01-28T11:25:00Z
 * Prompt: Fullstack Communication Audit
 * Ruleset: Enterprise+ Standards
 */
interface ApiConfig {
  timeout: number; // Timeout em ms
  maxRetries: number; // Máximo de tentativas
  retryDelay: number; // Delay entre tentativas em ms
  backoffMultiplier: number; // Multiplicador de backoff exponencial
}

const DEFAULT_CONFIG: ApiConfig = {
  timeout: 30000, // 30 segundos
  maxRetries: 3,
  retryDelay: 1000, // 1 segundo
  backoffMultiplier: 2
};

/**
 * Hook para requisições REST com timeout global, retry logic e feedback visual.
 * 
 * Funcionalidades:
 * - Timeout configurável para prevenir travamentos
 * - Retry logic com backoff exponencial
 * - Feedback visual de progresso
 * - Tratamento de erros estruturado
 * - Autenticação automática com Bearer Token
 * 
 * @example
 * const { data, loading, error, request, retryCount } = useApi();
 * useEffect(() => { request('/api/blogs'); }, []);
 */
export function useApi<T = any>(config: Partial<ApiConfig> = {}) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [timeoutReached, setTimeoutReached] = useState(false);
  const { token } = useAuth();
  
  // Configuração final (merge com defaults)
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  
  // Ref para controlar timeout
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  /**
   * Cria um timeout para a requisição.
   */
  const createTimeout = (timeoutMs: number): Promise<never> => {
    return new Promise((_, reject) => {
      timeoutRef.current = setTimeout(() => {
        setTimeoutReached(true);
        reject(new Error(`Timeout: Requisição excedeu ${timeoutMs}ms`));
      }, timeoutMs);
    });
  };

  /**
   * Calcula delay para retry com backoff exponencial.
   */
  const calculateRetryDelay = (attempt: number): number => {
    return finalConfig.retryDelay * Math.pow(finalConfig.backoffMultiplier, attempt);
  };

  /**
   * Executa requisição com retry logic.
   */
  const executeWithRetry = async (
    url: string, 
    options: RequestInit, 
    attempt: number = 0
  ): Promise<any> => {
    try {
      // Cria AbortController para cancelar requisição
      abortControllerRef.current = new AbortController();
      
      // Combina signal do AbortController com options existentes
      const finalOptions = {
        ...options,
        signal: abortControllerRef.current.signal
      };

      // Executa requisição com timeout
      const response = await Promise.race([
        fetch(url, finalOptions),
        createTimeout(finalConfig.timeout)
      ]);

      // Limpa timeout se sucesso
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }

      if (!response.ok) {
        throw new Error(`Erro ${response.status}: ${response.statusText}`);
      }

      const json = await response.json();
      return json;

    } catch (err: any) {
      // Limpa timeout em caso de erro
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }

      // Verifica se deve tentar novamente
      if (attempt < finalConfig.maxRetries && !err.message.includes('Timeout')) {
        const delay = calculateRetryDelay(attempt);
        console.info(`[useApi] Tentativa ${attempt + 1} falhou, tentando novamente em ${delay}ms:`, err.message);
        
        setRetryCount(attempt + 1);
        await new Promise(resolve => setTimeout(resolve, delay));
        
        return executeWithRetry(url, options, attempt + 1);
      }

      throw err;
    }
  };

  const request = useCallback(async (url: string, options?: RequestInit) => {
    setLoading(true);
    setError(null);
    setRetryCount(0);
    setTimeoutReached(false);

    let finalOptions = { ...options };
    
    // Adiciona headers de autenticação
    if (token) {
      finalOptions.headers = {
        ...(options?.headers || {}),
        Authorization: `Bearer ${token}`,
      };
    }

    // Adiciona headers de rastreamento
    finalOptions.headers = {
      ...finalOptions.headers,
      'X-Request-ID': `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      'X-Client-Version': '1.0.0'
    };

    console.info('[useApi] Requisição iniciada:', { 
      url, 
      config: finalConfig,
      headers: finalOptions.headers 
    });

    try {
      const json = await executeWithRetry(url, finalOptions);
      
      setData(json);
      console.info('[useApi] Resposta bem-sucedida:', { 
        url, 
        retryCount,
        data: json 
      });
      
      return json;

    } catch (err: any) {
      const errorMessage = err.message || 'Erro desconhecido';
      setError(errorMessage);
      setData(null);
      
      console.warn('[useApi] Erro final:', { 
        url, 
        error: errorMessage,
        retryCount,
        timeoutReached 
      });
      
      return null;

    } finally {
      setLoading(false);
      // Limpa timeout se ainda existir
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    }
  }, [token, finalConfig]);

  /**
   * Cancela requisição em andamento.
   */
  const cancelRequest = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    
    setLoading(false);
    setError('Requisição cancelada pelo usuário');
    console.info('[useApi] Requisição cancelada pelo usuário');
  }, []);

  return { 
    data, 
    loading, 
    error, 
    request, 
    retryCount,
    timeoutReached,
    cancelRequest,
    config: finalConfig
  };
} 