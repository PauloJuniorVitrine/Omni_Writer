/**
 * useSWR.ts
 * 
 * Hooks customizados do SWR para gerenciamento de estado
 * Implementa retry policies e cache inteligente para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import useSWR, { SWRConfiguration, mutate } from 'swr';
import { useAuth } from './useAuth';
import { apiClient } from '../services/apiClient';

// Tipos baseados no código real do sistema
interface Blog {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}

interface Prompt {
  id: string;
  blog_id: string;
  content: string;
  created_at: string;
}

interface GenerateResponse {
  trace_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: {
    content: string;
    metadata: any;
  };
}

// Fetcher baseado no código real
const createFetcher = (token: string) => async (url: string) => {
  const response = await apiClient.get(url, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.data;
};

// Configuração enterprise do SWR
const createSWRConfig = (token: string): SWRConfiguration => ({
  // Retry policies enterprise
  errorRetryCount: 3,
  errorRetryInterval: (retryCount) => Math.min(1000 * 2 ** retryCount, 30000),
  onErrorRetry: (error, key, config, revalidate, { retryCount }) => {
    // Não retry para erros 4xx (exceto 408, 429)
    if (error?.response?.status >= 400 && error?.response?.status < 500) {
      if (error?.response?.status === 408 || error?.response?.status === 429) {
        if (retryCount < 3) {
          setTimeout(() => revalidate({ retryCount }), config.errorRetryInterval(retryCount));
        }
        return;
      }
      return; // Não retry para outros 4xx
    }
    
    // Retry para erros 5xx e de rede
    if (retryCount < 3) {
      setTimeout(() => revalidate({ retryCount }), config.errorRetryInterval(retryCount));
    }
  },
  
  // Cache inteligente enterprise
  dedupingInterval: 5 * 60 * 1000, // 5 minutos
  focusThrottleInterval: 5 * 1000, // 5 segundos
  
  // Configurações de performance
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  revalidateOnMount: true,
  
  // Configurações de suspense
  suspense: false,
  
  // Configurações de comparação
  compare: (a, b) => JSON.stringify(a) === JSON.stringify(b),
});

// Hook para buscar blogs
export const useSWRBlogs = (options?: SWRConfiguration) => {
  const { token } = useAuth();
  const config = createSWRConfig(token);
  
  return useSWR<Blog[]>(
    token ? '/api/blogs' : null,
    createFetcher(token),
    { ...config, ...options }
  );
};

// Hook para buscar blog específico
export const useSWRBlog = (id: string, options?: SWRConfiguration) => {
  const { token } = useAuth();
  const config = createSWRConfig(token);
  
  return useSWR<Blog>(
    token && id ? `/api/blogs/${id}` : null,
    createFetcher(token),
    { ...config, ...options }
  );
};

// Hook para buscar prompts de um blog
export const useSWRPrompts = (blogId: string, options?: SWRConfiguration) => {
  const { token } = useAuth();
  const config = createSWRConfig(token);
  
  return useSWR<Prompt[]>(
    token && blogId ? `/api/blogs/${blogId}/prompts` : null,
    createFetcher(token),
    { ...config, ...options }
  );
};

// Hook para buscar prompt específico
export const useSWRPrompt = (blogId: string, promptId: string, options?: SWRConfiguration) => {
  const { token } = useAuth();
  const config = createSWRConfig(token);
  
  return useSWR<Prompt>(
    token && blogId && promptId ? `/api/blogs/${blogId}/prompts/${promptId}` : null,
    createFetcher(token),
    { ...config, ...options }
  );
};

// Hook para status de geração com polling
export const useSWRGenerateStatus = (traceId: string, options?: SWRConfiguration) => {
  const { token } = useAuth();
  const config = createSWRConfig(token);
  
  return useSWR<GenerateResponse>(
    token && traceId ? `/status/${traceId}` : null,
    createFetcher(token),
    {
      ...config,
      // Polling para status de geração
      refreshInterval: (data) => {
        if (data?.status === 'pending' || data?.status === 'processing') {
          return 2000; // 2 segundos
        }
        return 0; // Para quando completed ou failed
      },
      ...options,
    }
  );
};

// Hook para criar blog
export const useSWRCreateBlog = () => {
  const { token } = useAuth();
  
  return async (blogData: Partial<Blog>) => {
    const response = await apiClient.post('/api/blogs', blogData, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    // Invalida cache de blogs
    await mutate('/api/blogs');
    
    return response.data;
  };
};

// Hook para criar prompt
export const useSWRCreatePrompt = () => {
  const { token } = useAuth();
  
  return async (blogId: string, content: string) => {
    const response = await apiClient.post(`/api/blogs/${blogId}/prompts`, { content }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    // Invalida cache de prompts do blog
    await mutate(`/api/blogs/${blogId}/prompts`);
    
    return response.data;
  };
};

// Hook para gerar conteúdo
export const useSWRGenerateContent = () => {
  const { token } = useAuth();
  
  return async (request: { blog_id: string; prompt_id: string; options?: any }) => {
    const response = await apiClient.post('/generate', request, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    return response.data;
  };
};

// Hook para download de arquivo
export const useSWRDownloadFile = () => {
  const { token } = useAuth();
  
  return async (traceId: string, format: string = 'pdf') => {
    const response = await apiClient.get(`/download?trace_id=${traceId}&format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
      responseType: 'blob',
    });
    
    return response.data;
  };
};

// Hook utilitário para cache inteligente
export const useSWRCacheManager = () => {
  return {
    // Limpar cache específico
    clearCache: (key: string) => {
      mutate(key, undefined, false);
    },
    
    // Limpar todo cache
    clearAllCache: () => {
      mutate(() => true, undefined, false);
    },
    
    // Pré-carregar dados
    prefetch: async (key: string, fetcher: () => Promise<any>) => {
      await mutate(key, fetcher, false);
    },
    
    // Obter dados do cache
    getCache: (key: string) => {
      return mutate(key);
    },
    
    // Definir dados no cache
    setCache: (key: string, data: any) => {
      mutate(key, data, false);
    },
    
    // Revalidar cache
    revalidate: (key: string) => {
      mutate(key);
    },
  };
};

// Hook para configuração global do SWR
export const useSWRConfig = () => {
  const { token } = useAuth();
  
  return {
    provider: () => new Map(),
    onSuccess: (data: any, key: string) => {
      console.log(`[SWR] Success: ${key}`, data);
    },
    onError: (err: any, key: string) => {
      console.error(`[SWR] Error: ${key}`, err);
    },
    onDiscarded: (key: string) => {
      console.log(`[SWR] Discarded: ${key}`);
    },
    isOnline: () => navigator.onLine,
    isVisible: () => !document.hidden,
    initFocus: () => {
      const onFocus = () => {
        mutate(() => true);
      };
      window.addEventListener('focus', onFocus);
      return () => window.removeEventListener('focus', onFocus);
    },
    initReconnect: () => {
      const onOnline = () => {
        mutate(() => true);
      };
      window.addEventListener('online', onOnline);
      return () => window.removeEventListener('online', onOnline);
    },
  };
}; 