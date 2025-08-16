/**
 * useReactQuery.ts
 * 
 * Hooks customizados do React Query (TanStack Query) para gerenciamento de estado
 * Implementa retry policies e cache inteligente para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import { useQuery, useMutation, useQueryClient, UseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
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

interface GenerateRequest {
  blog_id: string;
  prompt_id: string;
  options?: {
    max_tokens?: number;
    temperature?: number;
  };
}

interface GenerateResponse {
  trace_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: {
    content: string;
    metadata: any;
  };
}

// Query Keys para cache inteligente
export const queryKeys = {
  blogs: ['blogs'] as const,
  blog: (id: string) => ['blogs', id] as const,
  prompts: (blogId: string) => ['blogs', blogId, 'prompts'] as const,
  prompt: (blogId: string, promptId: string) => ['blogs', blogId, 'prompts', promptId] as const,
  generateStatus: (traceId: string) => ['generate', 'status', traceId] as const,
} as const;

// Hook para buscar blogs
export const useBlogs = (options?: UseQueryOptions<Blog[], Error>) => {
  const { token } = useAuth();
  
  return useQuery({
    queryKey: queryKeys.blogs,
    queryFn: async () => {
      const response = await apiClient.get('/api/blogs', {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    enabled: !!token,
    ...options,
  });
};

// Hook para buscar blog específico
export const useBlog = (id: string, options?: UseQueryOptions<Blog, Error>) => {
  const { token } = useAuth();
  
  return useQuery({
    queryKey: queryKeys.blog(id),
    queryFn: async () => {
      const response = await apiClient.get(`/api/blogs/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    enabled: !!token && !!id,
    ...options,
  });
};

// Hook para buscar prompts de um blog
export const usePrompts = (blogId: string, options?: UseQueryOptions<Prompt[], Error>) => {
  const { token } = useAuth();
  
  return useQuery({
    queryKey: queryKeys.prompts(blogId),
    queryFn: async () => {
      const response = await apiClient.get(`/api/blogs/${blogId}/prompts`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    enabled: !!token && !!blogId,
    ...options,
  });
};

// Hook para buscar prompt específico
export const usePrompt = (blogId: string, promptId: string, options?: UseQueryOptions<Prompt, Error>) => {
  const { token } = useAuth();
  
  return useQuery({
    queryKey: queryKeys.prompt(blogId, promptId),
    queryFn: async () => {
      const response = await apiClient.get(`/api/blogs/${blogId}/prompts/${promptId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    enabled: !!token && !!blogId && !!promptId,
    ...options,
  });
};

// Hook para status de geração
export const useGenerateStatus = (traceId: string, options?: UseQueryOptions<GenerateResponse, Error>) => {
  const { token } = useAuth();
  
  return useQuery({
    queryKey: queryKeys.generateStatus(traceId),
    queryFn: async () => {
      const response = await apiClient.get(`/status/${traceId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    enabled: !!token && !!traceId,
    // Polling para status de geração
    refetchInterval: (data) => {
      if (data?.status === 'pending' || data?.status === 'processing') {
        return 2000; // 2 segundos
      }
      return false; // Para quando completed ou failed
    },
    ...options,
  });
};

// Hook para criar blog
export const useCreateBlog = (options?: UseMutationOptions<Blog, Error, Partial<Blog>>) => {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (blogData: Partial<Blog>) => {
      const response = await apiClient.post('/api/blogs', blogData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    onSuccess: () => {
      // Invalida cache de blogs
      queryClient.invalidateQueries({ queryKey: queryKeys.blogs });
    },
    ...options,
  });
};

// Hook para criar prompt
export const useCreatePrompt = (options?: UseMutationOptions<Prompt, Error, { blogId: string; content: string }>) => {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async ({ blogId, content }: { blogId: string; content: string }) => {
      const response = await apiClient.post(`/api/blogs/${blogId}/prompts`, { content }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    onSuccess: (_, { blogId }) => {
      // Invalida cache de prompts do blog
      queryClient.invalidateQueries({ queryKey: queryKeys.prompts(blogId) });
    },
    ...options,
  });
};

// Hook para gerar conteúdo
export const useGenerateContent = (options?: UseMutationOptions<GenerateResponse, Error, GenerateRequest>) => {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (request: GenerateRequest) => {
      const response = await apiClient.post('/generate', request, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    },
    onSuccess: (data) => {
      // Invalida cache de status de geração
      if (data.trace_id) {
        queryClient.invalidateQueries({ queryKey: queryKeys.generateStatus(data.trace_id) });
      }
    },
    ...options,
  });
};

// Hook para download de arquivo
export const useDownloadFile = (options?: UseMutationOptions<Blob, Error, { traceId: string; format?: string }>) => {
  const { token } = useAuth();
  
  return useMutation({
    mutationFn: async ({ traceId, format = 'pdf' }: { traceId: string; format?: string }) => {
      const response = await apiClient.get(`/download?trace_id=${traceId}&format=${format}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob',
      });
      return response.data;
    },
    ...options,
  });
};

// Hook utilitário para cache inteligente
export const useCacheManager = () => {
  const queryClient = useQueryClient();
  
  return {
    // Limpar cache específico
    clearCache: (queryKey: readonly unknown[]) => {
      queryClient.removeQueries({ queryKey });
    },
    
    // Limpar todo cache
    clearAllCache: () => {
      queryClient.clear();
    },
    
    // Pré-carregar dados
    prefetchQuery: async (queryKey: readonly unknown[], queryFn: () => Promise<any>) => {
      await queryClient.prefetchQuery({ queryKey, queryFn });
    },
    
    // Obter dados do cache
    getQueryData: (queryKey: readonly unknown[]) => {
      return queryClient.getQueryData(queryKey);
    },
    
    // Definir dados no cache
    setQueryData: (queryKey: readonly unknown[], data: any) => {
      queryClient.setQueryData(queryKey, data);
    },
  };
}; 