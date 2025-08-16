/**
 * apiClient.ts
 * 
 * Cliente de API baseado no código real do sistema
 * Suporta React Query e SWR para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

// Configuração base do cliente API
const createApiClient = (): AxiosInstance => {
  const client = axios.create({
    baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
    timeout: 30000, // 30 segundos
    headers: {
      'Content-Type': 'application/json',
    },
  });

  // Interceptor de request para logging
  client.interceptors.request.use(
    (config) => {
      console.log(`[API] Request: ${config.method?.toUpperCase()} ${config.url}`, {
        data: config.data,
        params: config.params,
        headers: config.headers,
      });
      return config;
    },
    (error) => {
      console.error('[API] Request Error:', error);
      return Promise.reject(error);
    }
  );

  // Interceptor de response para logging e tratamento de erros
  client.interceptors.response.use(
    (response: AxiosResponse) => {
      console.log(`[API] Response: ${response.status} ${response.config.url}`, {
        data: response.data,
        headers: response.headers,
      });
      return response;
    },
    (error) => {
      console.error('[API] Response Error:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        url: error.config?.url,
        data: error.response?.data,
      });

      // Tratamento específico de erros
      if (error.response?.status === 401) {
        // Token expirado - redirecionar para login
        window.location.href = '/login';
      }

      if (error.response?.status === 429) {
        // Rate limit - aguardar antes de retry
        console.warn('[API] Rate limit exceeded, waiting before retry');
      }

      return Promise.reject(error);
    }
  );

  return client;
};

// Cliente API singleton
export const apiClient = createApiClient();

// Tipos baseados no código real
export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  message?: string;
  errors?: string[];
}

export interface PaginatedResponse<T = any> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

// Métodos de API baseados no código real
export const apiMethods = {
  // Blogs
  getBlogs: (config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<Blog[]>>('/api/blogs', config),
  
  getBlog: (id: string, config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<Blog>>(`/api/blogs/${id}`, config),
  
  createBlog: (data: Partial<Blog>, config?: AxiosRequestConfig) => 
    apiClient.post<ApiResponse<Blog>>('/api/blogs', data, config),
  
  updateBlog: (id: string, data: Partial<Blog>, config?: AxiosRequestConfig) => 
    apiClient.put<ApiResponse<Blog>>(`/api/blogs/${id}`, data, config),
  
  deleteBlog: (id: string, config?: AxiosRequestConfig) => 
    apiClient.delete<ApiResponse<void>>(`/api/blogs/${id}`, config),

  // Prompts
  getPrompts: (blogId: string, config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<Prompt[]>>(`/api/blogs/${blogId}/prompts`, config),
  
  getPrompt: (blogId: string, promptId: string, config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<Prompt>>(`/api/blogs/${blogId}/prompts/${promptId}`, config),
  
  createPrompt: (blogId: string, data: { content: string }, config?: AxiosRequestConfig) => 
    apiClient.post<ApiResponse<Prompt>>(`/api/blogs/${blogId}/prompts`, data, config),
  
  updatePrompt: (blogId: string, promptId: string, data: { content: string }, config?: AxiosRequestConfig) => 
    apiClient.put<ApiResponse<Prompt>>(`/api/blogs/${blogId}/prompts/${promptId}`, data, config),
  
  deletePrompt: (blogId: string, promptId: string, config?: AxiosRequestConfig) => 
    apiClient.delete<ApiResponse<void>>(`/api/blogs/${blogId}/prompts/${promptId}`, config),

  // Generation
  generateContent: (data: GenerateRequest, config?: AxiosRequestConfig) => 
    apiClient.post<ApiResponse<GenerateResponse>>('/generate', data, config),
  
  getGenerateStatus: (traceId: string, config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<GenerateResponse>>(`/status/${traceId}`, config),
  
  getGenerateEvents: (traceId: string, config?: AxiosRequestConfig) => 
    apiClient.get<ApiResponse<any>>(`/events/${traceId}`, config),

  // Download
  downloadFile: (traceId: string, format: string = 'pdf', config?: AxiosRequestConfig) => 
    apiClient.get(`/download?trace_id=${traceId}&format=${format}`, {
      ...config,
      responseType: 'blob',
    }),

  // Webhooks
  createWebhook: (data: any, config?: AxiosRequestConfig) => 
    apiClient.post<ApiResponse<any>>('/webhook', data, config),
};

// Tipos baseados no código real
export interface Blog {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface Prompt {
  id: string;
  blog_id: string;
  content: string;
  created_at: string;
}

export interface GenerateRequest {
  blog_id: string;
  prompt_id: string;
  options?: {
    max_tokens?: number;
    temperature?: number;
    top_p?: number;
    frequency_penalty?: number;
    presence_penalty?: number;
  };
}

export interface GenerateResponse {
  trace_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: {
    content: string;
    metadata: {
      tokens_used: number;
      model: string;
      finish_reason: string;
      processing_time: number;
    };
  };
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

// Utilitários para cache e retry
export const apiUtils = {
  // Gerar chave de cache
  getCacheKey: (endpoint: string, params?: any) => {
    const key = endpoint;
    if (params) {
      return `${key}?${JSON.stringify(params)}`;
    }
    return key;
  },

  // Verificar se deve retry
  shouldRetry: (error: any, retryCount: number): boolean => {
    // Não retry para erros 4xx (exceto 408, 429)
    if (error?.response?.status >= 400 && error?.response?.status < 500) {
      if (error?.response?.status === 408 || error?.response?.status === 429) {
        return retryCount < 3;
      }
      return false;
    }
    
    // Retry para erros 5xx e de rede
    return retryCount < 3;
  },

  // Calcular delay para retry
  getRetryDelay: (retryCount: number): number => {
    return Math.min(1000 * 2 ** retryCount, 30000);
  },

  // Transformar erro em formato padronizado
  normalizeError: (error: any) => {
    return {
      message: error.response?.data?.message || error.message || 'Erro desconhecido',
      status: error.response?.status,
      code: error.response?.data?.code || 'UNKNOWN_ERROR',
      details: error.response?.data?.details || error.response?.data,
    };
  },
};

export default apiClient; 