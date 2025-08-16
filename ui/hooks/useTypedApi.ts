import { useState, useCallback } from 'react';
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  Blog,
  Prompt,
  GenerationRequest,
  GenerationResponse,
  StatusResponse,
  ErrorResponse,
  WebhookRequest,
  WebhookResponse,
  validateBlog,
  validatePrompt,
  validateGenerationRequest,
  validateGenerationResponse,
  validateStatusResponse,
  validateErrorResponse,
  validateWebhookRequest,
  validateWebhookResponse
} from '../schemas/api-schemas';

// Configuração base do cliente API baseada em static/js/api.js
const createApiClient = (): AxiosInstance => {
  return axios.create({
    baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000',
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
    },
  });
};

// Hook principal para API tipada
export const useTypedApi = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const apiClient = createApiClient();

  // Função genérica para fazer requisições com validação
  const makeRequest = useCallback(async <T>(
    requestFn: () => Promise<AxiosResponse>,
    validator: (data: unknown) => T
  ): Promise<T> => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await requestFn();
      const validatedData = validator(response.data);
      return validatedData;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Erro desconhecido';
      setError(errorMessage);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  // Blogs API - baseado em app/main.py
  const blogsApi = {
    // GET /api/blogs
    getBlogs: useCallback(async (): Promise<Blog[]> => {
      return makeRequest(
        () => apiClient.get('/api/blogs'),
        (data) => Array.isArray(data) ? data.map(validateBlog) : []
      );
    }, [makeRequest]),

    // POST /api/blogs
    createBlog: useCallback(async (blog: Omit<Blog, 'id'>): Promise<Blog> => {
      return makeRequest(
        () => apiClient.post('/api/blogs', blog),
        validateBlog
      );
    }, [makeRequest]),

    // DELETE /api/blogs/<id>
    deleteBlog: useCallback(async (id: number): Promise<void> => {
      await apiClient.delete(`/api/blogs/${id}`);
    }, []),
  };

  // Prompts API - baseado em app/main.py
  const promptsApi = {
    // GET /api/blogs/<id>/prompts
    getPrompts: useCallback(async (blogId: number): Promise<Prompt[]> => {
      return makeRequest(
        () => apiClient.get(`/api/blogs/${blogId}/prompts`),
        (data) => Array.isArray(data) ? data.map(validatePrompt) : []
      );
    }, [makeRequest]),

    // POST /api/blogs/<id>/prompts
    createPrompt: useCallback(async (blogId: number, prompt: Omit<Prompt, 'id'>): Promise<Prompt> => {
      return makeRequest(
        () => apiClient.post(`/api/blogs/${blogId}/prompts`, prompt),
        validatePrompt
      );
    }, [makeRequest]),

    // DELETE /api/blogs/<id>/prompts/<prompt_id>
    deletePrompt: useCallback(async (blogId: number, promptId: number): Promise<void> => {
      await apiClient.delete(`/api/blogs/${blogId}/prompts/${promptId}`);
    }, []),
  };

  // Generation API - baseado em app/main.py
  const generationApi = {
    // POST /generate
    generateArticles: useCallback(async (request: GenerationRequest): Promise<GenerationResponse> => {
      return makeRequest(
        () => apiClient.post('/generate', request),
        validateGenerationResponse
      );
    }, [makeRequest]),

    // GET /status/<trace_id>
    getStatus: useCallback(async (traceId: string): Promise<StatusResponse> => {
      return makeRequest(
        () => apiClient.get(`/status/${traceId}`),
        validateStatusResponse
      );
    }, [makeRequest]),

    // GET /events/<trace_id> (SSE)
    subscribeToEvents: useCallback((traceId: string, onMessage: (data: any) => void): EventSource => {
      const eventSource = new EventSource(`/events/${traceId}`);
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data);
        } catch (err) {
          console.error('Erro ao processar evento SSE:', err);
        }
      };
      return eventSource;
    }, []),
  };

  // Download API - baseado em app/main.py
  const downloadApi = {
    // GET /download
    downloadArticles: useCallback(async (): Promise<Blob> => {
      const response = await apiClient.get('/download', {
        responseType: 'blob'
      });
      return response.data;
    }, []),

    // GET /download_multi
    downloadMultiArticles: useCallback(async (): Promise<Blob> => {
      const response = await apiClient.get('/download_multi', {
        responseType: 'blob'
      });
      return response.data;
    }, []),

    // GET /export_prompts
    exportPrompts: useCallback(async (): Promise<Blob> => {
      const response = await apiClient.get('/export_prompts', {
        responseType: 'blob'
      });
      return response.data;
    }, []),

    // GET /export_artigos_csv
    exportArticlesCsv: useCallback(async (): Promise<Blob> => {
      const response = await apiClient.get('/export_artigos_csv', {
        responseType: 'blob'
      });
      return response.data;
    }, []),
  };

  // Webhook API - baseado em app/main.py
  const webhookApi = {
    // POST /webhook
    registerWebhook: useCallback(async (webhook: WebhookRequest): Promise<WebhookResponse> => {
      return makeRequest(
        () => apiClient.post('/webhook', webhook),
        validateWebhookResponse
      );
    }, [makeRequest]),
  };

  return {
    loading,
    error,
    blogs: blogsApi,
    prompts: promptsApi,
    generation: generationApi,
    download: downloadApi,
    webhook: webhookApi,
  };
}; 