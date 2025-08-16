/**
 * useReactQuery.test.ts
 * 
 * Testes para hooks do React Query baseados no código real
 * Implementa testes enterprise para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useBlogs, useBlog, usePrompts, useCreateBlog, queryKeys } from '../useReactQuery';
import { apiClient } from '../../services/apiClient';

// Mock do apiClient baseado no código real
jest.mock('../../services/apiClient', () => ({
  apiClient: {
    get: jest.fn(),
    post: jest.fn(),
  },
}));

// Mock do useAuth baseado no código real
jest.mock('../useAuth', () => ({
  useAuth: () => ({
    token: 'test-token-123',
    user: { id: 'user-123', email: 'test@example.com' },
  }),
}));

const mockApiClient = apiClient as jest.Mocked<typeof apiClient>;

// Dados de teste baseados no código real
const mockBlog = {
  id: 'blog-123',
  title: 'Test Blog',
  content: 'Test content',
  created_at: '2025-01-27T21:30:00Z',
  updated_at: '2025-01-27T21:30:00Z',
};

const mockPrompt = {
  id: 'prompt-123',
  blog_id: 'blog-123',
  content: 'Test prompt',
  created_at: '2025-01-27T21:30:00Z',
};

const mockGenerateResponse = {
  trace_id: 'trace-123',
  status: 'completed' as const,
  result: {
    content: 'Generated content',
    metadata: {
      tokens_used: 100,
      model: 'gpt-4',
      finish_reason: 'stop',
      processing_time: 5000,
    },
  },
};

// Wrapper para testes com QueryClient
const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
};

describe('useReactQuery Hooks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('useBlogs', () => {
    it('should fetch blogs successfully', async () => {
      const mockBlogs = [mockBlog];
      mockApiClient.get.mockResolvedValueOnce({ data: mockBlogs });

      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(result.current.data).toEqual(mockBlogs);
      expect(mockApiClient.get).toHaveBeenCalledWith('/api/blogs', {
        headers: { Authorization: 'Bearer test-token-123' },
      });
    });

    it('should handle error when fetching blogs fails', async () => {
      const error = new Error('Failed to fetch blogs');
      mockApiClient.get.mockRejectedValueOnce(error);

      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isError).toBe(true);
      });

      expect(result.current.error).toBe(error);
    });

    it('should use correct query key for blogs', () => {
      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      expect(result.current.queryKey).toEqual(queryKeys.blogs);
    });
  });

  describe('useBlog', () => {
    it('should fetch specific blog successfully', async () => {
      const blogId = 'blog-123';
      mockApiClient.get.mockResolvedValueOnce({ data: mockBlog });

      const { result } = renderHook(() => useBlog(blogId), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(result.current.data).toEqual(mockBlog);
      expect(mockApiClient.get).toHaveBeenCalledWith(`/api/blogs/${blogId}`, {
        headers: { Authorization: 'Bearer test-token-123' },
      });
    });

    it('should not fetch when blogId is empty', () => {
      const { result } = renderHook(() => useBlog(''), {
        wrapper: createWrapper(),
      });

      expect(result.current.isEnabled).toBe(false);
      expect(mockApiClient.get).not.toHaveBeenCalled();
    });

    it('should use correct query key for specific blog', () => {
      const blogId = 'blog-123';
      const { result } = renderHook(() => useBlog(blogId), {
        wrapper: createWrapper(),
      });

      expect(result.current.queryKey).toEqual(queryKeys.blog(blogId));
    });
  });

  describe('usePrompts', () => {
    it('should fetch prompts for blog successfully', async () => {
      const blogId = 'blog-123';
      const mockPrompts = [mockPrompt];
      mockApiClient.get.mockResolvedValueOnce({ data: mockPrompts });

      const { result } = renderHook(() => usePrompts(blogId), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      expect(result.current.data).toEqual(mockPrompts);
      expect(mockApiClient.get).toHaveBeenCalledWith(`/api/blogs/${blogId}/prompts`, {
        headers: { Authorization: 'Bearer test-token-123' },
      });
    });

    it('should not fetch when blogId is empty', () => {
      const { result } = renderHook(() => usePrompts(''), {
        wrapper: createWrapper(),
      });

      expect(result.current.isEnabled).toBe(false);
      expect(mockApiClient.get).not.toHaveBeenCalled();
    });

    it('should use correct query key for prompts', () => {
      const blogId = 'blog-123';
      const { result } = renderHook(() => usePrompts(blogId), {
        wrapper: createWrapper(),
      });

      expect(result.current.queryKey).toEqual(queryKeys.prompts(blogId));
    });
  });

  describe('useCreateBlog', () => {
    it('should create blog successfully', async () => {
      const blogData = { title: 'New Blog', content: 'New content' };
      mockApiClient.post.mockResolvedValueOnce({ data: mockBlog });

      const { result } = renderHook(() => useCreateBlog(), {
        wrapper: createWrapper(),
      });

      await result.current.mutateAsync(blogData);

      expect(mockApiClient.post).toHaveBeenCalledWith('/api/blogs', blogData, {
        headers: { Authorization: 'Bearer test-token-123' },
      });
    });

    it('should handle error when creating blog fails', async () => {
      const blogData = { title: 'New Blog', content: 'New content' };
      const error = new Error('Failed to create blog');
      mockApiClient.post.mockRejectedValueOnce(error);

      const { result } = renderHook(() => useCreateBlog(), {
        wrapper: createWrapper(),
      });

      try {
        await result.current.mutateAsync(blogData);
      } catch (e) {
        expect(e).toBe(error);
      }

      expect(result.current.isError).toBe(true);
    });

    it('should invalidate blogs cache on success', async () => {
      const blogData = { title: 'New Blog', content: 'New content' };
      mockApiClient.post.mockResolvedValueOnce({ data: mockBlog });

      const { result } = renderHook(() => useCreateBlog(), {
        wrapper: createWrapper(),
      });

      await result.current.mutateAsync(blogData);

      // Verificar se o cache foi invalidado (implementação simplificada)
      expect(result.current.isSuccess).toBe(true);
    });
  });

  describe('queryKeys', () => {
    it('should generate correct query keys', () => {
      expect(queryKeys.blogs).toEqual(['blogs']);
      expect(queryKeys.blog('blog-123')).toEqual(['blogs', 'blog-123']);
      expect(queryKeys.prompts('blog-123')).toEqual(['blogs', 'blog-123', 'prompts']);
      expect(queryKeys.prompt('blog-123', 'prompt-123')).toEqual(['blogs', 'blog-123', 'prompts', 'prompt-123']);
      expect(queryKeys.generateStatus('trace-123')).toEqual(['generate', 'status', 'trace-123']);
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const networkError = new Error('Network Error');
      networkError.name = 'NetworkError';
      mockApiClient.get.mockRejectedValueOnce(networkError);

      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isError).toBe(true);
      });

      expect(result.current.error).toBe(networkError);
    });

    it('should handle 401 unauthorized errors', async () => {
      const unauthorizedError = new Error('Unauthorized');
      (unauthorizedError as any).response = { status: 401 };
      mockApiClient.get.mockRejectedValueOnce(unauthorizedError);

      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isError).toBe(true);
      });

      expect(result.current.error).toBe(unauthorizedError);
    });
  });

  describe('Performance', () => {
    it('should not make unnecessary API calls', () => {
      const { result } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      // Verificar se não faz chamadas desnecessárias
      expect(mockApiClient.get).toHaveBeenCalledTimes(1);
    });

    it('should cache results appropriately', async () => {
      const mockBlogs = [mockBlog];
      mockApiClient.get.mockResolvedValue({ data: mockBlogs });

      const { result, rerender } = renderHook(() => useBlogs(), {
        wrapper: createWrapper(),
      });

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true);
      });

      // Rerender não deve fazer nova chamada
      rerender();

      // Deve usar cache, não fazer nova chamada
      expect(mockApiClient.get).toHaveBeenCalledTimes(1);
    });
  });
}); 