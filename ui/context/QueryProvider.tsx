/**
 * QueryProvider.tsx
 * 
 * Provider do React Query (TanStack Query) com configurações enterprise
 * Implementa retry policies e cache inteligente para a ETAPA 7
 * 
 * Prompt: FULLSTACK_COMMUNICATION_CHECKLIST.md - ETAPA 7
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T21:30:00Z
 * Tracing ID: FULLSTACK_AUDIT_20250127_001
 */

import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';

// Configuração enterprise do QueryClient
const createQueryClient = () => {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Retry policies enterprise
        retry: (failureCount, error: any) => {
          // Não retry para erros 4xx (exceto 408, 429)
          if (error?.response?.status >= 400 && error?.response?.status < 500) {
            if (error?.response?.status === 408 || error?.response?.status === 429) {
              return failureCount < 3;
            }
            return false;
          }
          // Retry para erros 5xx até 3 vezes
          if (error?.response?.status >= 500) {
            return failureCount < 3;
          }
          // Retry para erros de rede
          return failureCount < 2;
        },
        retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
        
        // Cache inteligente enterprise
        staleTime: 5 * 60 * 1000, // 5 minutos
        gcTime: 10 * 60 * 1000, // 10 minutos (anteriormente cacheTime)
        
        // Configurações de performance
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        refetchOnMount: true,
        
        // Configurações de suspense
        suspense: false,
        
        // Configurações de placeholder
        placeholderData: undefined,
      },
      mutations: {
        // Retry policies para mutations
        retry: (failureCount, error: any) => {
          // Não retry mutations por padrão (evita duplicação)
          return false;
        },
        
        // Configurações de otimistic updates
        onMutate: undefined,
        onError: undefined,
        onSuccess: undefined,
        onSettled: undefined,
      },
    },
  });
};

interface QueryProviderProps {
  children: React.ReactNode;
}

export const QueryProvider: React.FC<QueryProviderProps> = ({ children }) => {
  const [queryClient] = React.useState(() => createQueryClient());

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {/* DevTools apenas em desenvolvimento */}
      {process.env.NODE_ENV === 'development' && (
        <ReactQueryDevtools initialIsOpen={false} />
      )}
    </QueryClientProvider>
  );
};

export default QueryProvider; 