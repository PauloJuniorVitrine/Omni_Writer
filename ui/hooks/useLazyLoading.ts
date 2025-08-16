/**
 * Hook para Lazy Loading - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-025.1
 * Data/Hora: 2025-01-28T02:35:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Lazy loading com React.lazy()
 * - Suspense boundaries
 * - Loading states customizados
 * - Error boundaries integrados
 * - Performance monitoring
 */

import React, { Suspense, lazy, useState, useEffect } from 'react';
import { Loading } from '../components/base/Loading';

// ===== TIPOS =====

interface LazyComponentConfig {
  component: React.LazyExoticComponent<any>;
  fallback?: React.ReactNode;
  errorBoundary?: React.ComponentType<any>;
  preload?: boolean;
  timeout?: number;
}

interface UseLazyLoadingReturn {
  LazyComponent: React.LazyExoticComponent<any>;
  isLoading: boolean;
  hasError: boolean;
  error: Error | null;
  preload: () => void;
  retry: () => void;
}

// ===== COMPONENTES =====

/**
 * Loading component customizado para lazy loading
 */
const LazyLoadingFallback: React.FC<{ componentName?: string }> = ({ componentName = 'Componente' }) => (
  <div className="flex items-center justify-center p-8">
    <Loading 
      size="lg" 
      text={`Carregando ${componentName}...`}
      variant="dots"
    />
  </div>
);

/**
 * Error boundary para componentes lazy
 */
class LazyErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode; fallback?: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Lazy loading error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="flex flex-col items-center justify-center p-8 text-red-600">
          <h3 className="text-lg font-semibold mb-2">Erro ao carregar componente</h3>
          <p className="text-sm text-gray-600 mb-4">{this.state.error?.message}</p>
          <button 
            onClick={() => this.setState({ hasError: false, error: null })}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Tentar novamente
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

// ===== HOOK PRINCIPAL =====

/**
 * Hook para lazy loading com Suspense e error handling
 */
export const useLazyLoading = (
  importFn: () => Promise<{ default: React.ComponentType<any> }>,
  config: Partial<LazyComponentConfig> = {}
): UseLazyLoadingReturn => {
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Criar componente lazy
  const LazyComponent = lazy(async () => {
    setIsLoading(true);
    setHasError(false);
    setError(null);

    try {
      const result = await importFn();
      setIsLoading(false);
      return result;
    } catch (err) {
      setIsLoading(false);
      setHasError(true);
      setError(err as Error);
      throw err;
    }
  });

  // Função para preload
  const preload = () => {
    if (config.preload) {
      importFn().catch(console.error);
    }
  };

  // Função para retry
  const retry = () => {
    setHasError(false);
    setError(null);
    // Força re-import do componente
    window.location.reload();
  };

  // Preload automático se configurado
  useEffect(() => {
    if (config.preload) {
      preload();
    }
  }, [config.preload]);

  return {
    LazyComponent,
    isLoading,
    hasError,
    error,
    preload,
    retry
  };
};

// ===== COMPONENTE WRAPPER =====

/**
 * Wrapper component para lazy loading com Suspense e Error Boundary
 */
export const LazyComponentWrapper: React.FC<{
  component: React.LazyExoticComponent<any>;
  fallback?: React.ReactNode;
  errorFallback?: React.ReactNode;
  componentName?: string;
  props?: Record<string, any>;
}> = ({ 
  component: LazyComponent, 
  fallback, 
  errorFallback,
  componentName = 'Componente',
  props = {}
}) => {
  return (
    <LazyErrorBoundary fallback={errorFallback}>
      <Suspense fallback={fallback || <LazyLoadingFallback componentName={componentName} />}>
        <LazyComponent {...props} />
      </Suspense>
    </LazyErrorBoundary>
  );
};

// ===== UTILITÁRIOS =====

/**
 * Criar lazy component com configuração padrão
 */
export const createLazyComponent = (
  importFn: () => Promise<{ default: React.ComponentType<any> }>,
  componentName?: string
) => {
  const { LazyComponent } = useLazyLoading(importFn);
  
  return (props: any) => (
    <LazyComponentWrapper 
      component={LazyComponent}
      componentName={componentName}
      props={props}
    />
  );
};

/**
 * Hook para monitorar performance de lazy loading
 */
export const useLazyLoadingPerformance = () => {
  const [metrics, setMetrics] = useState<{
    loadTimes: number[];
    averageLoadTime: number;
    totalLoads: number;
    errors: number;
  }>({
    loadTimes: [],
    averageLoadTime: 0,
    totalLoads: 0,
    errors: 0
  });

  const recordLoadTime = (loadTime: number) => {
    setMetrics(prev => {
      const newLoadTimes = [...prev.loadTimes, loadTime];
      const averageLoadTime = newLoadTimes.reduce((a, b) => a + b, 0) / newLoadTimes.length;
      
      return {
        loadTimes: newLoadTimes,
        averageLoadTime,
        totalLoads: prev.totalLoads + 1,
        errors: prev.errors
      };
    });
  };

  const recordError = () => {
    setMetrics(prev => ({
      ...prev,
      errors: prev.errors + 1
    }));
  };

  return {
    metrics,
    recordLoadTime,
    recordError
  };
};

export default useLazyLoading; 