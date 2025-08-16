/**
 * Teste de Lazy Loading - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-025.1
 * Data/Hora: 2025-01-28T02:43:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Teste do hook useLazyLoading
 * - Teste do componente LazyComponentWrapper
 * - Teste de performance de lazy loading
 * - Baseado no código real da aplicação
 */

import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { useLazyLoading, LazyComponentWrapper, createLazyComponent } from '../../ui/hooks/useLazyLoading';

// ===== COMPONENTES MOCK =====

// Componente mock para teste baseado no código real
const MockComponent = () => <div data-testid="mock-component">Mock Component</div>;

// Componente que simula erro baseado no código real
const ErrorComponent = () => {
  throw new Error('Erro simulado para teste');
};

// ===== TESTES DO HOOK =====

describe('useLazyLoading Hook', () => {
  test('deve criar componente lazy com configuração padrão', async () => {
    const TestComponent = () => {
      const { LazyComponent, isLoading, hasError } = useLazyLoading(
        () => import('./MockComponent').then(module => ({ default: MockComponent }))
      );

      return (
        <div>
          {isLoading && <div data-testid="loading">Carregando...</div>}
          {hasError && <div data-testid="error">Erro</div>}
          <LazyComponent />
        </div>
      );
    };

    render(<TestComponent />);
    
    // Verificar se o loading aparece inicialmente
    expect(screen.getByTestId('loading')).toBeInTheDocument();
    
    // Aguardar o componente carregar
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
    
    // Verificar se o loading desapareceu
    expect(screen.queryByTestId('loading')).not.toBeInTheDocument();
  });

  test('deve lidar com erro de carregamento', async () => {
    const TestComponent = () => {
      const { LazyComponent, isLoading, hasError, error } = useLazyLoading(
        () => Promise.reject(new Error('Erro de carregamento'))
      );

      return (
        <div>
          {isLoading && <div data-testid="loading">Carregando...</div>}
          {hasError && <div data-testid="error">Erro: {error?.message}</div>}
          <LazyComponent />
        </div>
      );
    };

    render(<TestComponent />);
    
    // Aguardar o erro aparecer
    await waitFor(() => {
      expect(screen.getByTestId('error')).toBeInTheDocument();
    });
    
    expect(screen.getByText('Erro: Erro de carregamento')).toBeInTheDocument();
  });

  test('deve executar preload quando configurado', async () => {
    const mockImportFn = jest.fn().mockResolvedValue({ default: MockComponent });
    
    const TestComponent = () => {
      const { preload } = useLazyLoading(mockImportFn, { preload: true });
      
      React.useEffect(() => {
        preload();
      }, [preload]);

      return <div>Teste</div>;
    };

    render(<TestComponent />);
    
    // Verificar se a função de import foi chamada
    await waitFor(() => {
      expect(mockImportFn).toHaveBeenCalled();
    });
  });
});

// ===== TESTES DO COMPONENTE WRAPPER =====

describe('LazyComponentWrapper', () => {
  test('deve renderizar componente lazy com fallback', async () => {
    const LazyMockComponent = React.lazy(() => 
      Promise.resolve({ default: MockComponent })
    );

    render(
      <LazyComponentWrapper
        component={LazyMockComponent}
        componentName="MockComponent"
      />
    );

    // Verificar se o fallback aparece
    expect(screen.getByText('Carregando MockComponent...')).toBeInTheDocument();
    
    // Aguardar o componente carregar
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
  });

  test('deve lidar com erro no componente lazy', async () => {
    const LazyErrorComponent = React.lazy(() => 
      Promise.resolve({ default: ErrorComponent })
    );

    render(
      <LazyComponentWrapper
        component={LazyErrorComponent}
        componentName="ErrorComponent"
      />
    );

    // Aguardar o erro aparecer
    await waitFor(() => {
      expect(screen.getByText('Erro ao carregar componente')).toBeInTheDocument();
    });
  });

  test('deve permitir retry após erro', async () => {
    const LazyErrorComponent = React.lazy(() => 
      Promise.resolve({ default: ErrorComponent })
    );

    render(
      <LazyComponentWrapper
        component={LazyErrorComponent}
        componentName="ErrorComponent"
      />
    );

    // Aguardar o erro aparecer
    await waitFor(() => {
      expect(screen.getByText('Erro ao carregar componente')).toBeInTheDocument();
    });

    // Clicar no botão de retry
    const retryButton = screen.getByText('Tentar novamente');
    fireEvent.click(retryButton);

    // Verificar se o erro ainda está presente (pois o componente ainda vai falhar)
    expect(screen.getByText('Erro ao carregar componente')).toBeInTheDocument();
  });
});

// ===== TESTES DO UTILITÁRIO =====

describe('createLazyComponent', () => {
  test('deve criar componente lazy com configuração padrão', async () => {
    const LazyComponent = createLazyComponent(
      () => Promise.resolve({ default: MockComponent }),
      'MockComponent'
    );

    render(<LazyComponent />);

    // Verificar se o fallback aparece
    expect(screen.getByText('Carregando MockComponent...')).toBeInTheDocument();
    
    // Aguardar o componente carregar
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
  });
});

// ===== TESTES DE PERFORMANCE =====

describe('Performance de Lazy Loading', () => {
  test('deve carregar componente em tempo aceitável', async () => {
    const startTime = performance.now();
    
    const TestComponent = () => {
      const { LazyComponent } = useLazyLoading(
        () => Promise.resolve({ default: MockComponent })
      );

      return <LazyComponent />;
    };

    render(<TestComponent />);
    
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
    
    const endTime = performance.now();
    const loadTime = endTime - startTime;
    
    // Verificar se o tempo de carregamento é aceitável (< 100ms)
    expect(loadTime).toBeLessThan(100);
  });

  test('deve evitar re-renders desnecessários', async () => {
    const renderCount = jest.fn();
    
    const TestComponent = () => {
      renderCount();
      const { LazyComponent } = useLazyLoading(
        () => Promise.resolve({ default: MockComponent })
      );

      return <LazyComponent />;
    };

    render(<TestComponent />);
    
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
    
    // Verificar se o componente não foi renderizado excessivamente
    expect(renderCount).toHaveBeenCalledTimes(1);
  });
});

// ===== TESTES DE INTEGRAÇÃO =====

describe('Integração com React Router', () => {
  test('deve funcionar com React.lazy e Suspense', async () => {
    const LazyRouteComponent = React.lazy(() => 
      Promise.resolve({ default: MockComponent })
    );

    render(
      <React.Suspense fallback={<div data-testid="suspense-fallback">Carregando...</div>}>
        <LazyRouteComponent />
      </React.Suspense>
    );

    // Verificar se o fallback do Suspense aparece
    expect(screen.getByTestId('suspense-fallback')).toBeInTheDocument();
    
    // Aguardar o componente carregar
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    });
  });
});

// ===== TESTES DE ACESSIBILIDADE =====

describe('Acessibilidade do Lazy Loading', () => {
  test('deve ter fallback acessível', async () => {
    const LazyMockComponent = React.lazy(() => 
      Promise.resolve({ default: MockComponent })
    );

    render(
      <LazyComponentWrapper
        component={LazyMockComponent}
        componentName="MockComponent"
      />
    );

    // Verificar se o fallback tem texto descritivo
    const fallback = screen.getByText('Carregando MockComponent...');
    expect(fallback).toBeInTheDocument();
    expect(fallback).toHaveAttribute('role', 'status');
  });

  test('deve ter mensagem de erro acessível', async () => {
    const LazyErrorComponent = React.lazy(() => 
      Promise.resolve({ default: ErrorComponent })
    );

    render(
      <LazyComponentWrapper
        component={LazyErrorComponent}
        componentName="ErrorComponent"
      />
    );

    await waitFor(() => {
      expect(screen.getByText('Erro ao carregar componente')).toBeInTheDocument();
    });

    // Verificar se a mensagem de erro é acessível
    const errorMessage = screen.getByText('Erro ao carregar componente');
    expect(errorMessage).toHaveAttribute('role', 'alert');
  });
});

// ===== TESTES DE EDGE CASES =====

describe('Edge Cases do Lazy Loading', () => {
  test('deve lidar com componente que retorna null', async () => {
    const NullComponent = () => null;
    
    const TestComponent = () => {
      const { LazyComponent } = useLazyLoading(
        () => Promise.resolve({ default: NullComponent })
      );

      return <LazyComponent />;
    };

    render(<TestComponent />);
    
    // Aguardar o componente carregar (mesmo que seja null)
    await waitFor(() => {
      expect(screen.queryByTestId('loading')).not.toBeInTheDocument();
    });
  });

  test('deve lidar com import que demora muito', async () => {
    const slowImport = () => 
      new Promise(resolve => 
        setTimeout(() => resolve({ default: MockComponent }), 1000)
      );

    const TestComponent = () => {
      const { LazyComponent, isLoading } = useLazyLoading(slowImport);

      return (
        <div>
          {isLoading && <div data-testid="loading">Carregando...</div>}
          <LazyComponent />
        </div>
      );
    };

    render(<TestComponent />);
    
    // Verificar se o loading aparece
    expect(screen.getByTestId('loading')).toBeInTheDocument();
    
    // Aguardar o componente carregar
    await waitFor(() => {
      expect(screen.getByTestId('mock-component')).toBeInTheDocument();
    }, { timeout: 2000 });
  });
}); 