import React from 'react';

/**
 * Interface para configuração do spinner.
 * 
 * Tracing ID: COMM_IMPL_20250128_001
 * Data/Hora: 2025-01-28T11:35:00Z
 * Prompt: Fullstack Communication Audit
 * Ruleset: Enterprise+ Standards
 */
interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'warning';
  text?: string;
  showText?: boolean;
  className?: string;
}

/**
 * Componente de spinner de carregamento com diferentes tamanhos e cores.
 * 
 * Funcionalidades:
 * - Múltiplos tamanhos (sm, md, lg, xl)
 * - Diferentes cores baseadas no contexto
 * - Texto opcional de carregamento
 * - Animações suaves
 * - Acessibilidade (aria-label)
 */
export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  color = 'primary',
  text,
  showText = false,
  className = ''
}) => {
  // Configurações de tamanho
  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'w-4 h-4';
      case 'md':
        return 'w-6 h-6';
      case 'lg':
        return 'w-8 h-8';
      case 'xl':
        return 'w-12 h-12';
      default:
        return 'w-6 h-6';
    }
  };

  // Configurações de cor
  const getColorClasses = () => {
    switch (color) {
      case 'primary':
        return 'text-blue-600';
      case 'secondary':
        return 'text-gray-600';
      case 'success':
        return 'text-green-600';
      case 'error':
        return 'text-red-600';
      case 'warning':
        return 'text-yellow-600';
      default:
        return 'text-blue-600';
    }
  };

  // Texto de carregamento padrão
  const loadingText = text || 'Carregando...';

  return (
    <div className={`flex flex-col items-center justify-center ${className}`}>
      {/* Spinner */}
      <div
        className={`${getSizeClasses()} ${getColorClasses()} animate-spin`}
        role="status"
        aria-label={loadingText}
      >
        <svg
          className="w-full h-full"
          fill="none"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      </div>

      {/* Texto de carregamento */}
      {showText && (
        <p className="mt-2 text-sm text-gray-600 animate-pulse">
          {loadingText}
        </p>
      )}
    </div>
  );
};

/**
 * Componente de loading overlay para páginas inteiras.
 */
interface LoadingOverlayProps {
  isLoading: boolean;
  text?: string;
  showSpinner?: boolean;
  className?: string;
}

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  text = 'Carregando...',
  showSpinner = true,
  className = ''
}) => {
  if (!isLoading) return null;

  return (
    <div className={`fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 ${className}`}>
      <div className="bg-white rounded-lg p-6 shadow-xl">
        {showSpinner && (
          <LoadingSpinner
            size="lg"
            color="primary"
            text={text}
            showText={true}
          />
        )}
      </div>
    </div>
  );
};

/**
 * Componente de loading inline para botões e elementos pequenos.
 */
interface InlineLoadingProps {
  isLoading: boolean;
  children: React.ReactNode;
  loadingText?: string;
  className?: string;
}

export const InlineLoading: React.FC<InlineLoadingProps> = ({
  isLoading,
  children,
  loadingText = 'Carregando...',
  className = ''
}) => {
  if (isLoading) {
    return (
      <div className={`inline-flex items-center ${className}`}>
        <LoadingSpinner size="sm" color="primary" />
        <span className="ml-2 text-sm text-gray-600">{loadingText}</span>
      </div>
    );
  }

  return <>{children}</>;
};

/**
 * Componente de loading com progresso.
 */
interface LoadingProgressProps {
  progress: number; // 0-100
  text?: string;
  showPercentage?: boolean;
  className?: string;
}

export const LoadingProgress: React.FC<LoadingProgressProps> = ({
  progress,
  text = 'Carregando...',
  showPercentage = true,
  className = ''
}) => {
  const clampedProgress = Math.max(0, Math.min(100, progress));

  return (
    <div className={`w-full ${className}`}>
      {/* Texto */}
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm text-gray-600">{text}</span>
        {showPercentage && (
          <span className="text-sm text-gray-600">{clampedProgress}%</span>
        )}
      </div>

      {/* Barra de progresso */}
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div
          className="bg-blue-600 h-2 rounded-full transition-all duration-300 ease-out"
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  );
};

/**
 * Hook para controlar estados de loading.
 */
export const useLoading = (initialState = false) => {
  const [isLoading, setIsLoading] = React.useState(initialState);
  const [loadingText, setLoadingText] = React.useState<string>('');

  const startLoading = React.useCallback((text?: string) => {
    setIsLoading(true);
    if (text) setLoadingText(text);
  }, []);

  const stopLoading = React.useCallback(() => {
    setIsLoading(false);
    setLoadingText('');
  }, []);

  const withLoading = React.useCallback(async <T,>(
    asyncFn: () => Promise<T>,
    text?: string
  ): Promise<T> => {
    startLoading(text);
    try {
      const result = await asyncFn();
      return result;
    } finally {
      stopLoading();
    }
  }, [startLoading, stopLoading]);

  return {
    isLoading,
    loadingText,
    startLoading,
    stopLoading,
    withLoading
  };
}; 