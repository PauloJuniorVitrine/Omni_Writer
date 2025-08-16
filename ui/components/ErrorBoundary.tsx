/**
 * Error Boundary - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-027.4
 * Data/Hora: 2025-01-28T02:41:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Captura de erros React
 * - Fallback UI
 * - Error reporting
 * - Recovery mechanisms
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Button } from './base/Button';

// ===== TIPOS =====

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  resetKey?: string | number;
  showDetails?: boolean;
  enableRecovery?: boolean;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorId: string;
}

// ===== COMPONENTE PRINCIPAL =====

/**
 * Error Boundary para captura de erros React
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return {
      hasError: true,
      error,
      errorId: `error_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    this.setState({ errorInfo });

    // Log do erro
    console.error('Error Boundary capturou um erro:', error, errorInfo);

    // Callback personalizado
    this.props.onError?.(error, errorInfo);

    // Enviar para serviço de monitoramento (ex: Sentry)
    this.reportError(error, errorInfo);
  }

  /**
   * Reportar erro para serviço de monitoramento
   */
  private reportError = (error: Error, errorInfo: ErrorInfo) => {
    try {
      // Aqui você pode integrar com Sentry, LogRocket, etc.
      if (typeof window !== 'undefined' && (window as any).Sentry) {
        (window as any).Sentry.captureException(error, {
          contexts: {
            react: {
              componentStack: errorInfo.componentStack
            }
          },
          tags: {
            errorId: this.state.errorId,
            component: 'ErrorBoundary'
          }
        });
      }

      // Log estruturado
      const errorReport = {
        errorId: this.state.errorId,
        timestamp: new Date().toISOString(),
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        },
        errorInfo: {
          componentStack: errorInfo.componentStack
        },
        userAgent: navigator.userAgent,
        url: window.location.href
      };

      console.log('Error Report:', errorReport);

      // Enviar para endpoint de monitoramento
      this.sendErrorReport(errorReport);
    } catch (reportError) {
      console.error('Erro ao reportar erro:', reportError);
    }
  };

  /**
   * Enviar relatório de erro para servidor
   */
  private sendErrorReport = async (errorReport: any) => {
    try {
      await fetch('/api/errors', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(errorReport)
      });
    } catch (error) {
      console.error('Falha ao enviar relatório de erro:', error);
    }
  };

  /**
   * Resetar o error boundary
   */
  private handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: ''
    });
  };

  /**
   * Reload da página
   */
  private handleReload = () => {
    window.location.reload();
  };

  /**
   * Copiar detalhes do erro
   */
  private handleCopyDetails = () => {
    const errorDetails = `
Error ID: ${this.state.errorId}
Timestamp: ${new Date().toISOString()}
URL: ${window.location.href}
User Agent: ${navigator.userAgent}

Error: ${this.state.error?.name}: ${this.state.error?.message}
Stack: ${this.state.error?.stack}

Component Stack: ${this.state.errorInfo?.componentStack}
    `.trim();

    navigator.clipboard.writeText(errorDetails).then(() => {
      alert('Detalhes do erro copiados para a área de transferência');
    });
  };

  render() {
    if (this.state.hasError) {
      // Fallback customizado
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Fallback padrão
      return (
        <div className="error-boundary min-h-screen flex items-center justify-center bg-gray-50">
          <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6">
            <div className="text-center">
              {/* Ícone de erro */}
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
                <svg
                  className="h-6 w-6 text-red-600"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                  />
                </svg>
              </div>

              {/* Título */}
              <h2 className="text-lg font-semibold text-gray-900 mb-2">
                Algo deu errado
              </h2>

              {/* Mensagem */}
              <p className="text-sm text-gray-600 mb-4">
                Ocorreu um erro inesperado. Nossa equipe foi notificada.
              </p>

              {/* Error ID */}
              <div className="bg-gray-100 rounded p-2 mb-4">
                <p className="text-xs text-gray-500">
                  Error ID: <span className="font-mono">{this.state.errorId}</span>
                </p>
              </div>

              {/* Detalhes do erro (opcional) */}
              {this.props.showDetails && this.state.error && (
                <details className="text-left mb-4">
                  <summary className="cursor-pointer text-sm text-gray-600 hover:text-gray-800">
                    Ver detalhes do erro
                  </summary>
                  <div className="mt-2 p-3 bg-red-50 rounded text-xs font-mono text-red-800 overflow-auto max-h-32">
                    <div className="mb-2">
                      <strong>Error:</strong> {this.state.error.name}: {this.state.error.message}
                    </div>
                    {this.state.error.stack && (
                      <div>
                        <strong>Stack:</strong>
                        <pre className="whitespace-pre-wrap">{this.state.error.stack}</pre>
                      </div>
                    )}
                    {this.state.errorInfo && (
                      <div className="mt-2">
                        <strong>Component Stack:</strong>
                        <pre className="whitespace-pre-wrap">{this.state.errorInfo.componentStack}</pre>
                      </div>
                    )}
                  </div>
                </details>
              )}

              {/* Ações */}
              <div className="flex flex-col gap-2">
                {this.props.enableRecovery && (
                  <Button
                    variant="primary"
                    onClick={this.handleReset}
                    className="w-full"
                  >
                    Tentar Novamente
                  </Button>
                )}

                <Button
                  variant="outline"
                  onClick={this.handleReload}
                  className="w-full"
                >
                  Recarregar Página
                </Button>

                {this.props.showDetails && (
                  <Button
                    variant="ghost"
                    onClick={this.handleCopyDetails}
                    className="w-full text-sm"
                  >
                    Copiar Detalhes
                  </Button>
                )}
              </div>

              {/* Link de suporte */}
              <div className="mt-4 pt-4 border-t border-gray-200">
                <p className="text-xs text-gray-500">
                  Se o problema persistir, entre em contato com o suporte.
                </p>
                <a
                  href="mailto:support@omniwriter.com"
                  className="text-xs text-blue-600 hover:text-blue-800"
                >
                  support@omniwriter.com
                </a>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// ===== HOOKS =====

/**
 * Hook para usar error boundary em componentes funcionais
 */
export const useErrorBoundary = () => {
  const [error, setError] = React.useState<Error | null>(null);

  const handleError = React.useCallback((error: Error) => {
    setError(error);
    console.error('Erro capturado pelo hook:', error);
  }, []);

  const resetError = React.useCallback(() => {
    setError(null);
  }, []);

  return {
    error,
    handleError,
    resetError,
    hasError: !!error
  };
};

// ===== COMPONENTES ESPECIALIZADOS =====

/**
 * Error Boundary para rotas específicas
 */
export const RouteErrorBoundary: React.FC<Props> = (props) => {
  return (
    <ErrorBoundary
      {...props}
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-gray-900 mb-4">
              Página não encontrada
            </h1>
            <p className="text-gray-600 mb-4">
              A página que você está procurando não existe ou foi movida.
            </p>
            <Button
              variant="primary"
              onClick={() => window.history.back()}
            >
              Voltar
            </Button>
          </div>
        </div>
      }
    />
  );
};

/**
 * Error Boundary para componentes específicos
 */
export const ComponentErrorBoundary: React.FC<Props> = (props) => {
  return (
    <ErrorBoundary
      {...props}
      fallback={
        <div className="p-4 border border-red-200 rounded bg-red-50">
          <div className="flex items-center">
            <svg
              className="h-5 w-5 text-red-400 mr-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
              />
            </svg>
            <span className="text-sm text-red-800">
              Erro ao carregar componente
            </span>
          </div>
        </div>
      }
    />
  );
};

export default ErrorBoundary; 