import React, { useState, useEffect, useCallback } from 'react';

/**
 * Tipos de toast disponíveis.
 * 
 * Tracing ID: COMM_IMPL_20250128_001
 * Data/Hora: 2025-01-28T11:30:00Z
 * Prompt: Fullstack Communication Audit
 * Ruleset: Enterprise+ Standards
 */
export type ToastType = 'success' | 'error' | 'warning' | 'info';

/**
 * Interface para configuração do toast.
 */
export interface ToastConfig {
  type: ToastType;
  title: string;
  message?: string;
  duration?: number; // Duração em ms, 0 = não fecha automaticamente
  showCloseButton?: boolean;
  showProgress?: boolean;
  onClose?: () => void;
  onAction?: () => void;
  actionLabel?: string;
}

/**
 * Interface para o contexto do toast.
 */
interface ToastContextType {
  showToast: (config: ToastConfig) => void;
  hideToast: (id: string) => void;
  clearAll: () => void;
}

/**
 * Contexto do toast.
 */
const ToastContext = React.createContext<ToastContextType | undefined>(undefined);

/**
 * Hook para usar o sistema de toast.
 */
export const useToast = () => {
  const context = React.useContext(ToastContext);
  if (!context) {
    throw new Error('useToast deve ser usado dentro de ToastProvider');
  }
  return context;
};

/**
 * Componente individual do toast.
 */
interface ToastItemProps extends Omit<ToastConfig, 'onClose'> {
  id: string;
  onClose: (id: string) => void;
}

const ToastItem: React.FC<ToastItemProps> = ({
  id,
  type,
  title,
  message,
  duration = 5000,
  showCloseButton = true,
  showProgress = true,
  onClose,
  onAction,
  actionLabel,
  onClose: closeToast
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [progress, setProgress] = useState(100);

  // Anima entrada
  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);

  // Progresso automático
  useEffect(() => {
    if (duration > 0 && showProgress) {
      const startTime = Date.now();
      const interval = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, 100 - (elapsed / duration) * 100);
        setProgress(remaining);
        
        if (remaining <= 0) {
          clearInterval(interval);
          handleClose();
        }
      }, 50);

      return () => clearInterval(interval);
    }
  }, [duration, showProgress]);

  const handleClose = useCallback(() => {
    setIsVisible(false);
    setTimeout(() => {
      closeToast(id);
      onClose?.();
    }, 300);
  }, [id, closeToast, onClose]);

  const handleAction = useCallback(() => {
    onAction?.();
    handleClose();
  }, [onAction, handleClose]);

  // Configurações por tipo
  const getToastStyles = () => {
    const baseStyles = "flex items-start p-4 rounded-lg shadow-lg transition-all duration-300 transform";
    
    switch (type) {
      case 'success':
        return `${baseStyles} bg-green-50 border border-green-200 text-green-800`;
      case 'error':
        return `${baseStyles} bg-red-50 border border-red-200 text-red-800`;
      case 'warning':
        return `${baseStyles} bg-yellow-50 border border-yellow-200 text-yellow-800`;
      case 'info':
        return `${baseStyles} bg-blue-50 border border-blue-200 text-blue-800`;
      default:
        return `${baseStyles} bg-gray-50 border border-gray-200 text-gray-800`;
    }
  };

  const getIcon = () => {
    switch (type) {
      case 'success':
        return (
          <svg className="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
        );
      case 'error':
        return (
          <svg className="w-5 h-5 text-red-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
        );
      case 'warning':
        return (
          <svg className="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        );
      case 'info':
        return (
          <svg className="w-5 h-5 text-blue-500" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
        );
      default:
        return null;
    }
  };

  return (
    <div
      className={`${getToastStyles()} ${
        isVisible ? 'translate-x-0 opacity-100' : 'translate-x-full opacity-0'
      }`}
      role="alert"
      aria-live="assertive"
    >
      {/* Ícone */}
      <div className="flex-shrink-0 mr-3 mt-0.5">
        {getIcon()}
      </div>

      {/* Conteúdo */}
      <div className="flex-1 min-w-0">
        <h4 className="text-sm font-medium">{title}</h4>
        {message && (
          <p className="mt-1 text-sm opacity-90">{message}</p>
        )}
        
        {/* Barra de progresso */}
        {showProgress && duration > 0 && (
          <div className="mt-2 w-full bg-gray-200 rounded-full h-1">
            <div
              className="bg-current h-1 rounded-full transition-all duration-100"
              style={{ width: `${progress}%` }}
            />
          </div>
        )}
      </div>

      {/* Ações */}
      <div className="flex items-center space-x-2 ml-4">
        {onAction && actionLabel && (
          <button
            onClick={handleAction}
            className="text-sm font-medium hover:opacity-80 transition-opacity"
          >
            {actionLabel}
          </button>
        )}
        
        {showCloseButton && (
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
            aria-label="Fechar notificação"
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
};

/**
 * Container principal do sistema de toast.
 */
export const ToastContainer: React.FC = () => {
  const [toasts, setToasts] = useState<Array<ToastConfig & { id: string }>>([]);

  const showToast = useCallback((config: ToastConfig) => {
    const id = `toast_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    setToasts(prev => [...prev, { ...config, id }]);
  }, []);

  const hideToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setToasts([]);
  }, []);

  // Limita número máximo de toasts
  useEffect(() => {
    if (toasts.length > 5) {
      setToasts(prev => prev.slice(-5));
    }
  }, [toasts.length]);

  return (
    <ToastContext.Provider value={{ showToast, hideToast, clearAll }}>
      {/* Container de toasts */}
      <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
        {toasts.map(toast => (
          <ToastItem
            key={toast.id}
            {...toast}
            onClose={hideToast}
          />
        ))}
      </div>
    </ToastContext.Provider>
  );
};

/**
 * Hook para usar toast com configurações pré-definidas.
 */
export const useToastHelpers = () => {
  const { showToast } = useToast();

  const showSuccess = useCallback((title: string, message?: string) => {
    showToast({ type: 'success', title, message });
  }, [showToast]);

  const showError = useCallback((title: string, message?: string) => {
    showToast({ type: 'error', title, message });
  }, [showToast]);

  const showWarning = useCallback((title: string, message?: string) => {
    showToast({ type: 'warning', title, message });
  }, [showToast]);

  const showInfo = useCallback((title: string, message?: string) => {
    showToast({ type: 'info', title, message });
  }, [showToast]);

  const showApiError = useCallback((error: string, retryCount?: number) => {
    const title = 'Erro na requisição';
    const message = retryCount && retryCount > 0 
      ? `${error} (Tentativa ${retryCount})`
      : error;
    
    showToast({
      type: 'error',
      title,
      message,
      duration: 8000,
      showCloseButton: true,
      showProgress: true
    });
  }, [showToast]);

  const showTimeoutError = useCallback((timeoutMs: number) => {
    showToast({
      type: 'warning',
      title: 'Timeout da requisição',
      message: `A requisição excedeu o tempo limite de ${timeoutMs / 1000}s`,
      duration: 10000,
      showCloseButton: true,
      showProgress: true
    });
  }, [showToast]);

  return {
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showApiError,
    showTimeoutError
  };
}; 