/**
 * Componente Toast - Omni Writer
 * 
 * Notificações temporárias com diferentes tipos
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { theme } from '../../theme';

// ===== TIPOS =====
interface ToastProps {
  /** ID único do toast */
  id: string;
  /** Tipo do toast */
  type?: 'success' | 'error' | 'warning' | 'info';
  /** Título do toast */
  title?: string;
  /** Mensagem do toast */
  message: string;
  /** Duração em milissegundos */
  duration?: number;
  /** Posição do toast */
  position?: 'top-left' | 'top-right' | 'top-center' | 'bottom-left' | 'bottom-right' | 'bottom-center';
  /** Mostrar botão de fechar */
  showCloseButton?: boolean;
  /** Função de fechamento */
  onClose?: (id: string) => void;
  /** Ícone customizado */
  icon?: React.ReactNode;
  /** Ações customizadas */
  actions?: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
  /** Auto-fechar */
  autoClose?: boolean;
  /** Pausar no hover */
  pauseOnHover?: boolean;
}

// ===== ESTILOS =====
const getToastContainerStyles = (position: string) => {
  const baseStyles = {
    position: 'fixed' as const,
    zIndex: 9999,
    display: 'flex',
    flexDirection: 'column' as const,
    gap: theme.spacing.spacing[8],
    maxWidth: '400px',
    pointerEvents: 'none',
  };

  const positionStyles = {
    'top-left': {
      top: theme.spacing.spacing[16],
      left: theme.spacing.spacing[16],
    },
    'top-right': {
      top: theme.spacing.spacing[16],
      right: theme.spacing.spacing[16],
    },
    'top-center': {
      top: theme.spacing.spacing[16],
      left: '50%',
      transform: 'translateX(-50%)',
    },
    'bottom-left': {
      bottom: theme.spacing.spacing[16],
      left: theme.spacing.spacing[16],
    },
    'bottom-right': {
      bottom: theme.spacing.spacing[16],
      right: theme.spacing.spacing[16],
    },
    'bottom-center': {
      bottom: theme.spacing.spacing[16],
      left: '50%',
      transform: 'translateX(-50%)',
    },
  };

  return {
    ...baseStyles,
    ...positionStyles[position as keyof typeof positionStyles],
  };
};

const getToastStyles = (type: string) => {
  const baseStyles = {
    display: 'flex',
    alignItems: 'flex-start',
    gap: theme.spacing.spacing[12],
    padding: theme.spacing.spacing[16],
    borderRadius: theme.spacing.spacing[8],
    boxShadow: theme.shadows.shadows.lg,
    backgroundColor: theme.colors.semantic.background.primary,
    border: `1px solid ${theme.colors.semantic.border.primary}`,
    minWidth: '300px',
    maxWidth: '400px',
    pointerEvents: 'auto',
    transition: 'all 0.3s ease-in-out',
    transform: 'translateX(0)',
    opacity: 1,
  };

  const typeStyles = {
    success: {
      borderLeft: `4px solid ${theme.colors.base.success[500]}`,
      backgroundColor: theme.colors.base.success[50],
    },
    error: {
      borderLeft: `4px solid ${theme.colors.base.error[500]}`,
      backgroundColor: theme.colors.base.error[50],
    },
    warning: {
      borderLeft: `4px solid ${theme.colors.base.warning[500]}`,
      backgroundColor: theme.colors.base.warning[50],
    },
    info: {
      borderLeft: `4px solid ${theme.colors.base.info[500]}`,
      backgroundColor: theme.colors.base.info[50],
    },
  };

  return {
    ...baseStyles,
    ...typeStyles[type as keyof typeof typeStyles],
  };
};

const getIconStyles = (type: string) => {
  const baseStyles = {
    flexShrink: 0,
    width: '20px',
    height: '20px',
    marginTop: '2px',
  };

  const typeColors = {
    success: theme.colors.base.success[500],
    error: theme.colors.base.error[500],
    warning: theme.colors.base.warning[500],
    info: theme.colors.base.info[500],
  };

  return {
    ...baseStyles,
    color: typeColors[type as keyof typeof typeColors],
  };
};

const getContentStyles = () => {
  return {
    flex: 1,
    minWidth: 0,
  };
};

const getTitleStyles = () => {
  return {
    fontSize: theme.typography.fontSizes.base,
    fontWeight: theme.typography.fonts.weight.semibold,
    color: theme.colors.semantic.text.primary,
    margin: 0,
    marginBottom: theme.spacing.spacing[4],
  };
};

const getMessageStyles = () => {
  return {
    fontSize: theme.typography.fontSizes.sm,
    color: theme.colors.semantic.text.secondary,
    margin: 0,
    lineHeight: theme.typography.fonts.lineHeight.normal,
  };
};

const getCloseButtonStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '24px',
    height: '24px',
    border: 'none',
    backgroundColor: 'transparent',
    borderRadius: theme.spacing.spacing[4],
    cursor: 'pointer',
    color: theme.colors.semantic.text.secondary,
    transition: 'all 0.2s ease-in-out',
    flexShrink: 0,
    marginTop: '2px',
  };
};

const getActionsStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[8],
    marginTop: theme.spacing.spacing[12],
  };
};

// ===== ÍCONES PADRÃO =====
const getDefaultIcon = (type: string) => {
  const icons = {
    success: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M20 6 9 17l-5-5"/>
      </svg>
    ),
    error: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M18 6 6 18M6 6l12 12"/>
      </svg>
    ),
    warning: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/>
        <line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    ),
    info: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="12" y1="16" x2="12" y2="12"/>
        <line x1="12" y1="8" x2="12.01" y2="8"/>
      </svg>
    ),
  };

  return icons[type as keyof typeof icons] || icons.info;
};

// ===== COMPONENTE =====
export const Toast: React.FC<ToastProps> = ({
  id,
  type = 'info',
  title,
  message,
  duration = 5000,
  position = 'top-right',
  showCloseButton = true,
  onClose,
  icon,
  actions,
  className = '',
  autoClose = true,
  pauseOnHover = true,
}) => {
  const [isVisible, setIsVisible] = useState(true);
  const [isPaused, setIsPaused] = useState(false);

  // Auto-fechar
  useEffect(() => {
    if (!autoClose || duration === 0) return;

    let timeoutId: NodeJS.Timeout;

    if (!isPaused) {
      timeoutId = setTimeout(() => {
        setIsVisible(false);
        setTimeout(() => {
          onClose?.(id);
        }, 300); // Aguardar animação de saída
      }, duration);
    }

    return () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [id, duration, autoClose, isPaused, onClose]);

  // Handlers
  const handleClose = () => {
    setIsVisible(false);
    setTimeout(() => {
      onClose?.(id);
    }, 300);
  };

  const handleMouseEnter = () => {
    if (pauseOnHover) {
      setIsPaused(true);
    }
  };

  const handleMouseLeave = () => {
    if (pauseOnHover) {
      setIsPaused(false);
    }
  };

  // Estilos
  const toastStyles = {
    ...getToastStyles(type),
    transform: isVisible ? 'translateX(0)' : 'translateX(100%)',
    opacity: isVisible ? 1 : 0,
  };

  const iconStyles = getIconStyles(type);
  const contentStyles = getContentStyles();
  const titleStyles = getTitleStyles();
  const messageStyles = getMessageStyles();
  const closeButtonStyles = getCloseButtonStyles();
  const actionsStyles = getActionsStyles();

  const defaultIcon = getDefaultIcon(type);
  const toastIcon = icon || defaultIcon;

  return (
    <div
      style={toastStyles}
      className={`omni-writer-toast omni-writer-toast--${type} ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      role="alert"
      aria-live="assertive"
      aria-atomic="true"
    >
      <div style={iconStyles} className="omni-writer-toast-icon">
        {toastIcon}
      </div>

      <div style={contentStyles} className="omni-writer-toast-content">
        {title && (
          <h4 style={titleStyles} className="omni-writer-toast-title">
            {title}
          </h4>
        )}
        <p style={messageStyles} className="omni-writer-toast-message">
          {message}
        </p>
        {actions && (
          <div style={actionsStyles} className="omni-writer-toast-actions">
            {actions}
          </div>
        )}
      </div>

      {showCloseButton && (
        <button
          style={closeButtonStyles}
          onClick={handleClose}
          className="omni-writer-toast-close"
          aria-label="Fechar notificação"
          type="button"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6 6 18M6 6l12 12"/>
          </svg>
        </button>
      )}
    </div>
  );
};

// ===== COMPONENTE CONTAINER =====
interface ToastContainerProps {
  /** Posição do container */
  position?: 'top-left' | 'top-right' | 'top-center' | 'bottom-left' | 'bottom-right' | 'bottom-center';
  /** Toasts ativos */
  toasts: ToastProps[];
  /** Função de remoção */
  removeToast: (id: string) => void;
  /** Classe CSS adicional */
  className?: string;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({
  position = 'top-right',
  toasts,
  removeToast,
  className = '',
}) => {
  const containerStyles = getToastContainerStyles(position);

  if (toasts.length === 0) return null;

  const containerContent = (
    <div
      style={containerStyles}
      className={`omni-writer-toast-container omni-writer-toast-container--${position} ${className}`}
    >
      {toasts.map((toast) => (
        <Toast
          key={toast.id}
          {...toast}
          onClose={removeToast}
        />
      ))}
    </div>
  );

  return createPortal(containerContent, document.body);
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const SuccessToast: React.FC<Omit<ToastProps, 'type'>> = (props) => (
  <Toast {...props} type="success" />
);

export const ErrorToast: React.FC<Omit<ToastProps, 'type'>> = (props) => (
  <Toast {...props} type="error" />
);

export const WarningToast: React.FC<Omit<ToastProps, 'type'>> = (props) => (
  <Toast {...props} type="warning" />
);

export const InfoToast: React.FC<Omit<ToastProps, 'type'>> = (props) => (
  <Toast {...props} type="info" />
);

export const PersistentToast: React.FC<Omit<ToastProps, 'autoClose'>> = (props) => (
  <Toast {...props} autoClose={false} />
);

export const QuickToast: React.FC<Omit<ToastProps, 'duration'>> = (props) => (
  <Toast {...props} duration={2000} />
);

// ===== HOOK PARA GERENCIAR TOASTS =====
interface UseToastReturn {
  toasts: ToastProps[];
  addToast: (toast: Omit<ToastProps, 'id'>) => void;
  removeToast: (id: string) => void;
  clearToasts: () => void;
}

export const useToast = (): UseToastReturn => {
  const [toasts, setToasts] = useState<ToastProps[]>([]);

  const addToast = (toast: Omit<ToastProps, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newToast = { ...toast, id };
    
    setToasts(prev => [...prev, newToast]);
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  };

  const clearToasts = () => {
    setToasts([]);
  };

  return {
    toasts,
    addToast,
    removeToast,
    clearToasts,
  };
};

// ===== EXPORTAÇÃO =====
Toast.displayName = 'Toast';
export default Toast; 