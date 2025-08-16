/**
 * Componente Modal - Omni Writer
 * 
 * Diálogos modais com diferentes variantes
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { theme } from '../../theme';

// ===== TIPOS =====
interface ModalProps {
  /** Estado de abertura */
  isOpen: boolean;
  /** Função de fechamento */
  onClose: () => void;
  /** Título do modal */
  title?: string;
  /** Conteúdo do modal */
  children: React.ReactNode;
  /** Tamanho do modal */
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  /** Variante do modal */
  variant?: 'default' | 'centered' | 'side' | 'fullscreen';
  /** Posição do modal */
  position?: 'center' | 'top' | 'bottom' | 'left' | 'right';
  /** Fechar ao clicar fora */
  closeOnOverlayClick?: boolean;
  /** Fechar ao pressionar ESC */
  closeOnEscape?: boolean;
  /** Mostrar overlay */
  showOverlay?: boolean;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
  /** Descrição para acessibilidade */
  description?: string;
  /** Largura customizada */
  width?: string;
  /** Altura customizada */
  height?: string;
  /** Z-index customizado */
  zIndex?: number;
}

// ===== ESTILOS =====
const getOverlayStyles = (showOverlay: boolean, zIndex: number) => {
  const baseStyles = {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: showOverlay ? 'rgba(0, 0, 0, 0.5)' : 'transparent',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: zIndex,
    backdropFilter: showOverlay ? 'blur(4px)' : 'none',
    transition: 'all 0.3s ease-in-out',
  };

  return baseStyles;
};

const getModalStyles = (size: string, variant: string, position: string, width?: string, height?: string) => {
  const baseStyles = {
    backgroundColor: theme.colors.semantic.background.primary,
    border: `1px solid ${theme.colors.semantic.border.primary}`,
    borderRadius: theme.spacing.spacing[8],
    boxShadow: theme.shadows.shadows.xl,
    position: 'relative' as const,
    outline: 'none',
    maxWidth: '90vw',
    maxHeight: '90vh',
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column' as const,
  };

  const sizeStyles = {
    sm: {
      width: width || '400px',
      minHeight: height || 'auto',
    },
    md: {
      width: width || '600px',
      minHeight: height || 'auto',
    },
    lg: {
      width: width || '800px',
      minHeight: height || 'auto',
    },
    xl: {
      width: width || '1200px',
      minHeight: height || 'auto',
    },
    full: {
      width: width || '95vw',
      height: height || '95vh',
    },
  };

  const variantStyles = {
    default: {
      borderRadius: theme.spacing.spacing[8],
    },
    centered: {
      borderRadius: theme.spacing.spacing[12],
      margin: 'auto',
    },
    side: {
      borderRadius: 0,
      height: '100vh',
      margin: 0,
    },
    fullscreen: {
      borderRadius: 0,
      width: '100vw',
      height: '100vh',
      margin: 0,
    },
  };

  const positionStyles = {
    center: {
      alignItems: 'center',
      justifyContent: 'center',
    },
    top: {
      alignItems: 'flex-start',
      justifyContent: 'center',
      paddingTop: theme.spacing.spacing[24],
    },
    bottom: {
      alignItems: 'flex-end',
      justifyContent: 'center',
      paddingBottom: theme.spacing.spacing[24],
    },
    left: {
      alignItems: 'center',
      justifyContent: 'flex-start',
      paddingLeft: theme.spacing.spacing[24],
    },
    right: {
      alignItems: 'center',
      justifyContent: 'flex-end',
      paddingRight: theme.spacing.spacing[24],
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
    ...variantStyles[variant as keyof typeof variantStyles],
    ...positionStyles[position as keyof typeof positionStyles],
  };
};

const getHeaderStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: theme.spacing.spacing[16],
    borderBottom: `1px solid ${theme.colors.semantic.border.primary}`,
    backgroundColor: theme.colors.semantic.background.secondary,
  };
};

const getTitleStyles = () => {
  return {
    fontSize: theme.typography.fontSizes.lg,
    fontWeight: theme.typography.fonts.weight.semibold,
    color: theme.colors.semantic.text.primary,
    margin: 0,
    flex: 1,
  };
};

const getCloseButtonStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: 'none',
    backgroundColor: 'transparent',
    borderRadius: theme.spacing.spacing[4],
    cursor: 'pointer',
    color: theme.colors.semantic.text.secondary,
    transition: 'all 0.2s ease-in-out',
    marginLeft: theme.spacing.spacing[8],
  };
};

const getBodyStyles = () => {
  return {
    padding: theme.spacing.spacing[16],
    flex: 1,
    overflowY: 'auto' as const,
    overflowX: 'hidden' as const,
  };
};

const getFooterStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
    gap: theme.spacing.spacing[8],
    padding: theme.spacing.spacing[16],
    borderTop: `1px solid ${theme.colors.semantic.border.primary}`,
    backgroundColor: theme.colors.semantic.background.secondary,
  };
};

// ===== COMPONENTE =====
export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = 'md',
  variant = 'default',
  position = 'center',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showOverlay = true,
  className = '',
  id,
  description,
  width,
  height,
  zIndex = 1000,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  // Gerenciar foco
  useEffect(() => {
    if (isOpen) {
      // Salvar elemento ativo anterior
      previousActiveElement.current = document.activeElement as HTMLElement;
      
      // Focar no modal
      setTimeout(() => {
        modalRef.current?.focus();
      }, 0);

      // Prevenir scroll do body
      document.body.style.overflow = 'hidden';
    } else {
      // Restaurar foco
      if (previousActiveElement.current) {
        previousActiveElement.current.focus();
      }

      // Restaurar scroll do body
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  // Handler para tecla ESC
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && closeOnEscape && isOpen) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
    }

    return () => {
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen, closeOnEscape, onClose]);

  // Handler para clique no overlay
  const handleOverlayClick = (e: React.MouseEvent) => {
    if (closeOnOverlayClick && e.target === e.currentTarget) {
      onClose();
    }
  };

  // Handler para clique no botão fechar
  const handleCloseClick = () => {
    onClose();
  };

  // Handler para teclas do modal
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && closeOnEscape) {
      onClose();
    }
  };

  if (!isOpen) return null;

  const overlayStyles = getOverlayStyles(showOverlay, zIndex);
  const modalStyles = getModalStyles(size, variant, position, width, height);
  const headerStyles = getHeaderStyles();
  const titleStyles = getTitleStyles();
  const closeButtonStyles = getCloseButtonStyles();
  const bodyStyles = getBodyStyles();

  const modalContent = (
    <div
      style={overlayStyles}
      onClick={handleOverlayClick}
      className={`omni-writer-modal-overlay ${className}`}
    >
      <div
        ref={modalRef}
        style={modalStyles}
        className={`omni-writer-modal omni-writer-modal--${size} omni-writer-modal--${variant}`}
        onKeyDown={handleKeyDown}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? `${id}-title` : undefined}
        aria-describedby={description ? `${id}-description` : undefined}
        id={id}
      >
        {title && (
          <div style={headerStyles} className="omni-writer-modal-header">
            <h2
              id={`${id}-title`}
              style={titleStyles}
              className="omni-writer-modal-title"
            >
              {title}
            </h2>
            <button
              style={closeButtonStyles}
              onClick={handleCloseClick}
              className="omni-writer-modal-close"
              aria-label="Fechar modal"
              type="button"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M18 6 6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
        )}

        <div
          style={bodyStyles}
          className="omni-writer-modal-body"
        >
          {description && (
            <div
              id={`${id}-description`}
              style={{
                color: theme.colors.semantic.text.secondary,
                fontSize: theme.typography.fontSizes.sm,
                marginBottom: theme.spacing.spacing[16],
              }}
            >
              {description}
            </div>
          )}
          {children}
        </div>
      </div>
    </div>
  );

  // Renderizar via portal para evitar problemas de z-index
  return createPortal(modalContent, document.body);
};

// ===== COMPONENTES ESPECIALIZADOS =====
interface ModalHeaderProps {
  /** Título do header */
  title?: string;
  /** Subtítulo */
  subtitle?: string;
  /** Ações do header */
  actions?: React.ReactNode;
  /** Função de fechamento */
  onClose?: () => void;
  /** Conteúdo customizado */
  children?: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
}

export const ModalHeader: React.FC<ModalHeaderProps> = ({
  title,
  subtitle,
  actions,
  onClose,
  children,
  className = '',
}) => {
  const headerStyles = getHeaderStyles();

  return (
    <div style={headerStyles} className={`omni-writer-modal-header ${className}`}>
      {children || (
        <>
          <div style={{ flex: 1 }}>
            {title && (
              <h2 style={getTitleStyles()} className="omni-writer-modal-title">
                {title}
              </h2>
            )}
            {subtitle && (
              <p style={{
                fontSize: theme.typography.fontSizes.sm,
                color: theme.colors.semantic.text.secondary,
                margin: 0,
                marginTop: theme.spacing.spacing[4],
              }}>
                {subtitle}
              </p>
            )}
          </div>
          {actions && (
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.spacing[8] }}>
              {actions}
            </div>
          )}
          {onClose && (
            <button
              style={getCloseButtonStyles()}
              onClick={onClose}
              className="omni-writer-modal-close"
              aria-label="Fechar modal"
              type="button"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path d="M18 6 6 18M6 6l12 12"/>
              </svg>
            </button>
          )}
        </>
      )}
    </div>
  );
};

interface ModalBodyProps {
  /** Conteúdo do body */
  children: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
  /** Padding customizado */
  padding?: string;
}

export const ModalBody: React.FC<ModalBodyProps> = ({
  children,
  className = '',
  padding,
}) => {
  const bodyStyles = {
    ...getBodyStyles(),
    ...(padding && { padding }),
  };

  return (
    <div style={bodyStyles} className={`omni-writer-modal-body ${className}`}>
      {children}
    </div>
  );
};

interface ModalFooterProps {
  /** Conteúdo do footer */
  children: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
}

export const ModalFooter: React.FC<ModalFooterProps> = ({
  children,
  className = '',
}) => {
  const footerStyles = getFooterStyles();

  return (
    <div style={footerStyles} className={`omni-writer-modal-footer ${className}`}>
      {children}
    </div>
  );
};

// ===== COMPONENTES DE CONVENIÊNCIA =====
export const SmallModal: React.FC<Omit<ModalProps, 'size'>> = (props) => (
  <Modal {...props} size="sm" />
);

export const LargeModal: React.FC<Omit<ModalProps, 'size'>> = (props) => (
  <Modal {...props} size="lg" />
);

export const ExtraLargeModal: React.FC<Omit<ModalProps, 'size'>> = (props) => (
  <Modal {...props} size="xl" />
);

export const FullScreenModal: React.FC<Omit<ModalProps, 'size' | 'variant'>> = (props) => (
  <Modal {...props} size="full" variant="fullscreen" />
);

export const SideModal: React.FC<Omit<ModalProps, 'variant'>> = (props) => (
  <Modal {...props} variant="side" />
);

export const CenteredModal: React.FC<Omit<ModalProps, 'variant'>> = (props) => (
  <Modal {...props} variant="centered" />
);

// ===== EXPORTAÇÃO =====
Modal.displayName = 'Modal';
export default Modal; 