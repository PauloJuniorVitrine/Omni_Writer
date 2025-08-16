/**
 * Componente Card - Omni Writer
 * 
 * Containers de conteúdo com diferentes variantes
 * Responsivo e acessível
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface CardProps {
  /** Variante do card */
  variant?: 'default' | 'elevated' | 'outlined' | 'filled';
  /** Tamanho do card */
  size?: 'sm' | 'md' | 'lg';
  /** Estado de hover */
  hoverable?: boolean;
  /** Estado clicável */
  clickable?: boolean;
  /** Conteúdo do card */
  children: React.ReactNode;
  /** Função de clique */
  onClick?: () => void;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
  /** Título para acessibilidade */
  title?: string;
  /** Padding customizado */
  padding?: string;
  /** Largura customizada */
  width?: string;
  /** Altura customizada */
  height?: string;
}

// ===== ESTILOS =====
const getCardStyles = (variant: string, size: string, hoverable: boolean, clickable: boolean) => {
  const baseStyles = {
    backgroundColor: theme.colors.semantic.background.primary,
    border: `1px solid ${theme.colors.semantic.border.primary}`,
    borderRadius: theme.spacing.spacing[8],
    boxShadow: theme.shadows.shadows.sm,
    transition: 'all 0.2s ease-in-out',
    cursor: clickable ? 'pointer' : 'default',
    overflow: 'hidden',
  };

  const variantStyles = {
    default: {
      backgroundColor: theme.colors.semantic.background.primary,
      border: `1px solid ${theme.colors.semantic.border.primary}`,
      boxShadow: theme.shadows.shadows.sm,
    },
    elevated: {
      backgroundColor: theme.colors.semantic.background.primary,
      border: 'none',
      boxShadow: theme.shadows.shadows.lg,
    },
    outlined: {
      backgroundColor: 'transparent',
      border: `2px solid ${theme.colors.semantic.border.primary}`,
      boxShadow: 'none',
    },
    filled: {
      backgroundColor: theme.colors.semantic.background.secondary,
      border: 'none',
      boxShadow: 'none',
    },
  };

  const sizeStyles = {
    sm: {
      padding: theme.spacing.spacing[12],
    },
    md: {
      padding: theme.spacing.spacing[16],
    },
    lg: {
      padding: theme.spacing.spacing[24],
    },
  };

  const hoverStyles = hoverable ? {
    '&:hover': {
      boxShadow: theme.shadows.shadows.md,
      transform: 'translateY(-2px)',
    },
  } : {};

  const clickableStyles = clickable ? {
    '&:active': {
      transform: 'translateY(0)',
      boxShadow: theme.shadows.shadows.sm,
    },
  } : {};

  return {
    ...baseStyles,
    ...variantStyles[variant as keyof typeof variantStyles],
    ...sizeStyles[size as keyof typeof sizeStyles],
    ...hoverStyles,
    ...clickableStyles,
  };
};

// ===== COMPONENTE =====
export const Card: React.FC<CardProps> = ({
  variant = 'default',
  size = 'md',
  hoverable = false,
  clickable = false,
  children,
  onClick,
  className = '',
  id,
  title,
  padding,
  width,
  height,
}) => {
  const cardStyles = getCardStyles(variant, size, hoverable, clickable);

  const handleClick = () => {
    if (clickable && onClick) {
      onClick();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (clickable && (e.key === 'Enter' || e.key === ' ') && onClick) {
      e.preventDefault();
      onClick();
    }
  };

  const finalStyles = {
    ...cardStyles,
    ...(padding && { padding }),
    ...(width && { width }),
    ...(height && { height }),
  };

  return (
    <div
      style={finalStyles}
      className={`omni-writer-card omni-writer-card--${variant} omni-writer-card--${size} ${className}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      id={id}
      title={title}
      role={clickable ? 'button' : undefined}
      tabIndex={clickable ? 0 : undefined}
      aria-label={title}
    >
      {children}
    </div>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
interface CardHeaderProps {
  /** Título do header */
  title?: string;
  /** Subtítulo */
  subtitle?: string;
  /** Ações do header */
  actions?: React.ReactNode;
  /** Conteúdo customizado */
  children?: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
}

export const CardHeader: React.FC<CardHeaderProps> = ({
  title,
  subtitle,
  actions,
  children,
  className = '',
}) => {
  const headerStyles = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingBottom: theme.spacing.spacing[16],
    borderBottom: `1px solid ${theme.colors.semantic.border.primary}`,
    marginBottom: theme.spacing.spacing[16],
  };

  const titleStyles = {
    fontSize: theme.typography.fontSizes.lg,
    fontWeight: theme.typography.fonts.weight.semibold,
    color: theme.colors.semantic.text.primary,
    margin: 0,
  };

  const subtitleStyles = {
    fontSize: theme.typography.fontSizes.sm,
    color: theme.colors.semantic.text.secondary,
    margin: `${theme.spacing.spacing[2]} 0 0 0`,
  };

  return (
    <div style={headerStyles} className={`omni-writer-card__header ${className}`}>
      <div className="omni-writer-card__header-content">
        {children || (
          <>
            {title && (
              <h3 style={titleStyles} className="omni-writer-card__title">
                {title}
              </h3>
            )}
            {subtitle && (
              <p style={subtitleStyles} className="omni-writer-card__subtitle">
                {subtitle}
              </p>
            )}
          </>
        )}
      </div>
      {actions && (
        <div className="omni-writer-card__header-actions">
          {actions}
        </div>
      )}
    </div>
  );
};

interface CardBodyProps {
  /** Conteúdo do body */
  children: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
  /** Padding customizado */
  padding?: string;
}

export const CardBody: React.FC<CardBodyProps> = ({
  children,
  className = '',
  padding,
}) => {
  const bodyStyles = {
    ...(padding && { padding }),
  };

  return (
    <div style={bodyStyles} className={`omni-writer-card__body ${className}`}>
      {children}
    </div>
  );
};

interface CardFooterProps {
  /** Conteúdo do footer */
  children: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
}

export const CardFooter: React.FC<CardFooterProps> = ({
  children,
  className = '',
}) => {
  const footerStyles = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: theme.spacing.spacing[16],
    borderTop: `1px solid ${theme.colors.semantic.border.primary}`,
    marginTop: theme.spacing.spacing[16],
  };

  return (
    <div style={footerStyles} className={`omni-writer-card__footer ${className}`}>
      {children}
    </div>
  );
};

// ===== VARIAÇÕES =====
export const ElevatedCard: React.FC<Omit<CardProps, 'variant'>> = (props) => (
  <Card {...props} variant="elevated" />
);

export const OutlinedCard: React.FC<Omit<CardProps, 'variant'>> = (props) => (
  <Card {...props} variant="outlined" />
);

export const FilledCard: React.FC<Omit<CardProps, 'variant'>> = (props) => (
  <Card {...props} variant="filled" />
);

export const HoverableCard: React.FC<Omit<CardProps, 'hoverable'>> = (props) => (
  <Card {...props} hoverable={true} />
);

export const ClickableCard: React.FC<Omit<CardProps, 'clickable'>> = (props) => (
  <Card {...props} clickable={true} />
);

// ===== EXPORTAÇÃO PADRÃO =====
export default Card; 