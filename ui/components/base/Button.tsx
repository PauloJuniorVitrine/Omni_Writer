/**
 * Componente Button - Omni Writer
 * 
 * Botões com diferentes variantes e estados
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface ButtonProps {
  /** Variante do botão */
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'link';
  /** Tamanho do botão */
  size?: 'sm' | 'md' | 'lg';
  /** Estado do botão */
  disabled?: boolean;
  /** Estado de carregamento */
  loading?: boolean;
  /** Ícone à esquerda */
  leftIcon?: React.ReactNode;
  /** Ícone à direita */
  rightIcon?: React.ReactNode;
  /** Texto do botão */
  children: React.ReactNode;
  /** Função de clique */
  onClick?: () => void;
  /** Tipo do botão */
  type?: 'button' | 'submit' | 'reset';
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
  /** Título para acessibilidade */
  title?: string;
}

// ===== ESTILOS =====
const getButtonStyles = (variant: string, size: string, disabled: boolean, loading: boolean) => {
  const baseStyles = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: theme.spacing.spacing[8],
    border: 'none',
    borderRadius: theme.spacing.spacing[6],
    fontFamily: theme.typography.fonts.family.primary,
    fontWeight: theme.typography.fonts.weight.medium,
    textDecoration: 'none',
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    transition: 'all 0.2s ease-in-out',
    position: 'relative',
    overflow: 'hidden',
    outline: 'none',
    userSelect: 'none' as const,
  };

  // Estilos por variante
  const variantStyles = {
    primary: {
      backgroundColor: disabled ? theme.colors.component.button.primary.disabled : theme.colors.component.button.primary.background,
      color: theme.colors.component.button.primary.text,
      boxShadow: disabled ? 'none' : theme.shadows.shadows.sm,
      '&:hover': {
        backgroundColor: disabled ? theme.colors.component.button.primary.disabled : theme.colors.component.button.primary.hover,
        boxShadow: disabled ? 'none' : theme.shadows.shadows.md,
      },
      '&:active': {
        backgroundColor: theme.colors.component.button.primary.active,
        transform: 'translateY(1px)',
      },
    },
    secondary: {
      backgroundColor: 'transparent',
      color: theme.colors.component.button.secondary.text,
      border: `1px solid ${theme.colors.component.button.secondary.border}`,
      '&:hover': {
        backgroundColor: theme.colors.component.button.secondary.hover,
        borderColor: theme.colors.component.button.secondary.hover,
      },
      '&:active': {
        backgroundColor: theme.colors.component.button.secondary.active,
      },
    },
    danger: {
      backgroundColor: disabled ? theme.colors.component.button.danger.disabled : theme.colors.component.button.danger.background,
      color: theme.colors.component.button.danger.text,
      boxShadow: disabled ? 'none' : theme.shadows.shadows.sm,
      '&:hover': {
        backgroundColor: disabled ? theme.colors.component.button.danger.disabled : theme.colors.component.button.danger.hover,
        boxShadow: disabled ? 'none' : theme.shadows.shadows.md,
      },
      '&:active': {
        backgroundColor: theme.colors.component.button.danger.active,
        transform: 'translateY(1px)',
      },
    },
    ghost: {
      backgroundColor: 'transparent',
      color: theme.colors.semantic.text.primary,
      '&:hover': {
        backgroundColor: theme.colors.semantic.state.hover,
      },
      '&:active': {
        backgroundColor: theme.colors.semantic.state.active,
      },
    },
    link: {
      backgroundColor: 'transparent',
      color: theme.colors.base.primary[500],
      textDecoration: 'underline',
      '&:hover': {
        color: theme.colors.base.primary[600],
        textDecoration: 'none',
      },
      '&:active': {
        color: theme.colors.base.primary[700],
      },
    },
  };

  // Estilos por tamanho
  const sizeStyles = {
    sm: {
      padding: theme.componentSpacing.button.padding.sm,
      fontSize: theme.typography.fontSizes.sm,
      minHeight: '32px',
    },
    md: {
      padding: theme.componentSpacing.button.padding.md,
      fontSize: theme.typography.fontSizes.base,
      minHeight: '40px',
    },
    lg: {
      padding: theme.componentSpacing.button.padding.lg,
      fontSize: theme.typography.fontSizes.lg,
      minHeight: '48px',
    },
  };

  return {
    ...baseStyles,
    ...variantStyles[variant as keyof typeof variantStyles],
    ...sizeStyles[size as keyof typeof sizeStyles],
    opacity: disabled ? 0.6 : 1,
  };
};

// ===== COMPONENTE =====
export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  leftIcon,
  rightIcon,
  children,
  onClick,
  type = 'button',
  className = '',
  id,
  title,
}) => {
  const buttonStyles = getButtonStyles(variant, size, disabled, loading);

  const handleClick = (e: React.MouseEvent) => {
    if (disabled || loading) {
      e.preventDefault();
      return;
    }
    if (onClick) {
      onClick();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (!disabled && !loading && onClick) {
        onClick();
      }
    }
  };

  return (
    <button
      style={buttonStyles}
      className={`omni-writer-button omni-writer-button--${variant} omni-writer-button--${size} ${className}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      disabled={disabled || loading}
      type={type}
      id={id}
      title={title}
      aria-disabled={disabled || loading}
      aria-busy={loading}
    >
      {/* Estado de carregamento */}
      {loading && (
        <div
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '16px',
            height: '16px',
            border: '2px solid transparent',
            borderTop: '2px solid currentColor',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
          }}
          className="omni-writer-button__loading"
        />
      )}

      {/* Conteúdo do botão */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing.spacing[8],
          opacity: loading ? 0 : 1,
        }}
        className="omni-writer-button__content"
      >
        {/* Ícone à esquerda */}
        {leftIcon && (
          <span className="omni-writer-button__left-icon">
            {leftIcon}
          </span>
        )}

        {/* Texto */}
        <span className="omni-writer-button__text">
          {children}
        </span>

        {/* Ícone à direita */}
        {rightIcon && (
          <span className="omni-writer-button__right-icon">
            {rightIcon}
          </span>
        )}
      </div>
    </button>
  );
};

// ===== VARIAÇÕES =====
export const PrimaryButton: React.FC<Omit<ButtonProps, 'variant'>> = (props) => (
  <Button {...props} variant="primary" />
);

export const SecondaryButton: React.FC<Omit<ButtonProps, 'variant'>> = (props) => (
  <Button {...props} variant="secondary" />
);

export const DangerButton: React.FC<Omit<ButtonProps, 'variant'>> = (props) => (
  <Button {...props} variant="danger" />
);

export const GhostButton: React.FC<Omit<ButtonProps, 'variant'>> = (props) => (
  <Button {...props} variant="ghost" />
);

export const LinkButton: React.FC<Omit<ButtonProps, 'variant'>> = (props) => (
  <Button {...props} variant="link" />
);

// ===== EXPORTAÇÃO PADRÃO =====
export default Button; 