import React from 'react';
import { colors, typography, shadows } from '../theme';

type ButtonVariant = 'primary' | 'secondary' | 'error' | 'success';

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  loading?: boolean;
  children: React.ReactNode;
};

const variantStyles = {
  primary: {
    background: colors.primary,
    color: '#fff',
    border: `1px solid ${colors.primary}`,
  },
  secondary: {
    background: colors.secondary,
    color: '#fff',
    border: `1px solid ${colors.secondary}`,
  },
  error: {
    background: colors.error,
    color: '#fff',
    border: `1px solid ${colors.error}`,
  },
  success: {
    background: colors.success,
    color: '#fff',
    border: `1px solid ${colors.success}`,
  },
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  loading = false,
  disabled,
  children,
  ...props
}) => {
  return (
    <button
      type="button"
      style={{
        ...variantStyles[variant],
        fontFamily: typography.fontFamily,
        fontWeight: typography.fontWeight.medium,
        fontSize: typography.fontSize.md,
        lineHeight: typography.lineHeight.normal,
        borderRadius: 6,
        padding: '0.5rem 1.25rem',
        boxShadow: shadows.sm,
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? 'not-allowed' : 'pointer',
        transition: 'background 0.2s, box-shadow 0.2s',
        outline: 'none',
        minWidth: 120,
        minHeight: 40,
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
      }}
      aria-disabled={disabled || loading}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span
          style={{
            width: 18,
            height: 18,
            border: '2px solid #fff',
            borderTop: `2px solid ${colors[variant] || colors.primary}`,
            borderRadius: '50%',
            display: 'inline-block',
            animation: 'spin 1s linear infinite',
          }}
          aria-label="Carregando"
        />
      )}
      <span>{children}</span>
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </button>
  );
}; 