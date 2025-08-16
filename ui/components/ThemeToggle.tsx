import React from 'react';
import { useTheme } from '../hooks/use_theme';
import { useI18n } from '../hooks/use_i18n';

interface ThemeToggleProps {
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
  style?: React.CSSProperties;
}

/**
 * Componente de toggle de tema aprimorado.
 * Suporta animações suaves e acessibilidade WCAG 2.1 AAA.
 */
export const ThemeToggle: React.FC<ThemeToggleProps> = ({ 
  size = 'medium', 
  showLabel = false,
  style 
}) => {
  const { mode, isDark, toggleTheme } = useTheme();
  const { t } = useI18n();

  const sizeMap = {
    small: { width: 32, height: 32, iconSize: 16 },
    medium: { width: 40, height: 40, iconSize: 20 },
    large: { width: 48, height: 48, iconSize: 24 }
  };

  const currentSize = sizeMap[size];

  return (
    <button
      onClick={toggleTheme}
      style={{
        position: 'relative',
        width: currentSize.width,
        height: currentSize.height,
        borderRadius: '50%',
        border: '2px solid var(--color-border)',
        background: 'var(--color-surface)',
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        outline: 'none',
        ...style
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'scale(1.05)';
        e.currentTarget.style.borderColor = 'var(--color-primary)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'scale(1)';
        e.currentTarget.style.borderColor = 'var(--color-border)';
      }}
      onFocus={(e) => {
        e.currentTarget.style.outline = '2px solid var(--color-primary)';
        e.currentTarget.style.outlineOffset = '2px';
      }}
      onBlur={(e) => {
        e.currentTarget.style.outline = 'none';
      }}
      aria-label={isDark ? t('theme_light') : t('theme_dark')}
      title={isDark ? t('theme_light') : t('theme_dark')}
      role="switch"
      aria-checked={isDark}
    >
      {/* Ícone do Sol */}
      <span
        role="img"
        aria-label="sun"
        style={{
          position: 'absolute',
          fontSize: currentSize.iconSize,
          opacity: isDark ? 0 : 1,
          transform: isDark ? 'rotate(90deg) scale(0.5)' : 'rotate(0deg) scale(1)',
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
          color: 'var(--color-warning)',
          filter: 'drop-shadow(0 0 4px rgba(251, 146, 60, 0.3))'
        }}
      >
        ☀️
      </span>

      {/* Ícone da Lua */}
      <span
        role="img"
        aria-label="moon"
        style={{
          position: 'absolute',
          fontSize: currentSize.iconSize,
          opacity: isDark ? 1 : 0,
          transform: isDark ? 'rotate(0deg) scale(1)' : 'rotate(-90deg) scale(0.5)',
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
          color: 'var(--color-info)',
          filter: 'drop-shadow(0 0 4px rgba(34, 211, 238, 0.3))'
        }}
      >
        🌙
      </span>

      {/* Indicador de modo automático */}
      {mode === 'auto' && (
        <div
          style={{
            position: 'absolute',
            top: -4,
            right: -4,
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: 'var(--color-primary)',
            border: '2px solid var(--color-surface)',
            fontSize: 6,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--color-text-inverse)',
            fontWeight: 'bold'
          }}
          title="Modo automático"
        >
          A
        </div>
      )}

      {/* Label opcional */}
      {showLabel && (
        <span
          style={{
            position: 'absolute',
            bottom: -24,
            left: '50%',
            transform: 'translateX(-50%)',
            fontSize: 12,
            color: 'var(--color-text-secondary)',
            whiteSpace: 'nowrap',
            fontWeight: 500
          }}
        >
          {isDark ? t('theme_dark') : t('theme_light')}
        </span>
      )}
    </button>
  );
}; 