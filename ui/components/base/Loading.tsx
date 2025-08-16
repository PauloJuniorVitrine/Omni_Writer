/**
 * Componente Loading - Omni Writer
 * 
 * Estados de carregamento com diferentes variantes
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface LoadingProps {
  /** Tipo de loading */
  type?: 'spinner' | 'dots' | 'bars' | 'pulse' | 'skeleton';
  /** Tamanho do loading */
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** Cor do loading */
  color?: string;
  /** Texto de loading */
  text?: string;
  /** Estado de carregamento */
  loading?: boolean;
  /** Overlay de fundo */
  overlay?: boolean;
  /** Posição do overlay */
  position?: 'center' | 'top' | 'bottom';
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
  /** Título para acessibilidade */
  title?: string;
  /** Largura customizada */
  width?: string;
  /** Altura customizada */
  height?: string;
}

// ===== ESTILOS =====
const getContainerStyles = (overlay: boolean, position: string) => {
  const baseStyles = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexDirection: 'column' as const,
    gap: theme.spacing.spacing[8],
  };

  if (overlay) {
    return {
      ...baseStyles,
      position: 'fixed' as const,
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(255, 255, 255, 0.8)',
      backdropFilter: 'blur(4px)',
      zIndex: 9999,
      ...(position === 'top' && { alignItems: 'flex-start', paddingTop: theme.spacing.spacing[24] }),
      ...(position === 'bottom' && { alignItems: 'flex-end', paddingBottom: theme.spacing.spacing[24] }),
    };
  }

  return baseStyles;
};

const getSpinnerStyles = (size: string, color: string) => {
  const sizeStyles = {
    sm: { width: '16px', height: '16px' },
    md: { width: '24px', height: '24px' },
    lg: { width: '32px', height: '32px' },
    xl: { width: '48px', height: '48px' },
  };

  return {
    ...sizeStyles[size as keyof typeof sizeStyles],
    border: `2px solid ${theme.colors.semantic.border.primary}`,
    borderTop: `2px solid ${color}`,
    borderRadius: '50%',
    animation: 'spin 1s linear infinite',
  };
};

const getDotsStyles = (size: string, color: string) => {
  const sizeStyles = {
    sm: { width: '4px', height: '4px' },
    md: { width: '6px', height: '6px' },
    lg: { width: '8px', height: '8px' },
    xl: { width: '12px', height: '12px' },
  };

  return {
    display: 'flex',
    gap: theme.spacing.spacing[4],
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getDotStyles = (color: string, delay: number) => {
  return {
    width: '100%',
    height: '100%',
    backgroundColor: color,
    borderRadius: '50%',
    animation: 'bounce 1.4s ease-in-out infinite both',
    animationDelay: `${delay}s`,
  };
};

const getBarsStyles = (size: string, color: string) => {
  const sizeStyles = {
    sm: { width: '3px', height: '16px' },
    md: { width: '4px', height: '24px' },
    lg: { width: '6px', height: '32px' },
    xl: { width: '8px', height: '48px' },
  };

  return {
    display: 'flex',
    gap: theme.spacing.spacing[2],
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getBarStyles = (color: string, delay: number) => {
  return {
    width: '100%',
    height: '100%',
    backgroundColor: color,
    animation: 'bars 1.2s ease-in-out infinite both',
    animationDelay: `${delay}s`,
  };
};

const getPulseStyles = (size: string, color: string) => {
  const sizeStyles = {
    sm: { width: '16px', height: '16px' },
    md: { width: '24px', height: '24px' },
    lg: { width: '32px', height: '32px' },
    xl: { width: '48px', height: '48px' },
  };

  return {
    ...sizeStyles[size as keyof typeof sizeStyles],
    backgroundColor: color,
    borderRadius: '50%',
    animation: 'pulse 1.5s ease-in-out infinite',
  };
};

const getSkeletonStyles = (width?: string, height?: string) => {
  return {
    width: width || '100%',
    height: height || '20px',
    backgroundColor: theme.colors.semantic.border.primary,
    borderRadius: theme.spacing.spacing[4],
    animation: 'skeleton 1.5s ease-in-out infinite',
  };
};

const getTextStyles = (size: string) => {
  const sizeStyles = {
    sm: { fontSize: theme.typography.fontSizes.sm },
    md: { fontSize: theme.typography.fontSizes.base },
    lg: { fontSize: theme.typography.fontSizes.lg },
    xl: { fontSize: theme.typography.fontSizes.xl },
  };

  return {
    color: theme.colors.semantic.text.secondary,
    margin: 0,
    textAlign: 'center' as const,
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

// ===== COMPONENTES DE ANIMAÇÃO =====
const Spinner: React.FC<{ size: string; color: string }> = ({ size, color }) => (
  <div style={getSpinnerStyles(size, color)} />
);

const Dots: React.FC<{ size: string; color: string }> = ({ size, color }) => (
  <div style={getDotsStyles(size, color)}>
    <div style={getDotStyles(color, 0)} />
    <div style={getDotStyles(color, 0.16)} />
    <div style={getDotStyles(color, 0.32)} />
  </div>
);

const Bars: React.FC<{ size: string; color: string }> = ({ size, color }) => (
  <div style={getBarsStyles(size, color)}>
    <div style={getBarStyles(color, 0)} />
    <div style={getBarStyles(color, 0.1)} />
    <div style={getBarStyles(color, 0.2)} />
    <div style={getBarStyles(color, 0.3)} />
  </div>
);

const Pulse: React.FC<{ size: string; color: string }> = ({ size, color }) => (
  <div style={getPulseStyles(size, color)} />
);

const Skeleton: React.FC<{ width?: string; height?: string }> = ({ width, height }) => (
  <div style={getSkeletonStyles(width, height)} />
);

// ===== COMPONENTE PRINCIPAL =====
export const Loading: React.FC<LoadingProps> = ({
  type = 'spinner',
  size = 'md',
  color = theme.colors.base.primary[500],
  text,
  loading = true,
  overlay = false,
  position = 'center',
  className = '',
  id,
  title,
  width,
  height,
}) => {
  if (!loading) return null;

  const containerStyles = getContainerStyles(overlay, position);
  const textStyles = getTextStyles(size);

  const renderLoader = () => {
    switch (type) {
      case 'spinner':
        return <Spinner size={size} color={color} />;
      case 'dots':
        return <Dots size={size} color={color} />;
      case 'bars':
        return <Bars size={size} color={color} />;
      case 'pulse':
        return <Pulse size={size} color={color} />;
      case 'skeleton':
        return <Skeleton width={width} height={height} />;
      default:
        return <Spinner size={size} color={color} />;
    }
  };

  return (
    <div
      style={containerStyles}
      className={`omni-writer-loading omni-writer-loading--${type} omni-writer-loading--${size} ${className}`}
      id={id}
      role="status"
      aria-live="polite"
      aria-label={title || `Carregando ${text || ''}`}
    >
      {renderLoader()}
      {text && (
        <p style={textStyles} className="omni-writer-loading-text">
          {text}
        </p>
      )}
    </div>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const SpinnerLoading: React.FC<Omit<LoadingProps, 'type'>> = (props) => (
  <Loading {...props} type="spinner" />
);

export const DotsLoading: React.FC<Omit<LoadingProps, 'type'>> = (props) => (
  <Loading {...props} type="dots" />
);

export const BarsLoading: React.FC<Omit<LoadingProps, 'type'>> = (props) => (
  <Loading {...props} type="bars" />
);

export const PulseLoading: React.FC<Omit<LoadingProps, 'type'>> = (props) => (
  <Loading {...props} type="pulse" />
);

export const SkeletonLoading: React.FC<Omit<LoadingProps, 'type'>> = (props) => (
  <Loading {...props} type="skeleton" />
);

export const SmallLoading: React.FC<Omit<LoadingProps, 'size'>> = (props) => (
  <Loading {...props} size="sm" />
);

export const LargeLoading: React.FC<Omit<LoadingProps, 'size'>> = (props) => (
  <Loading {...props} size="lg" />
);

export const ExtraLargeLoading: React.FC<Omit<LoadingProps, 'size'>> = (props) => (
  <Loading {...props} size="xl" />
);

export const OverlayLoading: React.FC<Omit<LoadingProps, 'overlay'>> = (props) => (
  <Loading {...props} overlay={true} />
);

// ===== COMPONENTE SKELETON ESPECIALIZADO =====
interface SkeletonProps {
  /** Tipo de skeleton */
  variant?: 'text' | 'circular' | 'rectangular' | 'rounded';
  /** Largura */
  width?: string | number;
  /** Altura */
  height?: string | number;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  variant = 'text',
  width,
  height,
  className = '',
  id,
}) => {
  const getSkeletonVariantStyles = () => {
    const baseStyles = {
      backgroundColor: theme.colors.semantic.border.primary,
      animation: 'skeleton 1.5s ease-in-out infinite',
    };

    const variantStyles = {
      text: {
        width: width || '100%',
        height: height || '1em',
        borderRadius: theme.spacing.spacing[2],
      },
      circular: {
        width: width || '40px',
        height: height || '40px',
        borderRadius: '50%',
      },
      rectangular: {
        width: width || '100%',
        height: height || '200px',
        borderRadius: 0,
      },
      rounded: {
        width: width || '100%',
        height: height || '200px',
        borderRadius: theme.spacing.spacing[8],
      },
    };

    return {
      ...baseStyles,
      ...variantStyles[variant as keyof typeof variantStyles],
    };
  };

  return (
    <div
      style={getSkeletonVariantStyles()}
      className={`omni-writer-skeleton omni-writer-skeleton--${variant} ${className}`}
      id={id}
      aria-hidden="true"
    />
  );
};

// ===== COMPONENTE SKELETON GROUP =====
interface SkeletonGroupProps {
  /** Número de itens */
  count?: number;
  /** Variante dos itens */
  variant?: 'text' | 'circular' | 'rectangular' | 'rounded';
  /** Largura dos itens */
  width?: string | number;
  /** Altura dos itens */
  height?: string | number;
  /** Espaçamento entre itens */
  spacing?: string;
  /** Classe CSS adicional */
  className?: string;
}

export const SkeletonGroup: React.FC<SkeletonGroupProps> = ({
  count = 3,
  variant = 'text',
  width,
  height,
  spacing = theme.spacing.spacing[8],
  className = '',
}) => {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: spacing,
      }}
      className={`omni-writer-skeleton-group ${className}`}
    >
      {Array.from({ length: count }).map((_, index) => (
        <Skeleton
          key={index}
          variant={variant}
          width={width}
          height={height}
        />
      ))}
    </div>
  );
};

// ===== ESTILOS CSS PARA ANIMAÇÕES =====
export const LoadingStyles = `
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes bounce {
    0%, 80%, 100% {
      transform: scale(0);
    }
    40% {
      transform: scale(1);
    }
  }

  @keyframes bars {
    0%, 40%, 100% {
      transform: scaleY(0.4);
    }
    20% {
      transform: scaleY(1);
    }
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  @keyframes skeleton {
    0% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
    100% {
      opacity: 1;
    }
  }
`;

// ===== EXPORTAÇÃO =====
Loading.displayName = 'Loading';
export default Loading; 