/**
 * Componente de Branding - Omni Writer
 * 
 * Logo e identidade visual do sistema
 * Responsivo e acessível
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../theme';

// ===== TIPOS =====
interface BrandingProps {
  /** Tamanho do logo */
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** Mostrar apenas o ícone */
  iconOnly?: boolean;
  /** Mostrar tagline */
  showTagline?: boolean;
  /** Cor do texto */
  color?: string;
  /** Classe CSS adicional */
  className?: string;
  /** Função de clique */
  onClick?: () => void;
}

// ===== ESTILOS =====
const getBrandingStyles = (size: string, color: string) => {
  const baseStyles = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[8],
    fontFamily: theme.typography.fonts.family.display,
    fontWeight: theme.typography.fonts.weight.bold,
    color: color,
    textDecoration: 'none',
    cursor: 'pointer',
    transition: 'all 0.2s ease-in-out',
  };

  const sizeStyles = {
    sm: {
      fontSize: theme.typography.fontSizes.lg,
      gap: theme.spacing.spacing[4],
    },
    md: {
      fontSize: theme.typography.fontSizes.xl,
      gap: theme.spacing.spacing[6],
    },
    lg: {
      fontSize: theme.typography.fontSizes['2xl'],
      gap: theme.spacing.spacing[8],
    },
    xl: {
      fontSize: theme.typography.fontSizes['3xl'],
      gap: theme.spacing.spacing[10],
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getIconStyles = (size: string) => {
  const iconSizes = {
    sm: '20px',
    md: '24px',
    lg: '32px',
    xl: '40px',
  };

  return {
    width: iconSizes[size as keyof typeof iconSizes],
    height: iconSizes[size as keyof typeof iconSizes],
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: theme.spacing.spacing[6],
    background: `linear-gradient(135deg, ${theme.colors.base.primary[500]}, ${theme.colors.base.primary[600]})`,
    color: '#ffffff',
    fontSize: iconSizes[size as keyof typeof iconSizes],
    fontWeight: theme.typography.fonts.weight.bold,
    boxShadow: theme.shadows.shadows.sm,
  };
};

const getTaglineStyles = (size: string, color: string) => {
  const taglineSizes = {
    sm: theme.typography.fontSizes.xs,
    md: theme.typography.fontSizes.sm,
    lg: theme.typography.fontSizes.base,
    xl: theme.typography.fontSizes.lg,
  };

  return {
    fontSize: taglineSizes[size as keyof typeof taglineSizes],
    fontWeight: theme.typography.fonts.weight.normal,
    color: color,
    opacity: 0.8,
    marginLeft: theme.spacing.spacing[4],
  };
};

// ===== COMPONENTE =====
export const Branding: React.FC<BrandingProps> = ({
  size = 'md',
  iconOnly = false,
  showTagline = false,
  color = theme.colors.semantic.text.primary,
  className = '',
  onClick,
}) => {
  const brandingStyles = getBrandingStyles(size, color);
  const iconStyles = getIconStyles(size);
  const taglineStyles = getTaglineStyles(size, color);

  const handleClick = () => {
    if (onClick) {
      onClick();
    }
  };

  return (
    <div
      style={brandingStyles}
      className={`omni-writer-branding ${className}`}
      onClick={handleClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={(e) => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
    >
      {/* Ícone/Logo */}
      <div style={iconStyles} className="omni-writer-logo">
        <span>OW</span>
      </div>

      {/* Texto do Brand */}
      {!iconOnly && (
        <div className="omni-writer-text">
          <span style={{ fontWeight: theme.typography.fonts.weight.bold }}>
            Omni
          </span>
          <span style={{ fontWeight: theme.typography.fonts.weight.normal }}>
            Writer
          </span>
        </div>
      )}

      {/* Tagline */}
      {showTagline && !iconOnly && (
        <div style={taglineStyles} className="omni-writer-tagline">
          AI-Powered Content Generation
        </div>
      )}
    </div>
  );
};

// ===== VARIAÇÕES =====
export const BrandingLogo: React.FC<Omit<BrandingProps, 'iconOnly' | 'showTagline'>> = (props) => (
  <Branding {...props} iconOnly={true} />
);

export const BrandingFull: React.FC<Omit<BrandingProps, 'iconOnly' | 'showTagline'>> = (props) => (
  <Branding {...props} iconOnly={false} showTagline={true} />
);

export const BrandingCompact: React.FC<Omit<BrandingProps, 'iconOnly' | 'showTagline'>> = (props) => (
  <Branding {...props} iconOnly={false} showTagline={false} />
);

// ===== EXPORTAÇÃO PADRÃO =====
export default Branding; 