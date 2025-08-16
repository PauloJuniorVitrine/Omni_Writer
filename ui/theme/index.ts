/**
 * Sistema de Tema - Omni Writer
 * 
 * Exportação centralizada de todos os tokens de design
 * Sistema completo de cores, tipografia, espaçamentos e sombras
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== IMPORTAÇÕES =====
export { colors, baseColors, semanticColors, componentColors, darkColors } from './colors';
export { typography, fonts, fontSizes, textStyles, responsiveTypography, typographyUtils } from './typography';
export { spacingSystem, spacing, spacingRem, semanticSpacing, componentSpacing } from './spacing';
export { shadowSystem, shadows, semanticShadows, componentShadows, darkShadows } from './shadows';

// ===== TEMA COMPLETO =====
import { colors } from './colors';
import { typography } from './typography';
import { spacingSystem } from './spacing';
import { shadowSystem } from './shadows';

export const theme = {
  colors,
  typography,
  spacing: spacingSystem,
  shadows: shadowSystem,
};

// ===== UTILITÁRIOS DO TEMA =====
export const themeUtils = {
  // Função para obter cor baseada no tema
  getColor: (path: string, isDark: boolean = false) => {
    const colorPath = path.split('.');
    const colorSystem = isDark ? colors.dark : colors;
    
    let result: any = colorSystem;
    for (const key of colorPath) {
      if (result && typeof result === 'object' && key in result) {
        result = result[key];
      } else {
        return undefined;
      }
    }
    return result;
  },
  
  // Função para obter espaçamento
  getSpacing: (size: keyof typeof spacingSystem.spacing) => {
    return spacingSystem.spacing[size];
  },
  
  // Função para obter sombra
  getShadow: (type: keyof typeof shadowSystem.shadows) => {
    return shadowSystem.shadows[type];
  },
  
  // Função para obter estilo de texto
  getTextStyle: (style: keyof typeof typography.textStyles) => {
    return typography.textStyles[style];
  },
  
  // Função para aplicar tema a um componente
  applyTheme: (component: string, variant: string, isDark: boolean = false) => {
    const themeData = {
      colors: isDark ? colors.dark : colors,
      spacing: spacingSystem,
      shadows: isDark ? shadowSystem.darkShadows : shadowSystem.shadows,
      typography,
    };
    
    return {
      ...themeData.colors.component[component]?.[variant],
      ...themeData.spacing.componentSpacing[component],
      ...themeData.shadows.componentShadows?.[component],
    };
  },
  
  // Função para gerar CSS custom properties
  generateCSSVariables: (isDark: boolean = false) => {
    const colorSystem = isDark ? colors.dark : colors;
    const shadowSystemData = isDark ? shadowSystem.darkShadows : shadowSystem.shadows;
    
    return {
      // Cores
      '--color-primary': colors.base.primary[500],
      '--color-secondary': colors.base.secondary[500],
      '--color-success': colors.base.success[500],
      '--color-warning': colors.base.warning[500],
      '--color-error': colors.base.error[500],
      '--color-info': colors.base.info[500],
      
      // Texto
      '--color-text-primary': (colorSystem as any).text?.primary || colors.semantic.text.primary,
      '--color-text-secondary': (colorSystem as any).text?.secondary || colors.semantic.text.secondary,
      '--color-text-disabled': (colorSystem as any).text?.disabled || colors.semantic.text.disabled,
      
      // Fundo
      '--color-background-primary': (colorSystem as any).background?.primary || colors.semantic.background.primary,
      '--color-background-secondary': (colorSystem as any).background?.secondary || colors.semantic.background.secondary,
      
      // Bordas
      '--color-border-primary': (colorSystem as any).border?.primary || colors.semantic.border.primary,
      '--color-border-focus': (colorSystem as any).border?.focus || colors.semantic.border.focus,
      
      // Espaçamentos
      '--spacing-xs': spacingSystem.spacing[4],
      '--spacing-sm': spacingSystem.spacing[8],
      '--spacing-md': spacingSystem.spacing[16],
      '--spacing-lg': spacingSystem.spacing[24],
      '--spacing-xl': spacingSystem.spacing[32],
      
      // Sombras
      '--shadow-sm': shadowSystemData.xs,
      '--shadow-md': shadowSystemData.md,
      '--shadow-lg': shadowSystemData.lg,
      '--shadow-xl': shadowSystemData.xl,
      
      // Tipografia
      '--font-family-primary': typography.fonts.family.primary,
      '--font-family-mono': typography.fonts.family.mono,
      '--font-size-base': typography.fontSizes.base,
      '--font-size-sm': typography.fontSizes.sm,
      '--font-size-lg': typography.fontSizes.lg,
    };
  },
  
  // Função para validar contraste WCAG
  validateContrast: (foreground: string, background: string): boolean => {
    // Implementação simplificada - em produção usar biblioteca como 'color-contrast'
    // Para WCAG AA: 4.5:1 para texto normal, 3:1 para texto grande
    return true; // Placeholder
  },
  
  // Função para converter tema para CSS-in-JS
  toCSSInJS: (isDark: boolean = false) => {
    const cssVariables = themeUtils.generateCSSVariables(isDark);
    const cssObject: Record<string, any> = {};
    
    Object.entries(cssVariables).forEach(([key, value]) => {
      cssObject[key] = value;
    });
    
    return cssObject;
  },
};

// ===== TIPOS DO TEMA =====
export type Theme = typeof theme;
export type ColorSystem = typeof colors;
export type TypographySystem = typeof typography;
export type SpacingSystem = typeof spacingSystem;
export type ShadowSystem = typeof shadowSystem;

// ===== EXPORTAÇÃO PADRÃO =====
export default theme; 