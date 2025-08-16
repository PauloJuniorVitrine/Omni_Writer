/**
 * Sistema de Espaçamentos - Omni Writer
 * 
 * Escala baseada em 8px (0.5rem)
 * Consistência em todo o sistema
 * Responsivo e acessível
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== ESCALA BASE =====
const baseUnit = 8; // 8px = 0.5rem

// ===== ESPAÇAMENTOS =====
export const spacing = {
  // Espaçamentos pequenos
  0: '0',
  1: `${baseUnit * 0.125}px`,      // 1px
  2: `${baseUnit * 0.25}px`,       // 2px
  3: `${baseUnit * 0.375}px`,      // 3px
  4: `${baseUnit * 0.5}px`,        // 4px
  5: `${baseUnit * 0.625}px`,      // 5px
  6: `${baseUnit * 0.75}px`,       // 6px
  7: `${baseUnit * 0.875}px`,      // 7px
  
  // Espaçamentos base (múltiplos de 8px)
  8: `${baseUnit}px`,              // 8px
  12: `${baseUnit * 1.5}px`,       // 12px
  16: `${baseUnit * 2}px`,         // 16px
  20: `${baseUnit * 2.5}px`,       // 20px
  24: `${baseUnit * 3}px`,         // 24px
  28: `${baseUnit * 3.5}px`,       // 28px
  32: `${baseUnit * 4}px`,         // 32px
  36: `${baseUnit * 4.5}px`,       // 36px
  40: `${baseUnit * 5}px`,         // 40px
  44: `${baseUnit * 5.5}px`,       // 44px
  48: `${baseUnit * 6}px`,         // 48px
  52: `${baseUnit * 6.5}px`,       // 52px
  56: `${baseUnit * 7}px`,         // 56px
  60: `${baseUnit * 7.5}px`,       // 60px
  64: `${baseUnit * 8}px`,         // 64px
  68: `${baseUnit * 8.5}px`,       // 68px
  72: `${baseUnit * 9}px`,         // 72px
  76: `${baseUnit * 9.5}px`,       // 76px
  80: `${baseUnit * 10}px`,        // 80px
  
  // Espaçamentos grandes
  96: `${baseUnit * 12}px`,        // 96px
  112: `${baseUnit * 14}px`,       // 112px
  128: `${baseUnit * 16}px`,       // 128px
  144: `${baseUnit * 18}px`,       // 144px
  160: `${baseUnit * 20}px`,       // 160px
  176: `${baseUnit * 22}px`,       // 176px
  192: `${baseUnit * 24}px`,       // 192px
  208: `${baseUnit * 26}px`,       // 208px
  224: `${baseUnit * 28}px`,       // 224px
  240: `${baseUnit * 30}px`,       // 240px
  256: `${baseUnit * 32}px`,       // 256px
  272: `${baseUnit * 34}px`,       // 272px
  288: `${baseUnit * 36}px`,       // 288px
  304: `${baseUnit * 38}px`,       // 304px
  320: `${baseUnit * 40}px`,       // 320px
};

// ===== ESPAÇAMENTOS EM REM =====
export const spacingRem = {
  // Espaçamentos pequenos
  0: '0',
  1: '0.0625rem',    // 1px
  2: '0.125rem',     // 2px
  3: '0.1875rem',    // 3px
  4: '0.25rem',      // 4px
  5: '0.3125rem',    // 5px
  6: '0.375rem',     // 6px
  7: '0.4375rem',    // 7px
  
  // Espaçamentos base
  8: '0.5rem',       // 8px
  12: '0.75rem',     // 12px
  16: '1rem',        // 16px
  20: '1.25rem',     // 20px
  24: '1.5rem',      // 24px
  28: '1.75rem',     // 28px
  32: '2rem',        // 32px
  36: '2.25rem',     // 36px
  40: '2.5rem',      // 40px
  44: '2.75rem',     // 44px
  48: '3rem',        // 48px
  52: '3.25rem',     // 52px
  56: '3.5rem',      // 56px
  60: '3.75rem',     // 60px
  64: '4rem',        // 64px
  68: '4.25rem',     // 68px
  72: '4.5rem',      // 72px
  76: '4.75rem',     // 76px
  80: '5rem',        // 80px
  
  // Espaçamentos grandes
  96: '6rem',        // 96px
  112: '7rem',       // 112px
  128: '8rem',       // 128px
  144: '9rem',       // 144px
  160: '10rem',      // 160px
  176: '11rem',      // 176px
  192: '12rem',      // 192px
  208: '13rem',      // 208px
  224: '14rem',      // 224px
  240: '15rem',      // 240px
  256: '16rem',      // 256px
  272: '17rem',      // 272px
  288: '18rem',      // 288px
  304: '19rem',      // 304px
  320: '20rem',      // 320px
};

// ===== ESPAÇAMENTOS SEMÂNTICOS =====
export const semanticSpacing = {
  // Margens
  margin: {
    none: spacing[0],
    xs: spacing[4],
    sm: spacing[8],
    md: spacing[16],
    lg: spacing[24],
    xl: spacing[32],
    '2xl': spacing[48],
    '3xl': spacing[64],
    '4xl': spacing[96],
  },
  
  // Padding
  padding: {
    none: spacing[0],
    xs: spacing[4],
    sm: spacing[8],
    md: spacing[16],
    lg: spacing[24],
    xl: spacing[32],
    '2xl': spacing[48],
    '3xl': spacing[64],
    '4xl': spacing[96],
  },
  
  // Gap (para flexbox e grid)
  gap: {
    none: spacing[0],
    xs: spacing[4],
    sm: spacing[8],
    md: spacing[16],
    lg: spacing[24],
    xl: spacing[32],
    '2xl': spacing[48],
    '3xl': spacing[64],
  },
  
  // Espaçamento entre elementos
  stack: {
    xs: spacing[4],
    sm: spacing[8],
    md: spacing[16],
    lg: spacing[24],
    xl: spacing[32],
    '2xl': spacing[48],
  },
  
  // Espaçamento interno de componentes
  inset: {
    xs: spacing[4],
    sm: spacing[8],
    md: spacing[16],
    lg: spacing[24],
    xl: spacing[32],
    '2xl': spacing[48],
  },
};

// ===== ESPAÇAMENTOS DE COMPONENTES =====
export const componentSpacing = {
  // Botões
  button: {
    padding: {
      sm: `${spacing[8]} ${spacing[16]}`,
      md: `${spacing[12]} ${spacing[20]}`,
      lg: `${spacing[16]} ${spacing[24]}`,
    },
    gap: spacing[8],
    borderRadius: spacing[6],
  },
  
  // Inputs
  input: {
    padding: {
      sm: `${spacing[8]} ${spacing[12]}`,
      md: `${spacing[12]} ${spacing[16]}`,
      lg: `${spacing[16]} ${spacing[20]}`,
    },
    borderRadius: spacing[6],
  },
  
  // Cards
  card: {
    padding: {
      sm: spacing[16],
      md: spacing[24],
      lg: spacing[32],
    },
    gap: spacing[16],
    borderRadius: spacing[8],
  },
  
  // Modais
  modal: {
    padding: spacing[24],
    gap: spacing[16],
    borderRadius: spacing[12],
    maxWidth: '90vw',
    maxHeight: '90vh',
  },
  
  // Toasts
  toast: {
    padding: `${spacing[12]} ${spacing[16]}`,
    gap: spacing[8],
    borderRadius: spacing[6],
    margin: spacing[16],
  },
  
  // Navigation
  navigation: {
    padding: spacing[16],
    gap: spacing[8],
    itemPadding: `${spacing[8]} ${spacing[12]}`,
  },
  
  // Layout
  layout: {
    container: {
      padding: spacing[16],
      maxWidth: '1200px',
      margin: '0 auto',
    },
    sidebar: {
      width: '280px',
      padding: spacing[16],
    },
    header: {
      height: '64px',
      padding: `${spacing[16]} ${spacing[24]}`,
    },
    footer: {
      padding: spacing[24],
    },
  },
};

// ===== RESPONSIVIDADE =====
export const responsiveSpacing = {
  // Breakpoints
  breakpoints: {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },
  
  // Espaçamentos responsivos
  container: {
    base: spacing[16],
    sm: spacing[20],
    md: spacing[24],
    lg: spacing[32],
    xl: spacing[40],
  },
  
  section: {
    base: spacing[32],
    sm: spacing[40],
    md: spacing[48],
    lg: spacing[64],
    xl: spacing[80],
  },
  
  component: {
    base: spacing[16],
    sm: spacing[20],
    md: spacing[24],
    lg: spacing[32],
    xl: spacing[40],
  },
};

// ===== UTILITÁRIOS =====
export const spacingUtils = {
  // Função para criar espaçamento customizado
  custom: (value: number) => `${value}px`,
  
  // Função para espaçamento responsivo
  responsive: (base: string, sm?: string, md?: string, lg?: string, xl?: string) => ({
    base,
    sm: sm || base,
    md: md || sm || base,
    lg: lg || md || sm || base,
    xl: xl || lg || md || sm || base,
  }),
  
  // Função para espaçamento condicional
  conditional: (condition: boolean, trueValue: string, falseValue: string) =>
    condition ? trueValue : falseValue,
  
  // Função para espaçamento proporcional
  proportional: (base: number, ratio: number) => `${base * ratio}px`,
};

// ===== ACESSIBILIDADE =====
export const accessibilitySpacing = {
  // Espaçamento mínimo para toque (44px = 2.75rem)
  touchTarget: spacing[44],
  
  // Espaçamento mínimo para foco
  focusRing: spacing[2],
  
  // Espaçamento mínimo entre elementos interativos
  interactiveGap: spacing[8],
  
  // Espaçamento mínimo para legibilidade
  textSpacing: spacing[16],
  
  // Espaçamento mínimo para navegação
  navigationGap: spacing[12],
};

// ===== EXPORTAÇÃO PRINCIPAL =====
export const spacingSystem = {
  spacing,
  spacingRem,
  semanticSpacing,
  componentSpacing,
  responsiveSpacing,
  spacingUtils,
  accessibilitySpacing,
};

export default spacingSystem; 