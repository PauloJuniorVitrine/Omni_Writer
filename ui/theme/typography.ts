/**
 * Sistema de Tipografia - Omni Writer
 * 
 * Hierarquia tipográfica responsiva
 * Suporte a múltiplos pesos e tamanhos
 * Otimizado para legibilidade e acessibilidade
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== FONTES =====
export const fonts = {
  // Família de fontes
  family: {
    primary: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    mono: '"JetBrains Mono", "Fira Code", "Consolas", "Monaco", monospace',
    display: '"Poppins", "Inter", sans-serif',
  },
  
  // Pesos das fontes
  weight: {
    light: 300,
    normal: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
    extrabold: 800,
  },
  
  // Altura da linha
  lineHeight: {
    tight: 1.2,
    normal: 1.5,
    relaxed: 1.75,
    loose: 2,
  },
};

// ===== TAMANHOS DE FONTE =====
export const fontSizes = {
  // Tamanhos base (rem)
  xs: '0.75rem',    // 12px
  sm: '0.875rem',   // 14px
  base: '1rem',     // 16px
  lg: '1.125rem',   // 18px
  xl: '1.25rem',    // 20px
  '2xl': '1.5rem',  // 24px
  '3xl': '1.875rem', // 30px
  '4xl': '2.25rem',  // 36px
  '5xl': '3rem',     // 48px
  '6xl': '3.75rem',  // 60px
  '7xl': '4.5rem',   // 72px
  '8xl': '6rem',     // 96px
  '9xl': '8rem',     // 128px
};

// ===== ESPAÇAMENTOS DE LETRAS =====
export const letterSpacing = {
  tighter: '-0.05em',
  tight: '-0.025em',
  normal: '0em',
  wide: '0.025em',
  wider: '0.05em',
  widest: '0.1em',
};

// ===== ESTILOS DE TEXTO =====
export const textStyles = {
  // Cabeçalhos
  h1: {
    fontSize: fontSizes['4xl'],
    fontWeight: fonts.weight.bold,
    lineHeight: fonts.lineHeight.tight,
    letterSpacing: letterSpacing.tight,
    fontFamily: fonts.family.display,
  },
  
  h2: {
    fontSize: fontSizes['3xl'],
    fontWeight: fonts.weight.semibold,
    lineHeight: fonts.lineHeight.tight,
    letterSpacing: letterSpacing.tight,
    fontFamily: fonts.family.display,
  },
  
  h3: {
    fontSize: fontSizes['2xl'],
    fontWeight: fonts.weight.semibold,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  h4: {
    fontSize: fontSizes.xl,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  h5: {
    fontSize: fontSizes.lg,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  h6: {
    fontSize: fontSizes.base,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  // Texto do corpo
  body: {
    fontSize: fontSizes.base,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.relaxed,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  bodySmall: {
    fontSize: fontSizes.sm,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.relaxed,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  bodyLarge: {
    fontSize: fontSizes.lg,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.relaxed,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  // Texto de interface
  label: {
    fontSize: fontSizes.sm,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
  
  caption: {
    fontSize: fontSizes.xs,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.wide,
    fontFamily: fonts.family.primary,
  },
  
  // Código
  code: {
    fontSize: fontSizes.sm,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.mono,
  },
  
  codeLarge: {
    fontSize: fontSizes.base,
    fontWeight: fonts.weight.normal,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.mono,
  },
  
  // Botões
  button: {
    fontSize: fontSizes.sm,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.wide,
    fontFamily: fonts.family.primary,
  },
  
  buttonLarge: {
    fontSize: fontSizes.base,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.wide,
    fontFamily: fonts.family.primary,
  },
  
  // Links
  link: {
    fontSize: fontSizes.base,
    fontWeight: fonts.weight.medium,
    lineHeight: fonts.lineHeight.normal,
    letterSpacing: letterSpacing.normal,
    fontFamily: fonts.family.primary,
  },
};

// ===== RESPONSIVIDADE =====
export const responsiveTypography = {
  // Breakpoints
  breakpoints: {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },
  
  // Tamanhos responsivos
  h1: {
    base: fontSizes['2xl'],
    sm: fontSizes['3xl'],
    md: fontSizes['4xl'],
    lg: fontSizes['5xl'],
    xl: fontSizes['6xl'],
  },
  
  h2: {
    base: fontSizes.xl,
    sm: fontSizes['2xl'],
    md: fontSizes['3xl'],
    lg: fontSizes['4xl'],
    xl: fontSizes['5xl'],
  },
  
  h3: {
    base: fontSizes.lg,
    sm: fontSizes.xl,
    md: fontSizes['2xl'],
    lg: fontSizes['3xl'],
    xl: fontSizes['4xl'],
  },
  
  body: {
    base: fontSizes.sm,
    sm: fontSizes.base,
    md: fontSizes.lg,
    lg: fontSizes.xl,
    xl: fontSizes['2xl'],
  },
};

// ===== UTILITÁRIOS =====
export const typographyUtils = {
  // Função para aplicar estilos de texto
  applyTextStyle: (style: keyof typeof textStyles) => {
    const textStyle = textStyles[style];
    return {
      fontSize: textStyle.fontSize,
      fontWeight: textStyle.fontWeight,
      lineHeight: textStyle.lineHeight,
      letterSpacing: textStyle.letterSpacing,
      fontFamily: textStyle.fontFamily,
    };
  },
  
  // Função para truncar texto
  truncate: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
  },
  
  // Função para quebrar palavras
  breakWords: {
    wordBreak: 'break-word' as const,
    overflowWrap: 'break-word' as const,
  },
  
  // Função para seleção de texto
  selection: {
    backgroundColor: 'rgba(59, 130, 246, 0.2)',
    color: 'inherit',
  },
};

// ===== ACESSIBILIDADE =====
export const accessibilityTypography = {
  // Tamanho mínimo para legibilidade
  minFontSize: fontSizes.sm,
  
  // Altura de linha mínima para legibilidade
  minLineHeight: fonts.lineHeight.normal,
  
  // Contraste mínimo para texto
  minContrastRatio: 4.5, // WCAG AA
  
  // Espaçamento mínimo entre linhas
  minLineSpacing: '1.2em',
  
  // Espaçamento mínimo entre parágrafos
  minParagraphSpacing: '1.5em',
};

// ===== EXPORTAÇÃO PRINCIPAL =====
export const typography = {
  fonts,
  fontSizes,
  letterSpacing,
  textStyles,
  responsiveTypography,
  typographyUtils,
  accessibilityTypography,
};

export default typography; 