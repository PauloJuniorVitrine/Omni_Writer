/**
 * Sistema de Sombras - Omni Writer
 * 
 * Hierarquia de elevação consistente
 * Suporte a modo claro/escuro
 * Otimizado para performance
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== SOMBRAS BASE =====
export const shadows = {
  // Sem sombra
  none: 'none',
  
  // Sombras pequenas
  xs: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
  sm: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
  
  // Sombras médias
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
  
  // Sombras grandes
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
  
  // Sombras especiais
  inner: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
  outline: '0 0 0 3px rgba(59, 130, 246, 0.5)',
};

// ===== SOMBRAS SEMÂNTICAS =====
export const semanticShadows = {
  // Componentes de interface
  card: {
    default: shadows.sm,
    hover: shadows.md,
    active: shadows.lg,
    elevated: shadows.xl,
  },
  
  // Botões
  button: {
    default: shadows.none,
    hover: shadows.sm,
    active: shadows.inner,
    disabled: shadows.none,
  },
  
  // Inputs
  input: {
    default: shadows.none,
    focus: shadows.outline,
    error: '0 0 0 3px rgba(239, 68, 68, 0.5)',
  },
  
  // Modais
  modal: {
    backdrop: '0 0 0 100vmax rgba(0, 0, 0, 0.5)',
    content: shadows['2xl'],
  },
  
  // Dropdowns
  dropdown: {
    menu: shadows.lg,
    item: shadows.none,
    itemHover: shadows.sm,
  },
  
  // Toasts
  toast: {
    success: shadows.md,
    error: shadows.md,
    warning: shadows.md,
    info: shadows.md,
  },
  
  // Tooltips
  tooltip: {
    default: shadows.lg,
    arrow: '0 2px 4px 0 rgba(0, 0, 0, 0.1)',
  },
  
  // Navigation
  navigation: {
    header: shadows.sm,
    sidebar: shadows.md,
    breadcrumb: shadows.none,
  },
  
  // Tables
  table: {
    header: shadows.sm,
    row: shadows.none,
    rowHover: shadows.xs,
  },
  
  // Forms
  form: {
    field: shadows.none,
    fieldFocus: shadows.outline,
    fieldError: '0 0 0 3px rgba(239, 68, 68, 0.5)',
    group: shadows.sm,
  },
};

// ===== SOMBRAS DE COMPONENTES =====
export const componentShadows = {
  // Cards
  card: {
    sm: shadows.sm,
    md: shadows.md,
    lg: shadows.lg,
    xl: shadows.xl,
  },
  
  // Botões
  button: {
    primary: {
      default: shadows.none,
      hover: shadows.sm,
      active: shadows.inner,
      disabled: shadows.none,
    },
    secondary: {
      default: shadows.none,
      hover: shadows.xs,
      active: shadows.inner,
      disabled: shadows.none,
    },
    danger: {
      default: shadows.none,
      hover: shadows.sm,
      active: shadows.inner,
      disabled: shadows.none,
    },
  },
  
  // Inputs
  input: {
    text: {
      default: shadows.none,
      focus: shadows.outline,
      error: '0 0 0 3px rgba(239, 68, 68, 0.5)',
      disabled: shadows.none,
    },
    select: {
      default: shadows.none,
      focus: shadows.outline,
      open: shadows.md,
      disabled: shadows.none,
    },
    textarea: {
      default: shadows.none,
      focus: shadows.outline,
      error: '0 0 0 3px rgba(239, 68, 68, 0.5)',
      disabled: shadows.none,
    },
  },
  
  // Modais
  modal: {
    overlay: '0 0 0 100vmax rgba(0, 0, 0, 0.5)',
    content: shadows['2xl'],
    header: shadows.none,
    body: shadows.none,
    footer: shadows.none,
  },
  
  // Drawers
  drawer: {
    overlay: '0 0 0 100vmax rgba(0, 0, 0, 0.5)',
    content: shadows.xl,
  },
  
  // Popovers
  popover: {
    content: shadows.lg,
    arrow: '0 2px 4px 0 rgba(0, 0, 0, 0.1)',
  },
  
  // Toasts
  toast: {
    container: shadows.md,
    success: shadows.md,
    error: shadows.md,
    warning: shadows.md,
    info: shadows.md,
  },
  
  // Navigation
  navigation: {
    header: shadows.sm,
    sidebar: shadows.md,
    breadcrumb: shadows.none,
    tabs: shadows.none,
    pagination: shadows.none,
  },
  
  // Data Display
  table: {
    container: shadows.sm,
    header: shadows.none,
    row: shadows.none,
    rowHover: shadows.xs,
    rowSelected: shadows.sm,
  },
  
  list: {
    container: shadows.none,
    item: shadows.none,
    itemHover: shadows.xs,
    itemSelected: shadows.sm,
  },
  
  // Feedback
  alert: {
    default: shadows.none,
    success: shadows.none,
    error: shadows.none,
    warning: shadows.none,
    info: shadows.none,
  },
  
  badge: {
    default: shadows.none,
    success: shadows.none,
    error: shadows.none,
    warning: shadows.none,
    info: shadows.none,
  },
  
  progress: {
    track: shadows.inner,
    bar: shadows.none,
  },
  
  skeleton: {
    default: shadows.none,
    animated: shadows.none,
  },
};

// ===== SOMBRAS RESPONSIVAS =====
export const responsiveShadows = {
  // Breakpoints
  breakpoints: {
    sm: '640px',
    md: '768px',
    lg: '1024px',
    xl: '1280px',
    '2xl': '1536px',
  },
  
  // Sombras responsivas por componente
  card: {
    base: shadows.sm,
    sm: shadows.md,
    md: shadows.lg,
    lg: shadows.xl,
    xl: shadows['2xl'],
  },
  
  modal: {
    base: shadows.lg,
    sm: shadows.xl,
    md: shadows['2xl'],
    lg: shadows['2xl'],
    xl: shadows['2xl'],
  },
  
  navigation: {
    base: shadows.xs,
    sm: shadows.sm,
    md: shadows.md,
    lg: shadows.lg,
    xl: shadows.lg,
  },
};

// ===== SOMBRAS PARA MODO ESCURO =====
export const darkShadows = {
  // Sombras base para modo escuro
  xs: '0 1px 2px 0 rgba(0, 0, 0, 0.3)',
  sm: '0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 1px 2px 0 rgba(0, 0, 0, 0.3)',
  md: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.3)',
  lg: '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3)',
  xl: '0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 10px 10px -5px rgba(0, 0, 0, 0.3)',
  '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
  
  // Sombras especiais para modo escuro
  inner: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.3)',
  outline: '0 0 0 3px rgba(96, 165, 250, 0.5)',
  
  // Componentes específicos para modo escuro
  component: {
    card: {
      default: '0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 1px 2px 0 rgba(0, 0, 0, 0.3)',
      hover: '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.3)',
      active: '0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3)',
      elevated: '0 20px 25px -5px rgba(0, 0, 0, 0.4), 0 10px 10px -5px rgba(0, 0, 0, 0.3)',
    },
    
    modal: {
      backdrop: '0 0 0 100vmax rgba(0, 0, 0, 0.7)',
      content: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
    },
    
    input: {
      focus: '0 0 0 3px rgba(96, 165, 250, 0.5)',
      error: '0 0 0 3px rgba(248, 113, 113, 0.5)',
    },
  },
};

// ===== UTILITÁRIOS =====
export const shadowUtils = {
  // Função para criar sombra customizada
  custom: (x: number, y: number, blur: number, spread: number, color: string) =>
    `${x}px ${y}px ${blur}px ${spread}px ${color}`,
  
  // Função para sombra com múltiplas camadas
  layered: (shadows: string[]) => shadows.join(', '),
  
  // Função para sombra responsiva
  responsive: (base: string, sm?: string, md?: string, lg?: string, xl?: string) => ({
    base,
    sm: sm || base,
    md: md || sm || base,
    lg: lg || md || sm || base,
    xl: xl || lg || md || sm || base,
  }),
  
  // Função para sombra condicional
  conditional: (condition: boolean, trueValue: string, falseValue: string) =>
    condition ? trueValue : falseValue,
  
  // Função para sombra com opacidade
  withOpacity: (shadow: string, opacity: number) => {
    const rgbaMatch = shadow.match(/rgba\([^)]+\)/);
    if (rgbaMatch) {
      return shadow.replace(rgbaMatch[0], rgbaMatch[0].replace(/[\d.]+\)$/, `${opacity})`));
    }
    return shadow;
  },
  
  // Função para sombra invertida (para modo escuro)
  invert: (shadow: string) => {
    return shadow
      .replace(/rgba\(0, 0, 0, ([^)]+)\)/g, (match, opacity) => {
        const numOpacity = parseFloat(opacity);
        return `rgba(255, 255, 255, ${numOpacity * 0.1})`;
      })
      .replace(/rgba\([^)]+\)/g, (match) => {
        // Ajusta outras cores para modo escuro
        return match.replace(/[\d.]+\)$/, '0.3)');
      });
  },
};

// ===== PERFORMANCE =====
export const shadowPerformance = {
  // Sombras otimizadas para performance
  optimized: {
    // Usa transform em vez de box-shadow quando possível
    card: 'transform: translateY(1px)',
    button: 'transform: translateY(1px)',
    input: 'transform: scale(1.02)',
  },
  
  // Sombras com will-change para animações
  animated: {
    card: 'will-change: box-shadow, transform',
    button: 'will-change: box-shadow, transform',
    modal: 'will-change: box-shadow, opacity',
  },
  
  // Sombras com GPU acceleration
  gpu: {
    card: 'transform: translateZ(0)',
    button: 'transform: translateZ(0)',
    modal: 'transform: translateZ(0)',
  },
};

// ===== ACESSIBILIDADE =====
export const accessibilityShadows = {
  // Sombras para indicar foco
  focus: {
    default: shadows.outline,
    error: '0 0 0 3px rgba(239, 68, 68, 0.5)',
    success: '0 0 0 3px rgba(34, 197, 94, 0.5)',
    warning: '0 0 0 3px rgba(245, 158, 11, 0.5)',
  },
  
  // Sombras para indicar estados
  state: {
    hover: shadows.sm,
    active: shadows.inner,
    disabled: shadows.none,
    loading: shadows.none,
  },
  
  // Sombras para navegação
  navigation: {
    current: shadows.sm,
    hover: shadows.md,
    active: shadows.lg,
  },
};

// ===== EXPORTAÇÃO PRINCIPAL =====
export const shadowSystem = {
  shadows,
  semanticShadows,
  componentShadows,
  responsiveShadows,
  darkShadows,
  shadowUtils,
  shadowPerformance,
  accessibilityShadows,
};

export default shadowSystem; 