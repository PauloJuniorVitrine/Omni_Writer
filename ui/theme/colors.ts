/**
 * Sistema de Cores - Omni Writer
 * 
 * Design Tokens baseados em WCAG 2.1 AA
 * Suporte a modo claro/escuro
 * Paleta semântica para componentes
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== CORES BASE =====
export const baseColors = {
  // Primárias
  primary: {
    50: '#eff6ff',
    100: '#dbeafe',
    200: '#bfdbfe',
    300: '#93c5fd',
    400: '#60a5fa',
    500: '#3b82f6', // Cor principal
    600: '#2563eb',
    700: '#1d4ed8',
    800: '#1e40af',
    900: '#1e3a8a',
  },
  
  // Secundárias
  secondary: {
    50: '#f8fafc',
    100: '#f1f5f9',
    200: '#e2e8f0',
    300: '#cbd5e1',
    400: '#94a3b8',
    500: '#64748b', // Cor secundária
    600: '#475569',
    700: '#334155',
    800: '#1e293b',
    900: '#0f172a',
  },
  
  // Sucesso
  success: {
    50: '#f0fdf4',
    100: '#dcfce7',
    200: '#bbf7d0',
    300: '#86efac',
    400: '#4ade80',
    500: '#22c55e', // Verde sucesso
    600: '#16a34a',
    700: '#15803d',
    800: '#166534',
    900: '#14532d',
  },
  
  // Aviso
  warning: {
    50: '#fffbeb',
    100: '#fef3c7',
    200: '#fde68a',
    300: '#fcd34d',
    400: '#fbbf24',
    500: '#f59e0b', // Amarelo aviso
    600: '#d97706',
    700: '#b45309',
    800: '#92400e',
    900: '#78350f',
  },
  
  // Erro
  error: {
    50: '#fef2f2',
    100: '#fee2e2',
    200: '#fecaca',
    300: '#fca5a5',
    400: '#f87171',
    500: '#ef4444', // Vermelho erro
    600: '#dc2626',
    700: '#b91c1c',
    800: '#991b1b',
    900: '#7f1d1d',
  },
  
  // Informação
  info: {
    50: '#eff6ff',
    100: '#dbeafe',
    200: '#bfdbfe',
    300: '#93c5fd',
    400: '#60a5fa',
    500: '#3b82f6', // Azul informação
    600: '#2563eb',
    700: '#1d4ed8',
    800: '#1e40af',
    900: '#1e3a8a',
  },
};

// ===== CORES SEMÂNTICAS =====
export const semanticColors = {
  // Texto
  text: {
    primary: '#1e293b',    // Texto principal
    secondary: '#64748b',  // Texto secundário
    disabled: '#94a3b8',   // Texto desabilitado
    inverse: '#ffffff',    // Texto em fundo escuro
  },
  
  // Fundo
  background: {
    primary: '#ffffff',    // Fundo principal
    secondary: '#f8fafc',  // Fundo secundário
    tertiary: '#f1f5f9',   // Fundo terciário
    inverse: '#1e293b',    // Fundo escuro
  },
  
  // Bordas
  border: {
    primary: '#e2e8f0',    // Borda principal
    secondary: '#cbd5e1',  // Borda secundária
    focus: '#3b82f6',      // Borda de foco
    error: '#ef4444',      // Borda de erro
  },
  
  // Estados
  state: {
    hover: '#f1f5f9',      // Estado hover
    active: '#e2e8f0',     // Estado ativo
    disabled: '#f8fafc',   // Estado desabilitado
    loading: '#f1f5f9',    // Estado carregando
  },
};

// ===== CORES DE COMPONENTES =====
export const componentColors = {
  // Botões
  button: {
    primary: {
      background: baseColors.primary[500],
      text: '#ffffff',
      hover: baseColors.primary[600],
      active: baseColors.primary[700],
      disabled: baseColors.primary[200],
    },
    secondary: {
      background: 'transparent',
      text: baseColors.primary[500],
      border: baseColors.primary[500],
      hover: baseColors.primary[50],
      active: baseColors.primary[100],
      disabled: semanticColors.state.disabled,
    },
    danger: {
      background: baseColors.error[500],
      text: '#ffffff',
      hover: baseColors.error[600],
      active: baseColors.error[700],
      disabled: baseColors.error[200],
    },
  },
  
  // Inputs
  input: {
    background: '#ffffff',
    border: semanticColors.border.primary,
    text: semanticColors.text.primary,
    placeholder: semanticColors.text.disabled,
    focus: {
      border: semanticColors.border.focus,
      background: '#ffffff',
    },
    error: {
      border: semanticColors.border.error,
      background: '#fef2f2',
    },
    disabled: {
      background: semanticColors.state.disabled,
      text: semanticColors.text.disabled,
    },
  },
  
  // Cards
  card: {
    background: '#ffffff',
    border: semanticColors.border.primary,
    shadow: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06)',
    shadowHover: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  },
  
  // Modais
  modal: {
    background: '#ffffff',
    overlay: 'rgba(0, 0, 0, 0.5)',
    shadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)',
  },
  
  // Toasts
  toast: {
    success: {
      background: baseColors.success[50],
      border: baseColors.success[200],
      text: baseColors.success[800],
      icon: baseColors.success[500],
    },
    error: {
      background: baseColors.error[50],
      border: baseColors.error[200],
      text: baseColors.error[800],
      icon: baseColors.error[500],
    },
    warning: {
      background: baseColors.warning[50],
      border: baseColors.warning[200],
      text: baseColors.warning[800],
      icon: baseColors.warning[500],
    },
    info: {
      background: baseColors.info[50],
      border: baseColors.info[200],
      text: baseColors.info[800],
      icon: baseColors.info[500],
    },
  },
};

// ===== MODO ESCURO =====
export const darkColors = {
  // Texto
  text: {
    primary: '#f8fafc',
    secondary: '#cbd5e1',
    disabled: '#64748b',
    inverse: '#1e293b',
  },
  
  // Fundo
  background: {
    primary: '#0f172a',
    secondary: '#1e293b',
    tertiary: '#334155',
    inverse: '#ffffff',
  },
  
  // Bordas
  border: {
    primary: '#334155',
    secondary: '#475569',
    focus: '#60a5fa',
    error: '#f87171',
  },
  
  // Estados
  state: {
    hover: '#1e293b',
    active: '#334155',
    disabled: '#1e293b',
    loading: '#1e293b',
  },
  
  // Componentes
  component: {
    input: {
      background: '#1e293b',
      border: '#334155',
      text: '#f8fafc',
      placeholder: '#64748b',
      focus: {
        border: '#60a5fa',
        background: '#1e293b',
      },
      error: {
        border: '#f87171',
        background: '#450a0a',
      },
      disabled: {
        background: '#1e293b',
        text: '#64748b',
      },
    },
    
    card: {
      background: '#1e293b',
      border: '#334155',
      shadow: '0 1px 3px 0 rgba(0, 0, 0, 0.3), 0 1px 2px 0 rgba(0, 0, 0, 0.2)',
      shadowHover: '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)',
    },
    
    modal: {
      background: '#1e293b',
      overlay: 'rgba(0, 0, 0, 0.7)',
      shadow: '0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.2)',
    },
  },
};

// ===== EXPORTAÇÃO PRINCIPAL =====
export const colors = {
  base: baseColors,
  semantic: semanticColors,
  component: componentColors,
  dark: darkColors,
};

export default colors; 