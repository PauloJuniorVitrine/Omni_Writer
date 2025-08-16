import { useState, useEffect } from 'react';
import { getThemeColors, validateWCAGContrast } from '../theme/colors';

type ThemeMode = 'light' | 'dark' | 'auto';

interface ThemeState {
  mode: ThemeMode;
  isDark: boolean;
  colors: ReturnType<typeof getThemeColors>;
}

/**
 * Hook para gerenciar tema com persistência e validação WCAG 2.1 AAA.
 * Suporta modo automático baseado na preferência do sistema.
 */
export const useTheme = () => {
  const [themeState, setThemeState] = useState<ThemeState>(() => {
    // Carrega tema salvo ou usa preferência do sistema
    const savedMode = localStorage.getItem('omni_writer_theme') as ThemeMode;
    const mode = savedMode || 'auto';
    
    // Determina se deve usar tema escuro
    const isDark = mode === 'dark' || 
      (mode === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    return {
      mode,
      isDark,
      colors: getThemeColors(isDark)
    };
  });

  // Atualiza tema quando preferência do sistema muda
  useEffect(() => {
    if (themeState.mode !== 'auto') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = (e: MediaQueryListEvent) => {
      setThemeState(prev => ({
        ...prev,
        isDark: e.matches,
        colors: getThemeColors(e.matches)
      }));
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [themeState.mode]);

  // Aplica tema ao documento
  useEffect(() => {
    const root = document.documentElement;
    
    if (themeState.isDark) {
      root.setAttribute('data-theme', 'dark');
      root.classList.add('dark');
    } else {
      root.setAttribute('data-theme', 'light');
      root.classList.remove('dark');
    }
    
    // Aplica cores CSS customizadas
    const colors = themeState.colors;
    root.style.setProperty('--color-primary', colors.primary);
    root.style.setProperty('--color-primary-hover', colors.primaryHover);
    root.style.setProperty('--color-secondary', colors.secondary);
    root.style.setProperty('--color-error', colors.error);
    root.style.setProperty('--color-success', colors.success);
    root.style.setProperty('--color-warning', colors.warning);
    root.style.setProperty('--color-info', colors.info);
    root.style.setProperty('--color-background', colors.background);
    root.style.setProperty('--color-surface', colors.surface);
    root.style.setProperty('--color-surface-hover', colors.surfaceHover);
    root.style.setProperty('--color-border', colors.border);
    root.style.setProperty('--color-text', colors.text);
    root.style.setProperty('--color-text-secondary', colors.textSecondary);
    root.style.setProperty('--color-text-tertiary', colors.textTertiary);
    
  }, [themeState]);

  // Função para alternar tema
  const toggleTheme = () => {
    const newMode: ThemeMode = themeState.mode === 'light' ? 'dark' : 'light';
    setThemeMode(newMode);
  };

  // Função para definir modo específico
  const setThemeMode = (mode: ThemeMode) => {
    const isDark = mode === 'dark' || 
      (mode === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    setThemeState({
      mode,
      isDark,
      colors: getThemeColors(isDark)
    });
    
    // Salva preferência
    localStorage.setItem('omni_writer_theme', mode);
  };

  // Função para validar contraste WCAG
  const validateContrast = (foreground: string, background: string): boolean => {
    return validateWCAGContrast(foreground, background);
  };

  // Função para obter contraste atual
  const getCurrentContrast = (): number => {
    // Implementação simplificada - em produção usar biblioteca real
    return themeState.isDark ? 21.0 : 21.0; // Contraste máximo
  };

  return {
    // Estado
    mode: themeState.mode,
    isDark: themeState.isDark,
    colors: themeState.colors,
    
    // Ações
    toggleTheme,
    setThemeMode,
    
    // Utilitários
    validateContrast,
    getCurrentContrast
  };
}; 