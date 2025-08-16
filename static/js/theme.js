/**
 * Gerenciamento de tema (dark/light/custom)
 * @module theme
 *
 * Possíveis valores de tema: 'light', 'dark', 'custom'
 */
import { DEFAULT_THEME } from './config.js';

let themeListeners = [];

/**
 * Aplica tema ao documento
 * @param {'light'|'dark'|'custom'} theme
 */
export const applyTheme = (theme) => {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  themeListeners.forEach((fn) => fn(theme));
};

/**
 * Alterna entre dark e light
 */
export const toggleTheme = () => {
  const atual = document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
  const novo = atual === 'dark' ? 'light' : 'dark';
  applyTheme(novo);
};

/**
 * Inicializa tema salvo
 */
export const initTheme = () => {
  const theme = localStorage.getItem('theme') || DEFAULT_THEME;
  applyTheme(theme);
};

/**
 * Adiciona listener para mudanças de tema
 * @param {Function} fn
 */
export const onThemeChange = (fn) => {
  themeListeners.push(fn);
}; 