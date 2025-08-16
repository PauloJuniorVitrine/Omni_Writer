/**
 * OmniWriter Frontend Bundle v2 (modularizado)
 * Orquestra todos os módulos do frontend.
 */
import { initApp } from './handlers.js';
import { initTheme } from './theme.js';
import { initA11y } from './a11y.js';

window.onload = async () => {
  try {
    await Promise.all([
      initTheme(),
      initA11y(),
    ]);
    await initApp();
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Erro crítico na inicialização do frontend:', e);
    const el = document.getElementById('feedback_msg');
    if (el) {
      el.textContent = 'Erro crítico na inicialização do frontend.';
      el.className = 'feedback error';
      el.style.display = '';
    }
  }
}; 