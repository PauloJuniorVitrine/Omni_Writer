/**
 * Acessibilidade: navegação por teclado, foco e ARIA
 * @module a11y
 */

/**
 * Inicializa acessibilidade básica
 */
export function initA11y() {
  // Exemplo: garantir foco visível em navegação por teclado
  document.body.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') document.body.classList.add('user-is-tabbing');
  });
  document.body.addEventListener('mousedown', () => {
    document.body.classList.remove('user-is-tabbing');
  });
  // Adicione outras práticas de acessibilidade conforme necessário
}

export function updateAriaLive(msg, mode = 'polite') {
  let el = document.getElementById('aria-live');
  if (!el) {
    el = document.createElement('div');
    el.id = 'aria-live';
    el.setAttribute('aria-live', mode);
    el.setAttribute('role', 'status');
    el.style.position = 'absolute';
    el.style.left = '-9999px';
    document.body.appendChild(el);
  }
  el.textContent = msg;
}

export function focusModal(modal) {
  if (modal && typeof modal.focus === 'function') modal.focus();
}

export function enableArrowNavigation(list) {
  if (!list) return;
  list.addEventListener('keydown', (e) => {
    const items = Array.from(list.querySelectorAll('[tabindex="0"]'));
    const idx = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' && idx < items.length - 1) {
      items[idx + 1].focus();
      e.preventDefault();
    } else if (e.key === 'ArrowUp' && idx > 0) {
      items[idx - 1].focus();
      e.preventDefault();
    }
  });
} 