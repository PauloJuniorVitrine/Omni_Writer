/**
 * Utilitários DOM e feedback visual
 * @module utils
 */

/**
 * Retorna elemento por ID
 * @param {string} id
 * @returns {HTMLElement|null}
 */
export const byId = (id) => document.getElementById(id);

/**
 * Retorna primeiro elemento por seletor
 * @param {string} sel
 * @returns {Element|null}
 */
export const qs = (sel) => document.querySelector(sel);

/**
 * Retorna todos elementos por seletor
 * @param {string} sel
 * @returns {Element[]}
 */
export const qsa = (sel) => Array.from(document.querySelectorAll(sel));

/**
 * Exibe elemento
 * @param {HTMLElement} el
 */
export const show = (el) => { if (el) el.style.display = ''; };

/**
 * Oculta elemento
 * @param {HTMLElement} el
 */
export const hide = (el) => { if (el) el.style.display = 'none'; };

/**
 * Limpa conteúdo de elemento
 * @param {HTMLElement} el
 */
export const clear = (el) => { if (el) el.innerHTML = ''; };

/**
 * Exibe mensagem de feedback
 * @param {string} msg
 * @param {'success'|'error'} [type='success']
 */
export const toast = (msg, type = 'success') => {
  const feedback = byId('feedback_msg');
  if (!feedback) return;
  feedback.textContent = msg;
  feedback.className = `feedback${type === 'error' ? ' error' : ''}`;
  show(feedback);
  setTimeout(() => hide(feedback), 4000);
}; 