/**
 * Feedbacks visuais e loaders
 * @module feedback
 */
import { byId, show, hide } from './utils.js';

/**
 * Exibe toast de feedback
 * @param {string} msg
 * @param {'success'|'error'} [type='success']
 * @param {number} [timeout=4000]
 */
export const showToast = (msg, type = 'success', timeout = 4000) => {
  const el = byId('feedback_msg');
  if (!el) return;
  el.textContent = msg;
  el.className = `feedback${type === 'error' ? ' error' : ''}`;
  show(el);
  if (timeout > 0) setTimeout(() => hide(el), timeout);
};

/**
 * Exibe mensagem persistente (não some automaticamente)
 * @param {string} msg
 * @param {'success'|'error'} [type='success']
 */
export const showPersistent = (msg, type = 'success') => {
  showToast(msg, type, 0);
};

/**
 * Exibe feedback inline abaixo de um campo
 * @param {HTMLElement} field
 * @param {string} msg
 * @param {'success'|'error'} [type='error']
 */
export const showInlineFeedback = (field, msg, type = 'error') => {
  if (!field) return;
  let el = field.parentElement.querySelector('.inline-feedback');
  if (!el) {
    el = document.createElement('div');
    el.className = 'inline-feedback';
    field.parentElement.appendChild(el);
  }
  el.textContent = msg;
  el.className = `inline-feedback${type === 'error' ? ' error' : ''}`;
  show(el);
};

/**
 * Exibe loader
 */
export const showLoader = () => {
  const el = byId('loader');
  if (el) el.classList.add('active');
};

/**
 * Oculta loader
 */
export const hideLoader = () => {
  const el = byId('loader');
  if (el) el.classList.remove('active');
}; 