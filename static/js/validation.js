/**
 * Validação e sanitização de entradas do usuário
 * @module validation
 */

const BLOG_NAME_MAX = 60;
const PROMPT_MAX = 500;
const BLOG_NAME_REGEX = /^[\w\s\-áéíóúãõâêîôûçÁÉÍÓÚÃÕÂÊÎÔÛÇ]+$/i;

/**
 * Valida nome de blog/nicho
 * @param {string} nome
 * @returns {boolean}
 */
export const validateBlogName = (nome) =>
  typeof nome === 'string' && nome.trim().length > 0 && nome.length <= BLOG_NAME_MAX && BLOG_NAME_REGEX.test(nome);

/**
 * Valida texto de prompt
 * @param {string} text
 * @returns {boolean}
 */
export const validatePromptText = (text) =>
  typeof text === 'string' && text.trim().length > 0 && text.length <= PROMPT_MAX;

/**
 * Sanitiza string para evitar XSS
 * @param {string} str
 * @returns {string}
 */
export const sanitize = (str) =>
  str.replace(/[&<>"'/]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;' }[c])); 