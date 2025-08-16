/**
 * Gerenciamento de estado global do frontend
 * @module state
 *
 * Formato do objeto state:
 * {
 *   blogs: Array<Object>,
 *   prompts: Array<Object>,
 *   selectedBlogIdx: number
 * }
 */

let state = {
  blogs: [],
  prompts: [],
  selectedBlogIdx: 0,
};

const listeners = [];

/**
 * Obtém o estado atual
 * @returns {Object}
 */
export const getState = () => ({ ...state });

/**
 * Atualiza o estado e notifica listeners
 * @param {Object} newState
 */
export const setState = (newState) => {
  state = { ...state, ...newState };
  listeners.forEach((fn) => fn(getState()));
};

/**
 * Adiciona listener para mudanças de estado
 * @param {Function} fn
 */
export const subscribe = (fn) => {
  listeners.push(fn);
};

/**
 * Remove listener
 * @param {Function} fn
 */
export const unsubscribe = (fn) => {
  const idx = listeners.indexOf(fn);
  if (idx !== -1) listeners.splice(idx, 1);
};

/**
 * Reseta o estado para o padrão inicial
 */
export const resetState = () => {
  state = { blogs: [], prompts: [], selectedBlogIdx: 0 };
  listeners.forEach((fn) => fn(getState()));
}; 