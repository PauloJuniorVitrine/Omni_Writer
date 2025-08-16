/**
 * Funções de integração RESTful para blogs e prompts
 * @module api
 */

/**
 * Lista todos os blogs
 * @returns {Promise<Object[]>}
 */
export const apiListBlogs = async () => {
  const resp = await fetch('/api/blogs');
  return resp.json();
};

/**
 * Cria um novo blog
 * @param {string} nome
 * @param {string} desc
 * @returns {Promise<Object>}
 */
export const apiCreateBlog = async (nome, desc) => {
  const resp = await fetch('/api/blogs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nome, desc })
  });
  if (!resp.ok) throw new Error((await resp.json()).error || 'Erro ao criar blog');
  return resp.json();
};

/**
 * Exclui um blog
 * @param {string|number} id
 * @returns {Promise<void>}
 */
export const apiDeleteBlog = async (id) => {
  const resp = await fetch(`/api/blogs/${id}`, { method: 'DELETE' });
  if (!resp.ok && resp.status !== 404) throw new Error('Erro ao excluir blog');
};

/**
 * Lista prompts de um blog
 * @param {string|number} blogId
 * @returns {Promise<Object[]>}
 */
export const apiListPrompts = async (blogId) => {
  const resp = await fetch(`/api/blogs/${blogId}/prompts`);
  return resp.json();
};

/**
 * Adiciona prompt a um blog
 * @param {string|number} blogId
 * @param {string} text
 * @returns {Promise<Object>}
 */
export const apiAddPrompt = async (blogId, text) => {
  const resp = await fetch(`/api/blogs/${blogId}/prompts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
  if (!resp.ok) throw new Error((await resp.json()).error || 'Erro ao adicionar prompt');
  return resp.json();
};

/**
 * Exclui prompt de um blog
 * @param {string|number} blogId
 * @param {string|number} promptId
 * @returns {Promise<void>}
 */
export const apiDeletePrompt = async (blogId, promptId) => {
  const resp = await fetch(`/api/blogs/${blogId}/prompts/${promptId}`, { method: 'DELETE' });
  if (!resp.ok && resp.status !== 404) throw new Error('Erro ao excluir prompt');
}; 