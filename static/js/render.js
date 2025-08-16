/**
 * Funções de renderização de blogs e prompts
 * @module render
 */
import { byId, clear, toast } from './utils.js';
import { apiListBlogs, apiDeleteBlog, apiListPrompts, apiDeletePrompt, apiAddPrompt } from './api.js';

/**
 * Renderiza lista de blogs
 * @param {Object[]} blogs
 * @param {number} selectedBlogIdx
 * @param {Function} onSelect
 * @param {Function} onDelete
 */
export const renderBlogs = (blogs, selectedBlogIdx, onSelect, onDelete) => {
  const ul = byId('blog_list');
  if (!ul) return;
  clear(ul);
  blogs.forEach((blog, idx) => {
    const li = document.createElement('li');
    li.tabIndex = 0;
    li.className = idx === selectedBlogIdx ? 'active' : '';
    li.innerHTML = `<i class="fa fa-book"></i> <span>${blog.nome}</span> <i class="fa fa-trash" title="Excluir"></i>`;
    li.onclick = () => onSelect(idx);
    li.onkeydown = (e) => { if (e.key === 'Enter') onSelect(idx); };
    li.querySelector('.fa-trash').onclick = (ev) => {
      ev.stopPropagation();
      onDelete(blog.id);
    };
    ul.appendChild(li);
  });
};

/**
 * Renderiza lista de prompts
 * @param {Object[]} prompts
 * @param {Function} onEdit
 * @param {Function} onDelete
 */
export const renderPrompts = (prompts, onEdit, onDelete) => {
  const ul = byId('prompt_list');
  if (!ul) return;
  clear(ul);
  prompts.forEach((p) => {
    const li = document.createElement('li');
    li.innerHTML = `<i class="fa fa-file-alt"></i> <span>${p.text}</span> <i class="fa fa-pen" title="Editar"></i> <i class="fa fa-trash" title="Excluir"></i>`;
    li.querySelector('.fa-trash').onclick = () => onDelete(p.id);
    li.querySelector('.fa-pen').onclick = () => onEdit(p);
    ul.appendChild(li);
  });
};

/**
 * Atualiza contador de prompts
 * @param {number} count
 */
export const updatePromptCount = (count) => {
  const el = byId('prompt_count');
  if (!el) return;
  el.textContent = count ? `${count} prompt${count > 1 ? 's' : ''}` : '';
}; 