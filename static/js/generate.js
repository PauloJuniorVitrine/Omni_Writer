/**
 * Geração de artigos
 * @module generate
 */
import { getApiKey, getModelType, validateApiKey } from './api_key.js';
import { getState } from './state.js';
import { showLoader, hideLoader, showToast } from './feedback.js';

/**
 * Coleta dados para geração
 * @param {boolean} lote
 * @returns {Promise<Object[]>}
 */
export const coletarInstancias = async (lote = false) => {
  const { blogs, selectedBlogIdx } = getState();
  if (lote) {
    return blogs.map((b) => ({
      nome: b.nome,
      modelo: getModelType(),
      api_key: getApiKey(),
      prompts: b.prompts ? b.prompts.map((p) => p.text) : [],
    }));
  }
  const blog = blogs[selectedBlogIdx];
  return [{
    nome: blog.nome,
    modelo: getModelType(),
    api_key: getApiKey(),
    prompts: blog.prompts ? blog.prompts.map((p) => p.text) : [],
  }];
};

/**
 * Envia requisição de geração de artigos
 * @param {boolean} lote
 * @param {Function} [callback]
 */
export const gerarArtigos = async (lote = false, callback) => {
  const apiKey = getApiKey();
  if (!validateApiKey(apiKey)) return showToast('Chave API obrigatória', 'error');
  showLoader();
  try {
    const instancias = await coletarInstancias(lote);
    const form = new FormData();
    form.append('instancias_json', JSON.stringify(instancias));
    form.append('prompts', instancias[0].prompts.join('\n'));
    form.append('api_key', apiKey);
    form.append('model_type', getModelType());
    const resp = await fetch('/generate', { method: 'POST', body: form });
    if (!resp.ok) {
      const errText = await resp.text();
      console.error('Erro HTTP:', resp.status, errText);
      showToast(`Erro ao gerar artigos: ${resp.status}`, 'error');
      if (callback) callback(false, resp.status, errText);
      return;
    }
    const html = await resp.text();
    document.open(); document.write(html); document.close();
    if (callback) callback(true, 200, html);
  } catch (e) {
    console.error('Erro na geração:', e);
    showToast('Erro ao gerar artigos', 'error');
    if (callback) callback(false, 0, e.message);
  } finally {
    hideLoader();
  }
}; 