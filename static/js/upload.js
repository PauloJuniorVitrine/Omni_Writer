/**
 * Upload e parsing de arquivos .txt para prompts
 * @module upload
 */
import { byId } from './utils.js';
import { apiAddPrompt } from './api.js';
import { showToast } from './feedback.js';

const MAX_FILE_SIZE = 1024 * 1024; // 1MB

/**
 * Lê arquivo .txt e retorna linhas não vazias
 * @param {File} file
 * @returns {Promise<string[]>}
 */
export const parsePromptsFromFile = (file) => new Promise((resolve, reject) => {
  if (file.type !== 'text/plain') return reject(new Error('Tipo de arquivo inválido.'));
  if (file.size > MAX_FILE_SIZE) return reject(new Error('Arquivo muito grande.'));
  const reader = new FileReader();
  reader.onload = (ev) => {
    const lines = ev.target.result.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (!lines.length) return reject(new Error('Arquivo vazio.'));
    resolve(lines);
  };
  reader.onerror = (ev) => {
    reject(ev?.target?.error || new Error('Falha de leitura'));
  };
  reader.readAsText(file, 'utf-8');
});

/**
 * Handler para input de arquivo (múltiplos arquivos)
 * @param {Event} e
 * @param {string|number} blogId
 */
export const handleFileUpload = async (e, blogId) => {
  const files = e.target.files;
  if (!files || !files.length) return;
  for (const file of files) {
    try {
      const lines = await parsePromptsFromFile(file);
      for (const line of lines) await apiAddPrompt(blogId, line);
      showToast(`Prompts de ${file.name} carregados!`);
    } catch (err) {
      showToast(`Erro em ${file.name}: ${err.message}`, 'error');
    }
  }
}; 