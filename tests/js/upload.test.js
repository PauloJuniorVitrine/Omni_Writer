import { parsePromptsFromFile, handleFileUpload } from '../upload.js';
import { apiAddPrompt } from '../api.js';

global.FileReader = class {
  constructor() { this.onload = null; this.onerror = null; }
  readAsText(file) {
    if (file.error) this.onerror({ target: { error: file.error } });
    else this.onload({ target: { result: file.content } });
  }
};

function mockInputWithFiles(files) {
  return { target: { files } };
}

describe('upload.js', () => {
  it('lê prompts de arquivo .txt válido', async () => {
    const file = { type: 'text/plain', size: 10, content: 'a\nb\nc' };
    const lines = await parsePromptsFromFile(file);
    expect(lines).toEqual(['a', 'b', 'c']);
  });

  it('lê prompts ignorando linhas em branco', async () => {
    const file = { type: 'text/plain', size: 10, content: 'a\n\n  \nb' };
    const lines = await parsePromptsFromFile(file);
    expect(lines).toEqual(['a', 'b']);
  });

  it('rejeita arquivo de tipo inválido', async () => {
    const file = { type: 'image/png', size: 10, content: '' };
    await expect(parsePromptsFromFile(file)).rejects.toThrow('Tipo de arquivo inválido.');
  });

  it('rejeita arquivo muito grande', async () => {
    const file = { type: 'text/plain', size: 2 * 1024 * 1024, content: '' };
    await expect(parsePromptsFromFile(file)).rejects.toThrow('Arquivo muito grande.');
  });

  it('rejeita arquivo vazio', async () => {
    const file = { type: 'text/plain', size: 10, content: '' };
    await expect(parsePromptsFromFile(file)).rejects.toThrow('Arquivo vazio.');
  });

  it('handleFileUpload chama apiAddPrompt para cada linha de múltiplos arquivos', async () => {
    const file1 = { type: 'text/plain', size: 10, content: 'a\nb' };
    const file2 = { type: 'text/plain', size: 10, content: 'c' };
    apiAddPrompt.mockClear();
    await handleFileUpload(mockInputWithFiles([file1, file2]), 1);
    expect(apiAddPrompt).toHaveBeenCalledWith(1, 'a');
    expect(apiAddPrompt).toHaveBeenCalledWith(1, 'b');
    expect(apiAddPrompt).toHaveBeenCalledWith(1, 'c');
  });

  it('handleFileUpload não lança erro com input vazio', async () => {
    await expect(handleFileUpload(mockInputWithFiles([]), 1)).resolves.toBeUndefined();
  });

  it('parsePromptsFromFile trata erro de leitura', async () => {
    const file = { type: 'text/plain', size: 10, content: '', error: new Error('Falha de leitura') };
    await expect(parsePromptsFromFile(file)).rejects.toThrow('Falha de leitura');
  });
});

jest.mock('../api.js', () => ({
  apiAddPrompt: jest.fn(() => Promise.resolve()),
})); 