import { coletarInstancias, gerarArtigos } from '../generate.js';

jest.mock('../api_key.js', () => ({
  getApiKey: () => '1234567890abcdef',
  getModelType: () => 'gpt',
  validateApiKey: () => true,
}));
jest.mock('../state.js', () => ({
  getState: () => ({ blogs: [{ nome: 'Blog', prompts: [{ text: 'p1' }] }], selectedBlogIdx: 0 }),
}));
jest.mock('../feedback.js', () => ({
  showLoader: jest.fn(),
  hideLoader: jest.fn(),
  showToast: jest.fn(),
}));

global.fetch = jest.fn(() => Promise.resolve({ ok: true, text: () => Promise.resolve('<html>ok</html>') }));
global.document.open = jest.fn();
global.document.write = jest.fn();
global.document.close = jest.fn();

describe('generate.js', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('coleta instâncias corretamente', async () => {
    const inst = await coletarInstancias(false);
    expect(inst[0].nome).toBe('Blog');
    expect(inst[0].prompts).toEqual(['p1']);
  });

  it('gera artigos com sucesso', async () => {
    await gerarArtigos(false);
    expect(global.fetch).toHaveBeenCalled();
    expect(global.document.open).toHaveBeenCalled();
    expect(global.document.write).toHaveBeenCalled();
    expect(global.document.close).toHaveBeenCalled();
  });

  it('gera artigos em lote', async () => {
    await gerarArtigos(true);
    expect(global.fetch).toHaveBeenCalled();
  });

  it('trata erro HTTP', async () => {
    global.fetch.mockImplementationOnce(() => Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve('erro') }));
    await gerarArtigos(false);
    expect(require('../feedback.js').showToast).toHaveBeenCalled();
  });

  it('trata erro de rede', async () => {
    global.fetch.mockImplementationOnce(() => Promise.reject(new Error('Falha de rede')));
    await gerarArtigos(false);
    expect(require('../feedback.js').showToast).toHaveBeenCalled();
  });

  it('executa callback de sucesso', async () => {
    const cb = jest.fn();
    await gerarArtigos(false, cb);
    expect(cb).toHaveBeenCalledWith(true, 200, expect.any(String));
  });

  it('executa callback de erro', async () => {
    global.fetch.mockImplementationOnce(() => Promise.resolve({ ok: false, status: 500, text: () => Promise.resolve('erro') }));
    const cb = jest.fn();
    await gerarArtigos(false, cb);
    expect(cb).toHaveBeenCalledWith(false, 500, 'erro');
  });

  it('trata ausência de blogs/prompts', async () => {
    jest.doMock('../state.js', () => ({ getState: () => ({ blogs: [], selectedBlogIdx: 0 }) }));
    const { coletarInstancias } = await import('../generate.js');
    const inst = await coletarInstancias(false);
    expect(inst[0]).toBeDefined();
  });
}); 