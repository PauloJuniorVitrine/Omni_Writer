import * as api from '../api.js';

global.fetch = jest.fn();

describe('api.js', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('apiListBlogs retorna lista de blogs', async () => {
    fetch.mockResolvedValue({ json: () => Promise.resolve([{ id: 1 }]) });
    const blogs = await api.apiListBlogs();
    expect(blogs).toEqual([{ id: 1 }]);
    expect(fetch).toHaveBeenCalledWith('/api/blogs');
  });

  it('apiCreateBlog cria blog com sucesso', async () => {
    fetch.mockResolvedValue({ ok: true, json: () => Promise.resolve({ id: 1 }) });
    const blog = await api.apiCreateBlog('Blog', 'desc');
    expect(blog).toEqual({ id: 1 });
    expect(fetch).toHaveBeenCalledWith('/api/blogs', expect.objectContaining({ method: 'POST' }));
  });

  it('apiCreateBlog lança erro se resposta não for ok', async () => {
    fetch.mockResolvedValue({ ok: false, json: () => Promise.resolve({ error: 'erro' }) });
    await expect(api.apiCreateBlog('Blog', 'desc')).rejects.toThrow('erro');
  });

  it('apiCreateBlog lança erro padrão se resposta não for ok e sem error', async () => {
    fetch.mockResolvedValue({ ok: false, json: () => Promise.resolve({}) });
    await expect(api.apiCreateBlog('Blog', 'desc')).rejects.toThrow('Erro ao criar blog');
  });

  it('apiDeleteBlog deleta blog com sucesso', async () => {
    fetch.mockResolvedValue({ ok: true, status: 204 });
    await expect(api.apiDeleteBlog(1)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledWith('/api/blogs/1', expect.objectContaining({ method: 'DELETE' }));
  });

  it('apiDeleteBlog ignora erro 404', async () => {
    fetch.mockResolvedValue({ ok: false, status: 404 });
    await expect(api.apiDeleteBlog(1)).resolves.toBeUndefined();
  });

  it('apiDeleteBlog lança erro para outros status', async () => {
    fetch.mockResolvedValue({ ok: false, status: 500 });
    await expect(api.apiDeleteBlog(1)).rejects.toThrow('Erro ao excluir blog');
  });

  it('apiListPrompts retorna prompts', async () => {
    fetch.mockResolvedValue({ json: () => Promise.resolve([{ id: 1 }]) });
    const prompts = await api.apiListPrompts(1);
    expect(prompts).toEqual([{ id: 1 }]);
    expect(fetch).toHaveBeenCalledWith('/api/blogs/1/prompts');
  });

  it('apiAddPrompt adiciona prompt com sucesso', async () => {
    fetch.mockResolvedValue({ ok: true, json: () => Promise.resolve({ id: 1 }) });
    const prompt = await api.apiAddPrompt(1, 'texto');
    expect(prompt).toEqual({ id: 1 });
    expect(fetch).toHaveBeenCalledWith('/api/blogs/1/prompts', expect.objectContaining({ method: 'POST' }));
  });

  it('apiAddPrompt lança erro se resposta não for ok', async () => {
    fetch.mockResolvedValue({ ok: false, json: () => Promise.resolve({ error: 'erro' }) });
    await expect(api.apiAddPrompt(1, 'texto')).rejects.toThrow('erro');
  });

  it('apiAddPrompt lança erro padrão se resposta não for ok e sem error', async () => {
    fetch.mockResolvedValue({ ok: false, json: () => Promise.resolve({}) });
    await expect(api.apiAddPrompt(1, 'texto')).rejects.toThrow('Erro ao adicionar prompt');
  });

  it('apiDeletePrompt deleta prompt com sucesso', async () => {
    fetch.mockResolvedValue({ ok: true, status: 204 });
    await expect(api.apiDeletePrompt(1, 2)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledWith('/api/blogs/1/prompts/2', expect.objectContaining({ method: 'DELETE' }));
  });

  it('apiDeletePrompt ignora erro 404', async () => {
    fetch.mockResolvedValue({ ok: false, status: 404 });
    await expect(api.apiDeletePrompt(1, 2)).resolves.toBeUndefined();
  });

  it('apiDeletePrompt lança erro para outros status', async () => {
    fetch.mockResolvedValue({ ok: false, status: 500 });
    await expect(api.apiDeletePrompt(1, 2)).rejects.toThrow('Erro ao excluir prompt');
  });
}); 