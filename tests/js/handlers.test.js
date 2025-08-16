import * as handlers from '../handlers.js';
import * as api from '../api.js';
import * as render from '../render.js';
import * as utils from '../utils.js';
import { renderAll } from '../handlers.js';

describe('handlers.js', () => {
  let origLocalStorage;
  let origDocument;
  beforeEach(() => {
    // Mock DOM
    document.body.innerHTML = `
      <button id="add_blog_btn"></button>
      <button id="theme_toggle"></button>
      <ul id="blog_list"></ul>
      <ul id="prompt_list"></ul>
      <span id="prompt_count"></span>
      <div id="feedback_msg"></div>
    `;
    origLocalStorage = global.localStorage;
    global.localStorage = {
      store: {},
      getItem: function (k) { return this.store[k]; },
      setItem: function (k, v) { this.store[k] = v; },
      clear: function () { this.store = {}; },
      removeItem: function (k) { delete this.store[k]; },
    };
    origDocument = global.document;
  });
  afterEach(() => {
    global.localStorage = origLocalStorage;
    global.document = origDocument;
    jest.clearAllMocks();
  });

  it('inicializa app com tema salvo e renderiza blogs', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockResolvedValue([]);
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    await handlers.initApp();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(render.renderBlogs).toHaveBeenCalled();
  });

  it('alterna tema ao clicar em theme_toggle', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockResolvedValue([]);
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    await handlers.initApp();
    document.getElementById('theme_toggle').click();
    expect(['light', 'dark']).toContain(document.documentElement.getAttribute('data-theme'));
  });

  it('cria blog ao clicar em add_blog_btn', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockResolvedValue([]);
    jest.spyOn(api, 'apiCreateBlog').mockResolvedValue({});
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    global.prompt = jest.fn()
      .mockReturnValueOnce('Blog Teste')
      .mockReturnValueOnce('Descrição');
    await handlers.initApp();
    document.getElementById('add_blog_btn').click();
    expect(api.apiCreateBlog).toHaveBeenCalledWith('Blog Teste', 'Descrição');
  });

  it('não cria blog se prompt for vazio', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockResolvedValue([]);
    jest.spyOn(api, 'apiCreateBlog').mockResolvedValue({});
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    global.prompt = jest.fn().mockReturnValueOnce('');
    await handlers.initApp();
    document.getElementById('add_blog_btn').click();
    expect(api.apiCreateBlog).not.toHaveBeenCalled();
  });

  it('trata erro ao criar blog', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockResolvedValue([]);
    jest.spyOn(api, 'apiCreateBlog').mockRejectedValue(new Error('Falha'));
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    global.prompt = jest.fn()
      .mockReturnValueOnce('Blog Teste')
      .mockReturnValueOnce('Descrição');
    await handlers.initApp();
    document.getElementById('add_blog_btn').click();
    await Promise.resolve();
    expect(utils.toast).toHaveBeenCalledWith('Falha', 'error');
  });

  it('trata erro crítico na inicialização', async () => {
    jest.spyOn(utils, 'byId').mockImplementation((id) => document.getElementById(id));
    jest.spyOn(api, 'apiListBlogs').mockRejectedValue(new Error('Falha crítica'));
    jest.spyOn(render, 'renderBlogs').mockImplementation(() => {});
    jest.spyOn(render, 'renderPrompts').mockImplementation(() => {});
    jest.spyOn(render, 'updatePromptCount').mockImplementation(() => {});
    jest.spyOn(utils, 'toast').mockImplementation(() => {});
    await handlers.initApp();
    expect(utils.toast).toHaveBeenCalledWith('Erro crítico na inicialização: Falha crítica', 'error');
  });
});

describe('renderAll (handlers.js) - refatorado', () => {
  it('deleta blog com sucesso', async () => {
    let blogs = [{ id: 1, nome: 'Blog1' }];
    let deleteCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve(blogs));
    const apiDeleteBlog = jest.fn((id) => { blogs = []; return Promise.resolve(); });
    const renderBlogs = jest.fn((b, idx, onSelect, onDelete) => {
      if (!deleteCalled) { deleteCalled = true; onDelete(1); }
    });
    const apiListPrompts = jest.fn(() => Promise.resolve([]));
    const renderPrompts = jest.fn();
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiDeleteBlog, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, toast, prompt: () => null });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(apiDeleteBlog).toHaveBeenCalledWith(1);
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["Blog excluído!"]]))
  });

  it('deleta blog com erro', async () => {
    let blogs = [{ id: 1, nome: 'Blog1' }];
    let deleteCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve(blogs));
    const apiDeleteBlog = jest.fn(() => Promise.reject(new Error('erro')));
    const renderBlogs = jest.fn((b, idx, onSelect, onDelete) => {
      if (!deleteCalled) { deleteCalled = true; onDelete(1); }
    });
    const apiListPrompts = jest.fn(() => Promise.resolve([]));
    const renderPrompts = jest.fn();
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiDeleteBlog, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, toast, prompt: () => null });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["erro", "error"]]))
  });

  it('edita prompt com sucesso', async () => {
    let prompts = [{ id: 1, text: 'Prompt1' }];
    let editCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve([{ id: 1, nome: 'Blog1' }]));
    const apiListPrompts = jest.fn(() => Promise.resolve(prompts));
    const renderBlogs = jest.fn();
    const apiDeletePrompt = jest.fn((blogId, promptId) => { prompts = prompts.filter((pr) => pr.id !== promptId); return Promise.resolve(); });
    const apiAddPrompt = jest.fn((blogId, text) => { prompts.push({ id: 2, text }); return Promise.resolve(); });
    const renderPrompts = jest.fn((p, onEdit) => {
      if (!editCalled) { editCalled = true; onEdit(prompts[0]); }
    });
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, apiDeletePrompt, apiAddPrompt, toast, prompt: () => 'Novo texto' });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(apiDeletePrompt).toHaveBeenCalledWith(1, 1);
    expect(apiAddPrompt).toHaveBeenCalledWith(1, 'Novo texto');
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["Prompt editado!"]]))
  });

  it('edita prompt com erro', async () => {
    let editCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve([{ id: 1, nome: 'Blog1' }]));
    const apiListPrompts = jest.fn(() => Promise.resolve([{ id: 1, text: 'Prompt1' }]));
    const renderBlogs = jest.fn();
    const apiDeletePrompt = jest.fn(() => Promise.reject(new Error('erro')));
    const apiAddPrompt = jest.fn();
    const renderPrompts = jest.fn((p, onEdit) => {
      if (!editCalled) { editCalled = true; onEdit({ id: 1, text: 'Prompt1' }); }
    });
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, apiDeletePrompt, apiAddPrompt, toast, prompt: () => 'Novo texto' });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["erro", "error"]]))
  });

  it('deleta prompt com sucesso', async () => {
    let prompts = [{ id: 1, text: 'Prompt1' }];
    let deleteCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve([{ id: 1, nome: 'Blog1' }]));
    const apiListPrompts = jest.fn(() => Promise.resolve(prompts));
    const renderBlogs = jest.fn();
    const apiDeletePrompt = jest.fn((blogId, promptId) => { prompts = prompts.filter((pr) => pr.id !== promptId); return Promise.resolve(); });
    const renderPrompts = jest.fn((p, onEdit, onDelete) => {
      if (!deleteCalled) { deleteCalled = true; onDelete(1); }
    });
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, apiDeletePrompt, toast, prompt: () => null });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(apiDeletePrompt).toHaveBeenCalledWith(1, 1);
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["Prompt excluído!"]]))
  });

  it('deleta prompt com erro', async () => {
    let deleteCalled = false;
    const apiListBlogs = jest.fn(() => Promise.resolve([{ id: 1, nome: 'Blog1' }]));
    const apiListPrompts = jest.fn(() => Promise.resolve([{ id: 1, text: 'Prompt1' }]));
    const renderBlogs = jest.fn();
    const apiDeletePrompt = jest.fn(() => Promise.reject(new Error('erro')));
    const renderPrompts = jest.fn((p, onEdit, onDelete) => {
      if (!deleteCalled) { deleteCalled = true; onDelete(1); }
    });
    const updatePromptCount = jest.fn();
    const toast = jest.fn();
    await renderAll({ apiListBlogs, apiListPrompts, renderBlogs, renderPrompts, updatePromptCount, apiDeletePrompt, toast, prompt: () => null });
    await Promise.resolve();
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(toast.mock.calls).toEqual(expect.arrayContaining([["erro", "error"]]))
  });

  it('renderiza sem blogs', async () => {
    const apiListBlogs = jest.fn(() => Promise.resolve([]));
    const renderBlogs = jest.fn();
    const renderPrompts = jest.fn();
    const updatePromptCount = jest.fn();
    await renderAll({ apiListBlogs, renderBlogs, renderPrompts, updatePromptCount, apiListPrompts: jest.fn(), apiDeleteBlog: jest.fn(), apiDeletePrompt: jest.fn(), apiAddPrompt: jest.fn(), toast: jest.fn(), prompt: () => null });
    expect(renderPrompts).toHaveBeenCalledWith([], expect.any(Function), expect.any(Function));
    expect(updatePromptCount).toHaveBeenCalledWith(0);
  });
}); 