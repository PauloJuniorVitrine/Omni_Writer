import * as render from '../render.js';

describe('render.js', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <ul id="blog_list"></ul>
      <ul id="prompt_list"></ul>
      <span id="prompt_count"></span>
    `;
  });

  it('renderBlogs renderiza lista de blogs e ativa callback de seleção', () => {
    const blogs = [
      { id: 1, nome: 'Blog1' },
      { id: 2, nome: 'Blog2' },
    ];
    const onSelect = jest.fn();
    const onDelete = jest.fn();
    render.renderBlogs(blogs, 1, onSelect, onDelete);
    const items = document.querySelectorAll('#blog_list li');
    expect(items).toHaveLength(2);
    expect(items[1].className).toBe('active');
    items[0].click();
    expect(onSelect).toHaveBeenCalledWith(0);
    // Testa delete
    const trash = items[0].querySelector('.fa-trash');
    trash.onclick({ stopPropagation: jest.fn() });
    expect(onDelete).toHaveBeenCalledWith(1);
  });

  it('renderBlogs não lança erro se ul não existe', () => {
    document.body.innerHTML = '';
    expect(() => render.renderBlogs([], 0, jest.fn(), jest.fn())).not.toThrow();
  });

  it('renderPrompts renderiza lista de prompts e ativa callbacks', () => {
    const prompts = [
      { id: 1, text: 'Prompt1' },
      { id: 2, text: 'Prompt2' },
    ];
    const onEdit = jest.fn();
    const onDelete = jest.fn();
    render.renderPrompts(prompts, onEdit, onDelete);
    const items = document.querySelectorAll('#prompt_list li');
    expect(items).toHaveLength(2);
    items[0].querySelector('.fa-pen').onclick();
    expect(onEdit).toHaveBeenCalledWith(prompts[0]);
    items[1].querySelector('.fa-trash').onclick();
    expect(onDelete).toHaveBeenCalledWith(2);
  });

  it('renderPrompts não lança erro se ul não existe', () => {
    document.body.innerHTML = '';
    expect(() => render.renderPrompts([], jest.fn(), jest.fn())).not.toThrow();
  });

  it('updatePromptCount atualiza contador corretamente', () => {
    const el = document.getElementById('prompt_count');
    render.updatePromptCount(1);
    expect(el.textContent).toBe('1 prompt');
    render.updatePromptCount(2);
    expect(el.textContent).toBe('2 prompts');
    render.updatePromptCount(0);
    expect(el.textContent).toBe('');
  });

  it('updatePromptCount não lança erro se elemento não existe', () => {
    document.body.innerHTML = '';
    expect(() => render.updatePromptCount(3)).not.toThrow();
  });
}); 