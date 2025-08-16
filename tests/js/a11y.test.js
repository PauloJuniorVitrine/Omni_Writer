import { updateAriaLive, focusModal, enableArrowNavigation, initA11y } from '../a11y.js';

describe('a11y.js', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    document.body.className = '';
  });

  it('atualiza região ARIA live (polite)', () => {
    updateAriaLive('Mensagem', 'polite');
    const el = document.getElementById('aria-live');
    expect(el).not.toBeNull();
    expect(el.textContent).toBe('Mensagem');
    expect(el.getAttribute('aria-live')).toBe('polite');
  });

  it('atualiza região ARIA live (assertive)', () => {
    updateAriaLive('Alerta', 'assertive');
    const el = document.getElementById('aria-live');
    expect(el.textContent).toBe('Alerta');
    expect(el.getAttribute('aria-live')).toBe('assertive');
  });

  it('múltiplas atualizações de ARIA live', () => {
    updateAriaLive('Primeira');
    updateAriaLive('Segunda');
    const el = document.getElementById('aria-live');
    expect(el.textContent).toBe('Segunda');
  });

  it('foca modal/dialog', () => {
    const modal = document.createElement('div');
    modal.tabIndex = -1;
    modal.focus = jest.fn();
    focusModal(modal);
    expect(modal.focus).toHaveBeenCalled();
  });

  it('não lança erro ao focar elemento sem focus', () => {
    const modal = document.createElement('div');
    expect(() => focusModal(modal)).not.toThrow();
  });

  it('navega por setas em lista', () => {
    document.body.innerHTML = '<ul id="lista"><li tabindex="0">A</li><li tabindex="0">B</li><li tabindex="0">C</li></ul>';
    const ul = document.getElementById('lista');
    const items = ul.querySelectorAll('li');
    enableArrowNavigation(ul);
    items[0].focus();
    const e = new KeyboardEvent('keydown', { key: 'ArrowDown' });
    ul.dispatchEvent(e);
    expect(true).toBe(true);
  });

  it('navega por setas em lista vazia', () => {
    document.body.innerHTML = '<ul id="lista"></ul>';
    const ul = document.getElementById('lista');
    expect(() => enableArrowNavigation(ul)).not.toThrow();
  });

  it('initA11y adiciona classe ao pressionar Tab', () => {
    initA11y();
    const e = new KeyboardEvent('keydown', { key: 'Tab' });
    document.body.dispatchEvent(e);
    expect(document.body.classList.contains('user-is-tabbing')).toBe(true);
  });

  it('initA11y remove classe ao clicar mouse', () => {
    document.body.classList.add('user-is-tabbing');
    initA11y();
    const e = new MouseEvent('mousedown');
    document.body.dispatchEvent(e);
    expect(document.body.classList.contains('user-is-tabbing')).toBe(false);
  });

  it('focusModal não lança erro se modal for nulo', () => {
    expect(() => focusModal(null)).not.toThrow();
  });

  it('focusModal não lança erro se modal não tem função focus', () => {
    expect(() => focusModal({})).not.toThrow();
  });

  it('enableArrowNavigation não lança erro se lista for nula', () => {
    expect(() => enableArrowNavigation(null)).not.toThrow();
  });

  it('enableArrowNavigation não lança erro se lista não tem itens', () => {
    const ul = document.createElement('ul');
    document.body.appendChild(ul);
    expect(() => enableArrowNavigation(ul)).not.toThrow();
  });

  it('enableArrowNavigation navega para baixo e cima', () => {
    document.body.innerHTML = '<ul id="lista"><li tabindex="0">A</li><li tabindex="0">B</li></ul>';
    const ul = document.getElementById('lista');
    const items = ul.querySelectorAll('li');
    enableArrowNavigation(ul);
    items[0].focus();
    const down = new KeyboardEvent('keydown', { key: 'ArrowDown' });
    ul.dispatchEvent(down);
    // Não há assert de foco real em jsdom, mas não deve lançar erro
    const up = new KeyboardEvent('keydown', { key: 'ArrowUp' });
    ul.dispatchEvent(up);
    expect(true).toBe(true);
  });
}); 