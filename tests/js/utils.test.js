import * as utils from '../utils.js';

describe('utils.js', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div id="el1"></div>
      <div id="el2" style="display:none"></div>
      <div id="feedback_msg"></div>
      <ul class="list"><li>A</li><li>B</li></ul>
    `;
  });

  it('byId retorna elemento por id', () => {
    expect(utils.byId('el1')).not.toBeNull();
    expect(utils.byId('nao_existe')).toBeNull();
  });

  it('qs retorna primeiro elemento por seletor', () => {
    expect(utils.qs('.list')).not.toBeNull();
    expect(utils.qs('.nao_existe')).toBeNull();
  });

  it('qsa retorna todos elementos por seletor', () => {
    expect(utils.qsa('li')).toHaveLength(2);
    expect(utils.qsa('.nao_existe')).toHaveLength(0);
  });

  it('show exibe elemento', () => {
    const el = utils.byId('el2');
    utils.show(el);
    expect(el.style.display).toBe('');
  });

  it('hide oculta elemento', () => {
    const el = utils.byId('el1');
    utils.hide(el);
    expect(el.style.display).toBe('none');
  });

  it('clear limpa conteúdo do elemento', () => {
    const el = utils.byId('el1');
    el.innerHTML = 'abc';
    utils.clear(el);
    expect(el.innerHTML).toBe('');
  });

  it('toast exibe mensagem de sucesso', () => {
    const el = utils.byId('feedback_msg');
    jest.useFakeTimers();
    utils.toast('ok');
    expect(el.textContent).toBe('ok');
    expect(el.className).toBe('feedback');
    jest.runAllTimers();
    expect(el.style.display).toBe('none');
    jest.useRealTimers();
  });

  it('toast exibe mensagem de erro', () => {
    const el = utils.byId('feedback_msg');
    jest.useFakeTimers();
    utils.toast('erro', 'error');
    expect(el.textContent).toBe('erro');
    expect(el.className).toBe('feedback error');
    jest.runAllTimers();
    expect(el.style.display).toBe('none');
    jest.useRealTimers();
  });

  it('toast não lança erro se feedback_msg não existe', () => {
    document.body.innerHTML = '';
    expect(() => utils.toast('msg')).not.toThrow();
  });
}); 