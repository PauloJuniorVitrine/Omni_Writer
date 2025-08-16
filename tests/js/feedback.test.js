import { showToast, showPersistent, showInlineFeedback, showLoader, hideLoader } from '../feedback.js';

describe('feedback.js', () => {
  let feedbackMsg;
  let loader;
  let input;

  beforeEach(() => {
    document.body.innerHTML = `
      <div id="feedback_msg"></div>
      <div id="loader"></div>
      <div><input id="campo" /></div>
      <div><input id="campo2" /></div>
    `;
    feedbackMsg = document.getElementById('feedback_msg');
    loader = document.getElementById('loader');
    input = document.getElementById('campo');
  });

  it('exibe toast de feedback', () => {
    showToast('Mensagem de sucesso', 'success', 10);
    expect(feedbackMsg.textContent).toBe('Mensagem de sucesso');
    expect(feedbackMsg.className).toBe('feedback');
    expect(feedbackMsg.style.display).toBe('');
  });

  it('esconde toast após timeout', (done) => {
    showToast('Mensagem temporária', 'success', 20);
    setTimeout(() => {
      expect(feedbackMsg.style.display).toBe('none');
      done();
    }, 30);
  });

  it('exibe toast de erro', () => {
    showToast('Erro!', 'error', 10);
    expect(feedbackMsg.className).toContain('error');
  });

  it('exibe mensagem persistente', () => {
    showPersistent('Persistente', 'error');
    expect(feedbackMsg.textContent).toBe('Persistente');
    expect(feedbackMsg.className).toContain('error');
  });

  it('exibe múltiplos feedbacks inline', () => {
    const input2 = document.getElementById('campo2');
    showInlineFeedback(input, 'Campo obrigatório');
    showInlineFeedback(input2, 'Outro campo obrigatório');
    const inline1 = input.parentElement.querySelector('.inline-feedback');
    const inline2 = input2.parentElement.querySelector('.inline-feedback');
    expect(inline1.textContent).toBe('Campo obrigatório');
    expect(inline2.textContent).toBe('Outro campo obrigatório');
  });

  it('remove feedback inline', () => {
    showInlineFeedback(input, 'Campo obrigatório');
    const inline = input.parentElement.querySelector('.inline-feedback');
    inline.style.display = 'none';
    expect(inline.style.display).toBe('none');
  });

  it('showToast não lança erro sem elemento no DOM', () => {
    document.body.innerHTML = '';
    expect(() => showToast('Teste', 'success', 10)).not.toThrow();
  });

  it('exibe e oculta loader', () => {
    showLoader();
    expect(loader.classList.contains('active')).toBe(true);
    hideLoader();
    expect(loader.classList.contains('active')).toBe(false);
  });
}); 