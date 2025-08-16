import { applyTheme, toggleTheme, initTheme, onThemeChange } from '../theme.js';

describe('theme.js', () => {
  beforeEach(() => {
    document.documentElement.setAttribute('data-theme', 'light');
    localStorage.clear();
  });

  it('aplica tema corretamente', () => {
    applyTheme('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('theme')).toBe('dark');
  });

  it('aplica tema customizado', () => {
    applyTheme('custom');
    expect(document.documentElement.getAttribute('data-theme')).toBe('custom');
    expect(localStorage.getItem('theme')).toBe('custom');
  });

  it('alterna entre dark e light', () => {
    applyTheme('light');
    toggleTheme();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    toggleTheme();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('inicializa tema salvo', () => {
    localStorage.setItem('theme', 'dark');
    initTheme();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('persiste tema após reload', () => {
    applyTheme('dark');
    // Simula reload
    document.documentElement.setAttribute('data-theme', 'light');
    initTheme();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('notifica múltiplos listeners ao mudar tema', () => {
    const fn1 = jest.fn();
    const fn2 = jest.fn();
    onThemeChange(fn1);
    onThemeChange(fn2);
    applyTheme('custom');
    expect(fn1).toHaveBeenCalledWith('custom');
    expect(fn2).toHaveBeenCalledWith('custom');
  });
}); 