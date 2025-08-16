import { getApiKey, setApiKey, clearApiKey, getModelType, setModelType, clearModelType, validateApiKey } from '../api_key.js';

describe('api_key.js', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <input id="api_key" />
      <select id="model_type"><option value="gpt">gpt</option></select>
    `;
  });

  it('define, obtém e limpa chave API', () => {
    setApiKey('1234567890abcdef');
    expect(getApiKey()).toBe('1234567890abcdef');
    clearApiKey();
    expect(getApiKey()).toBe('');
  });

  it('define, obtém e limpa modelo', () => {
    setModelType('gpt');
    expect(getModelType()).toBe('gpt');
    clearModelType();
    expect(getModelType()).toBe('');
  });

  it('valida formato da chave API', () => {
    expect(validateApiKey('1234567890abcdef')).toBe(true);
    expect(validateApiKey('a'.repeat(16))).toBe(true);
    expect(validateApiKey('a'.repeat(64))).toBe(true);
    expect(validateApiKey('chave-invalida!')).toBe(false);
    expect(validateApiKey('')).toBe(false);
    expect(validateApiKey('a'.repeat(15))).toBe(false);
    expect(validateApiKey('a'.repeat(65))).toBe(false);
  });

  it('get/set/clear não lança erro sem elementos no DOM', () => {
    document.body.innerHTML = '';
    expect(() => setApiKey('abc')).not.toThrow();
    expect(getApiKey()).toBe('');
    expect(() => clearApiKey()).not.toThrow();
    expect(() => setModelType('gpt')).not.toThrow();
    expect(getModelType()).toBe('');
    expect(() => clearModelType()).not.toThrow();
  });
}); 