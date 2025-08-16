import { validateBlogName, validatePromptText, sanitize } from '../validation.js';

describe('validation.js', () => {
  it('valida nome de blog corretamente', () => {
    expect(validateBlogName('Blog Válido')).toBe(true);
    expect(validateBlogName('')).toBe(false);
    expect(validateBlogName('a'.repeat(61))).toBe(false);
    expect(validateBlogName('Blog@Invalido!')).toBe(false);
    expect(validateBlogName('ÁÉÍÓÚãõç')).toBe(true);
    expect(validateBlogName('a'.repeat(60))).toBe(true);
  });

  it('valida texto de prompt corretamente', () => {
    expect(validatePromptText('Prompt válido')).toBe(true);
    expect(validatePromptText('')).toBe(false);
    expect(validatePromptText('a'.repeat(501))).toBe(false);
    expect(validatePromptText('a'.repeat(500))).toBe(true);
  });

  it('valida entradas inválidas', () => {
    expect(validateBlogName(null)).toBe(false);
    expect(validateBlogName(undefined)).toBe(false);
    expect(validatePromptText(null)).toBe(false);
    expect(validatePromptText(undefined)).toBe(false);
    expect(validateBlogName(123)).toBe(false);
    expect(validatePromptText(123)).toBe(false);
  });

  it('sanitiza todos os caracteres especiais suportados', () => {
    expect(sanitize('<>"&\'/')).toBe('&lt;&gt;&quot;&amp;&#39;&#x2F;');
  });

  it('sanitiza strings perigosas', () => {
    expect(sanitize('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;&#x2F;script&gt;');
    expect(sanitize('O "teste" & o /teste/')).toBe('O &quot;teste&quot; &amp; o &#x2F;teste&#x2F;');
    expect(sanitize("'single quotes' /slashes/")).toBe('&#39;single quotes&#39; &#x2F;slashes&#x2F;');
  });
}); 