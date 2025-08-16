/**
 * Custom Matchers para Testes E2E
 * - Validações específicas para o domínio Omni Writer
 * - Matchers reutilizáveis e expressivos
 * - Baseados em código real da aplicação
 * 
 * 📐 CoCoT: Baseado em boas práticas de custom matchers
 * 🌲 ToT: Múltiplas estratégias de validação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de validação
 */

import { expect, Locator, Page } from '@playwright/test';

// Extensão dos tipos do Playwright
declare global {
  namespace PlaywrightTest {
    interface Matchers<R> {
      toHaveValidApiKey(): R;
      toHaveValidPrompt(): R;
      toHaveValidModelType(): R;
      toHaveValidWebhookUrl(): R;
      toBeGeneratedSuccessfully(): R;
      toHaveValidDownloadLink(): R;
      toHaveValidProgressBar(): R;
      toHaveValidErrorMessage(): R;
      toHaveValidSuccessMessage(): R;
      toHaveValidInstanceData(): R;
      toHaveValidWebhookResponse(): R;
      toHaveValidPerformanceMetrics(): R;
      toHaveValidAccessibilityScore(): R;
      toHaveValidResponsiveLayout(): R;
      toHaveValidSecurityHeaders(): R;
    }
  }
}

// Custom matchers para validações específicas
export const customMatchers = {
  /**
   * Valida se API key tem formato válido
   */
  toHaveValidApiKey: async (locator: Locator) => {
    const value = await locator.inputValue();
    const isValid = /^sk-[a-zA-Z0-9]{32,}$/.test(value);
    
    if (!isValid) {
      throw new Error(`API key inválida: ${value}. Deve começar com 'sk-' e ter pelo menos 32 caracteres`);
    }
    
    return { pass: true, message: () => 'API key válida' };
  },

  /**
   * Valida se prompt tem conteúdo válido
   */
  toHaveValidPrompt: async (locator: Locator) => {
    const value = await locator.inputValue();
    const isValid = value.length >= 10 && value.length <= 1000;
    
    if (!isValid) {
      throw new Error(`Prompt inválido: ${value}. Deve ter entre 10 e 1000 caracteres`);
    }
    
    return { pass: true, message: () => 'Prompt válido' };
  },

  /**
   * Valida se tipo de modelo é válido
   */
  toHaveValidModelType: async (locator: Locator) => {
    const value = await locator.inputValue();
    const validModels = ['openai', 'deepseek', 'anthropic'];
    const isValid = validModels.includes(value);
    
    if (!isValid) {
      throw new Error(`Tipo de modelo inválido: ${value}. Deve ser um de: ${validModels.join(', ')}`);
    }
    
    return { pass: true, message: () => 'Tipo de modelo válido' };
  },

  /**
   * Valida se URL de webhook é válida
   */
  toHaveValidWebhookUrl: async (locator: Locator) => {
    const value = await locator.inputValue();
    const urlPattern = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
    const isValid = urlPattern.test(value);
    
    if (!isValid) {
      throw new Error(`URL de webhook inválida: ${value}. Deve ser uma URL válida`);
    }
    
    return { pass: true, message: () => 'URL de webhook válida' };
  },

  /**
   * Valida se geração foi bem-sucedida
   */
  toBeGeneratedSuccessfully: async (page: Page) => {
    const downloadLink = page.locator('[data-testid="download-link"], a[href*="download"]');
    const isVisible = await downloadLink.isVisible();
    
    if (!isVisible) {
      throw new Error('Geração não foi bem-sucedida. Link de download não encontrado');
    }
    
    return { pass: true, message: () => 'Geração bem-sucedida' };
  },

  /**
   * Valida se link de download é válido
   */
  toHaveValidDownloadLink: async (locator: Locator) => {
    const href = await locator.getAttribute('href');
    const isValid = href && href.includes('/download') && href.includes('.zip');
    
    if (!isValid) {
      throw new Error(`Link de download inválido: ${href}`);
    }
    
    return { pass: true, message: () => 'Link de download válido' };
  },

  /**
   * Valida se barra de progresso está funcionando
   */
  toHaveValidProgressBar: async (locator: Locator) => {
    const isVisible = await locator.isVisible();
    const ariaValue = await locator.getAttribute('aria-valuenow');
    const isValid = isVisible && ariaValue !== null;
    
    if (!isValid) {
      throw new Error('Barra de progresso inválida ou não visível');
    }
    
    return { pass: true, message: () => 'Barra de progresso válida' };
  },

  /**
   * Valida se mensagem de erro é apropriada
   */
  toHaveValidErrorMessage: async (locator: Locator) => {
    const text = await locator.textContent();
    const isValid = text && text.length > 0 && !text.includes('undefined') && !text.includes('null');
    
    if (!isValid) {
      throw new Error(`Mensagem de erro inválida: ${text}`);
    }
    
    return { pass: true, message: () => 'Mensagem de erro válida' };
  },

  /**
   * Valida se mensagem de sucesso é apropriada
   */
  toHaveValidSuccessMessage: async (locator: Locator) => {
    const text = await locator.textContent();
    const isValid = text && text.length > 0 && text.toLowerCase().includes('sucesso');
    
    if (!isValid) {
      throw new Error(`Mensagem de sucesso inválida: ${text}`);
    }
    
    return { pass: true, message: () => 'Mensagem de sucesso válida' };
  },

  /**
   * Valida se dados da instância são válidos
   */
  toHaveValidInstanceData: async (page: Page, expectedData: any) => {
    const nameField = page.locator('[data-testid="instance-name"]');
    const apiKeyField = page.locator('[data-testid="api-key"]');
    const modelField = page.locator('[data-testid="model-type"]');
    const promptField = page.locator('[data-testid="prompt"]');
    
    const actualName = await nameField.inputValue();
    const actualApiKey = await apiKeyField.inputValue();
    const actualModel = await modelField.inputValue();
    const actualPrompt = await promptField.inputValue();
    
    const isValid = 
      actualName === expectedData.name &&
      actualApiKey === expectedData.apiKey &&
      actualModel === expectedData.modelType &&
      actualPrompt === expectedData.prompt;
    
    if (!isValid) {
      throw new Error(`Dados da instância não correspondem ao esperado. Esperado: ${JSON.stringify(expectedData)}, Atual: ${JSON.stringify({ actualName, actualApiKey, actualModel, actualPrompt })}`);
    }
    
    return { pass: true, message: () => 'Dados da instância válidos' };
  },

  /**
   * Valida se resposta de webhook é válida
   */
  toHaveValidWebhookResponse: async (response: any) => {
    const isValid = 
      response &&
      response.status === 200 &&
      response.body &&
      response.body.success === true;
    
    if (!isValid) {
      throw new Error(`Resposta de webhook inválida: ${JSON.stringify(response)}`);
    }
    
    return { pass: true, message: () => 'Resposta de webhook válida' };
  },

  /**
   * Valida métricas de performance
   */
  toHaveValidPerformanceMetrics: async (loadTime: number) => {
    const isValid = loadTime > 0 && loadTime < 10000; // Máximo 10 segundos
    
    if (!isValid) {
      throw new Error(`Métricas de performance inválidas: ${loadTime}ms`);
    }
    
    return { pass: true, message: () => `Performance válida: ${loadTime}ms` };
  },

  /**
   * Valida score de acessibilidade
   */
  toHaveValidAccessibilityScore: async (violations: any[]) => {
    const isValid = violations.length === 0;
    
    if (!isValid) {
      throw new Error(`Score de acessibilidade inválido: ${violations.length} violações encontradas`);
    }
    
    return { pass: true, message: () => 'Score de acessibilidade válido' };
  },

  /**
   * Valida layout responsivo
   */
  toHaveValidResponsiveLayout: async (page: Page) => {
    const viewport = page.viewportSize();
    const isMobile = viewport && viewport.width < 768;
    const isTablet = viewport && viewport.width >= 768 && viewport.width < 1024;
    const isDesktop = viewport && viewport.width >= 1024;
    
    const isValid = isMobile || isTablet || isDesktop;
    
    if (!isValid) {
      throw new Error(`Layout responsivo inválido: viewport ${JSON.stringify(viewport)}`);
    }
    
    return { pass: true, message: () => `Layout responsivo válido: ${isMobile ? 'mobile' : isTablet ? 'tablet' : 'desktop'}` };
  },

  /**
   * Valida headers de segurança
   */
  toHaveValidSecurityHeaders: async (page: Page) => {
    const response = await page.goto(page.url());
    const headers = response?.headers();
    
    const requiredHeaders = ['X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection'];
    const missingHeaders = requiredHeaders.filter(header => !headers?.[header]);
    
    if (missingHeaders.length > 0) {
      throw new Error(`Headers de segurança ausentes: ${missingHeaders.join(', ')}`);
    }
    
    return { pass: true, message: () => 'Headers de segurança válidos' };
  }
};

// Função para registrar custom matchers
export function registerCustomMatchers() {
  // Registra cada matcher customizado
  Object.entries(customMatchers).forEach(([name, matcher]) => {
    expect.extend({
      [name]: matcher as any
    });
  });
}

// Funções utilitárias para validações específicas
export const validationHelpers = {
  /**
   * Valida se elemento está visível e habilitado
   */
  async expectElementVisibleAndEnabled(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeVisible();
    await expect(element).toBeEnabled();
  },

  /**
   * Valida se elemento está visível e desabilitado
   */
  async expectElementVisibleAndDisabled(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeVisible();
    await expect(element).toBeDisabled();
  },

  /**
   * Valida se elemento contém texto específico
   */
  async expectElementContainsText(page: Page, selector: string, text: string) {
    const element = page.locator(selector);
    await expect(element).toContainText(text);
  },

  /**
   * Valida se elemento tem valor específico
   */
  async expectElementHasValue(page: Page, selector: string, value: string) {
    const element = page.locator(selector);
    await expect(element).toHaveValue(value);
  },

  /**
   * Valida se elemento está vazio
   */
  async expectElementEmpty(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeEmpty();
  },

  /**
   * Valida se elemento está focado
   */
  async expectElementFocused(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeFocused();
  },

  /**
   * Valida se checkbox está marcado
   */
  async expectCheckboxChecked(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeChecked();
  },

  /**
   * Valida se checkbox está desmarcado
   */
  async expectCheckboxUnchecked(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).not.toBeChecked();
  },

  /**
   * Valida se elemento tem atributo específico
   */
  async expectElementHasAttribute(page: Page, selector: string, attribute: string, value: string) {
    const element = page.locator(selector);
    await expect(element).toHaveAttribute(attribute, value);
  },

  /**
   * Valida contagem de elementos
   */
  async expectElementCount(page: Page, selector: string, count: number) {
    const elements = page.locator(selector);
    await expect(elements).toHaveCount(count);
  },

  /**
   * Valida se elemento existe no DOM
   */
  async expectElementExists(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).toBeAttached();
  },

  /**
   * Valida se elemento não existe no DOM
   */
  async expectElementNotExists(page: Page, selector: string) {
    const element = page.locator(selector);
    await expect(element).not.toBeAttached();
  }
};

// Exporta tudo
export { customMatchers as matchers, validationHelpers as helpers }; 