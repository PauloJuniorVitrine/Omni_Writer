/**
 * Base Page Object para Testes E2E
 * - Métodos comuns para todas as páginas
 * - Abstração de interações comuns
 * - Padronização de práticas
 * 
 * 📐 CoCoT: Baseado em boas práticas de Page Object Model
 * 🌲 ToT: Múltiplas estratégias de abstração implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de interação
 */

import { Page, expect, Locator } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';
import path from 'path';

export interface PageConfig {
  baseUrl: string;
  timeouts: {
    short: number;
    medium: number;
    long: number;
  };
  retryAttempts: number;
  retryDelay: number;
  screenshotDir: string;
}

export abstract class BasePage {
  protected page: Page;
  protected config: PageConfig;
  protected testLogs: string[] = [];

  constructor(page: Page, config: PageConfig) {
    this.page = page;
    this.config = config;
  }

  /**
   * Navega para a página
   */
  async navigateTo(path: string = ''): Promise<void> {
    const url = `${this.config.baseUrl}${path}`;
    await this.page.goto(url);
    await this.waitForPageLoad();
  }

  /**
   * Aguarda carregamento da página
   */
  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Aguarda elemento com retry logic
   */
  async waitForElement(selector: string, timeout: number = this.config.timeouts.medium): Promise<Locator> {
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        await this.page.waitForSelector(selector, { timeout: timeout / this.config.retryAttempts });
        return this.page.locator(selector);
      } catch (error) {
        if (attempt === this.config.retryAttempts) {
          throw new Error(`Elemento ${selector} não encontrado após ${this.config.retryAttempts} tentativas`);
        }
        await this.page.waitForTimeout(this.config.retryDelay);
      }
    }
    throw new Error(`Elemento ${selector} não encontrado`);
  }

  /**
   * Clica em elemento com retry logic
   */
  async clickElement(selector: string): Promise<void> {
    const element = await this.waitForElement(selector);
    await element.click();
  }

  /**
   * Preenche campo com retry logic
   */
  async fillField(selector: string, value: string): Promise<void> {
    const element = await this.waitForElement(selector);
    await element.fill(value);
  }

  /**
   * Seleciona opção em dropdown
   */
  async selectOption(selector: string, value: string): Promise<void> {
    await this.page.selectOption(selector, value);
  }

  /**
   * Valida se texto está visível
   */
  async expectTextVisible(text: string): Promise<void> {
    await expect(this.page.locator(`text=${text}`)).toBeVisible();
  }

  /**
   * Valida se elemento está visível
   */
  async expectElementVisible(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeVisible();
  }

  /**
   * Valida valor de elemento
   */
  async expectElementValue(selector: string, expectedValue: string): Promise<void> {
    await expect(this.page.locator(selector)).toHaveValue(expectedValue);
  }

  /**
   * Tira screenshot
   */
  async takeScreenshot(name: string): Promise<void> {
    const screenshotPath = path.join(this.config.screenshotDir, `${name}.png`);
    await this.page.screenshot({ path: screenshotPath, fullPage: true });
    this.log(`Screenshot salvo: ${screenshotPath}`);
  }

  /**
   * Executa validação de acessibilidade
   */
  async runAccessibilityCheck(): Promise<void> {
    const accessibilityScan = await new AxeBuilder({ page: this.page }).analyze();
    expect(accessibilityScan.violations).toEqual([]);
    this.log('Acessibilidade validada');
  }

  /**
   * Mede tempo de carregamento da página
   */
  async measurePageLoadTime(): Promise<number> {
    const startTime = Date.now();
    await this.waitForPageLoad();
    const loadTime = Date.now() - startTime;
    this.log(`Tempo de carregamento: ${loadTime}ms`);
    return loadTime;
  }

  /**
   * Mede tempo de execução de uma ação
   */
  async measureActionTime(action: () => Promise<void>): Promise<number> {
    const startTime = Date.now();
    await action();
    const actionTime = Date.now() - startTime;
    this.log(`Tempo de ação: ${actionTime}ms`);
    return actionTime;
  }

  /**
   * Executa health check da página
   */
  async performHealthCheck(): Promise<boolean> {
    try {
      await this.waitForElement('body', this.config.timeouts.short);
      return true;
    } catch (error) {
      this.log(`Health check falhou: ${error}`);
      return false;
    }
  }

  /**
   * Aguarda elemento desaparecer
   */
  async waitForElementToDisappear(selector: string, timeout: number = this.config.timeouts.medium): Promise<void> {
    await this.page.waitForSelector(selector, { state: 'hidden', timeout });
  }

  /**
   * Valida URL atual
   */
  async expectCurrentUrl(expectedUrl: string): Promise<void> {
    await expect(this.page).toHaveURL(expectedUrl);
  }

  /**
   * Valida título da página
   */
  async expectPageTitle(expectedTitle: string | RegExp): Promise<void> {
    await expect(this.page).toHaveTitle(expectedTitle);
  }

  /**
   * Executa ação com scroll
   */
  async scrollToElement(selector: string): Promise<void> {
    const element = await this.waitForElement(selector);
    await element.scrollIntoViewIfNeeded();
  }

  /**
   * Valida atributo de elemento
   */
  async expectElementAttribute(selector: string, attribute: string, expectedValue: string): Promise<void> {
    await expect(this.page.locator(selector)).toHaveAttribute(attribute, expectedValue);
  }

  /**
   * Valida contagem de elementos
   */
  async expectElementCount(selector: string, expectedCount: number): Promise<void> {
    await expect(this.page.locator(selector)).toHaveCount(expectedCount);
  }

  /**
   * Executa ação com teclado
   */
  async pressKey(key: string): Promise<void> {
    await this.page.keyboard.press(key);
  }

  /**
   * Valida se elemento está habilitado
   */
  async expectElementEnabled(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeEnabled();
  }

  /**
   * Valida se elemento está desabilitado
   */
  async expectElementDisabled(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeDisabled();
  }

  /**
   * Valida se checkbox está marcado
   */
  async expectCheckboxChecked(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeChecked();
  }

  /**
   * Valida se checkbox está desmarcado
   */
  async expectCheckboxUnchecked(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).not.toBeChecked();
  }

  /**
   * Marca checkbox
   */
  async checkCheckbox(selector: string): Promise<void> {
    await this.page.locator(selector).check();
  }

  /**
   * Desmarca checkbox
   */
  async uncheckCheckbox(selector: string): Promise<void> {
    await this.page.locator(selector).uncheck();
  }

  /**
   * Valida se elemento está focado
   */
  async expectElementFocused(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeFocused();
  }

  /**
   * Foca em elemento
   */
  async focusElement(selector: string): Promise<void> {
    await this.page.locator(selector).focus();
  }

  /**
   * Valida se elemento contém texto
   */
  async expectElementContainsText(selector: string, text: string): Promise<void> {
    await expect(this.page.locator(selector)).toContainText(text);
  }

  /**
   * Valida se elemento tem texto exato
   */
  async expectElementHasText(selector: string, text: string): Promise<void> {
    await expect(this.page.locator(selector)).toHaveText(text);
  }

  /**
   * Limpa campo
   */
  async clearField(selector: string): Promise<void> {
    await this.page.locator(selector).clear();
  }

  /**
   * Valida se elemento está vazio
   */
  async expectElementEmpty(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeEmpty();
  }

  /**
   * Executa hover sobre elemento
   */
  async hoverElement(selector: string): Promise<void> {
    await this.page.locator(selector).hover();
  }

  /**
   * Executa double click
   */
  async doubleClickElement(selector: string): Promise<void> {
    await this.page.locator(selector).dblclick();
  }

  /**
   * Executa right click
   */
  async rightClickElement(selector: string): Promise<void> {
    await this.page.locator(selector).click({ button: 'right' });
  }

  /**
   * Valida se elemento está visível e habilitado
   */
  async expectElementVisibleAndEnabled(selector: string): Promise<void> {
    await this.expectElementVisible(selector);
    await this.expectElementEnabled(selector);
  }

  /**
   * Valida se elemento está visível e desabilitado
   */
  async expectElementVisibleAndDisabled(selector: string): Promise<void> {
    await this.expectElementVisible(selector);
    await this.expectElementDisabled(selector);
  }

  /**
   * Log de evidências
   */
  log(message: string): void {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${this.constructor.name}] ${message}`;
    console.log(logEntry);
    this.testLogs.push(logEntry);
  }

  /**
   * Salva logs em arquivo
   */
  saveLogs(filename: string): void {
    const logDir = 'logs/e2e';
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    
    const logPath = path.join(logDir, filename);
    fs.writeFileSync(logPath, this.testLogs.join('\n'));
  }

  /**
   * Obtém logs
   */
  getLogs(): string[] {
    return this.testLogs;
  }

  /**
   * Limpa logs
   */
  clearLogs(): void {
    this.testLogs = [];
  }

  /**
   * Método abstrato para validações específicas da página
   */
  abstract validatePage(): Promise<void>;
} 