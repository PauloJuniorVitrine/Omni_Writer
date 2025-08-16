/**
 * Base Class para Testes E2E
 * - Métodos comuns e configurações padronizadas
 * - Reutilização de código entre testes
 * - Padronização de práticas
 * 
 * 📐 CoCoT: Baseado em boas práticas de base classes para E2E
 * 🌲 ToT: Múltiplas estratégias de abstração implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de teste
 */

import { test as base, Page, expect, Download } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';
import path from 'path';
import { TestInstance, TestUser, TestArticle, TestWebhook, TestDataHelper } from '../fixtures/test-data';

// Configurações da base class
interface E2EBaseConfig {
  baseUrl: string;
  timeouts: {
    short: number;
    medium: number;
    long: number;
    veryLong: number;
  };
  retryAttempts: number;
  retryDelay: number;
  screenshotDir: string;
  logDir: string;
}

// Extensão da base class com fixtures
export const test = base.extend<{
  e2eBase: E2EBase;
  testInstance: TestInstance;
  testUser: TestUser;
  testArticle: TestArticle;
  testWebhook: TestWebhook;
}>({
  e2eBase: async ({ page }, use) => {
    const e2eBase = new E2EBase(page);
    await use(e2eBase);
  },
  
  testInstance: async ({}, use) => {
    await use(TestDataHelper.getInstanceByType('success'));
  },
  
  testUser: async ({}, use) => {
    await use(TestDataHelper.getUserByRole('user'));
  },
  
  testArticle: async ({}, use) => {
    await use(TestDataHelper.getArticleByStatus('published'));
  },
  
  testWebhook: async ({}, use) => {
    await use(TestDataHelper.getWebhookByResponse(200));
  }
});

export class E2EBase {
  private page: Page;
  private config: E2EBaseConfig;
  private testLogs: string[] = [];
  private testStartTime: number;

  constructor(page: Page) {
    this.page = page;
    this.config = {
      baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
      timeouts: {
        short: 5000,
        medium: 15000,
        long: 60000,
        veryLong: 120000
      },
      retryAttempts: 3,
      retryDelay: 1000,
      screenshotDir: 'tests/e2e/snapshots',
      logDir: 'logs/e2e'
    };
    this.testStartTime = Date.now();
  }

  // Métodos de navegação
  async navigateTo(path: string = '/'): Promise<void> {
    const url = `${this.config.baseUrl}${path}`;
    await this.page.goto(url);
    await this.waitForPageLoad();
  }

  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  // Métodos de espera com retry
  async waitForElement(selector: string, timeout: number = this.config.timeouts.medium): Promise<void> {
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        await this.page.waitForSelector(selector, { timeout });
        return;
      } catch (error) {
        if (attempt === this.config.retryAttempts) {
          throw new Error(`Elemento ${selector} não encontrado após ${this.config.retryAttempts} tentativas`);
        }
        this.log(`Tentativa ${attempt}/${this.config.retryAttempts} falhou para ${selector}`);
        await this.page.waitForTimeout(this.config.retryDelay);
      }
    }
  }

  async waitForCondition(
    condition: () => Promise<boolean>,
    timeout: number = this.config.timeouts.long,
    interval: number = 1000
  ): Promise<void> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        if (await condition()) {
          return;
        }
      } catch (error) {
        // Continua tentando
      }
      await this.page.waitForTimeout(interval);
    }
    
    throw new Error(`Condição não satisfeita após ${timeout}ms`);
  }

  // Métodos de interação
  async clickElement(selector: string): Promise<void> {
    await this.waitForElement(selector);
    await this.page.click(selector);
  }

  async fillInput(selector: string, value: string): Promise<void> {
    await this.waitForElement(selector);
    await this.page.fill(selector, value);
  }

  async selectOption(selector: string, value: string): Promise<void> {
    await this.waitForElement(selector);
    await this.page.selectOption(selector, value);
  }

  async typeText(selector: string, text: string): Promise<void> {
    await this.waitForElement(selector);
    await this.page.type(selector, text);
  }

  // Métodos de validação
  async expectElementVisible(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).toBeVisible();
  }

  async expectElementNotVisible(selector: string): Promise<void> {
    await expect(this.page.locator(selector)).not.toBeVisible();
  }

  async expectTextVisible(text: string): Promise<void> {
    await expect(this.page.locator(`text=${text}`)).toBeVisible();
  }

  async expectElementText(selector: string, expectedText: string): Promise<void> {
    await expect(this.page.locator(selector)).toHaveText(expectedText);
  }

  async expectElementValue(selector: string, expectedValue: string): Promise<void> {
    await expect(this.page.locator(selector)).toHaveValue(expectedValue);
  }

  // Métodos de screenshot e logging
  async takeScreenshot(name: string, fullPage: boolean = true): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${name}_${timestamp}.png`;
    const filepath = path.join(this.config.screenshotDir, filename);
    
    // Cria diretório se não existir
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    await this.page.screenshot({ path: filepath, fullPage });
    this.log(`Screenshot salvo: ${filepath}`);
  }

  log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    this.testLogs.push(logEntry);
    console.log(logEntry);
  }

  async saveTestLogs(testName: string): Promise<void> {
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `${testName}_${timestamp}.log`;
    const filepath = path.join(this.config.logDir, filename);
    
    // Cria diretório se não existir
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    const logContent = this.testLogs.join('\n');
    fs.writeFileSync(filepath, logContent);
    this.log(`Logs salvos: ${filepath}`);
  }

  // Métodos de acessibilidade
  async runAccessibilityCheck(): Promise<void> {
    const accessibilityScan = await new AxeBuilder({ page: this.page }).analyze();
    
    if (accessibilityScan.violations.length > 0) {
      this.log(`Violações de acessibilidade encontradas: ${accessibilityScan.violations.length}`, 'warn');
      accessibilityScan.violations.forEach(violation => {
        this.log(`- ${violation.id}: ${violation.description}`, 'warn');
      });
    } else {
      this.log('Acessibilidade validada com sucesso');
    }
    
    expect(accessibilityScan.violations).toEqual([]);
  }

  // Métodos específicos do Omni Writer
  async fillInstanceForm(instance: TestInstance): Promise<void> {
    await this.fillInput('[data-testid="instance-name"]', instance.name);
    await this.selectOption('[data-testid="model-type"]', instance.modelType);
    await this.fillInput('[data-testid="api-key"]', instance.apiKey);
    await this.fillInput('[data-testid="prompts"]', instance.prompt);
  }

  async submitInstanceForm(): Promise<void> {
    await this.clickElement('button[type="submit"]:has-text("Adicionar Instância")');
    await this.waitForElement('#instancias_lista li');
  }

  async registerWebhook(webhook: TestWebhook): Promise<void> {
    await this.page.evaluate(async (webhookUrl) => {
      await fetch('/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(webhookUrl)}`
      });
    }, webhook.url);
  }

  async submitGeneration(): Promise<void> {
    await this.clickElement('[data-testid="submit-btn"]');
  }

  async waitForGenerationComplete(): Promise<void> {
    await this.waitForCondition(
      async () => {
        const downloadLink = this.page.locator('[data-testid="download-link"]');
        const statusMessage = this.page.locator('[data-testid="status-message"]');
        const errorMessage = this.page.locator('[data-testid="error-message"]');
        
        return await downloadLink.isVisible() || 
               await statusMessage.isVisible() || 
               await errorMessage.isVisible();
      },
      this.config.timeouts.long
    );
  }

  async downloadGeneratedArticle(): Promise<Download> {
    await this.waitForCondition(
      async () => {
        const downloadLink = this.page.locator('[data-testid="download-link"]');
        return await downloadLink.isVisible();
      },
      this.config.timeouts.veryLong
    );

    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      this.page.click('[data-testid="download-link"]'),
    ]);
    
    return download;
  }

  // Métodos de performance
  async measurePageLoadTime(): Promise<number> {
    const startTime = Date.now();
    await this.waitForPageLoad();
    const loadTime = Date.now() - startTime;
    this.log(`Tempo de carregamento da página: ${loadTime}ms`);
    return loadTime;
  }

  async measureActionTime(action: () => Promise<void>): Promise<number> {
    const startTime = Date.now();
    await action();
    const actionTime = Date.now() - startTime;
    this.log(`Tempo da ação: ${actionTime}ms`);
    return actionTime;
  }

  // Métodos de limpeza
  async clearTestData(): Promise<void> {
    // Limpa dados de teste se necessário
    this.testLogs = [];
  }

  getTestDuration(): number {
    return Date.now() - this.testStartTime;
  }

  // Métodos de configuração
  setConfig(newConfig: Partial<E2EBaseConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  getConfig(): E2EBaseConfig {
    return { ...this.config };
  }

  // Métodos de debug
  async pause(): Promise<void> {
    await this.page.pause();
  }

  async debugScreenshot(): Promise<void> {
    await this.takeScreenshot('debug', true);
  }

  async savePageHTML(filename: string): Promise<void> {
    const html = await this.page.content();
    const filepath = path.join(this.config.logDir, `${filename}.html`);
    
    const dir = path.dirname(filepath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(filepath, html);
    this.log(`HTML salvo: ${filepath}`);
  }
}

// Exporta para uso em testes
export { expect }; 