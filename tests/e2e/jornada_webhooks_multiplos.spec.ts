/**
 * Teste E2E: Jornada de Integração com Múltiplos Webhooks Simultâneos
 * - Valida registro, disparo e recebimento de múltiplos webhooks
 * - Garante isolamento, persistência, side effects, acessibilidade, screenshots e logs
 * - IMPLEMENTAÇÕES: Mock server, validações reais, retry logic
 * 
 * 📐 CoCoT: Baseado em app/services/generation_service.py e webhook handlers
 * 🌲 ToT: Múltiplas estratégias de validação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de webhook
 */
import { test, expect, Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';
import { MockServer } from './utils/mock-server';
import { A11YCoverageValidator } from './utils/a11y-coverage-validator';

/**
 * Teste E2E: Múltiplos Webhooks
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T10:30:00Z
 * **Tracing ID:** E2E_JORNADA_WEBHOOKS_MULTIPLOS.SPEC_md1ppfhs
 * **Origem:** app/services/generation_service.py, webhook handlers
 * 
 * Testes end-to-end baseados em código real da aplicação Omni Writer
 */

// Configuração dinâmica
const config = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  mockServerPort: 9999,
  webhookUrls: [
    'http://localhost:9999/webhook-mock-1',
    'http://localhost:9999/webhook-mock-2',
    'http://localhost:9999/webhook-mock-3'
  ],
  timeouts: {
    short: 5000,
    medium: 15000,
    long: 60000
  },
  retryAttempts: 3,
  retryDelay: 1000
};

// Utilitários com retry logic
async function takeStepScreenshot(page: Page, step: string) {
  await page.screenshot({ 
    path: `tests/e2e/snapshots/webhooks_multiplos/${step}.png`, 
    fullPage: true 
  });
}

async function logEvidence(step: string, message: string) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${step}] ${message}`;
  console.log(logEntry);
  
  // Salva em arquivo de log
  fs.appendFileSync('logs/e2e/webhooks_multiplos.log', logEntry + '\n');
}

async function waitForElementWithRetry(page: Page, selector: string, timeout: number = config.timeouts.medium) {
  for (let attempt = 1; attempt <= config.retryAttempts; attempt++) {
    try {
      await page.waitForSelector(selector, { timeout: timeout / config.retryAttempts });
      return true;
    } catch (error) {
      if (attempt === config.retryAttempts) {
        throw new Error(`Elemento ${selector} não encontrado após ${config.retryAttempts} tentativas`);
      }
      await page.waitForTimeout(config.retryDelay);
    }
  }
}

async function performHealthCheck(page: Page): Promise<boolean> {
  try {
    await page.goto(config.baseUrl);
    await page.waitForSelector('body', { timeout: config.timeouts.short });
    return true;
  } catch (error) {
    console.error('Health check falhou:', error);
    return false;
  }
}

// Função para registrar webhook baseada no código real
async function registrarWebhook(page: Page, webhookUrl: string) {
  await page.fill('input[name="webhook_url"]', webhookUrl);
  await page.click('button[type="submit"]:has-text("Registrar Webhook")');
  
  // Aguarda confirmação
  await waitForElementWithRetry(page, '.webhook-success, .alert-success');
}

// Função para validar webhook recebido via mock server
async function validateWebhookReceived(mockServer: MockServer, webhookUrl: string, expectedData?: any): Promise<boolean> {
  const webhooks = await mockServer.getWebhooks();
  const receivedWebhook = webhooks.find(w => w.url === webhookUrl);
  
  if (!receivedWebhook) {
    return false;
  }
  
  if (expectedData) {
    // Valida dados específicos se fornecidos
    return JSON.stringify(receivedWebhook.body).includes(JSON.stringify(expectedData));
  }
  
  return true;
}

test.describe('Jornada E2E: Múltiplos Webhooks Simultâneos', () => {
  let mockServer: MockServer;
  let a11yValidator: A11YCoverageValidator;

  test.beforeAll(async () => {
    // Inicia mock server
    mockServer = new MockServer(config.mockServerPort);
    await mockServer.start();
    
    // Configura respostas mock para diferentes cenários
    await mockServer.configureMockResponse('webhook-mock-1', {
      status: 200,
      body: { success: true, message: 'Webhook 1 processado' },
      delay: 100
    });
    
    await mockServer.configureMockResponse('webhook-mock-2', {
      status: 200,
      body: { success: true, message: 'Webhook 2 processado' },
      delay: 200
    });
    
    await mockServer.configureMockResponse('webhook-mock-3', {
      status: 500, // Simula falha
      body: { error: 'Webhook 3 falhou' },
      delay: 150
    });
  });

  test.afterAll(async () => {
    if (mockServer) {
      await mockServer.stop();
    }
  });

  test.beforeEach(async ({ page }) => {
    // Inicializar validador A11Y
    a11yValidator = new A11YCoverageValidator();
    
    // Health check antes de cada teste
    const isHealthy = await performHealthCheck(page);
    if (!isHealthy) {
      throw new Error('Sistema não está saudável para execução dos testes');
    }
    
    // Limpa webhooks do mock server
    await mockServer.clearWebhooks();
  });

  test('Fluxo principal: registro e disparo de múltiplos webhooks', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    
    await test.step('Navegação inicial e validação A11Y', async () => {
      await page.goto(config.baseUrl);
      await expect(page).toHaveTitle(/Omni Gerador de Artigos/i);
      await takeStepScreenshot(page, 'inicio');
      logEvidence('inicio', 'Página inicial carregada');
      
      // Validação A11Y - Página Inicial
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Webhooks - Página Inicial coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
      
      // Acessibilidade inicial
      const accessibilityScan = await new AxeBuilder({ page }).analyze();
      expect(accessibilityScan.violations).toEqual([]);
      logEvidence('a11y_inicio', 'Acessibilidade inicial validada');
    });
    
    // Navega para seção de webhooks (baseado em rotas reais)
    await test.step('Navegação para webhooks e validação A11Y', async () => {
      await page.goto(`${config.baseUrl}/webhooks`);
      await waitForElementWithRetry(page, 'input[name="webhook_url"]');
      await takeStepScreenshot(page, 'webhooks_page');
      logEvidence('webhooks_page', 'Página de webhooks carregada');
      
      // Validação A11Y - Página de Webhooks
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Webhooks - Página de Webhooks coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });
    
    // Registra múltiplos webhooks
    await test.step('Registro de webhooks e validação A11Y', async () => {
      for (let i = 0; i < config.webhookUrls.length; i++) {
        const webhookUrl = config.webhookUrls[i];
        await registrarWebhook(page, webhookUrl);
        logEvidence(`webhook_${i + 1}`, `Webhook ${i + 1} registrado: ${webhookUrl}`);
        
        // Aguarda confirmação visual
        await waitForElementWithRetry(page, '.webhook-success, .alert-success');
      }
      
      await takeStepScreenshot(page, 'webhooks_registrados');
      logEvidence('webhooks_registrados', 'Todos os webhooks registrados com sucesso');
      
      // Validação A11Y - Após Registro de Webhooks
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Webhooks - Após Registro coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });
    
    // Valida DOM - webhooks devem estar visíveis na lista
    await test.step('Validação DOM e A11Y', async () => {
      for (const webhookUrl of config.webhookUrls) {
        const webhookElement = page.locator(`text=${webhookUrl}`);
        await expect(webhookElement).toBeVisible();
      }
      
      // Validação A11Y - Lista de Webhooks
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Webhooks - Lista de Webhooks coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });
    
    // Dispara evento que aciona webhooks (geração de artigo)
    await test.step('Disparo de webhooks e validação A11Y', async () => {
      await page.goto(`${config.baseUrl}/artigos`);
      await waitForElementWithRetry(page, 'button#gerar-artigo, [data-testid="generate-button"]');
      
      // Validação A11Y - Página de Artigos
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Webhooks - Página de Artigos coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });
    
    // Preenche dados mínimos para geração
    await page.fill('textarea[name="prompts"], [data-testid="prompt-input"]', 'Teste webhook múltiplos E2E');
    await page.selectOption('select[name="model_type"], [data-testid="model-select"]', 'openai');
    
    await takeStepScreenshot(page, 'pre_geracao');
    logEvidence('pre_geracao', 'Dados preenchidos, iniciando geração');
    
    // Inicia geração
    await page.click('button#gerar-artigo, [data-testid="generate-button"]');
    
    // Aguarda processamento
    await waitForElementWithRetry(page, '[data-testid="download-link"], .generation-complete, .error-message', config.timeouts.long);
    await takeStepScreenshot(page, 'pos_geracao');
    logEvidence('pos_geracao', 'Geração concluída, verificando webhooks');
    
    // Aguarda um tempo para webhooks serem processados
    await page.waitForTimeout(2000);
    
    // Valida recebimento nos webhooks via mock server
    for (let i = 0; i < config.webhookUrls.length; i++) {
      const webhookUrl = config.webhookUrls[i];
      const isReceived = await validateWebhookReceived(mockServer, webhookUrl);
      
      if (i < 2) {
        // Webhooks 1 e 2 devem ter sucesso
        expect(isReceived).toBe(true);
        logEvidence(`webhook_${i + 1}_validado`, `Webhook ${i + 1} recebido com sucesso`);
      } else {
        // Webhook 3 deve falhar (configurado para retornar 500)
        expect(isReceived).toBe(false);
        logEvidence(`webhook_${i + 1}_falha`, `Webhook ${i + 1} falhou conforme esperado`);
      }
    }
    
    // Valida persistência - webhooks devem permanecer registrados
    await page.goto(`${config.baseUrl}/webhooks`);
    for (const webhookUrl of config.webhookUrls) {
      const webhookElement = page.locator(`text=${webhookUrl}`);
      await expect(webhookElement).toBeVisible();
    }
    
    // Valida acessibilidade final
    const finalAccessibilityScan = await new AxeBuilder({ page }).analyze();
    expect(finalAccessibilityScan.violations).toEqual([]);
    logEvidence('a11y_final', 'Acessibilidade final validada');
    
    // Salva logs completos
    fs.writeFileSync('logs/e2e/webhooks_multiplos_complete.log', logs.join('\n'));
  });

  test('Cenário de falha: webhook com URL inválida', async ({ page }) => {
    await page.goto(`${config.baseUrl}/webhooks`);
    
    // Tenta registrar webhook com URL inválida
    await page.fill('input[name="webhook_url"]', 'http://invalid-url-that-does-not-exist');
    await page.click('button[type="submit"]:has-text("Registrar Webhook")');
    
    // Deve mostrar erro de validação
    await waitForElementWithRetry(page, '.error-message, .alert-danger');
    await takeStepScreenshot(page, 'webhook_invalido');
    logEvidence('webhook_invalido', 'Erro de validação para URL inválida');
    
    // Valida DOM - erro deve estar visível
    const errorElement = page.locator('.error-message, .alert-danger');
    await expect(errorElement).toBeVisible();
  });

  test('Cenário de concorrência: múltiplos eventos simultâneos', async ({ page }) => {
    await page.goto(config.baseUrl);
    
    // Registra webhook
    await page.goto(`${config.baseUrl}/webhooks`);
    await registrarWebhook(page, config.webhookUrls[0]);
    
    // Dispara múltiplos eventos rapidamente
    for (let i = 0; i < 3; i++) {
      await page.goto(`${config.baseUrl}/artigos`);
      await page.fill('textarea[name="prompts"]', `Evento concorrente ${i + 1}`);
      await page.click('button#gerar-artigo');
      
      // Aguarda um pouco entre eventos
      await page.waitForTimeout(500);
    }
    
    // Aguarda processamento
    await page.waitForTimeout(3000);
    
    // Valida que todos os eventos foram recebidos
    const webhooks = await mockServer.getWebhooks();
    expect(webhooks.length).toBeGreaterThanOrEqual(3);
    logEvidence('concorrencia', `Múltiplos eventos processados: ${webhooks.length}`);
  });
}); 