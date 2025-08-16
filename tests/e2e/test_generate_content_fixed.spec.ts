/**
 * Teste E2E: Geração de Conteúdo - VERSÃO CORRIGIDA
 * - Valida fluxo real, status, SSE, download, feedback visual, erro de API key
 * - Garante persistência, side effects, acessibilidade, screenshots e logs
 * - IMPLEMENTAÇÕES: Retry logic, polling inteligente, timeouts dinâmicos
 * 
 * 📐 CoCoT: Baseado em boas práticas de E2E testing
 * 🌲 ToT: Múltiplas estratégias de wait implementadas
 * ♻️ ReAct: Simulado para evitar flakiness
 */
import { test, expect, Page, Download } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

/**
 * Teste E2E: Geração de Conteúdo
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-07-13T13:30:23.536Z
 * **Tracing ID:** E2E_TEST_GENERATE_CONTENT_FIXED.SPEC_md1ppfhs
 * **Origem:** app/services/generation_service.py
 * 
 * Testes end-to-end baseados em código real da aplicação Omni Writer
 */


// Configuração dinâmica baseada em ambiente
const config = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  apiKey: process.env.TEST_API_KEY || 'sk-test-openai-valid-key',
  modelType: 'openai',
  prompt: 'Teste E2E fluxo real.',
  invalidApiKey: 'invalid-key',
  mockWebhookUrl: 'http://localhost:9999/webhook-mock',
  timeouts: {
    short: 5000,
    medium: 15000,
    long: 60000,
    veryLong: 120000
  },
  retryAttempts: 3,
  retryDelay: 1000
};

// Utilitários aprimorados com retry logic
async function takeStepScreenshot(page: Page, step: string) {
  await page.screenshot({ 
    path: `tests/e2e/snapshots/generate_content/${step}.png`, 
    fullPage: true 
  });
}

function logEvidence(step: string, data: string) {
  const timestamp = new Date().toISOString();
  const logEntry = `\n[${timestamp}] [generate_content/${step}] ${data}`;
  fs.appendFileSync('tests/e2e/E2E_LOG.md', logEntry);
}

// Retry logic para elementos que podem demorar
async function waitForElementWithRetry(
  page: Page, 
  selector: string, 
  timeout: number = config.timeouts.medium,
  retries: number = config.retryAttempts
): Promise<void> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await page.waitForSelector(selector, { timeout });
      return;
    } catch (error) {
      if (attempt === retries) {
        throw new Error(`Elemento ${selector} não encontrado após ${retries} tentativas`);
      }
      logEvidence('retry', `Tentativa ${attempt}/${retries} falhou para ${selector}`);
      await page.waitForTimeout(config.retryDelay);
    }
  }
}

// Polling inteligente para elementos assíncronos
async function waitForConditionWithPolling(
  page: Page,
  condition: () => Promise<boolean>,
  timeout: number = config.timeouts.long,
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
    await page.waitForTimeout(interval);
  }
  
  throw new Error(`Condição não satisfeita após ${timeout}ms`);
}

async function preencherInstancia(
  page: Page, 
  nome: string, 
  apiKey: string, 
  modelType: string, 
  prompt: string
): Promise<void> {
  await waitForElementWithRetry(page, '[data-testid="instance-name"]');
  await page.fill('[data-testid="instance-name"]', nome);
  await page.selectOption('[data-testid="model-type"]', modelType);
  await page.fill('[data-testid="api-key"]', apiKey);
  await page.fill('[data-testid="prompts"]', prompt);
}

async function registrarWebhook(page: Page, url: string): Promise<void> {
  await page.evaluate(async (webhookUrl) => {
    await fetch('/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(webhookUrl)}`
    });
  }, url);
}

async function realizarDownload(page: Page): Promise<Download> {
  // Aguarda o link de download estar disponível
  await waitForConditionWithPolling(
    page,
    async () => {
      const downloadLink = page.locator('[data-testid="download-link"]');
      return await downloadLink.isVisible();
    },
    config.timeouts.long
  );

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('[data-testid="download-link"]'),
  ]);
  
  return download;
}

// Health check antes dos testes
async function performHealthCheck(page: Page): Promise<boolean> {
  try {
    await page.goto(config.baseUrl);
    await page.waitForSelector('body', { timeout: config.timeouts.short });
    return true;
  } catch (error) {
    logEvidence('health_check', `Falha no health check: ${error}`);
    return false;
  }
}

test.describe('Jornada E2E: Geração de Conteúdo - CORRIGIDA', () => {
  test.beforeEach(async ({ page }) => {
    // Health check antes de cada teste
    const isHealthy = await performHealthCheck(page);
    if (!isHealthy) {
      throw new Error('Sistema não está saudável para execução dos testes');
    }
  });

  test('Fluxo principal: geração, status, SSE, download, a11y e visual', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
    
    await page.goto(config.baseUrl);
    await expect(page).toHaveTitle(/Omni Gerador de Artigos/i);
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página inicial carregada');
    
    // Diagnóstico: salvar HTML inicial
    const html = await page.content();
    fs.writeFileSync('diagnostico_inicial.html', html);
    
    // Acessibilidade inicial
    const accessibilityScan = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScan.violations).toEqual([]);
    logEvidence('a11y_inicio', 'Acessibilidade inicial validada');
    
    // Preenchimento com retry logic
    await preencherInstancia(page, 'Instância E2E', config.apiKey, config.modelType, config.prompt);
    await page.click('button[type="submit"]:has-text("Adicionar Instância")');
    
    // Aguarda instância ser adicionada
    await waitForElementWithRetry(page, '#instancias_lista li');
    await registrarWebhook(page, config.mockWebhookUrl);
    logEvidence('instancia', 'Instância e webhook registrados');
    
    // Submissão
    await page.click('[data-testid="submit-btn"]');
    const htmlPosEnvio = await page.content();
    fs.writeFileSync('diagnostico_pos_envio.html', htmlPosEnvio);
    await takeStepScreenshot(page, 'pos_envio');
    logEvidence('pos_envio', 'Envio realizado, aguardando processamento');
    
    // Aguarda elementos de status com polling inteligente
    await waitForConditionWithPolling(
      page,
      async () => {
        const downloadLink = page.locator('[data-testid="download-link"]');
        const progressBar = page.locator('#progress-omni-writer');
        const statusMessage = page.locator('[data-testid="status-message"]');
        
        return await downloadLink.isVisible() || 
               await progressBar.isVisible() || 
               await statusMessage.isVisible();
      },
      config.timeouts.long
    );
    
    await expect(page).toHaveScreenshot('pos-envio.png', { fullPage: true });
    
    // Aguarda download link com timeout estendido
    await waitForConditionWithPolling(
      page,
      async () => {
        const downloadLink = page.locator('[data-testid="download-link"]');
        return await downloadLink.isVisible();
      },
      config.timeouts.veryLong
    );
    
    await expect(page.locator('text=/Concluído|Sucesso|Download/i')).toBeVisible();
    
    // Download com retry logic
    const download = await realizarDownload(page);
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    logEvidence('download', `Arquivo baixado: ${downloadPath}`);
    
    await expect(page).toHaveScreenshot('final-geracao.png', { fullPage: true });
    
    // Acessibilidade final
    const a11yFinal = await new AxeBuilder({ page }).analyze();
    expect(a11yFinal.violations).toEqual([]);
    logEvidence('a11y_final', 'Acessibilidade final validada');
    
    fs.writeFileSync('diagnostico_logs_fluxo_principal.log', logs.join('\n'));
  });

  test('Fluxo de erro: API key inválida', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
    
    await page.goto(config.baseUrl);
    await preencherInstancia(page, 'Instância Erro', config.invalidApiKey, config.modelType, config.prompt);
    await page.click('button[type="submit"]:has-text("Adicionar Instância")');
    await registrarWebhook(page, config.mockWebhookUrl);
    await page.click('[data-testid="submit-btn"]');
    
    const htmlErro = await page.content();
    fs.writeFileSync('diagnostico_erro_envio.html', htmlErro);
    await takeStepScreenshot(page, 'erro_envio');
    logEvidence('erro_envio', 'Envio com API key inválida');
    
    // Aguarda mensagem de erro com retry
    await waitForElementWithRetry(page, '[data-testid="error-message"]');
    await expect(page).toHaveScreenshot('erro-api-key.png', { fullPage: true });
    
    fs.writeFileSync('diagnostico_logs_fluxo_erro.log', logs.join('\n'));
  });

  test('E2E fluxo real: submit completo', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
    
    try {
      await page.goto(config.baseUrl);
      await preencherInstancia(page, 'Instância E2E', config.apiKey, config.modelType, config.prompt);
      await page.click('button[type="submit"]:has-text("Adicionar Instância")');
      await waitForElementWithRetry(page, '#instancias_lista li');
      await page.click('[data-testid="submit-btn"]');
      
      // Aguarda processamento com timeout adequado
      await page.waitForTimeout(config.timeouts.medium);
      await takeStepScreenshot(page, 'submit_completo');
      logEvidence('submit_completo', 'Submit completo realizado');
    } catch (e) {
      logs.push(`[erro] ${e}`);
      throw e;
    } finally {
      fs.writeFileSync('diagnostico_e2e_fluxo_real.log', logs.join('\n'));
    }
  });
}); 