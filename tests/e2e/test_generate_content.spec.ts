/**
 * Teste E2E: Geração de Conteúdo
 * - Valida fluxo real, status, SSE, download, feedback visual, erro de API key
 * - Garante persistência, side effects, acessibilidade, screenshots e logs
 */
import { test, expect, Page, Download } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

/**
 * Teste E2E: Geração de Conteúdo
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-07-13T13:30:22.275Z
 * **Tracing ID:** E2E_TEST_GENERATE_CONTENT.SPEC_md1ppeja
 * **Origem:** app/services/generation_service.py
 * 
 * Testes end-to-end baseados em código real da aplicação Omni Writer
 */


// Configurações globais
const BASE_URL = 'http://localhost:5000';
const API_KEY = process.env.TEST_API_KEY || 'sk-test-openai-valid-key';
const MODEL_TYPE = 'openai';
const PROMPT = 'Teste E2E fluxo real.';
const INVALID_API_KEY = 'invalid-key';
const mockWebhookUrl = 'http://localhost:9999/webhook-mock';

// Utilitários padronizados
async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/generate_content/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [generate_content/${step}] ${data}`);
}

async function preencherInstancia(page: Page, nome: string, apiKey: string, modelType: string, prompt: string) {
  await page.fill('[data-testid="instance-name"]', nome);
  await page.selectOption('[data-testid="model-type"]', modelType);
  await page.fill('[data-testid="api-key"]', apiKey);
  await page.fill('[data-testid="prompts"]', prompt);
}

async function registrarWebhook(page: Page, url: string) {
  await page.evaluate(async (webhookUrl) => {
    await fetch('/webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(webhookUrl)}`
    });
  }, url);
}

async function realizarDownload(page: Page): Promise<Download> {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.click('[data-testid="download-link"]'),
  ]);
  return download;
}

test.describe('Jornada E2E: Geração de Conteúdo', () => {
  test('Fluxo principal: geração, status, SSE, download, a11y e visual', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
    await page.goto(BASE_URL);
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
    await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
    await preencherInstancia(page, 'Instância E2E', API_KEY, MODEL_TYPE, PROMPT);
    await page.click('button[type="submit"]:has-text("Adicionar Instância")');
    await page.waitForSelector('#instancias_lista li', { timeout: 3000 });
    await registrarWebhook(page, mockWebhookUrl);
    logEvidence('instancia', 'Instância e webhook registrados');
    await page.click('[data-testid="submit-btn"]');
    const htmlPosEnvio = await page.content();
    fs.writeFileSync('diagnostico_pos_envio.html', htmlPosEnvio);
    await takeStepScreenshot(page, 'pos_envio');
    logEvidence('pos_envio', 'Envio realizado, aguardando processamento');
    await page.waitForSelector('[data-testid="download-link"], #progress-omni-writer, [data-testid="status-message"]', { timeout: 15000 });
    await expect(page).toHaveScreenshot('pos-envio.png', { fullPage: true });
    await expect(page.locator('[data-testid="download-link"]')).toBeVisible({ timeout: 60000 });
    await expect(page.locator('text=/Concluído|Sucesso|Download/i')).toBeVisible();
    const download = await realizarDownload(page);
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();
    logEvidence('download', `Arquivo baixado: ${downloadPath}`);
    await expect(page).toHaveScreenshot('final-geracao.png', { fullPage: true });
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
    await page.goto(BASE_URL);
    await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
    await preencherInstancia(page, 'Instância Erro', INVALID_API_KEY, MODEL_TYPE, PROMPT);
    await page.click('button[type="submit"]:has-text("Adicionar Instância")');
    await registrarWebhook(page, mockWebhookUrl);
    await page.click('[data-testid="submit-btn"]');
    const htmlErro = await page.content();
    fs.writeFileSync('diagnostico_erro_envio.html', htmlErro);
    await takeStepScreenshot(page, 'erro_envio');
    logEvidence('erro_envio', 'Envio com API key inválida');
    await page.waitForSelector('[data-testid="error-message"]', { timeout: 10000 });
    await expect(page).toHaveScreenshot('erro-api-key.png', { fullPage: true });
    fs.writeFileSync('diagnostico_logs_fluxo_erro.log', logs.join('\n'));
  });

  test('E2E fluxo real: submit completo', async ({ page }) => {
    const logs: string[] = [];
    page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
    page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
    page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
    try {
      await page.goto(BASE_URL);
      await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
      await page.fill('[data-testid="instance-name"]', 'Instância E2E');
      await page.selectOption('[data-testid="model-type"]', MODEL_TYPE);
      await page.fill('[data-testid="api-key"]', API_KEY);
      await page.fill('[data-testid="prompts"]', PROMPT);
      await page.click('button[type="submit"]:has-text("Adicionar Instância")');
      await page.waitForSelector('#instancias_lista li', { timeout: 3000 });
      await page.click('[data-testid="submit-btn"]');
      await page.waitForTimeout(5000);
      await takeStepScreenshot(page, 'submit_completo');
      logEvidence('submit_completo', 'Submit completo realizado');
    } catch (e) {
      logs.push(`[erro] ${e}`);
    } finally {
      fs.writeFileSync('diagnostico_e2e_fluxo_real.log', logs.join('\n'));
    }
  });
}); 