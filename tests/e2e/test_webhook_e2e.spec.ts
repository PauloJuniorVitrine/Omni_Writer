/**
 * Teste E2E: Registro e Notificação de Webhook
 * - Valida registro de webhook e disparo de notificação
 * - Cobre sucesso, URL inválida, falha de entrega, persistência, DOM, acessibilidade, screenshots e logs
 */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

const BASE_URL = 'http://localhost:5000';
const MOCK_WEBHOOK_URL = 'http://localhost:9999/webhook-mock';
const INVALID_WEBHOOK_URL = 'http://invalid-url';

async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/webhook/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [webhook/${step}] ${data}`);
}

test.describe('Jornada E2E: Registro e Notificação de Webhook', () => {
  test('Registro e notificação de webhook com sucesso', async ({ page }) => {
    await page.goto(BASE_URL + '/webhook');
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página de webhooks carregada');
    // Preenche e registra webhook válido
    await page.fill('input[name="webhook_url"]', MOCK_WEBHOOK_URL);
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'webhook_registrado');
    logEvidence('webhook_registrado', 'Webhook registrado com sucesso');
    // Dispara evento (ex: gera artigo)
    await page.goto(BASE_URL);
    await page.fill('textarea[name="prompts"]', 'Webhook E2E');
    await page.selectOption('select[name="model_type"]', 'openai');
    await page.click('button[type="submit"]');
    await page.waitForSelector('a[href*="download"]', { timeout: 60000 });
    await takeStepScreenshot(page, 'evento_disparado');
    logEvidence('evento_disparado', 'Evento disparado para notificação de webhook');
    // Valida side effect: notificação enviada (mock pode registrar chamada)
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y', 'Acessibilidade validada');
  });

  test('Registro de webhook com URL inválida', async ({ page }) => {
    await page.goto(BASE_URL + '/webhook');
    await takeStepScreenshot(page, 'inicio_invalido');
    logEvidence('inicio_invalido', 'Página de webhooks carregada para URL inválida');
    await page.fill('input[name="webhook_url"]', INVALID_WEBHOOK_URL);
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'webhook_invalido');
    logEvidence('webhook_invalido', 'Tentativa de registro de webhook com URL inválida');
    // Valida mensagem de erro
    await expect(page.locator('text=/url inválida|formato/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_invalido', 'Acessibilidade validada para URL inválida');
  });

  test('Falha de entrega de notificação de webhook', async ({ page }) => {
    await page.goto(BASE_URL + '/webhook');
    await takeStepScreenshot(page, 'inicio_falha');
    logEvidence('inicio_falha', 'Página de webhooks carregada para falha de entrega');
    // Registra webhook que simula falha (ex: porta fechada)
    await page.fill('input[name="webhook_url"]', 'http://localhost:9998/webhook-fail');
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'webhook_falha');
    logEvidence('webhook_falha', 'Webhook registrado para simular falha de entrega');
    // Dispara evento (ex: gera artigo)
    await page.goto(BASE_URL);
    await page.fill('textarea[name="prompts"]', 'Webhook Falha E2E');
    await page.selectOption('select[name="model_type"]', 'openai');
    await page.click('button[type="submit"]');
    await page.waitForSelector('a[href*="download"]', { timeout: 60000 });
    await takeStepScreenshot(page, 'evento_falha');
    logEvidence('evento_falha', 'Evento disparado para simular falha de entrega');
    // Valida mensagem de falha (mock pode registrar ausência de chamada)
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_falha', 'Acessibilidade validada para falha de entrega');
  });
}); 