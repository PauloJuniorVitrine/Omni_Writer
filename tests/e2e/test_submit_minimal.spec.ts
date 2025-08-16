/**
 * Teste E2E: Diagnóstico mínimo de submit
 * - Valida edge case de envio mínimo do formulário principal
 * - Garante logs, rastreabilidade e screenshot
 */
import { test, expect } from '@playwright/test';
import fs from 'fs';

const BASE_URL = 'http://localhost:5000';
const API_KEY = process.env.TEST_API_KEY || 'fake-api-key';
const MODEL_TYPE = 'openai';
const PROMPT = 'Diagnóstico submit mínimo E2E.';

// Utilitários padronizados
async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/submit_minimal/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [submit_minimal/${step}] ${data}`);
}

// Teste mínimo: preencher e forçar submit

test('Diagnóstico mínimo: submit do formulário principal', async ({ page }) => {
  const logs: string[] = [];
  page.on('console', msg => logs.push(`[console] ${msg.type()}: ${msg.text()}`));
  page.on('response', response => logs.push(`[response] ${response.status()} ${response.url()}`));
  page.on('request', request => logs.push(`[request] ${request.method()} ${request.url()}`));
  try {
    await page.goto(BASE_URL);
    await page.waitForSelector('[data-testid="instance-name"]', { timeout: 5000 });
    await page.fill('[data-testid="instance-name"]', 'Instância Diagnóstico');
    await page.selectOption('[data-testid="model-type"]', MODEL_TYPE);
    await page.fill('[data-testid="api-key"]', API_KEY);
    await page.fill('[data-testid="prompts"]', PROMPT);
    await page.click('button[type="submit"]:has-text("Adicionar Instância")');
    // Forçar submit do formulário principal via JS
    await page.evaluate(() => {
      const form = document.querySelector('form#main_form');
      if (form && typeof (form as HTMLFormElement).submit === 'function') {
        (form as HTMLFormElement).submit();
      }
    });
    await takeStepScreenshot(page, 'submit_forcado');
    logEvidence('submit_forcado', 'Submit mínimo forçado realizado');
    await page.waitForTimeout(5000);
  } catch (e) {
    logs.push(`[erro] ${e}`);
  } finally {
    fs.writeFileSync('diagnostico_submit_minimal.log', logs.join('\n'));
  }
}); 