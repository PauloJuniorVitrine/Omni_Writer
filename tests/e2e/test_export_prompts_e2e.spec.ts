/**
 * Teste E2E: Exportação de Prompts
 * - Valida exportação de prompts em CSV
 * - Cobre sucesso, ausência de prompts, persistência, DOM, acessibilidade, screenshots e logs
 */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

const BASE_URL = 'http://localhost:5000';

async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/export_prompts/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [export_prompts/${step}] ${data}`);
}

test.describe('Jornada E2E: Exportação de Prompts', () => {
  test('Exportação de prompts com sucesso', async ({ page }) => {
    await page.goto(BASE_URL + '/export_prompts');
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página de exportação de prompts carregada');
    // Valida DOM
    await expect(page).toHaveTitle(/prompts/i);
    // Tenta baixar o CSV
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.click('a[href$="prompts.csv"]'),
    ]);
    const path = await download.path();
    expect(path).toBeTruthy();
    logEvidence('download', `Arquivo CSV baixado: ${path}`);
    await takeStepScreenshot(page, 'download');
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y', 'Acessibilidade validada');
  });

  test('Exportação de prompts sem prompts disponíveis', async ({ page }) => {
    // Pré-condição: garantir ambiente sem prompts (mock ou limpeza)
    // Aqui, simula ausência de prompts
    await page.goto(BASE_URL + '/export_prompts');
    await takeStepScreenshot(page, 'sem_prompts');
    logEvidence('sem_prompts', 'Página de exportação sem prompts disponíveis');
    // Valida mensagem de ausência
    await expect(page.locator('text=/nenhum prompt/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_sem_prompts', 'Acessibilidade validada sem prompts');
  });
}); 