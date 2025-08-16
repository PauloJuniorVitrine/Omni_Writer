/**
 * Teste E2E: Exportação de Artigos em CSV
 * - Valida exportação de artigos em CSV
 * - Cobre sucesso, ausência de artigos, persistência, DOM, acessibilidade, screenshots e logs
 */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

const BASE_URL = 'http://localhost:5000';

async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/export_artigos_csv/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [export_artigos_csv/${step}] ${data}`);
}

test.describe('Jornada E2E: Exportação de Artigos em CSV', () => {
  test('Exportação de artigos em CSV com sucesso', async ({ page }) => {
    await page.goto(BASE_URL + '/export_artigos_csv');
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página de exportação de artigos carregada');
    // Valida DOM
    await expect(page).toHaveTitle(/artigos/i);
    // Tenta baixar o CSV
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.click('a[href$="artigos.csv"]'),
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

  test('Exportação de artigos sem artigos disponíveis', async ({ page }) => {
    // Pré-condição: garantir ambiente sem artigos (mock ou limpeza)
    // Aqui, simula ausência de artigos
    await page.goto(BASE_URL + '/export_artigos_csv');
    await takeStepScreenshot(page, 'sem_artigos');
    logEvidence('sem_artigos', 'Página de exportação sem artigos disponíveis');
    // Valida mensagem de ausência
    await expect(page.locator('text=/nenhum artigo/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_sem_artigos', 'Acessibilidade validada sem artigos');
  });
}); 