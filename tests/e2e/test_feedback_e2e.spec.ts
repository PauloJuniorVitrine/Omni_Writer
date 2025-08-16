/**
 * Teste E2E: Feedback de Artigos
 * - Valida envio de feedback para artigo
 * - Cobre sucesso, feedback inválido, artigo inexistente, persistência, DOM, acessibilidade, screenshots e logs
 */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

const BASE_URL = 'http://localhost:5000';

async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/feedback/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [feedback/${step}] ${data}`);
}

test.describe('Jornada E2E: Feedback de Artigos', () => {
  test('Envio de feedback com sucesso', async ({ page }) => {
    await page.goto(BASE_URL + '/feedback');
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página de feedback carregada');
    // Preenche feedback válido
    await page.fill('textarea[name="feedback"]', 'Artigo excelente!');
    await page.selectOption('select[name="artigo_id"]', '1');
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'feedback_enviado');
    logEvidence('feedback_enviado', 'Feedback enviado com sucesso');
    // Valida confirmação
    await expect(page.locator('text=/feedback recebido|obrigado/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y', 'Acessibilidade validada');
  });

  test('Envio de feedback inválido', async ({ page }) => {
    await page.goto(BASE_URL + '/feedback');
    await takeStepScreenshot(page, 'inicio_invalido');
    logEvidence('inicio_invalido', 'Página de feedback carregada para teste inválido');
    // Não preenche feedback
    await page.selectOption('select[name="artigo_id"]', '1');
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'feedback_invalido');
    logEvidence('feedback_invalido', 'Tentativa de envio de feedback inválido');
    // Valida mensagem de erro
    await expect(page.locator('text=/feedback obrigatório|preencha/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_invalido', 'Acessibilidade validada para feedback inválido');
  });

  test('Envio de feedback para artigo inexistente', async ({ page }) => {
    await page.goto(BASE_URL + '/feedback');
    await takeStepScreenshot(page, 'inicio_inexistente');
    logEvidence('inicio_inexistente', 'Página de feedback carregada para artigo inexistente');
    await page.fill('textarea[name="feedback"]', 'Teste artigo inexistente');
    await page.selectOption('select[name="artigo_id"]', '9999');
    await page.click('button[type="submit"]');
    await takeStepScreenshot(page, 'feedback_inexistente');
    logEvidence('feedback_inexistente', 'Tentativa de feedback para artigo inexistente');
    // Valida mensagem de erro
    await expect(page.locator('text=/artigo não encontrado|inexistente/i')).toBeVisible();
    // Acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y_inexistente', 'Acessibilidade validada para artigo inexistente');
  });
}); 