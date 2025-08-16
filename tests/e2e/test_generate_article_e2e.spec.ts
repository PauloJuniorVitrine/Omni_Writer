/**
 * Teste E2E: Geração de Artigos
 * - Valida sucesso, falha de validação, falha de API, multi-instância
 * - Garante persistência, side effects, acessibilidade, screenshots e logs
 */
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

/**
 * Teste E2E: Geração de Conteúdo
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-07-13T13:30:22.423Z
 * **Tracing ID:** E2E_TEST_GENERATE_ARTICLE_E2E.SPEC_md1ppemv
 * **Origem:** app/services/generation_service.py
 * 
 * Testes end-to-end baseados em código real da aplicação Omni Writer
 */


// Configurações
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5000';

// Utilitário para screenshot e log
async function takeStepScreenshot(page, step) {
  await page.screenshot({ path: `tests/e2e/snapshots/generate_article/${step}.png`, fullPage: true });
}
function logEvidence(step, data) {
  fs.appendFileSync('tests/e2e/E2E_LOG.md', `\n[${new Date().toISOString()}] [generate_article/${step}] ${data}`);
}

test.describe('Jornada E2E: Geração de Artigos', () => {
  test('Fluxo principal de sucesso', async ({ page }) => {
    await page.goto(BASE_URL);
    await takeStepScreenshot(page, 'inicio');
    logEvidence('inicio', 'Página inicial carregada');
    // Preenche prompts e configurações
    await page.fill('textarea[name="prompts"]', 'Prompt E2E Playwright');
    await page.selectOption('select[name="model_type"]', 'openai');
    await takeStepScreenshot(page, 'pre_submit');
    logEvidence('pre_submit', 'Prompts e modelo preenchidos');
    // Submete geração
    await page.click('button[type="submit"]');
    // Aguarda link de download
    await page.waitForSelector('a[href*="download"]', { timeout: 60000 });
    await takeStepScreenshot(page, 'pos_submit');
    logEvidence('pos_submit', 'Link de download visível');
    // Valida DOM
    const downloadLink = await page.getByRole('link', { name: /download/i });
    await expect(downloadLink).toBeVisible();
    // Valida persistência (simples: link existe)
    const href = await downloadLink.getAttribute('href');
    expect(href).toContain('/download');
    // Baixa arquivo ZIP
    const [ download ] = await Promise.all([
      page.waitForEvent('download'),
      downloadLink.click()
    ]);
    const path = await download.path();
    expect(path).toBeTruthy();
    logEvidence('download', `Arquivo baixado: ${path}`);
    await takeStepScreenshot(page, 'download');
    // Valida acessibilidade
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
    expect(accessibilityScanResults.violations).toEqual([]);
    logEvidence('a11y', 'Acessibilidade validada');
  });

  test('Falha de validação de prompt', async ({ page }) => {
    await page.goto(BASE_URL);
    await page.fill('textarea[name="prompts"]', '');
    await page.click('button[type="submit"]');
    await expect(page.getByText(/prompts obrigatórios/i)).toBeVisible();
    await takeStepScreenshot(page, 'falha_validacao');
    logEvidence('falha_validacao', 'Validação de prompt obrigatória acionada');
  });

  test('Falha de geração (API externa indisponível)', async ({ page }) => {
    await page.goto(BASE_URL);
    await page.fill('textarea[name="prompts"]', 'Prompt E2E Falha');
    await page.selectOption('select[name="model_type"]', 'openai');
    // Simula indisponibilidade via mock/test (exemplo: intercepta request) - Omni Writer E2E Test
    await page.route('**/v1/chat/completions', route => route.abort());
    await page.click('button[type="submit"]');
    await expect(page.getByText(/erro ao gerar artigos/i)).toBeVisible();
    await takeStepScreenshot(page, 'falha_geracao');
    logEvidence('falha_geracao', 'Falha simulada de API externa');
  });

  test('Geração multi-instância', async ({ page }) => {
    await page.goto(BASE_URL);
    await page.fill('textarea[name="prompts"]', 'Prompt 1\nPrompt 2');
    await page.selectOption('select[name="model_type"]', 'deepseek');
    await takeStepScreenshot(page, 'multi_pre_submit');
    logEvidence('multi_pre_submit', 'Multi-instância preenchida');
    await page.click('button[type="submit"]');
    await page.waitForSelector('a[href*="download"]', { timeout: 60000 });
    await takeStepScreenshot(page, 'multi_pos_submit');
    logEvidence('multi_pos_submit', 'Link de download multi visível');
    const downloadLink = await page.getByRole('link', { name: /download/i });
    await expect(downloadLink).toBeVisible();
  });
}); 