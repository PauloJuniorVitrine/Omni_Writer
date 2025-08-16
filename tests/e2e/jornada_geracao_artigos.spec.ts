import { test, expect } from '@playwright/test';
import { A11YCoverageValidator } from './utils/a11y-coverage-validator';

// Jornada real: Geração de Artigos
// Fluxo baseado em /generate (POST), /status/<trace_id>, /download
// Referência: app/routes.py, AuthContext.tsx, handlers.js

test.describe('Jornada: Geração de Artigos', () => {
  let a11yValidator: A11YCoverageValidator;

  test.beforeEach(async ({ page }) => {
    a11yValidator = new A11YCoverageValidator();
  });

  test('Fluxo principal de geração', async ({ page }) => {
    // Login real
    await test.step('Login e autenticação', async () => {
      await page.goto('/login');
      await page.fill('input[name="usuario"]', 'usuario1');
      await page.fill('input[name="senha"]', 'usuario123');
      await page.click('button#entrar');
      await expect(page.locator('text=Painel')).toBeVisible();

      // Validação A11Y - Login
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Jornada Geração - Login coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });

    // Preencher prompts e configurações
    await test.step('Preenchimento de formulário', async () => {
      await page.goto('/');
      await page.fill('textarea[name="prompt"]', 'Exemplo de prompt real');
      await page.selectOption('select[name="modelo"]', 'openai');
      await page.click('button#gerar-artigos');

      // Validação A11Y - Formulário de Geração
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Jornada Geração - Formulário coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });

    // Aguardar processamento e status
    await test.step('Processamento e status', async () => {
      await expect(page.locator('text=Processando')).toBeVisible();
      // Simular polling de status
      await page.waitForSelector('a#download-link', { timeout: 60000 });

      // Validação A11Y - Status de Processamento
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Jornada Geração - Status coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });

    // Download do ZIP
    // (Não executa download real neste ciclo)
    // const [ download ] = await Promise.all([
    //   page.waitForEvent('download'),
    //   page.click('a#download-link')
    // ]);
    // expect(download.suggestedFilename()).toMatch(/\.zip$/);

    // Validação de logs e side effects
    await test.step('Logs e side effects', async () => {
      await page.goto('/logs');
      await expect(page.locator('text=geracao')).toBeVisible();

      // Validação A11Y - Página de Logs
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Jornada Geração - Logs coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });

    // Acessibilidade básica
    await test.step('Validação de acessibilidade', async () => {
      await expect(page.locator('button#gerar-artigos')).toBeVisible();
      await expect(page.locator('button#gerar-artigos')).toBeEnabled();

      // Validação A11Y - Elementos Interativos
      const a11yReport = await a11yValidator.generateA11YReport(page, page.url());
      console.log(`[A11Y] Jornada Geração - Elementos Interativos coverage: ${a11yReport.coverageScore}%`);
      expect(a11yReport.coverageScore).toBeGreaterThanOrEqual(90);
      expect(a11yReport.overallStatus).not.toBe('critical');
    });
  });
  // Ramificações e variações podem ser descritas em outros testes
}); 