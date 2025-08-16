import { test, expect } from '@playwright/test';

// Jornada real: Download de Artigos
// Fluxo baseado em /download
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Download de Artigos', () => {
  test('Fluxo principal de download', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de download
    await page.goto('/download');
    // Validar existência do link de download
    await expect(page.locator('a#download-link')).toBeVisible();
    // (Não executa download real neste ciclo)
    // const [ download ] = await Promise.all([
    //   page.waitForEvent('download'),
    //   page.click('a#download-link')
    // ]);
    // expect(download.suggestedFilename()).toMatch(/\.zip$/);
  });
  // Ramificações: arquivo não encontrado, permissão negada
}); 