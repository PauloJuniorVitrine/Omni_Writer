import { test, expect } from '@playwright/test';

// Jornada real: Exportação de Artigos em CSV
// Fluxo baseado em /export_artigos_csv
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Exportação de Artigos em CSV', () => {
  test('Fluxo principal de exportação', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de exportação
    await page.goto('/export_artigos_csv');
    // Validar existência do botão/link de exportação
    await expect(page.locator('button#exportar-artigos-csv')).toBeVisible();
    // (Não executa exportação real neste ciclo)
  });
  // Ramificações: nenhum artigo disponível
}); 