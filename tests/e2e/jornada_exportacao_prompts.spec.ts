import { test, expect } from '@playwright/test';

// Jornada real: Exportação de Prompts
// Fluxo baseado em /export_prompts
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Exportação de Prompts', () => {
  test('Fluxo principal de exportação', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de exportação
    await page.goto('/export_prompts');
    // Validar existência do botão/link de exportação
    await expect(page.locator('button#exportar-prompts')).toBeVisible();
    // (Não executa exportação real neste ciclo)
  });
  // Ramificações: nenhum prompt disponível
}); 