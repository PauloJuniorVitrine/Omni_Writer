import { test, expect } from '@playwright/test';

// Jornada real: Feedback de Artigos
// Fluxo baseado em /feedback
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Feedback de Artigos', () => {
  test('Fluxo principal de feedback', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de feedback
    await page.goto('/feedback');
    // Preencher e enviar feedback
    await page.fill('textarea[name="comentario"]', 'Ótimo artigo!');
    await page.click('button#enviar-feedback');
    // Validar confirmação
    await expect(page.locator('text=Feedback enviado')).toBeVisible();
  });
  // Ramificações: feedback inválido, artigo inexistente
}); 