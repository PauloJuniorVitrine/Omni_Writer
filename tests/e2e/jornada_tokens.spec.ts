import { test, expect } from '@playwright/test';

// Jornada real: Rotação e Revogação de Tokens
// Fluxo baseado em /tokens, /token/rotate, interações de UI
// Referência: ui/context/AuthContext.tsx, static/js/handlers.js

test.describe('Jornada: Rotação e Revogação de Tokens', () => {
  test('Fluxo de rotação e revogação de token', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de tokens
    await page.goto('/tokens');
    // Rotacionar token
    await page.click('button#rotacionar-token');
    await expect(page.locator('text=Token rotacionado')).toBeVisible();
    // Revogar token
    await page.click('button#revogar-token');
    await expect(page.locator('text=Token revogado')).toBeVisible();
  });
  // Ramificações: token inválido, erro de permissão
}); 