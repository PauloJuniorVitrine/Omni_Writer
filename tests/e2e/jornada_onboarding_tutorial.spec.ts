import { test, expect } from '@playwright/test';

// Jornada real: Onboarding/Tutorial Visual
// Fluxo baseado em /onboarding, interações de UI
// Referência: static/js/handlers.js, ui/components/Onboarding

test.describe('Jornada: Onboarding/Tutorial Visual', () => {
  test('Fluxo principal do tour guiado', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Iniciar onboarding
    await page.goto('/onboarding');
    await expect(page.locator('text=Boas-vindas')).toBeVisible();
    // Navegar entre passos do tour
    await page.click('button#avancar');
    await expect(page.locator('text=Passo 2')).toBeVisible();
    await page.click('button#avancar');
    await expect(page.locator('text=Passo 3')).toBeVisible();
    // Finalizar tour
    await page.click('button#finalizar');
    await expect(page.locator('text=Onboarding finalizado')).toBeVisible();
  });
  // Ramificações: pular passos, fechar tour antes do fim
}); 