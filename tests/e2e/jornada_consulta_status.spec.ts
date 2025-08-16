import { test, expect } from '@playwright/test';

// Jornada real: Consulta de Status
// Fluxo baseado em /status/<trace_id>
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Consulta de Status', () => {
  test('Fluxo principal de consulta de status', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de status
    await page.goto('/status/traceid123');
    // Validar status de geração
    await expect(page.locator('text=Status da geração')).toBeVisible();
    // (Não executa polling real neste ciclo)
  });
  // Ramificações: trace ID inexistente
}); 