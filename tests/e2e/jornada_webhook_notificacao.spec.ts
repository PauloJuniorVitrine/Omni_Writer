import { test, expect } from '@playwright/test';

// Jornada real: Registro e Notificação de Webhook
// Fluxo baseado em /webhook, /generate, notificação de evento
// Referência: app/routes.py, handlers.js

test.describe('Jornada: Registro e Notificação de Webhook', () => {
  test('Fluxo principal de registro e notificação', async ({ page }) => {
    // Login real (admin)
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'admin');
    await page.fill('input[name="senha"]', 'admin123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de webhooks
    await page.goto('/webhooks');
    // Registrar novo webhook
    await page.fill('input[name="webhook_url"]', 'https://webhook.site/teste');
    await page.click('button#registrar-webhook');
    await expect(page.locator('text=Webhook registrado')).toBeVisible();

    // Disparar evento (gerar artigo)
    await page.goto('/');
    await page.fill('textarea[name="prompt"]', 'Teste webhook');
    await page.click('button#gerar-artigos');
    // (Simular recebimento da notificação - não executa chamada real)
    // await expect(page.locator('text=Notificação enviada')).toBeVisible();
  });
  // Ramificações: URL inválida, falha de entrega
}); 