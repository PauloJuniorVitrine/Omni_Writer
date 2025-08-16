import { test, expect } from '@playwright/test';

test('Jornada de atualização em tempo real via SSE com múltiplos clientes', async ({ browser }) => {
  const context1 = await browser.newContext();
  const context2 = await browser.newContext();
  const page1 = await context1.newPage();
  const page2 = await context2.newPage();
  await page1.goto('/eventos');
  await page2.goto('/eventos');
  // Dispara evento
  await page1.click('button#disparar-evento');
  // Valida recebimento simultâneo
  await expect(page1.locator('.evento-recebido')).toBeVisible();
  await expect(page2.locator('.evento-recebido')).toBeVisible();
  await context1.close();
  await context2.close();
}); 