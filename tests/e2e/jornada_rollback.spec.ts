import { test, expect } from '@playwright/test';

test('Jornada de recuperação após falha (rollback/undo)', async ({ page }) => {
  await page.goto('/artigos');
  await page.click('button#gerar-artigo');
  // Simula falha intermediária (mock/fake)
  await page.route('/api/generate', route => route.abort());
  await page.click('button#confirmar-geracao');
  await expect(page.locator('.alert-error')).toHaveText(/falha|erro/i);
  // Valida rollback visual e ausência de artigo gerado
  await page.goto('/artigos');
  await expect(page.locator('text=Artigo Gerado')).toHaveCount(0);
}); 