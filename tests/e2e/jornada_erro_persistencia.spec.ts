import { test, expect } from '@playwright/test';

test('Jornada de erro de persistência ao salvar blog', async ({ page }) => {
  await page.goto('/blogs');
  await page.click('button#novo-blog');
  await page.fill('input[name="nome"]', 'Blog com erro');
  await page.fill('input[name="desc"]', 'Descrição');
  // Simula falha de backend (mock/fake)
  await page.route('/api/blogs', route => route.abort());
  await page.click('button#salvar');
  await expect(page.locator('.alert-error')).toHaveText(/erro/i);
  // Valida que não houve persistência
  await page.reload();
  await expect(page.locator('text=Blog com erro')).toHaveCount(0);
}); 