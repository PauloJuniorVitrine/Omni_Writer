import { test, expect } from '@playwright/test';

test('Jornada de abuso de API (rate limit, flood, injection)', async ({ page }) => {
  await page.goto('/api/blogs');
  // Flood de requisições
  for (let i = 0; i < 50; i++) {
    await page.evaluate(() => fetch('/api/blogs'));
  }
  // Valida bloqueio por rate limit
  await expect(page.locator('.alert-error')).toHaveText(/limite|rate|bloqueado|429/i);
  // Testa injection
  await page.goto('/api/blogs');
  await page.fill('input[name="nome"]', "<script>alert('xss')</script>");
  await page.click('button#salvar');
  await expect(page.locator('.alert-error')).toHaveText(/invalido|erro|bloqueado/i);
}); 