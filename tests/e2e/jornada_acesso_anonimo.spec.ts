import { test, expect } from '@playwright/test';

test('Jornada de acesso anônimo vs autenticado', async ({ page }) => {
  await page.goto('/blogs');
  // Tenta acessar rota protegida sem login
  await page.goto('/api/blogs');
  await expect(page.locator('.alert-error')).toHaveText(/acesso negado|não autorizado|unauthorized/i);
  // Realiza login
  await page.goto('/login');
  await page.fill('input[name="usuario"]', 'usuario1');
  await page.fill('input[name="senha"]', 'senha123');
  await page.click('button#entrar');
  // Acessa novamente
  await page.goto('/api/blogs');
  await expect(page.locator('text=Blogs')).toBeVisible();
}); 