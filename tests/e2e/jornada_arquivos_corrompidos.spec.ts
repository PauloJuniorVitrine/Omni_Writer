import { test, expect } from '@playwright/test';

test('Jornada de manipulação de arquivos corrompidos', async ({ page }) => {
  await page.goto('/artigos');
  // Simula geração de artigo
  await page.click('button#gerar-artigo');
  // Corrompe arquivo no backend (mock/fake)
  await page.route('/download', route => route.fulfill({ status: 500, body: 'Arquivo corrompido' }));
  await page.click('button#baixar-artigo');
  await expect(page.locator('.alert-error')).toHaveText(/corrompido|erro/i);
}); 