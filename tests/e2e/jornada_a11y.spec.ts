import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('Jornada de acessibilidade completa (a11y)', async ({ page }) => {
  await page.goto('/');
  // Navegação por teclado
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus-visible')).toBeVisible();
  // Valida contraste e labels ARIA
  const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
  expect(accessibilityScanResults.violations).toEqual([]);
}); 