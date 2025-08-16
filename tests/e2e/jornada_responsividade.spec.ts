import { test, expect, devices } from '@playwright/test';

// Jornada real: Responsividade Multi-Dispositivo
// Fluxo cobre mobile, tablet e desktop
// Referência: docs/interface_fluxo_ux.json, ui/pages/*

const viewports = [
  { name: 'mobile', options: devices['Pixel 5'] },
  { name: 'tablet', options: devices['iPad (gen 7)'] },
  { name: 'desktop', options: { viewport: { width: 1920, height: 1080 } } }
];

for (const vp of viewports) {
  test.describe(`Jornada: Responsividade em ${vp.name}`, () => {
    test.use(vp.options);
    test(`Fluxo principal (${vp.name})`, async ({ page }) => {
      // Login real
      await page.goto('/login');
      await page.fill('input[name="usuario"]', 'usuario1');
      await page.fill('input[name="senha"]', 'usuario123');
      await page.click('button#entrar');
      await expect(page.locator('text=Painel')).toBeVisible();

      // Acessar página inicial e validar layout
      await page.goto('/');
      await expect(page.locator('header')).toBeVisible();
      await expect(page.locator('nav')).toBeVisible();
      // Validar responsividade de cards, botões, menus
      await expect(page.locator('button#gerar-artigos')).toBeVisible();
      // (Captura de screenshot pode ser feita manualmente)
    });
    // Ramificações: quebra de layout, elementos sobrepostos
  });
} 