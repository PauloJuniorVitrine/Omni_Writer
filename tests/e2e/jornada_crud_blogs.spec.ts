import { test, expect } from '@playwright/test';

// Jornada real: CRUD de Blogs
// Fluxo baseado em /blogs, /api/blogs, interações de frontend
// Referência: static/js/handlers.js, app/routes.py

test.describe('Jornada: CRUD de Blogs', () => {
  test('Fluxo de criação, edição e exclusão de blog', async ({ page }) => {
    // Login real
    await page.goto('/login');
    await page.fill('input[name="usuario"]', 'usuario1');
    await page.fill('input[name="senha"]', 'usuario123');
    await page.click('button#entrar');
    await expect(page.locator('text=Painel')).toBeVisible();

    // Acessar página de blogs
    await page.goto('/blogs');
    // Criar novo blog
    await page.click('button#novo-blog');
    await page.fill('input[name="nome_blog"]', 'Blog Teste E2E');
    await page.fill('input[name="descricao_blog"]', 'Blog criado via teste E2E');
    await page.click('button#salvar-blog');
    await expect(page.locator('text=Blog Teste E2E')).toBeVisible();

    // Editar blog
    await page.click('button#editar-blog');
    await page.fill('input[name="nome_blog"]', 'Blog Teste E2E Editado');
    await page.click('button#salvar-blog');
    await expect(page.locator('text=Blog Teste E2E Editado')).toBeVisible();

    // Excluir blog
    await page.click('button#excluir-blog');
    await page.click('button#confirmar-exclusao');
    await expect(page.locator('text=Blog Teste E2E Editado')).not.toBeVisible();
  });
  // Ramificações: criação inválida, edição/exclusão de blog inexistente
}); 