/**
 * Web Vitals Integration Tests
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md
 * Ruleset: enterprise_control_layer.yaml
 * Execução: 2025-01-28T10:50:00Z
 * 
 * Testes integrados com validação de Web Vitals
 * Baseado em código real da aplicação Omni Writer
 */

import { test, expect } from '@playwright/test';
import { WebVitalsValidator } from '../utils/web-vitals-validator';

const webVitalsValidator = new WebVitalsValidator();

test.describe('Web Vitals Integration Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Configurar timeout aumentado para validação de performance
    test.setTimeout(120000);
  });

  test('Web Vitals - Geração de Artigos', async ({ page }) => {
    console.log('[WEB_VITALS] Testando Web Vitals na geração de artigos');

    // Navegar para página de geração de artigos
    await page.goto('/article-generation');
    await page.waitForSelector('[data-testid="article-generation-form"]');

    // Validar Web Vitals na página inicial
    const initialWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar LCP específico
    const lcpValid = await webVitalsValidator.validateLCP(page);
    expect(lcpValid).toBe(true);

    // Preencher formulário com dados reais
    await page.fill('[data-testid="article-title"]', 'Artigo Teste Web Vitals');
    await page.fill('[data-testid="article-content"]', 'Conteúdo para teste de performance');
    await page.selectOption('[data-testid="article-category"]', 'Tecnologia');

    // Validar Web Vitals após interação
    const interactionWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar FID após interação
    const fidValid = await webVitalsValidator.validateFID(page);
    expect(fidValid).toBe(true);

    // Submeter geração
    await page.click('[data-testid="submit-article"]');
    await page.waitForSelector('[data-testid="generation-progress"]');

    // Validar Web Vitals durante geração
    const generationWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar TTI durante geração
    const ttiValid = await webVitalsValidator.validateTTI(page);
    expect(ttiValid).toBe(true);

    // Aguardar conclusão
    await page.waitForSelector('[data-testid="generation-complete"]', { timeout: 30000 });

    // Validar Web Vitals final
    const finalWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar CLS final
    const clsValid = await webVitalsValidator.validateCLS(page);
    expect(clsValid).toBe(true);

    // Assertions baseadas em dados reais
    expect(finalWebVitals.isValid).toBe(true);
    expect(finalWebVitals.performanceScore).toBeGreaterThanOrEqual(85);
    expect(finalWebVitals.violations.length).toBe(0);
  });

  test('Web Vitals - CRUD de Blogs', async ({ page }) => {
    console.log('[WEB_VITALS] Testando Web Vitals no CRUD de blogs');

    // Navegar para página de blogs
    await page.goto('/blogs');
    await page.waitForSelector('[data-testid="blogs-page"]');

    // Validar Web Vitals na listagem
    const listWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar FCP na listagem
    const fcpValid = await webVitalsValidator.validateFCP(page);
    expect(fcpValid).toBe(true);

    // Criar novo blog
    await page.click('[data-testid="create-blog-btn"]');
    await page.waitForSelector('[data-testid="blog-form"]');

    // Validar Web Vitals no formulário
    const formWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar TBT no formulário
    const tbtValid = await webVitalsValidator.validateTBT(page);
    expect(tbtValid).toBe(true);

    // Preencher dados reais
    await page.fill('[data-testid="blog-name"]', 'Blog Teste Web Vitals');
    await page.fill('[data-testid="blog-description"]', 'Descrição para teste de performance');
    await page.selectOption('[data-testid="blog-category"]', 'Tecnologia');

    // Salvar blog
    await page.click('[data-testid="save-blog"]');
    await page.waitForSelector('text=Blog criado com sucesso');

    // Validar Web Vitals após criação
    const createWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar SI após criação
    const siValid = await webVitalsValidator.validateSI(page);
    expect(siValid).toBe(true);

    // Assertions baseadas em dados reais
    expect(createWebVitals.isValid).toBe(true);
    expect(createWebVitals.performanceScore).toBeGreaterThanOrEqual(85);
    expect(createWebVitals.violations.length).toBe(0);
  });

  test('Web Vitals - Autenticação', async ({ page }) => {
    console.log('[WEB_VITALS] Testando Web Vitals na autenticação');

    // Navegar para página de login
    await page.goto('/login');
    await page.waitForSelector('[data-testid="login-form"]');

    // Validar Web Vitals na página de login
    const loginWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar LCP no login
    const lcpValid = await webVitalsValidator.validateLCP(page);
    expect(lcpValid).toBe(true);

    // Preencher credenciais reais
    await page.fill('[data-testid="email-input"]', 'test@omniwriter.com');
    await page.fill('[data-testid="password-input"]', 'TestPassword123!');

    // Submeter login
    await page.click('[data-testid="submit-login"]');
    await page.waitForURL('**/dashboard');

    // Validar Web Vitals no dashboard
    const dashboardWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar FID no dashboard
    const fidValid = await webVitalsValidator.validateFID(page);
    expect(fidValid).toBe(true);

    // Assertions baseadas em dados reais
    expect(dashboardWebVitals.isValid).toBe(true);
    expect(dashboardWebVitals.performanceScore).toBeGreaterThanOrEqual(85);
    expect(dashboardWebVitals.violations.length).toBe(0);
  });

  test('Web Vitals - Webhooks', async ({ page }) => {
    console.log('[WEB_VITALS] Testando Web Vitals em webhooks');

    // Navegar para configurações de webhooks
    await page.goto('/webhooks');
    await page.waitForSelector('[data-testid="webhooks-page"]');

    // Validar Web Vitals na página de webhooks
    const webhooksWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar FCP em webhooks
    const fcpValid = await webVitalsValidator.validateFCP(page);
    expect(fcpValid).toBe(true);

    // Criar webhook
    await page.click('[data-testid="create-webhook-btn"]');
    await page.waitForSelector('[data-testid="webhook-form"]');

    // Validar Web Vitals no formulário de webhook
    const formWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar TBT no formulário
    const tbtValid = await webVitalsValidator.validateTBT(page);
    expect(tbtValid).toBe(true);

    // Configurar webhook real
    await page.fill('[data-testid="webhook-url"]', 'https://webhook.site/test-webvitals');
    await page.check('[data-testid="event-article-created"]');
    await page.check('[data-testid="event-blog-updated"]');

    // Salvar webhook
    await page.click('[data-testid="save-webhook"]');
    await page.waitForSelector('text=Webhook criado com sucesso');

    // Validar Web Vitals após criação
    const createWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar SI após criação
    const siValid = await webVitalsValidator.validateSI(page);
    expect(siValid).toBe(true);

    // Assertions baseadas em dados reais
    expect(createWebVitals.isValid).toBe(true);
    expect(createWebVitals.performanceScore).toBeGreaterThanOrEqual(85);
    expect(createWebVitals.violations.length).toBe(0);
  });

  test('Web Vitals - Performance Crítica', async ({ page }) => {
    console.log('[WEB_VITALS] Testando Web Vitals em cenários críticos');

    // Testar carregamento inicial
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Validar todos os Web Vitals críticos
    const criticalWebVitals = await webVitalsValidator.validateAllWebVitals(page);
    
    // Validar LCP crítico
    const lcpValid = await webVitalsValidator.validateLCP(page);
    expect(lcpValid).toBe(true);

    // Validar CLS crítico
    const clsValid = await webVitalsValidator.validateCLS(page);
    expect(clsValid).toBe(true);

    // Validar TTI crítico
    const ttiValid = await webVitalsValidator.validateTTI(page);
    expect(ttiValid).toBe(true);

    // Validar FID crítico
    const fidValid = await webVitalsValidator.validateFID(page);
    expect(fidValid).toBe(true);

    // Validar FCP crítico
    const fcpValid = await webVitalsValidator.validateFCP(page);
    expect(fcpValid).toBe(true);

    // Validar TBT crítico
    const tbtValid = await webVitalsValidator.validateTBT(page);
    expect(tbtValid).toBe(true);

    // Validar SI crítico
    const siValid = await webVitalsValidator.validateSI(page);
    expect(siValid).toBe(true);

    // Assertions críticas baseadas em dados reais
    expect(criticalWebVitals.isValid).toBe(true);
    expect(criticalWebVitals.performanceScore).toBeGreaterThanOrEqual(90);
    expect(criticalWebVitals.violations.length).toBe(0);
    expect(criticalWebVitals.metrics.lcp).toBeLessThanOrEqual(2500);
    expect(criticalWebVitals.metrics.cls).toBeLessThanOrEqual(0.1);
    expect(criticalWebVitals.metrics.tti).toBeLessThanOrEqual(3000);
    expect(criticalWebVitals.metrics.fid).toBeLessThanOrEqual(100);
    expect(criticalWebVitals.metrics.fcp).toBeLessThanOrEqual(1800);
    expect(criticalWebVitals.metrics.tbt).toBeLessThanOrEqual(200);
    expect(criticalWebVitals.metrics.si).toBeLessThanOrEqual(3400);
  });
}); 