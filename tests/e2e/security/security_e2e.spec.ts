import { test, expect } from '@playwright/test';

/**
 * Testes E2E de Segurança - Omni Writer
 * 
 * Implementa cenários de teste de segurança end-to-end:
 * - Ataques de injeção via interface
 * - Bypass de autenticação
 * - Violações de autorização
 * - Rate limiting na UI
 * - Validação de headers de segurança
 * 
 * Prompt: Testes E2E de Segurança - Item 11
 * Ruleset: Enterprise+ Standards
 * Data/Hora: 2025-01-28T12:00:00Z
 * Tracing ID: ENTERPRISE_20250128_011_E2E
 */

test.describe('🔒 Testes E2E de Segurança', () => {
  test.beforeEach(async ({ page }) => {
    // Configuração de segurança para todos os testes
    await page.setExtraHTTPHeaders({
      'X-Forwarded-For': '192.168.1.100',
      'User-Agent': 'Security-Test-Bot/1.0'
    });
  });

  test('Prevenção de XSS na interface de geração', async ({ page }) => {
    await page.goto('/');
    
    // Testa XSS no campo de prompt
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")',
      '<svg onload=alert("XSS")>',
      '<iframe src=javascript:alert("XSS")></iframe>'
    ];

    for (const payload of xssPayloads) {
      await page.fill('[data-testid="prompt-input"]', payload);
      await page.click('[data-testid="generate-button"]');
      
      // Verifica se o XSS foi bloqueado
      await expect(page.locator('.alert-error')).toHaveText(/invalido|erro|bloqueado/i);
      
      // Verifica se não há alertas JavaScript executados
      const dialogPromise = page.waitForEvent('dialog', { timeout: 1000 }).catch(() => null);
      await page.waitForTimeout(100);
      const dialog = await dialogPromise;
      expect(dialog).toBeNull();
    }
  });

  test('Prevenção de SQL Injection na interface', async ({ page }) => {
    await page.goto('/');
    
    // Testa SQL injection nos campos
    const sqlPayloads = [
      "'; DROP TABLE users; --",
      "' OR 1=1; --",
      "' UNION SELECT * FROM users; --",
      "admin'--",
      "admin'/*",
      "') OR ('1'='1"
    ];

    for (const payload of sqlPayloads) {
      await page.fill('[data-testid="api-key-input"]', payload);
      await page.fill('[data-testid="prompt-input"]', 'Test prompt');
      await page.click('[data-testid="generate-button"]');
      
      // Verifica se foi bloqueado
      await expect(page.locator('.alert-error')).toHaveText(/invalido|erro|bloqueado/i);
    }
  });

  test('Bypass de autenticação via interface', async ({ page }) => {
    // Testa acesso a páginas protegidas sem autenticação
    const protectedPages = [
      '/admin',
      '/config',
      '/users',
      '/logs'
    ];

    for (const pagePath of protectedPages) {
      await page.goto(pagePath);
      
      // Verifica se foi redirecionado para login
      await expect(page).toHaveURL(/login|auth/i);
      
      // Verifica se há mensagem de acesso negado
      await expect(page.locator('body')).toContainText(/acesso negado|não autorizado|login/i);
    }
  });

  test('Violação de autorização via interface', async ({ page }) => {
    // Login como usuário comum
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'user@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('/dashboard');
    
    // Tenta acessar recursos de admin
    const adminResources = [
      '/admin/users',
      '/admin/config',
      '/admin/logs'
    ];

    for (const resource of adminResources) {
      await page.goto(resource);
      
      // Verifica se foi bloqueado
      await expect(page.locator('body')).toContainText(/acesso negado|não autorizado|permissão/i);
    }
  });

  test('Rate limiting na interface', async ({ page }) => {
    await page.goto('/');
    
    // Faz múltiplas requisições rapidamente
    const requests = [];
    for (let i = 0; i < 20; i++) {
      requests.push(
        page.click('[data-testid="generate-button"]').catch(() => {})
      );
    }
    
    await Promise.all(requests);
    
    // Verifica se o rate limiting foi aplicado
    await expect(page.locator('.alert-error')).toHaveText(/limite|rate|bloqueado|429/i);
  });

  test('Validação de headers de segurança', async ({ page }) => {
    const response = await page.goto('/');
    
    // Verifica headers de segurança obrigatórios
    const headers = response?.headers();
    
    expect(headers).toHaveProperty('x-content-type-options');
    expect(headers).toHaveProperty('x-frame-options');
    expect(headers).toHaveProperty('x-xss-protection');
    expect(headers).toHaveProperty('strict-transport-security');
    expect(headers).toHaveProperty('content-security-policy');
    
    // Verifica valores específicos
    expect(headers?.['x-content-type-options']).toBe('nosniff');
    expect(headers?.['x-frame-options']).toBe('DENY');
    expect(headers?.['x-xss-protection']).toBe('1; mode=block');
  });

  test('Prevenção de CSRF na interface', async ({ page }) => {
    await page.goto('/');
    
    // Tenta fazer requisição POST sem CSRF token
    const response = await page.request.post('/api/generate', {
      data: {
        prompt: 'Test prompt',
        api_key: 'test-key'
      }
    });
    
    // Verifica se foi bloqueado por CSRF
    expect(response.status()).toBe(403);
    
    const responseBody = await response.text();
    expect(responseBody).toContain('csrf');
  });

  test('Validação de entrada de arquivos', async ({ page }) => {
    await page.goto('/');
    
    // Testa upload de arquivos maliciosos
    const maliciousFiles = [
      { name: 'test.exe', content: 'malicious content' },
      { name: 'test.php', content: '<?php system($_GET["cmd"]); ?>' },
      { name: 'test.sh', content: '#!/bin/bash\nrm -rf /' },
      { name: 'test.bat', content: '@echo off\ndel /f /s /q C:\\' }
    ];

    for (const file of maliciousFiles) {
      // Simula upload de arquivo
      await page.setInputFiles('[data-testid="file-input"]', {
        name: file.name,
        mimeType: 'application/octet-stream',
        buffer: Buffer.from(file.content)
      });
      
      await page.click('[data-testid="upload-button"]');
      
      // Verifica se foi bloqueado
      await expect(page.locator('.alert-error')).toHaveText(/arquivo invalido|tipo nao permitido|bloqueado/i);
    }
  });

  test('Prevenção de clickjacking', async ({ page }) => {
    // Testa se a página pode ser carregada em iframe
    await page.goto('/');
    
    // Tenta carregar a página em iframe
    await page.evaluate(() => {
      const iframe = document.createElement('iframe');
      iframe.src = window.location.href;
      document.body.appendChild(iframe);
    });
    
    // Verifica se o iframe foi bloqueado
    const iframe = page.locator('iframe');
    await expect(iframe).toHaveCount(0);
  });

  test('Validação de sessão e logout', async ({ page }) => {
    // Login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'user@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('/dashboard');
    
    // Logout
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('/login');
    
    // Tenta acessar página protegida após logout
    await page.goto('/dashboard');
    
    // Verifica se foi redirecionado para login
    await expect(page).toHaveURL(/login/i);
  });

  test('Prevenção de ataques de timing', async ({ page }) => {
    await page.goto('/login');
    
    const validCredentials = { username: 'user@example.com', password: 'password123' };
    const invalidCredentials = { username: 'user@example.com', password: 'wrongpassword' };
    
    const times = [];
    
    // Mede tempo de resposta para credenciais válidas
    for (let i = 0; i < 5; i++) {
      const startTime = Date.now();
      await page.fill('[data-testid="username-input"]', validCredentials.username);
      await page.fill('[data-testid="password-input"]', validCredentials.password);
      await page.click('[data-testid="login-button"]');
      await page.waitForResponse(response => response.url().includes('/login'));
      times.push(Date.now() - startTime);
    }
    
    const avgValidTime = times.reduce((a, b) => a + b, 0) / times.length;
    
    // Mede tempo de resposta para credenciais inválidas
    times.length = 0;
    for (let i = 0; i < 5; i++) {
      const startTime = Date.now();
      await page.fill('[data-testid="username-input"]', invalidCredentials.username);
      await page.fill('[data-testid="password-input"]', invalidCredentials.password);
      await page.click('[data-testid="login-button"]');
      await page.waitForResponse(response => response.url().includes('/login'));
      times.push(Date.now() - startTime);
    }
    
    const avgInvalidTime = times.reduce((a, b) => a + b, 0) / times.length;
    
    // Verifica se a diferença de timing é aceitável (< 100ms)
    const timeDifference = Math.abs(avgValidTime - avgInvalidTime);
    expect(timeDifference).toBeLessThan(100);
  });

  test('Validação de tokens e sessões', async ({ page }) => {
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'user@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('/dashboard');
    
    // Verifica se o token está presente
    const token = await page.evaluate(() => {
      return localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    });
    
    expect(token).toBeTruthy();
    
    // Tenta usar token inválido
    await page.evaluate(() => {
      localStorage.setItem('auth_token', 'invalid-token');
    });
    
    await page.reload();
    
    // Verifica se foi redirecionado para login
    await expect(page).toHaveURL(/login/i);
  });

  test('Prevenção de ataques de força bruta', async ({ page }) => {
    await page.goto('/login');
    
    // Tenta múltiplas vezes com senha incorreta
    for (let i = 0; i < 10; i++) {
      await page.fill('[data-testid="username-input"]', 'user@example.com');
      await page.fill('[data-testid="password-input"]', `wrongpassword${i}`);
      await page.click('[data-testid="login-button"]');
      
      await page.waitForTimeout(100);
    }
    
    // Verifica se a conta foi bloqueada
    await expect(page.locator('.alert-error')).toHaveText(/bloqueado|temporariamente|muitas tentativas/i);
    
    // Tenta com senha correta
    await page.fill('[data-testid="username-input"]', 'user@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // Verifica se ainda está bloqueado
    await expect(page.locator('.alert-error')).toHaveText(/bloqueado|temporariamente/i);
  });

  test('Validação de dados sensíveis na interface', async ({ page }) => {
    await page.goto('/config');
    
    // Verifica se dados sensíveis estão mascarados
    const sensitiveFields = [
      '[data-testid="api-key-display"]',
      '[data-testid="password-display"]',
      '[data-testid="secret-display"]'
    ];

    for (const field of sensitiveFields) {
      const element = page.locator(field);
      if (await element.count() > 0) {
        const text = await element.textContent();
        expect(text).toMatch(/\*{3,}/); // Deve estar mascarado com asteriscos
      }
    }
  });

  test('Prevenção de ataques de enumeração', async ({ page }) => {
    await page.goto('/login');
    
    // Testa com usuário existente
    await page.fill('[data-testid="username-input"]', 'user@example.com');
    await page.fill('[data-testid="password-input"]', 'wrongpassword');
    await page.click('[data-testid="login-button"]');
    
    const existingUserMessage = await page.locator('.alert-error').textContent();
    
    // Testa com usuário inexistente
    await page.fill('[data-testid="username-input"]', 'nonexistent@example.com');
    await page.fill('[data-testid="password-input"]', 'wrongpassword');
    await page.click('[data-testid="login-button"]');
    
    const nonExistentUserMessage = await page.locator('.alert-error').textContent();
    
    // Verifica se as mensagens são idênticas (não revelam se usuário existe)
    expect(existingUserMessage).toBe(nonExistentUserMessage);
  });
}); 