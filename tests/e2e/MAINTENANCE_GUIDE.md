# 📚 GUIA DE MANUTENÇÃO - TESTES E2E OMNI WRITER

## 🎯 **VISÃO GERAL**

Este guia fornece instruções completas para manutenção, troubleshooting e extensão da suite de testes E2E do Omni Writer.

### **📐 CoCoT - Fundamentação**
- **Comprovação**: Baseado em boas práticas de testes E2E e experiências reais
- **Causalidade**: Problemas comuns e suas causas raiz identificadas
- **Contexto**: Específico para a arquitetura e funcionalidades do Omni Writer
- **Tendência**: Abordagens modernas de debugging e manutenção

### **🌲 ToT - Múltiplas Estratégias**
- Diagnóstico sistemático de problemas
- Múltiplas abordagens de resolução
- Prevenção de problemas futuros

### **♻️ ReAct - Simulação e Reflexão**
- Cenários de falha simulados
- Efeitos colaterais documentados
- Riscos mitigáveis identificados

---

## 🚨 **PROBLEMAS COMUNS E SOLUÇÕES**

### **1. Testes Falhando por Timing**

#### **Sintomas**
- `TimeoutError: waiting for selector`
- `Element not found`
- Testes intermitentes (flaky)

#### **Causas Comuns**
- Elementos carregam assincronamente
- JavaScript ainda executando
- Dependências externas lentas
- Mudanças na UI não refletidas nos seletores

#### **Soluções**

**A. Usar Wait Conditions Robustas**
```typescript
// ❌ Ruim
await page.click('button');

// ✅ Bom
await page.waitForSelector('button', { state: 'visible' });
await page.click('button');

// ✅ Melhor - com retry logic
await waitForElementWithRetry(page, 'button', 5000, 3);
```

**B. Implementar Retry Logic**
```typescript
async function waitForElementWithRetry(
  page: Page, 
  selector: string, 
  timeout: number = 5000, 
  retries: number = 3
) {
  for (let i = 0; i < retries; i++) {
    try {
      await page.waitForSelector(selector, { timeout });
      return;
    } catch (error) {
      if (i === retries - 1) throw error;
      await page.waitForTimeout(1000);
    }
  }
}
```

**C. Usar Data Attributes Consistentes**
```typescript
// ❌ Ruim - seletores frágeis
await page.click('button:has-text("Salvar")');

// ✅ Bom - data attributes
await page.click('[data-testid="save-button"]');
```

### **2. Problemas de Estado do Banco**

#### **Sintomas**
- Dados não persistem entre operações
- Validações falham inconsistentemente
- Side effects não detectados

#### **Soluções**

**A. Usar DatabaseValidator**
```typescript
const dbValidator = new DatabaseValidator(page);

// Validar criação
const result = await dbValidator.validateDataPersistence('create_blog', {
  nome: 'Blog Teste'
});

expect(result.success).toBe(true);
```

**B. Limpar Estado Entre Testes**
```typescript
test.beforeEach(async ({ page }) => {
  // Limpar dados de teste
  await page.request.post('/api/test/cleanup');
});
```

### **3. Problemas de Performance**

#### **Sintomas**
- Testes muito lentos
- Timeouts frequentes
- Sistema sobrecarregado

#### **Soluções**

**A. Otimizar Configurações**
```typescript
// playwright.config.ts
export default {
  timeout: 30000,
  retries: 1,
  workers: 2, // Reduzir para evitar sobrecarga
  use: {
    actionTimeout: 10000,
    navigationTimeout: 20000
  }
};
```

**B. Usar Testes de Smoke para Validação Rápida**
```bash
# Executar apenas smoke tests
npx playwright test tests/e2e/smoke-tests.spec.ts
```

### **4. Problemas de Mock Server**

#### **Sintomas**
- Webhooks não recebidos
- APIs externas indisponíveis
- Testes isolados falhando

#### **Soluções**

**A. Verificar Mock Server**
```typescript
// Verificar se mock server está rodando
const mockServer = new MockServer(9999);
await mockServer.start();

// Verificar endpoints
const response = await page.request.get('http://localhost:9999/health');
expect(response.status()).toBe(200);
```

**B. Implementar Fallbacks**
```typescript
try {
  await mockServer.start();
} catch (error) {
  console.warn('Mock server não disponível, usando fallback');
  // Implementar fallback
}
```

---

## 🔧 **MANUTENÇÃO PREVENTIVA**

### **1. Validação Regular de Seletores**

#### **Script de Validação**
```typescript
// scripts/validate-selectors.ts
import { chromium } from '@playwright/test';

async function validateSelectors() {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  
  const selectors = [
    '[data-testid="save-button"]',
    '[data-testid="login-form"]',
    // ... outros seletores
  ];
  
  for (const selector of selectors) {
    try {
      await page.goto('http://localhost:5000');
      await page.waitForSelector(selector, { timeout: 5000 });
      console.log(`✅ ${selector} - OK`);
    } catch (error) {
      console.error(`❌ ${selector} - FALHOU: ${error.message}`);
    }
  }
  
  await browser.close();
}
```

### **2. Monitoramento de Performance**

#### **Métricas a Acompanhar**
- Tempo de execução dos testes
- Taxa de sucesso
- Falsos positivos
- Uso de recursos

#### **Script de Monitoramento**
```typescript
// scripts/monitor-performance.ts
import fs from 'fs';

function analyzeTestResults() {
  const results = JSON.parse(fs.readFileSync('test-results/results.json', 'utf8'));
  
  const metrics = {
    totalTests: results.length,
    passed: results.filter(r => r.status === 'passed').length,
    failed: results.filter(r => r.status === 'failed').length,
    avgDuration: results.reduce((sum, r) => sum + r.duration, 0) / results.length
  };
  
  console.log('📊 Métricas de Performance:', metrics);
  
  // Alertas
  if (metrics.avgDuration > 30000) {
    console.warn('⚠️ Tempo médio de execução alto (>30s)');
  }
  
  if (metrics.failed / metrics.totalTests > 0.1) {
    console.error('🚨 Taxa de falha alta (>10%)');
  }
}
```

### **3. Validação de Cobertura**

#### **Script de Análise de Cobertura**
```typescript
// scripts/analyze-coverage.ts
import { DatabaseValidator } from './utils/database-validator';

async function analyzeCoverage() {
  const criticalFlows = [
    'login',
    'create_blog',
    'generate_content',
    'download_article',
    'export_prompts'
  ];
  
  const coveredFlows = [];
  
  for (const flow of criticalFlows) {
    const testFile = `tests/e2e/${flow}.spec.ts`;
    if (fs.existsSync(testFile)) {
      coveredFlows.push(flow);
    }
  }
  
  const coverage = (coveredFlows.length / criticalFlows.length) * 100;
  console.log(`📈 Cobertura de Fluxos Críticos: ${coverage}%`);
  
  if (coverage < 80) {
    console.warn('⚠️ Cobertura baixa - implementar testes faltantes');
  }
}
```

---

## 🛠️ **EXTENSÃO E NOVOS TESTES**

### **1. Criando Novos Testes**

#### **Template Padrão**
```typescript
/**
 * Teste E2E: [Nome da Funcionalidade]
 * - Valida [descrição do que valida]
 * - Baseado em [código fonte referenciado]
 * 
 * **Prompt:** [referência do prompt]
 * **Data/Hora:** [timestamp]
 * **Tracing ID:** [ID único]
 * **Origem:** [arquivo/funcionalidade referenciada]
 */

import { test, expect } from '@playwright/test';
import { TraceValidator } from './utils/trace-validator';
import { DatabaseValidator } from './utils/database-validator';

test.describe('Jornada: [Nome da Jornada]', () => {
  let traceValidator: TraceValidator;
  let databaseValidator: DatabaseValidator;

  test.beforeEach(async ({ page }) => {
    traceValidator = new TraceValidator(page, 'test-name');
    databaseValidator = new DatabaseValidator(page);
  });

  test('Fluxo principal', async ({ page }) => {
    // Implementação do teste
  });
});
```

### **2. Adicionando Validações de Estado**

#### **Novas Validações no DatabaseValidator**
```typescript
// Adicionar ao database-validator.ts
async validateNewOperation(expectedData: any): Promise<ValidationResult> {
  // Implementar validação específica
  return {
    success: true,
    message: 'Validação implementada',
    timestamp: new Date().toISOString()
  };
}
```

### **3. Criando Custom Matchers**

#### **Novos Matchers**
```typescript
// Adicionar ao custom-matchers.ts
expect.extend({
  toHaveValidState(received: any, expectedState: string) {
    const pass = received.state === expectedState;
    return {
      pass,
      message: () => `Esperado estado ${expectedState}, recebido ${received.state}`
    };
  }
});
```

---

## 📊 **MONITORAMENTO E RELATÓRIOS**

### **1. Relatórios Automáticos**

#### **Configuração de Relatórios**
```typescript
// playwright.config.ts
export default {
  reporter: [
    ['html', { outputFolder: 'test-results/html-report' }],
    ['json', { outputFile: 'test-results/results.json' }],
    ['junit', { outputFile: 'test-results/results.xml' }],
    ['allure-playwright', { 
      outputFolder: 'test-results/allure-results'
    }]
  ]
};
```

### **2. Dashboards de Métricas**

#### **Métricas Importantes**
- **Tempo de Execução**: < 10 minutos para suite completa
- **Taxa de Sucesso**: > 95%
- **Cobertura**: 100% dos fluxos críticos
- **Falsos Positivos**: < 5%

#### **Script de Geração de Dashboard**
```typescript
// scripts/generate-dashboard.ts
function generateDashboard() {
  const metrics = {
    executionTime: calculateExecutionTime(),
    successRate: calculateSuccessRate(),
    coverage: calculateCoverage(),
    falsePositives: calculateFalsePositives()
  };
  
  const html = `
    <html>
      <head><title>E2E Metrics Dashboard</title></head>
      <body>
        <h1>E2E Test Metrics</h1>
        <div>Execution Time: ${metrics.executionTime}ms</div>
        <div>Success Rate: ${metrics.successRate}%</div>
        <div>Coverage: ${metrics.coverage}%</div>
        <div>False Positives: ${metrics.falsePositives}%</div>
      </body>
    </html>
  `;
  
  fs.writeFileSync('test-results/dashboard.html', html);
}
```

---

## 🚀 **CI/CD INTEGRATION**

### **1. GitHub Actions**

#### **Workflow Básico**
```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Start application
      run: npm run start:dev &
      
    - name: Wait for application
      run: npx wait-on http://localhost:5000
      
    - name: Run E2E tests
      run: npx playwright test tests/e2e/
      
    - name: Upload test results
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: test-results/
```

### **2. Notificações**

#### **Configuração de Alertas**
```typescript
// scripts/notify-failures.ts
async function notifyFailures() {
  const results = JSON.parse(fs.readFileSync('test-results/results.json', 'utf8'));
  const failures = results.filter(r => r.status === 'failed');
  
  if (failures.length > 0) {
    // Enviar notificação via Slack/Email
    console.log(`🚨 ${failures.length} testes falharam`);
    
    // Detalhes das falhas
    failures.forEach(failure => {
      console.log(`- ${failure.title}: ${failure.error}`);
    });
  }
}
```

---

## 🔍 **TROUBLESHOOTING AVANÇADO**

### **1. Debugging de Testes Flaky**

#### **Estratégias de Debug**
```typescript
// 1. Capturar screenshots em cada passo
await page.screenshot({ path: `debug-${Date.now()}.png` });

// 2. Logar estado da página
const html = await page.content();
fs.writeFileSync(`debug-${Date.now()}.html`, html);

// 3. Usar TraceValidator para rastreamento detalhado
const trace = new TraceValidator(page, 'debug-test');
await trace.traceNavigation(url, 'Debug navigation');
```

### **2. Análise de Performance**

#### **Profiling de Testes**
```typescript
// scripts/profile-tests.ts
import { performance } from 'perf_hooks';

async function profileTest(testFunction: () => Promise<void>) {
  const start = performance.now();
  
  try {
    await testFunction();
  } finally {
    const end = performance.now();
    console.log(`Test execution time: ${end - start}ms`);
  }
}
```

### **3. Isolamento de Problemas**

#### **Teste de Isolamento**
```typescript
test('Teste isolado para debugging', async ({ page }) => {
  // Configurar ambiente limpo
  await page.request.post('/api/test/reset');
  
  // Executar apenas o passo problemático
  await page.goto('/specific-page');
  
  // Validar estado específico
  await expect(page.locator('[data-testid="specific-element"]')).toBeVisible();
});
```

---

## 📝 **CHECKLIST DE MANUTENÇÃO**

### **Diário**
- [ ] Executar smoke tests
- [ ] Verificar relatórios de falha
- [ ] Revisar métricas de performance

### **Semanal**
- [ ] Executar suite completa
- [ ] Analisar tendências de performance
- [ ] Atualizar documentação
- [ ] Revisar cobertura de testes

### **Mensal**
- [ ] Auditoria de seletores
- [ ] Revisão de configurações
- [ ] Atualização de dependências
- [ ] Treinamento da equipe

---

## 🎯 **PRÓXIMOS PASSOS**

### **Melhorias Planejadas**
1. **Paralelização**: Implementar execução paralela de testes
2. **Cache**: Otimizar cache de dependências
3. **Visual Regression**: Implementar testes de regressão visual
4. **Load Testing**: Adicionar testes de carga
5. **Security Testing**: Implementar testes de segurança

### **Métricas de Sucesso**
- Tempo de execução < 5 minutos
- Taxa de sucesso > 98%
- Zero falsos positivos
- Cobertura 100% dos fluxos críticos

---

**Responsável**: Equipe de QA/Desenvolvimento  
**Última Atualização**: 2025-01-28  
**Versão**: 1.0 