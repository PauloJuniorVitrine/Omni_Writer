# 🔧 GUIA DE TROUBLESHOOTING - TESTES E2E OMNI WRITER

## 📋 **VISÃO GERAL**

Este guia fornece soluções para problemas comuns encontrados durante o desenvolvimento e execução de testes E2E no projeto Omni Writer.

**📐 CoCoT**: Baseado em problemas reais identificados durante desenvolvimento  
**🌲 ToT**: Múltiplas estratégias de resolução para cada problema  
**♻️ ReAct**: Soluções testadas e validadas em ambiente real  

---

## 🚨 **PROBLEMAS CRÍTICOS**

### **1. Aplicação Não Inicia**

#### **Sintomas**
- Erro: `ECONNREFUSED` ao tentar conectar com `http://localhost:5000`
- Timeout nos testes de navegação
- Health check falha

#### **Soluções**

**Opção 1: Iniciar aplicação manualmente**
```bash
# Terminal 1 - Iniciar aplicação
npm run start:dev

# Terminal 2 - Executar testes
npm run test:e2e:smoke
```

**Opção 2: Verificar portas**
```bash
# Verificar se porta 5000 está em uso
netstat -ano | findstr :5000

# Matar processo se necessário
taskkill /PID <PID> /F
```

**Opção 3: Usar porta alternativa**
```bash
# Configurar porta diferente
set PORT=5001
npm run start:dev

# Atualizar configuração E2E
set E2E_BASE_URL=http://localhost:5001
```

#### **Prevenção**
- Sempre verificar se a aplicação está rodando antes dos testes
- Usar health checks automáticos
- Configurar timeouts adequados

---

### **2. Timeouts Frequentes**

#### **Sintomas**
- Testes falham com `TimeoutError`
- Elementos não encontrados
- Navegação lenta

#### **Soluções**

**Opção 1: Aumentar timeouts**
```typescript
// tests/e2e/e2e.config.ts
const config: PlaywrightTestConfig = {
  timeout: 60000, // 60 segundos
  expect: {
    timeout: 15000 // 15 segundos para assertions
  },
  use: {
    actionTimeout: 15000,
    navigationTimeout: 30000
  }
};
```

**Opção 2: Implementar retry logic**
```typescript
// tests/e2e/utils/retry-helper.ts
export async function waitForElement(page: Page, selector: string, timeout = 10000) {
  return page.waitForSelector(selector, { timeout });
}

export async function retryAction(action: () => Promise<void>, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await action();
      return;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await page.waitForTimeout(1000);
    }
  }
}
```

**Opção 3: Otimizar seletores**
```typescript
// ❌ Ruim - Seletores frágeis
await page.click('.btn');

// ✅ Bom - Seletores robustos
await page.click('[data-testid="generate-button"]');
await page.click('button:has-text("Gerar Artigo")');
```

#### **Prevenção**
- Usar seletores data-testid
- Implementar wait conditions adequadas
- Monitorar performance da aplicação

---

### **3. Browsers Não Instalam**

#### **Sintomas**
- Erro: `Browser not found`
- Falha na instalação do Playwright
- Browsers corrompidos

#### **Soluções**

**Opção 1: Reinstalar browsers**
```bash
# Limpar cache do Playwright
npx playwright install --with-deps

# Ou reinstalar browsers específicos
npx playwright install chromium
npx playwright install firefox
npx playwright install webkit
```

**Opção 2: Usar cache local**
```bash
# Configurar cache local
set PLAYWRIGHT_BROWSERS_PATH=./.playwright-browsers

# Reinstalar com cache local
npx playwright install --with-deps
```

**Opção 3: Limpar completamente**
```bash
# Limpar tudo e reinstalar
npm run test:e2e:clean
npm run test:e2e:install
```

#### **Prevenção**
- Manter cache de browsers
- Usar versões estáveis do Playwright
- Configurar CI/CD adequadamente

---

## ⚠️ **PROBLEMAS DE PERFORMANCE**

### **4. Testes Lentos**

#### **Sintomas**
- Execução > 10 minutos
- Browsers lentos
- Muitos timeouts

#### **Soluções**

**Opção 1: Otimizar configuração**
```typescript
// tests/e2e/performance/parallel-execution.config.ts
const config: PlaywrightTestConfig = {
  workers: 4, // Executar em paralelo
  timeout: 30000, // Reduzir timeout
  retries: 0, // Desabilitar retries em CI
  use: {
    launchOptions: {
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-sandbox'
      ]
    }
  }
};
```

**Opção 2: Usar cache inteligente**
```bash
# Configurar cache de dependências
npm run test:e2e:cache

# Usar cache de browsers
set PLAYWRIGHT_BROWSERS_PATH=./.playwright-cache/browsers
```

**Opção 3: Executar testes incrementais**
```bash
# Executar apenas testes que mudaram
npm run test:e2e:incremental
```

#### **Prevenção**
- Monitorar tempo de execução
- Usar paralelização adequada
- Implementar cache eficiente

---

### **5. Memória Insuficiente**

#### **Sintomas**
- Erro: `Out of memory`
- Browsers travam
- Sistema lento

#### **Soluções**

**Opção 1: Limitar workers**
```typescript
// Reduzir número de workers
workers: 2, // Em vez de 4
```

**Opção 2: Configurar limites de memória**
```typescript
use: {
  launchOptions: {
    args: [
      '--max-old-space-size=2048',
      '--disable-dev-shm-usage'
    ]
  }
}
```

**Opção 3: Limpar recursos**
```typescript
// Em cada teste
test.afterEach(async ({ page }) => {
  await page.close();
});

test.afterAll(async ({ browser }) => {
  await browser.close();
});
```

#### **Prevenção**
- Monitorar uso de memória
- Fechar browsers adequadamente
- Usar workers apropriados

---

## 🔍 **PROBLEMAS DE DEBUGGING**

### **6. Falhas Intermitentes**

#### **Sintomas**
- Testes passam/falham aleatoriamente
- Difícil reproduzir problemas
- Falsos positivos

#### **Soluções**

**Opção 1: Usar modo debug**
```bash
# Executar com debug
npm run test:e2e:debug

# Ou com headed mode
npm run test:e2e:headed
```

**Opção 2: Capturar traces**
```typescript
// Habilitar traces
use: {
  trace: 'on-first-retry'
}

// Analisar traces
npx playwright show-trace test-results/trace.zip
```

**Opção 3: Implementar logging detalhado**
```typescript
// tests/e2e/utils/logger.ts
export class TestLogger {
  static log(message: string, level = 'INFO') {
    console.log(`[${level}] ${new Date().toISOString()}: ${message}`);
  }
  
  static error(message: string, error?: Error) {
    console.error(`[ERROR] ${new Date().toISOString()}: ${message}`, error);
  }
}
```

#### **Prevenção**
- Implementar logging estruturado
- Usar traces para debugging
- Documentar cenários de falha

---

### **7. Screenshots Não Gerados**

#### **Sintomas**
- Falta de evidências visuais
- Screenshots vazios
- Diretório não criado

#### **Soluções**

**Opção 1: Configurar screenshots**
```typescript
// Habilitar screenshots
use: {
  screenshot: 'only-on-failure'
}

// Ou sempre
use: {
  screenshot: 'on'
}
```

**Opção 2: Screenshots manuais**
```typescript
// Em testes específicos
await page.screenshot({ 
  path: 'test-results/screenshot.png',
  fullPage: true 
});
```

**Opção 3: Verificar diretórios**
```bash
# Criar diretório se não existir
mkdir -p test-results/screenshots
```

#### **Prevenção**
- Configurar screenshots adequadamente
- Verificar permissões de diretório
- Implementar screenshots automáticos

---

## 🛠️ **PROBLEMAS DE CONFIGURAÇÃO**

### **8. Variáveis de Ambiente**

#### **Sintomas**
- Configurações incorretas
- URLs hardcoded
- Ambientes misturados

#### **Soluções**

**Opção 1: Configurar variáveis**
```bash
# Definir ambiente
set E2E_ENV=dev
set E2E_BASE_URL=http://localhost:5000

# Ou usar arquivo .env
echo "E2E_ENV=dev" > .env
echo "E2E_BASE_URL=http://localhost:5000" >> .env
```

**Opção 2: Validar configuração**
```typescript
// tests/e2e/utils/config-validator.ts
export function validateConfig() {
  const required = ['E2E_ENV', 'E2E_BASE_URL'];
  
  for (const var of required) {
    if (!process.env[var]) {
      throw new Error(`Variável de ambiente ${var} não definida`);
    }
  }
}
```

**Opção 3: Usar configuração dinâmica**
```typescript
// tests/e2e/e2e.config.ts
const environments = {
  dev: { baseUrl: 'http://localhost:5000' },
  staging: { baseUrl: 'https://staging.omni-writer.com' },
  prod: { baseUrl: 'https://omni-writer.com' }
};

const currentEnv = process.env.E2E_ENV || 'dev';
const config = environments[currentEnv];
```

#### **Prevenção**
- Usar variáveis de ambiente
- Validar configuração
- Documentar ambientes

---

### **9. Dependências Desatualizadas**

#### **Sintomas**
- Versões incompatíveis
- Erros de build
- Funcionalidades quebradas

#### **Soluções**

**Opção 1: Atualizar dependências**
```bash
# Atualizar Playwright
npm update @playwright/test

# Reinstalar browsers
npx playwright install --with-deps
```

**Opção 2: Verificar compatibilidade**
```bash
# Verificar versões
npm list @playwright/test
node --version
npm --version
```

**Opção 3: Reset completo**
```bash
# Limpar tudo e reinstalar
npm run test:e2e:reset
```

#### **Prevenção**
- Manter dependências atualizadas
- Usar lockfiles
- Testar em CI/CD

---

## 📊 **PROBLEMAS DE RELATÓRIOS**

### **10. Relatórios Não Gerados**

#### **Sintomas**
- Falta de relatórios HTML
- Métricas não disponíveis
- Dados incompletos

#### **Soluções**

**Opção 1: Configurar reporters**
```typescript
// Habilitar múltiplos reporters
reporter: [
  ['html', { outputFolder: 'test-results/html-report' }],
  ['json', { outputFile: 'test-results/results.json' }],
  ['junit', { outputFile: 'test-results/results.xml' }]
]
```

**Opção 2: Gerar relatórios manualmente**
```bash
# Gerar relatório HTML
npx playwright show-report test-results/html-report

# Ou abrir relatório existente
npm run test:e2e:report
```

**Opção 3: Implementar relatórios customizados**
```typescript
// tests/e2e/utils/custom-reporter.ts
export class CustomReporter {
  onEnd(result: any) {
    // Gerar relatório customizado
    this.generateCustomReport(result);
  }
}
```

#### **Prevenção**
- Configurar reporters adequadamente
- Verificar permissões de escrita
- Implementar relatórios customizados

---

## 🚀 **COMANDOS ÚTEIS**

### **Comandos de Diagnóstico**
```bash
# Verificar setup
npm run test:e2e:setup

# Validar testes
npm run test:e2e:validate

# Limpar cache
npm run test:e2e:clean

# Reset completo
npm run test:e2e:reset
```

### **Comandos de Debug**
```bash
# Modo debug
npm run test:e2e:debug

# Modo headed
npm run test:e2e:headed

# Interface UI
npm run test:e2e:ui

# Codegen
npm run test:e2e:codegen
```

### **Comandos de Performance**
```bash
# Testes rápidos
npm run test:e2e:quick

# Testes paralelos
npm run test:e2e:parallel

# Testes incrementais
npm run test:e2e:incremental
```

---

## 📞 **SUPORTE**

### **Quando Pedir Ajuda**
- Problema persiste após tentar todas as soluções
- Erro não documentado
- Comportamento inesperado

### **Informações para Incluir**
- Versão do Node.js e npm
- Versão do Playwright
- Logs completos de erro
- Screenshots/traces
- Configuração do ambiente

### **Canais de Suporte**
- Issues no GitHub
- Documentação do projeto
- Guia de manutenção
- Equipe de desenvolvimento

---

## 📝 **NOTAS IMPORTANTES**

### **Boas Práticas**
- Sempre testar em ambiente limpo
- Documentar problemas encontrados
- Manter dependências atualizadas
- Usar seletores robustos
- Implementar logging adequado

### **Prevenção**
- Monitorar métricas de performance
- Implementar health checks
- Usar cache eficiente
- Configurar CI/CD adequadamente
- Manter documentação atualizada

---

**Última Atualização**: 2025-01-28  
**Versão**: 1.0  
**Responsável**: Equipe de QA/Desenvolvimento 