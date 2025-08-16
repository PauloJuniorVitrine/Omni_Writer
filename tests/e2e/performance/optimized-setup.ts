/**
 * Setup/Teardown Otimizado para Testes E2E
 * - Redução de tempo de execução
 * - Reutilização de recursos
 * - Cache inteligente
 * - Limpeza eficiente
 * 
 * 📐 CoCoT: Baseado em boas práticas de otimização de setup/teardown
 * 🌲 ToT: Múltiplas estratégias de otimização implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de performance
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T11:35:00Z
 * **Tracing ID:** OPTIMIZED_SETUP_TEARDOWN_md1ppfhs
 * **Origem:** Necessidade de otimização de setup/teardown para performance
 */

import { chromium, FullConfig, Browser, BrowserContext } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { performance } from 'perf_hooks';

// Cache global para reutilização
let globalBrowser: Browser | null = null;
let globalContext: BrowserContext | null = null;
let setupStartTime: number;

// Configurações de otimização
const OPTIMIZATION_CONFIG = {
  // Cache de browser
  browserCache: {
    enabled: true,
    maxAge: 5 * 60 * 1000, // 5 minutos
    lastUsed: 0
  },
  
  // Cache de contexto
  contextCache: {
    enabled: true,
    maxAge: 2 * 60 * 1000, // 2 minutos
    lastUsed: 0
  },
  
  // Configurações de limpeza
  cleanup: {
    autoCleanup: true,
    cleanupInterval: 10 * 60 * 1000, // 10 minutos
    maxCacheSize: 100 * 1024 * 1024, // 100MB
  },
  
  // Configurações de performance
  performance: {
    enableTracing: false,
    enableScreenshots: false,
    enableVideos: false,
    lazyLoad: true,
    preload: false
  }
};

/**
 * Setup global otimizado
 */
async function globalSetup(config: FullConfig) {
  setupStartTime = performance.now();
  console.log('🚀 Iniciando Setup Global Otimizado...');
  
  const environment = process.env.E2E_ENV || 'dev';
  const baseUrl = config.projects[0]?.use?.baseURL || 'http://localhost:5000';
  
  console.log(`📍 Ambiente: ${environment}`);
  console.log(`🌐 Base URL: ${baseUrl}`);
  
  // Criar diretórios necessários
  await createDirectories();
  
  // Health check otimizado
  await performHealthCheck(baseUrl);
  
  // Inicializar cache se habilitado
  if (OPTIMIZATION_CONFIG.browserCache.enabled) {
    await initializeBrowserCache();
  }
  
  // Configurar limpeza automática
  if (OPTIMIZATION_CONFIG.cleanup.autoCleanup) {
    setupAutoCleanup();
  }
  
  const setupDuration = performance.now() - setupStartTime;
  console.log(`✅ Setup Global concluído em ${setupDuration.toFixed(2)}ms`);
}

/**
 * Teardown global otimizado
 */
async function globalTeardown(config: FullConfig) {
  console.log('🧹 Iniciando Teardown Global Otimizado...');
  
  const teardownStartTime = performance.now();
  
  // Limpar cache
  await cleanupCache();
  
  // Fechar recursos
  await closeResources();
  
  // Gerar relatório de performance
  await generatePerformanceReport();
  
  const teardownDuration = performance.now() - teardownStartTime;
  console.log(`✅ Teardown Global concluído em ${teardownDuration.toFixed(2)}ms`);
}

/**
 * Setup otimizado por worker
 */
async function workerSetup() {
  console.log('🔧 Iniciando Setup de Worker...');
  
  // Reutilizar browser se disponível
  if (globalBrowser && isBrowserCacheValid()) {
    console.log('♻️ Reutilizando browser do cache');
    OPTIMIZATION_CONFIG.browserCache.lastUsed = Date.now();
  } else {
    console.log('🆕 Criando novo browser');
    globalBrowser = await createOptimizedBrowser();
  }
  
  // Reutilizar contexto se disponível
  if (globalContext && isContextCacheValid()) {
    console.log('♻️ Reutilizando contexto do cache');
    OPTIMIZATION_CONFIG.contextCache.lastUsed = Date.now();
  } else {
    console.log('🆕 Criando novo contexto');
    globalContext = await createOptimizedContext(globalBrowser!);
  }
}

/**
 * Teardown otimizado por worker
 */
async function workerTeardown() {
  console.log('🧹 Iniciando Teardown de Worker...');
  
  // Não fechar browser/contexto imediatamente
  // Manter no cache para reutilização
  console.log('💾 Mantendo recursos no cache para reutilização');
}

/**
 * Criar diretórios necessários
 */
async function createDirectories() {
  const directories = [
    'test-results',
    'test-results/html-report',
    'test-results/allure-results',
    'tests/e2e/snapshots',
    'tests/e2e/snapshots/generate_content',
    'tests/e2e/snapshots/webhooks_multiplos',
    'logs/e2e',
    '.playwright-cache'
  ];
  
  for (const dir of directories) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`📁 Diretório criado: ${dir}`);
    }
  }
}

/**
 * Health check otimizado
 */
async function performHealthCheck(baseUrl: string) {
  console.log('🏥 Executando health check otimizado...');
  
  try {
    const browser = await chromium.launch({ 
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Health check com timeout reduzido
    const response = await page.goto(`${baseUrl}/health`, { 
      timeout: 10000,
      waitUntil: 'domcontentloaded'
    });
    
    if (response?.status() === 200) {
      console.log('✅ Health check passou');
    } else {
      throw new Error(`Health check falhou: ${response?.status()}`);
    }
    
    await browser.close();
    
  } catch (error) {
    console.warn(`⚠️ Health check falhou: ${error}`);
    // Não falhar o setup por causa do health check
  }
}

/**
 * Inicializar cache de browser
 */
async function initializeBrowserCache() {
  console.log('💾 Inicializando cache de browser...');
  
  try {
    globalBrowser = await createOptimizedBrowser();
    OPTIMIZATION_CONFIG.browserCache.lastUsed = Date.now();
    console.log('✅ Cache de browser inicializado');
  } catch (error) {
    console.warn(`⚠️ Falha ao inicializar cache de browser: ${error}`);
  }
}

/**
 * Criar browser otimizado
 */
async function createOptimizedBrowser(): Promise<Browser> {
  return await chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-web-security',
      '--disable-features=VizDisplayCompositor',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-renderer-backgrounding',
      '--disable-field-trial-config',
      '--disable-ipc-flooding-protection'
    ]
  });
}

/**
 * Criar contexto otimizado
 */
async function createOptimizedContext(browser: Browser): Promise<BrowserContext> {
  return await browser.newContext({
    viewport: { width: 1280, height: 720 },
    locale: 'pt-BR',
    timezoneId: 'America/Sao_Paulo',
    permissions: ['geolocation'],
    geolocation: { longitude: -46.6388, latitude: -23.5489 },
    extraHTTPHeaders: {
      'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
    },
    // Otimizações de performance
    reducedMotion: 'reduce',
    colorScheme: 'light',
    // Cache de recursos
    serviceWorkers: 'block',
    bypassCSP: true
  });
}

/**
 * Verificar se cache de browser é válido
 */
function isBrowserCacheValid(): boolean {
  if (!globalBrowser) return false;
  
  const age = Date.now() - OPTIMIZATION_CONFIG.browserCache.lastUsed;
  return age < OPTIMIZATION_CONFIG.browserCache.maxAge;
}

/**
 * Verificar se cache de contexto é válido
 */
function isContextCacheValid(): boolean {
  if (!globalContext) return false;
  
  const age = Date.now() - OPTIMIZATION_CONFIG.contextCache.lastUsed;
  return age < OPTIMIZATION_CONFIG.contextCache.maxAge;
}

/**
 * Configurar limpeza automática
 */
function setupAutoCleanup() {
  console.log('🔄 Configurando limpeza automática...');
  
  setInterval(async () => {
    await cleanupCache();
  }, OPTIMIZATION_CONFIG.cleanup.cleanupInterval);
}

/**
 * Limpar cache
 */
async function cleanupCache() {
  console.log('🧹 Limpando cache...');
  
  // Limpar cache de contexto se expirado
  if (globalContext && !isContextCacheValid()) {
    await globalContext.close();
    globalContext = null;
    console.log('🗑️ Contexto expirado removido do cache');
  }
  
  // Limpar cache de browser se expirado
  if (globalBrowser && !isBrowserCacheValid()) {
    await globalBrowser.close();
    globalBrowser = null;
    console.log('🗑️ Browser expirado removido do cache');
  }
  
  // Limpar cache de arquivos
  await cleanupFileCache();
}

/**
 * Limpar cache de arquivos
 */
async function cleanupFileCache() {
  const cacheDir = '.playwright-cache';
  
  if (fs.existsSync(cacheDir)) {
    try {
      const stats = fs.statSync(cacheDir);
      const size = stats.size;
      
      if (size > OPTIMIZATION_CONFIG.cleanup.maxCacheSize) {
        console.log('🗑️ Cache de arquivos muito grande, limpando...');
        fs.rmSync(cacheDir, { recursive: true, force: true });
        fs.mkdirSync(cacheDir, { recursive: true });
      }
    } catch (error) {
      console.warn(`⚠️ Erro ao limpar cache de arquivos: ${error}`);
    }
  }
}

/**
 * Fechar recursos
 */
async function closeResources() {
  console.log('🔒 Fechando recursos...');
  
  if (globalContext) {
    await globalContext.close();
    globalContext = null;
  }
  
  if (globalBrowser) {
    await globalBrowser.close();
    globalBrowser = null;
  }
}

/**
 * Gerar relatório de performance
 */
async function generatePerformanceReport() {
  const totalDuration = performance.now() - setupStartTime;
  
  const report = {
    timestamp: new Date().toISOString(),
    performance: {
      setupDuration: setupStartTime,
      totalDuration,
      optimization: {
        browserCacheUsed: OPTIMIZATION_CONFIG.browserCache.enabled,
        contextCacheUsed: OPTIMIZATION_CONFIG.contextCache.enabled,
        autoCleanupEnabled: OPTIMIZATION_CONFIG.cleanup.autoCleanup
      }
    },
    resources: {
      browserReused: globalBrowser !== null,
      contextReused: globalContext !== null
    }
  };
  
  const reportPath = 'test-results/performance-report.json';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  
  console.log(`📊 Relatório de performance salvo em: ${reportPath}`);
}

// Exportar funções para uso
export {
  globalSetup,
  globalTeardown,
  workerSetup,
  workerTeardown,
  OPTIMIZATION_CONFIG
}; 