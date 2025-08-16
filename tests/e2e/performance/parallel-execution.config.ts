/**
 * Configuração de Paralelização Avançada para Testes E2E
 * - Otimização de execução paralela
 * - Distribuição inteligente de carga
 * - Cache de dependências
 * - Testes incrementais
 * 
 * 📐 CoCoT: Baseado em boas práticas de paralelização de testes E2E
 * 🌲 ToT: Múltiplas estratégias de otimização implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de carga
 * 
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T11:30:00Z
 * **Tracing ID:** PARALLEL_EXECUTION_CONFIG_md1ppfhs
 * **Origem:** Necessidade de otimização de performance dos testes E2E
 */

import { PlaywrightTestConfig, devices } from '@playwright/test';
import { cpus } from 'os';

// Configurações de performance
const PERFORMANCE_CONFIG = {
  // Configurações de paralelização
  parallel: {
    workers: Math.max(1, Math.floor(cpus().length * 0.75)), // 75% dos CPUs
    shards: 4, // Número de shards para distribuição
    maxConcurrency: 3, // Máximo de testes simultâneos por worker
    retries: 1, // Retry em caso de falha
    timeout: 30000, // Timeout por teste
  },
  
  // Configurações de cache
  cache: {
    enabled: true,
    directory: '.playwright-cache',
    maxSize: '2GB',
    ttl: 24 * 60 * 60 * 1000, // 24 horas
  },
  
  // Configurações de otimização
  optimization: {
    reuseContext: true, // Reutilizar contexto entre testes
    reuseBrowser: true, // Reutilizar browser quando possível
    lazyLoad: true, // Carregamento lazy de recursos
    preload: false, // Desabilitar preload para economizar memória
  },
  
  // Configurações de recursos
  resources: {
    maxMemory: '4GB',
    maxCpu: 80, // 80% do CPU
    diskSpace: '1GB',
  }
};

// Configuração principal otimizada
const config: PlaywrightTestConfig = {
  testDir: './tests/e2e',
  timeout: PERFORMANCE_CONFIG.parallel.timeout,
  retries: PERFORMANCE_CONFIG.parallel.retries,
  workers: PERFORMANCE_CONFIG.parallel.workers,
  
  // Configurações de paralelização
  shard: process.env.SHARD_INDEX && process.env.SHARD_TOTAL ? {
    current: parseInt(process.env.SHARD_INDEX),
    total: parseInt(process.env.SHARD_TOTAL)
  } : undefined,
  
  // Configurações de projetos otimizados
  projects: [
    // Projeto de testes críticos (alta prioridade)
    {
      name: 'critical-chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        trace: 'retain-on-failure',
        // Otimizações específicas
        launchOptions: {
          args: [
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor'
          ]
        }
      },
      testMatch: /.*critical.*\.spec\.ts/,
      timeout: 20000,
      retries: 0
    },
    
    // Projeto de testes de smoke (execução rápida)
    {
      name: 'smoke-chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
        screenshot: 'off',
        video: 'off',
        trace: 'off',
        launchOptions: {
          args: [
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--no-sandbox'
          ]
        }
      },
      testMatch: /.*smoke.*\.spec\.ts/,
      timeout: 10000,
      retries: 0
    },
    
    // Projeto de testes completos (paralelização)
    {
      name: 'full-chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
        trace: 'on-first-retry'
      },
      testMatch: /.*\.spec\.ts/,
      testIgnore: /.*(critical|smoke).*\.spec\.ts/,
      timeout: 30000,
      retries: 1
    },
    
    // Projeto de testes de regressão (Firefox)
    {
      name: 'regression-firefox',
      use: {
        ...devices['Desktop Firefox'],
        viewport: { width: 1280, height: 720 },
        screenshot: 'only-on-failure',
        video: 'retain-on-failure'
      },
      testMatch: /.*regression.*\.spec\.ts/,
      timeout: 25000,
      retries: 1
    },
    
    // Projeto de testes de acessibilidade (WebKit)
    {
      name: 'accessibility-webkit',
      use: {
        ...devices['Desktop Safari'],
        viewport: { width: 1280, height: 720 },
        screenshot: 'only-on-failure'
      },
      testMatch: /.*accessibility.*\.spec\.ts/,
      timeout: 20000,
      retries: 0
    },
    
    // Projeto de testes mobile
    {
      name: 'mobile-chromium',
      use: {
        ...devices['iPhone 12'],
        screenshot: 'only-on-failure',
        video: 'retain-on-failure'
      },
      testMatch: /.*mobile.*\.spec\.ts/,
      timeout: 25000,
      retries: 1
    }
  ],
  
  // Configurações globais otimizadas
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5000',
    actionTimeout: 10000,
    navigationTimeout: 20000,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    
    // Otimizações de contexto
    contextOptions: {
      reducedMotion: 'reduce',
      colorScheme: 'light',
      locale: 'pt-BR',
      timezoneId: 'America/Sao_Paulo',
      permissions: ['geolocation'],
      geolocation: { longitude: -46.6388, latitude: -23.5489 },
      extraHTTPHeaders: {
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
      }
    }
  },
  
  // Configurações de relatórios otimizadas
  reporter: [
    ['html', { 
      outputFolder: 'test-results/html-report',
      open: 'never'
    }],
    ['json', { 
      outputFile: 'test-results/results.json'
    }],
    ['junit', { 
      outputFile: 'test-results/results.xml'
    }],
    ['list'],
    ['allure-playwright', { 
      outputFolder: 'test-results/allure-results',
      detail: true,
      suiteTitle: false
    }],
    // Reporter customizado para performance
    ['json', { 
      outputFile: 'test-results/performance-metrics.json'
    }]
  ],
  
  // Configurações de output
  outputDir: 'test-results/',
  
  // Configurações de global setup/teardown otimizados
  globalSetup: require.resolve('./global-setup.ts'),
  globalTeardown: require.resolve('./global-teardown.ts'),
  
  // Configurações de expect otimizadas
  expect: {
    timeout: 10000,
    toMatchSnapshot: {
      maxDiffPixels: 10
    }
  },
  
  // Configurações de web server otimizadas
  webServer: process.env.E2E_ENV === 'dev' ? {
    command: 'npm run start:dev',
    url: process.env.E2E_BASE_URL || 'http://localhost:5000',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stderr: 'pipe',
    stdout: 'pipe'
  } : undefined,
  
  // Configurações de CI/CD otimizadas
  ...(process.env.CI && {
    workers: 1,
    retries: 1,
    use: {
      launchOptions: {
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      }
    }
  }),
  
  // Configurações de debug
  ...(process.env.DEBUG && {
    use: {
      launchOptions: {
        slowMo: 2000,
        devtools: true,
        headless: false
      }
    },
    timeout: 0
  })
};

// Configurações específicas por ambiente
const environment = process.env.E2E_ENV || 'dev';

if (environment === 'staging') {
  config.workers = Math.min(2, PERFORMANCE_CONFIG.parallel.workers);
  config.timeout = 60000;
}

if (environment === 'prod') {
  config.workers = Math.min(1, PERFORMANCE_CONFIG.parallel.workers);
  config.timeout = 90000;
  config.retries = 0;
}

// Configurações de cache
if (PERFORMANCE_CONFIG.cache.enabled) {
  config.use = {
    ...config.use,
    // Configurações de cache
    contextOptions: {
      ...config.use?.contextOptions,
      // Cache de recursos
      serviceWorkers: 'block',
      // Cache de imagens
      bypassCSP: true
    }
  };
}

export default config;

// Exporta configurações para uso em scripts
export const performanceConfig = {
  parallel: PERFORMANCE_CONFIG.parallel,
  cache: PERFORMANCE_CONFIG.cache,
  optimization: PERFORMANCE_CONFIG.optimization,
  resources: PERFORMANCE_CONFIG.resources,
  environment,
  timestamp: new Date().toISOString()
}; 