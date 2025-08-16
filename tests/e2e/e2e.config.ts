/**
 * Configuração Dinâmica para Testes E2E
 * - Suporte a múltiplos ambientes (dev, staging, prod)
 * - Configurações baseadas em variáveis de ambiente
 * - Health checks e validações automáticas
 * 
 * 📐 CoCoT: Baseado em padrões de configuração de testes E2E
 * 🌲 ToT: Múltiplas estratégias de configuração implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de ambiente
 */

import { defineConfig, devices } from '@playwright/test';

/**
 * Configuração E2E - Omni Writer
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md - Item 11.2
 * Data/Hora: 2025-01-28T12:30:00Z
 * Versão: 1.0.0
 */

// Configuração de variáveis de ambiente
const config = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  shadowEnabled: process.env.SHADOW_ENABLED === 'true',
  regions: process.env.REGIONS?.split(',') || ['us-east-1'],
  webVitalsEnabled: process.env.WEB_VITALS_ENABLED === 'true',
  a11yEnabled: process.env.A11Y_COVERAGE_ENABLED === 'true',
  semanticValidationEnabled: process.env.SEMANTIC_VALIDATION_ENABLED === 'true',
  visualRegressionEnabled: process.env.VISUAL_REGRESSION_ENABLED === 'true',
  reliabilityThreshold: parseInt(process.env.RELIABILITY_THRESHOLD || '95'),
  performanceThreshold: parseInt(process.env.PERFORMANCE_THRESHOLD || '90'),
  a11yThreshold: parseInt(process.env.A11Y_COVERAGE_THRESHOLD || '90'),
  smokeModeEnabled: process.env.SMOKE_MODE_ENABLED === 'true',
  retryAttempts: parseInt(process.env.RETRY_ATTEMPTS || '3'),
  retryDelay: parseInt(process.env.RETRY_DELAY || '1000'),
  screenshotOnFailure: process.env.SCREENSHOT_ON_FAILURE === 'true',
  traceEnabled: process.env.TRACE_ENABLED === 'true',
  videoRecordingEnabled: process.env.VIDEO_RECORDING_ENABLED === 'true'
};

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: config.retryAttempts,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html', { outputFolder: 'test-results/html' }],
    ['json', { outputFile: 'test-results/results.json' }],
    ['junit', { outputFile: 'test-results/results.xml' }],
    ['list'],
    ['github']
  ],
  use: {
    baseURL: config.baseUrl,
    trace: config.traceEnabled ? 'on-first-retry' : 'off',
    video: config.videoRecordingEnabled ? 'retain-on-failure' : 'off',
    screenshot: config.screenshotOnFailure ? 'only-on-failure' : 'off',
    // Configuração de viewport para diferentes dispositivos
    viewport: { width: 1280, height: 720 },
    // Configuração de geolocalização para multi-região
    geolocation: { longitude: -74.006, latitude: 40.7128 }, // NYC por padrão
    permissions: ['geolocation'],
    // Configuração de timezone
    timezoneId: 'America/New_York',
    // Configuração de locale
    locale: 'en-US',
    // Configuração de user agent
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    // Configuração de extra headers
    extraHTTPHeaders: {
      'Accept-Language': 'en-US,en;q=0.9',
      'X-Test-Environment': 'e2e',
      'X-Test-Version': '1.0.0'
    }
  },

  // Configuração de projetos para diferentes cenários
  projects: [
    // Configuração para Desktop - Chrome
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        // Configuração específica para Chrome
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox'
          ]
        }
      },
    },

    // Configuração para Desktop - Firefox
    {
      name: 'firefox',
      use: { 
        ...devices['Desktop Firefox'],
        // Configuração específica para Firefox
        launchOptions: {
          firefoxUserPrefs: {
            'dom.webdriver.enabled': false,
            'useAutomationExtension': false
          }
        }
      },
    },

    // Configuração para Desktop - Safari
    {
      name: 'webkit',
      use: { 
        ...devices['Desktop Safari'],
        // Configuração específica para Safari
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor'
          ]
        }
      },
    },

    // Configuração para Mobile - iPhone
    {
      name: 'Mobile Safari',
      use: { 
        ...devices['iPhone 12'],
        // Configuração específica para mobile
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 3,
        isMobile: true,
        hasTouch: true
      },
    },

    // Configuração para Tablet - iPad
    {
      name: 'Tablet Safari',
      use: { 
        ...devices['iPad (gen 7)'],
        // Configuração específica para tablet
        viewport: { width: 810, height: 1080 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true
      },
    },

    // Configuração Multi-Região - US East
    {
      name: 'us-east-1',
      use: { 
        ...devices['Desktop Chrome'],
        geolocation: { longitude: -74.006, latitude: 40.7128 },
        timezoneId: 'America/New_York',
        locale: 'en-US',
        extraHTTPHeaders: {
          'Accept-Language': 'en-US,en;q=0.9',
          'X-Test-Region': 'us-east-1'
        }
      },
    },

    // Configuração Multi-Região - EU Central
    {
      name: 'eu-central-1',
      use: { 
        ...devices['Desktop Chrome'],
        geolocation: { longitude: 8.6821, latitude: 50.1109 },
        timezoneId: 'Europe/Berlin',
        locale: 'de-DE',
        extraHTTPHeaders: {
          'Accept-Language': 'de-DE,de;q=0.9,en;q=0.8',
          'X-Test-Region': 'eu-central-1'
        }
      },
    },

    // Configuração Multi-Região - SA East
    {
      name: 'sa-east-1',
      use: { 
        ...devices['Desktop Chrome'],
        geolocation: { longitude: -46.6333, latitude: -23.5505 },
        timezoneId: 'America/Sao_Paulo',
        locale: 'pt-BR',
        extraHTTPHeaders: {
          'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
          'X-Test-Region': 'sa-east-1'
        }
      },
    },

    // Configuração Multi-Região - AP Southeast
    {
      name: 'ap-southeast-1',
      use: { 
        ...devices['Desktop Chrome'],
        geolocation: { longitude: 103.8198, latitude: 1.3521 },
        timezoneId: 'Asia/Singapore',
        locale: 'en-SG',
        extraHTTPHeaders: {
          'Accept-Language': 'en-SG,en;q=0.9',
          'X-Test-Region': 'ap-southeast-1'
        }
      },
    },

    // Configuração Shadow Testing - Produção
    {
      name: 'shadow-prod',
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: process.env.PROD_URL || 'https://omni-writer.com',
        extraHTTPHeaders: {
          'X-Test-Environment': 'shadow-prod',
          'X-Test-Type': 'shadow'
        }
      },
    },

    // Configuração Shadow Testing - Canary
    {
      name: 'shadow-canary',
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: process.env.CANARY_URL || 'https://canary.omni-writer.com',
        extraHTTPHeaders: {
          'X-Test-Environment': 'shadow-canary',
          'X-Test-Type': 'shadow'
        }
      },
    },

    // Configuração Smoke Tests
    {
      name: 'smoke',
      use: { 
        ...devices['Desktop Chrome'],
        // Configuração otimizada para smoke tests
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--disable-software-rasterizer'
          ]
        }
      },
      testMatch: '**/smoke-tests.spec.ts',
      timeout: 120000, // 2 minutos para smoke tests
    },

    // Configuração A11Y Tests
    {
      name: 'a11y',
      use: { 
        ...devices['Desktop Chrome'],
        // Configuração específica para testes de acessibilidade
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--enable-logging',
            '--v=1'
          ]
        }
      },
      testMatch: '**/jornada_a11y.spec.ts',
    },

    // Configuração Performance Tests
    {
      name: 'performance',
      use: { 
        ...devices['Desktop Chrome'],
        // Configuração específica para testes de performance
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--disable-software-rasterizer',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding'
          ]
        }
      },
      testMatch: '**/performance/**/*.spec.ts',
    },

    // Configuração Visual Regression Tests
    {
      name: 'visual',
      use: { 
        ...devices['Desktop Chrome'],
        // Configuração específica para testes de regressão visual
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--disable-software-rasterizer',
            '--force-device-scale-factor=1'
          ]
        }
      },
      testMatch: '**/visual/**/*.spec.ts',
    }
  ],

  // Configuração de web server
  webServer: {
    command: 'npm run start:e2e',
    url: config.baseUrl,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stdout: 'pipe',
    stderr: 'pipe',
  },

  // Configuração de global setup e teardown
  globalSetup: require.resolve('./tests/e2e/global-setup.ts'),
  globalTeardown: require.resolve('./tests/e2e/global-teardown.ts'),

  // Configuração de expect
  expect: {
    timeout: 10000,
    toMatchSnapshot: {
      maxDiffPixels: 10,
    },
  },

  // Configuração de output
  outputDir: 'test-results/',
  
  // Configuração de snapshot
  snapshotPathTemplate: '{testDir}/__snapshots__/{testFileDir}/{testFileName}-snapshots/{arg}{ext}',

  // Configuração de timeout
  timeout: 30000,

  // Configuração de metadata
  metadata: {
    config: {
      shadowEnabled: config.shadowEnabled,
      regions: config.regions,
      webVitalsEnabled: config.webVitalsEnabled,
      a11yEnabled: config.a11yEnabled,
      semanticValidationEnabled: config.semanticValidationEnabled,
      visualRegressionEnabled: config.visualRegressionEnabled,
      reliabilityThreshold: config.reliabilityThreshold,
      performanceThreshold: config.performanceThreshold,
      a11yThreshold: config.a11yThreshold,
      smokeModeEnabled: config.smokeModeEnabled
    }
  }
}); 