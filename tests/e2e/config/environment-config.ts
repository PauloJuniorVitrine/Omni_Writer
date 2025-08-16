/**
 * Configuração de Ambientes para Shadow Testing
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - TEST-005
 * Data/Hora: 2025-01-28T02:20:00Z
 * Tracing ID: ENV_CONFIG_20250128_001
 * 
 * Configuração de ambientes para validação shadow
 * Baseado em código real da aplicação Omni Writer
 */

export interface EnvironmentConfig {
  prod: EnvironmentSettings;
  canary: EnvironmentSettings;
  staging: EnvironmentSettings;
  dev: EnvironmentSettings;
  global: GlobalSettings;
}

export interface EnvironmentSettings {
  url: string;
  timeout: number;
  retries: number;
  workers: number;
  apiKey?: string;
  headers?: Record<string, string>;
  enableScreenshots: boolean;
  enableMetrics: boolean;
  enableLogs: boolean;
}

export interface GlobalSettings {
  similarityThreshold: number;
  performanceThreshold: number;
  responseTimeThreshold: number;
  enableShadowTesting: boolean;
  enableMultiRegion: boolean;
  enableA11YValidation: boolean;
  enableWebVitals: boolean;
  enableSemanticValidation: boolean;
  maxRetries: number;
  retryDelay: number;
  screenshotDir: string;
  reportDir: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  // Configurações Multi-Região
  regions: string[];
  regionTimeout: number;
  latencyThreshold: number;
}

/**
 * Carrega configuração de ambiente
 */
export function loadEnvironmentConfig(): EnvironmentConfig {
  const config: EnvironmentConfig = {
    prod: {
      url: process.env.PROD_URL || 'https://omni-writer.com',
      timeout: parseInt(process.env.PROD_TIMEOUT || '90000'),
      retries: parseInt(process.env.PROD_RETRIES || '0'),
      workers: parseInt(process.env.PROD_WORKERS || '3'),
      apiKey: process.env.PROD_API_KEY,
      headers: {
        'User-Agent': 'Omni-Writer-Shadow-Test/1.0',
        'X-Environment': 'production'
      },
      enableScreenshots: process.env.PROD_ENABLE_SCREENSHOTS !== 'false',
      enableMetrics: process.env.PROD_ENABLE_METRICS !== 'false',
      enableLogs: process.env.PROD_ENABLE_LOGS !== 'false'
    },
    canary: {
      url: process.env.CANARY_URL || 'https://canary.omni-writer.com',
      timeout: parseInt(process.env.CANARY_TIMEOUT || '60000'),
      retries: parseInt(process.env.CANARY_RETRIES || '1'),
      workers: parseInt(process.env.CANARY_WORKERS || '2'),
      apiKey: process.env.CANARY_API_KEY,
      headers: {
        'User-Agent': 'Omni-Writer-Shadow-Test/1.0',
        'X-Environment': 'canary'
      },
      enableScreenshots: process.env.CANARY_ENABLE_SCREENSHOTS !== 'false',
      enableMetrics: process.env.CANARY_ENABLE_METRICS !== 'false',
      enableLogs: process.env.CANARY_ENABLE_LOGS !== 'false'
    },
    staging: {
      url: process.env.STAGING_URL || 'https://staging.omni-writer.com',
      timeout: parseInt(process.env.STAGING_TIMEOUT || '60000'),
      retries: parseInt(process.env.STAGING_RETRIES || '1'),
      workers: parseInt(process.env.STAGING_WORKERS || '2'),
      apiKey: process.env.STAGING_API_KEY,
      headers: {
        'User-Agent': 'Omni-Writer-Shadow-Test/1.0',
        'X-Environment': 'staging'
      },
      enableScreenshots: process.env.STAGING_ENABLE_SCREENSHOTS !== 'false',
      enableMetrics: process.env.STAGING_ENABLE_METRICS !== 'false',
      enableLogs: process.env.STAGING_ENABLE_LOGS !== 'false'
    },
    dev: {
      url: process.env.DEV_URL || 'http://localhost:5000',
      timeout: parseInt(process.env.DEV_TIMEOUT || '30000'),
      retries: parseInt(process.env.DEV_RETRIES || '2'),
      workers: parseInt(process.env.DEV_WORKERS || '1'),
      apiKey: process.env.DEV_API_KEY || 'dev-fake-key',
      headers: {
        'User-Agent': 'Omni-Writer-Shadow-Test/1.0',
        'X-Environment': 'development'
      },
      enableScreenshots: process.env.DEV_ENABLE_SCREENSHOTS !== 'false',
      enableMetrics: process.env.DEV_ENABLE_METRICS !== 'false',
      enableLogs: process.env.DEV_ENABLE_LOGS !== 'false'
    },
    global: {
      similarityThreshold: parseFloat(process.env.SIMILARITY_THRESHOLD || '0.90'),
      performanceThreshold: parseInt(process.env.PERFORMANCE_THRESHOLD || '1000'),
      responseTimeThreshold: parseInt(process.env.RESPONSE_TIME_THRESHOLD || '1000'),
      enableShadowTesting: process.env.SHADOW_ENABLED !== 'false',
      enableMultiRegion: process.env.MULTI_REGION_ENABLED === 'true',
      enableA11YValidation: process.env.A11Y_ENABLED !== 'false',
      enableWebVitals: process.env.WEB_VITALS_ENABLED !== 'false',
      enableSemanticValidation: process.env.SEMANTIC_VALIDATION_ENABLED !== 'false',
      maxRetries: parseInt(process.env.MAX_RETRIES || '3'),
      retryDelay: parseInt(process.env.RETRY_DELAY || '1000'),
      screenshotDir: process.env.SCREENSHOT_DIR || 'test-results/screenshots',
      reportDir: process.env.REPORT_DIR || 'test-results/reports',
      logLevel: (process.env.LOG_LEVEL as any) || 'info',
      // Configurações Multi-Região
      regions: process.env.REGIONS ? process.env.REGIONS.split(',') : ['us-east-1', 'eu-central-1', 'sa-east-1', 'ap-southeast-1'],
      regionTimeout: parseInt(process.env.REGION_TIMEOUT || '30000'),
      latencyThreshold: parseInt(process.env.LATENCY_THRESHOLD || '200')
    }
  };

  return config;
}

/**
 * Valida configuração de ambiente
 */
export function validateEnvironmentConfig(config: EnvironmentConfig): ValidationResult {
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    warnings: [],
    recommendations: []
  };

  // Validação de URLs
  if (!isValidUrl(config.prod.url)) {
    result.errors.push('URL de produção inválida');
    result.isValid = false;
  }

  if (!isValidUrl(config.canary.url)) {
    result.errors.push('URL de canary inválida');
    result.isValid = false;
  }

  // Validação de timeouts
  if (config.prod.timeout < 10000) {
    result.warnings.push('Timeout de produção muito baixo (< 10s)');
  }

  if (config.canary.timeout < 10000) {
    result.warnings.push('Timeout de canary muito baixo (< 10s)');
  }

  // Validação de thresholds
  if (config.global.similarityThreshold < 0.8) {
    result.warnings.push('Threshold de similaridade muito baixo (< 0.8)');
  }

  if (config.global.similarityThreshold > 0.95) {
    result.warnings.push('Threshold de similaridade muito alto (> 0.95)');
  }

  // Validação de workers
  if (config.prod.workers > 5) {
    result.warnings.push('Muitos workers em produção (> 5)');
  }

  if (config.canary.workers > 3) {
    result.warnings.push('Muitos workers em canary (> 3)');
  }

  // Recomendações
  if (!config.prod.apiKey) {
    result.recommendations.push('Configurar API key de produção para testes completos');
  }

  if (!config.canary.apiKey) {
    result.recommendations.push('Configurar API key de canary para testes completos');
  }

  if (!config.global.enableShadowTesting) {
    result.recommendations.push('Habilitar shadow testing para validação completa');
  }

  return result;
}

/**
 * Gera configuração para shadow testing
 */
export function generateShadowConfig(config: EnvironmentConfig): ShadowConfig {
  return {
    prodUrl: config.prod.url,
    canaryUrl: config.canary.url,
    timeout: Math.max(config.prod.timeout, config.canary.timeout),
    similarityThreshold: config.global.similarityThreshold,
    enableScreenshots: config.prod.enableScreenshots && config.canary.enableScreenshots,
    enableMetrics: config.prod.enableMetrics && config.canary.enableMetrics
  };
}

/**
 * Gera template de variáveis de ambiente
 */
export function generateEnvTemplate(): string {
  return `# Configuração de Ambientes para Shadow Testing
# Omni Writer - Testes E2E

# URLs dos Ambientes
PROD_URL=https://omni-writer.com
CANARY_URL=https://canary.omni-writer.com
STAGING_URL=https://staging.omni-writer.com
DEV_URL=http://localhost:5000

# Timeouts (em ms)
PROD_TIMEOUT=90000
CANARY_TIMEOUT=60000
STAGING_TIMEOUT=60000
DEV_TIMEOUT=30000

# Retries
PROD_RETRIES=0
CANARY_RETRIES=1
STAGING_RETRIES=1
DEV_RETRIES=2

# Workers
PROD_WORKERS=3
CANARY_WORKERS=2
STAGING_WORKERS=2
DEV_WORKERS=1

# API Keys (configurar conforme necessário)
PROD_API_KEY=your_prod_api_key_here
CANARY_API_KEY=your_canary_api_key_here
STAGING_API_KEY=your_staging_api_key_here
DEV_API_KEY=dev-fake-key

# Screenshots
PROD_ENABLE_SCREENSHOTS=true
CANARY_ENABLE_SCREENSHOTS=true
STAGING_ENABLE_SCREENSHOTS=true
DEV_ENABLE_SCREENSHOTS=true

# Métricas
PROD_ENABLE_METRICS=true
CANARY_ENABLE_METRICS=true
STAGING_ENABLE_METRICS=true
DEV_ENABLE_METRICS=true

# Logs
PROD_ENABLE_LOGS=true
CANARY_ENABLE_LOGS=true
STAGING_ENABLE_LOGS=true
DEV_ENABLE_LOGS=true

# Configurações Globais
SIMILARITY_THRESHOLD=0.90
PERFORMANCE_THRESHOLD=1000
RESPONSE_TIME_THRESHOLD=1000

# Funcionalidades
SHADOW_ENABLED=true
MULTI_REGION_ENABLED=false
A11Y_ENABLED=true
WEB_VITALS_ENABLED=true
SEMANTIC_VALIDATION_ENABLED=true

# Retry e Delay
MAX_RETRIES=3
RETRY_DELAY=1000

# Diretórios
SCREENSHOT_DIR=test-results/screenshots
REPORT_DIR=test-results/reports

# Log Level
LOG_LEVEL=info
`;
}

// Interfaces e tipos auxiliares

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  recommendations: string[];
}

export interface ShadowConfig {
  prodUrl: string;
  canaryUrl: string;
  timeout: number;
  similarityThreshold: number;
  enableScreenshots: boolean;
  enableMetrics: boolean;
}

// Funções auxiliares

function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// Exporta configuração padrão
export const defaultEnvironmentConfig = loadEnvironmentConfig(); 