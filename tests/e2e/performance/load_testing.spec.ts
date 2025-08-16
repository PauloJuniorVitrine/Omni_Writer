/**
 * Testes E2E de Carga - Omni Writer
 * - Testes de carga usando Playwright
 * - Complementa testes Locust existentes
 * - Validação de performance em cenários reais
 * 
 * 📐 CoCoT: Baseado em cenários reais de uso da aplicação
 * 🌲 ToT: Múltiplas estratégias de carga implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de stress
 *
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T14:00:00Z
 * **Tracing ID:** E2E_LOAD_TESTING_md1ppfhs
 * **Origem:** Funcionalidades críticas do sistema Omni Writer
 */

import { test, expect, chromium } from '@playwright/test';
import { PerformanceMetrics, LoadTestConfig } from '../utils/performance-validator';

// Configuração para testes de carga
const LOAD_CONFIG: LoadTestConfig = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  concurrentUsers: 10,
  rampUpTime: 30, // segundos
  testDuration: 120, // segundos
  thresholds: {
    responseTime: 3000, // ms
    errorRate: 5, // %
    throughput: 10 // requests/segundo
  },
  scenarios: {
    generateContent: {
      weight: 3,
      endpoint: '/generate',
      method: 'POST'
    },
    downloadContent: {
      weight: 2,
      endpoint: '/download',
      method: 'GET'
    },
    checkStatus: {
      weight: 2,
      endpoint: '/status',
      method: 'GET'
    },
    sendFeedback: {
      weight: 1,
      endpoint: '/feedback',
      method: 'POST'
    }
  }
};

// Métricas de performance coletadas
const performanceMetrics: PerformanceMetrics[] = [];

test.describe('🧪 Testes E2E de Carga', () => {
  let browser;
  let contexts = [];
  let pages = [];

  test.beforeAll(async () => {
    // Inicializar browser para testes de carga
    browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });
  });

  test.afterAll(async () => {
    // Limpar recursos
    for (const page of pages) {
      await page.close();
    }
    for (const context of contexts) {
      await context.close();
    }
    await browser.close();
  });

  test('Carga Básica - 10 Usuários Concorrentes', async () => {
    const startTime = Date.now();
    const results = [];

    // Criar contextos e páginas para usuários concorrentes
    for (let i = 0; i < LOAD_CONFIG.concurrentUsers; i++) {
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: `LoadTest-User-${i + 1}`
      });
      contexts.push(context);
      
      const page = await context.newPage();
      pages.push(page);
      
      // Configurar interceptação de requests para métricas
      page.on('response', (response) => {
        const url = response.url();
        const status = response.status();
        const timing = response.timing();
        
        if (url.includes(LOAD_CONFIG.baseUrl)) {
          results.push({
            url,
            status,
            responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
            timestamp: Date.now()
          });
        }
      });
    }

    // Executar cenários de carga
    const loadPromises = pages.map(async (page, index) => {
      const userResults = [];
      
      // Navegar para página inicial
      const navStart = Date.now();
      await page.goto(LOAD_CONFIG.baseUrl);
      const navTime = Date.now() - navStart;
      userResults.push({ action: 'navigate', responseTime: navTime });

      // Executar cenários baseados em peso
      for (const [scenarioName, scenario] of Object.entries(LOAD_CONFIG.scenarios)) {
        for (let j = 0; j < scenario.weight; j++) {
          const scenarioStart = Date.now();
          
          try {
            if (scenario.method === 'GET') {
              const response = await page.request.get(`${LOAD_CONFIG.baseUrl}${scenario.endpoint}`);
              userResults.push({
                action: scenarioName,
                responseTime: Date.now() - scenarioStart,
                status: response.status(),
                success: response.ok()
              });
            } else if (scenario.method === 'POST') {
              const payload = generatePayload(scenarioName);
              const response = await page.request.post(`${LOAD_CONFIG.baseUrl}${scenario.endpoint}`, {
                data: payload
              });
              userResults.push({
                action: scenarioName,
                responseTime: Date.now() - scenarioStart,
                status: response.status(),
                success: response.ok()
              });
            }
          } catch (error) {
            userResults.push({
              action: scenarioName,
              responseTime: Date.now() - scenarioStart,
              status: 0,
              success: false,
              error: error.message
            });
          }
        }
      }
      
      return userResults;
    });

    // Aguardar conclusão de todos os usuários
    const allResults = await Promise.all(loadPromises);
    const totalDuration = Date.now() - startTime;

    // Analisar resultados
    const analysis = analyzeLoadResults(allResults, totalDuration);
    
    // Validar thresholds
    expect(analysis.avgResponseTime).toBeLessThan(LOAD_CONFIG.thresholds.responseTime);
    expect(analysis.errorRate).toBeLessThan(LOAD_CONFIG.thresholds.errorRate);
    expect(analysis.throughput).toBeGreaterThan(LOAD_CONFIG.thresholds.throughput);

    // Salvar métricas
    performanceMetrics.push({
      testName: 'Carga Básica - 10 Usuários',
      timestamp: new Date().toISOString(),
      duration: totalDuration,
      concurrentUsers: LOAD_CONFIG.concurrentUsers,
      avgResponseTime: analysis.avgResponseTime,
      maxResponseTime: analysis.maxResponseTime,
      minResponseTime: analysis.minResponseTime,
      errorRate: analysis.errorRate,
      throughput: analysis.throughput,
      totalRequests: analysis.totalRequests,
      successfulRequests: analysis.successfulRequests,
      failedRequests: analysis.failedRequests
    });

    console.log('📊 Resultados do Teste de Carga:');
    console.log(`  Tempo Total: ${totalDuration}ms`);
    console.log(`  Tempo Médio de Resposta: ${analysis.avgResponseTime}ms`);
    console.log(`  Taxa de Erro: ${analysis.errorRate}%`);
    console.log(`  Throughput: ${analysis.throughput} req/s`);
  });

  test('Teste de Stress - 50 Usuários Concorrentes', async () => {
    const stressConfig = { ...LOAD_CONFIG, concurrentUsers: 50 };
    const startTime = Date.now();
    const results = [];

    // Criar contextos para teste de stress
    const stressContexts = [];
    const stressPages = [];

    for (let i = 0; i < stressConfig.concurrentUsers; i++) {
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: `StressTest-User-${i + 1}`
      });
      stressContexts.push(context);
      
      const page = await context.newPage();
      stressPages.push(page);
      
      // Interceptar responses
      page.on('response', (response) => {
        const url = response.url();
        const status = response.status();
        const timing = response.timing();
        
        if (url.includes(stressConfig.baseUrl)) {
          results.push({
            url,
            status,
            responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
            timestamp: Date.now()
          });
        }
      });
    }

    // Executar cenário de stress focado em geração de conteúdo
    const stressPromises = stressPages.map(async (page, index) => {
      const userResults = [];
      
      // Navegar para página inicial
      await page.goto(stressConfig.baseUrl);
      
      // Executar múltiplas gerações de conteúdo
      for (let j = 0; j < 5; j++) {
        const start = Date.now();
        
        try {
          const payload = {
            api_key: `sk-test-${index}-${j}`,
            model_type: 'openai',
            prompts: [
              { text: `Prompt de stress ${j} do usuário ${index}`, index: 0 }
            ]
          };
          
          const response = await page.request.post(`${stressConfig.baseUrl}/generate`, {
            data: payload
          });
          
          userResults.push({
            action: 'generate_content',
            responseTime: Date.now() - start,
            status: response.status(),
            success: response.ok()
          });
        } catch (error) {
          userResults.push({
            action: 'generate_content',
            responseTime: Date.now() - start,
            status: 0,
            success: false,
            error: error.message
          });
        }
      }
      
      return userResults;
    });

    // Aguardar conclusão
    const allResults = await Promise.all(stressPromises);
    const totalDuration = Date.now() - startTime;

    // Analisar resultados de stress
    const analysis = analyzeLoadResults(allResults, totalDuration);
    
    // Validar thresholds de stress (mais permissivos)
    expect(analysis.avgResponseTime).toBeLessThan(LOAD_CONFIG.thresholds.responseTime * 2);
    expect(analysis.errorRate).toBeLessThan(LOAD_CONFIG.thresholds.errorRate * 2);

    // Salvar métricas de stress
    performanceMetrics.push({
      testName: 'Teste de Stress - 50 Usuários',
      timestamp: new Date().toISOString(),
      duration: totalDuration,
      concurrentUsers: stressConfig.concurrentUsers,
      avgResponseTime: analysis.avgResponseTime,
      maxResponseTime: analysis.maxResponseTime,
      minResponseTime: analysis.minResponseTime,
      errorRate: analysis.errorRate,
      throughput: analysis.throughput,
      totalRequests: analysis.totalRequests,
      successfulRequests: analysis.successfulRequests,
      failedRequests: analysis.failedRequests
    });

    // Limpar recursos de stress
    for (const page of stressPages) {
      await page.close();
    }
    for (const context of stressContexts) {
      await context.close();
    }

    console.log('📊 Resultados do Teste de Stress:');
    console.log(`  Tempo Total: ${totalDuration}ms`);
    console.log(`  Tempo Médio de Resposta: ${analysis.avgResponseTime}ms`);
    console.log(`  Taxa de Erro: ${analysis.errorRate}%`);
    console.log(`  Throughput: ${analysis.throughput} req/s`);
  });

  test('Teste de Concorrência - Múltiplas Operações Simultâneas', async () => {
    const startTime = Date.now();
    const results = [];

    // Criar contexto para teste de concorrência
    const context = await browser.newContext({
      viewport: { width: 1280, height: 720 }
    });
    const page = await context.newPage();

    // Interceptar responses
    page.on('response', (response) => {
      const url = response.url();
      const status = response.status();
      const timing = response.timing();
      
      if (url.includes(LOAD_CONFIG.baseUrl)) {
        results.push({
          url,
          status,
          responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
          timestamp: Date.now()
        });
      }
    });

    // Navegar para página inicial
    await page.goto(LOAD_CONFIG.baseUrl);

    // Executar operações concorrentes
    const concurrentOperations = [
      // Geração de conteúdo
      page.request.post(`${LOAD_CONFIG.baseUrl}/generate`, {
        data: {
          api_key: 'sk-test-concurrent-1',
          model_type: 'openai',
          prompts: [{ text: 'Prompt concorrente 1', index: 0 }]
        }
      }),
      
      // Download de conteúdo
      page.request.get(`${LOAD_CONFIG.baseUrl}/download`),
      
      // Verificação de status
      page.request.get(`${LOAD_CONFIG.baseUrl}/status/test-trace-1`),
      
      // Envio de feedback
      page.request.post(`${LOAD_CONFIG.baseUrl}/feedback`, {
        data: {
          article_id: 1,
          feedback: 'positivo',
          comentario: 'Teste concorrente'
        }
      }),
      
      // Registro de webhook
      page.request.post(`${LOAD_CONFIG.baseUrl}/webhook`, {
        data: { url: 'http://localhost:8080/webhook' }
      })
    ];

    // Executar todas as operações simultaneamente
    const start = Date.now();
    const responses = await Promise.allSettled(concurrentOperations);
    const totalTime = Date.now() - start;

    // Analisar resultados
    const successfulOperations = responses.filter(r => r.status === 'fulfilled').length;
    const failedOperations = responses.filter(r => r.status === 'rejected').length;
    
    const avgResponseTime = totalTime / concurrentOperations.length;
    const errorRate = (failedOperations / concurrentOperations.length) * 100;

    // Validar concorrência
    expect(avgResponseTime).toBeLessThan(LOAD_CONFIG.thresholds.responseTime);
    expect(errorRate).toBeLessThan(LOAD_CONFIG.thresholds.errorRate);
    expect(successfulOperations).toBeGreaterThan(concurrentOperations.length * 0.8);

    // Salvar métricas
    performanceMetrics.push({
      testName: 'Teste de Concorrência',
      timestamp: new Date().toISOString(),
      duration: totalTime,
      concurrentUsers: 1,
      avgResponseTime,
      maxResponseTime: totalTime,
      minResponseTime: totalTime,
      errorRate,
      throughput: concurrentOperations.length / (totalTime / 1000),
      totalRequests: concurrentOperations.length,
      successfulRequests: successfulOperations,
      failedRequests: failedOperations
    });

    await context.close();

    console.log('📊 Resultados do Teste de Concorrência:');
    console.log(`  Operações Simultâneas: ${concurrentOperations.length}`);
    console.log(`  Sucessos: ${successfulOperations}`);
    console.log(`  Falhas: ${failedOperations}`);
    console.log(`  Tempo Médio: ${avgResponseTime}ms`);
    console.log(`  Taxa de Erro: ${errorRate}%`);
  });

  test('Geração de Relatório de Performance', async () => {
    // Gerar relatório consolidado
    const report = generatePerformanceReport(performanceMetrics);
    
    // Salvar relatório
    const fs = require('fs');
    const path = require('path');
    
    const reportDir = 'test-results/performance';
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    const reportPath = path.join(reportDir, `load-test-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log(`📊 Relatório salvo em: ${reportPath}`);
    
    // Validar métricas gerais
    const overallMetrics = calculateOverallMetrics(performanceMetrics);
    
    expect(overallMetrics.avgResponseTime).toBeLessThan(LOAD_CONFIG.thresholds.responseTime);
    expect(overallMetrics.errorRate).toBeLessThan(LOAD_CONFIG.thresholds.errorRate);
    expect(overallMetrics.throughput).toBeGreaterThan(LOAD_CONFIG.thresholds.throughput);
  });
});

// Funções auxiliares
function generatePayload(scenarioName: string): any {
  switch (scenarioName) {
    case 'generateContent':
      return {
        api_key: `sk-test-${Date.now()}`,
        model_type: 'openai',
        prompts: [
          { text: `Prompt de teste ${Date.now()}`, index: 0 }
        ]
      };
    case 'sendFeedback':
      return {
        article_id: Math.floor(Math.random() * 100) + 1,
        feedback: ['positivo', 'negativo', 'neutro'][Math.floor(Math.random() * 3)],
        comentario: `Comentário de teste ${Date.now()}`
      };
    default:
      return {};
  }
}

function analyzeLoadResults(results: any[], totalDuration: number) {
  const allResponses = results.flat();
  const responseTimes = allResponses.map(r => r.responseTime).filter(t => t > 0);
  const successfulRequests = allResponses.filter(r => r.success).length;
  const failedRequests = allResponses.filter(r => !r.success).length;
  const totalRequests = allResponses.length;

  return {
    avgResponseTime: responseTimes.length > 0 ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length : 0,
    maxResponseTime: responseTimes.length > 0 ? Math.max(...responseTimes) : 0,
    minResponseTime: responseTimes.length > 0 ? Math.min(...responseTimes) : 0,
    errorRate: totalRequests > 0 ? (failedRequests / totalRequests) * 100 : 0,
    throughput: totalRequests / (totalDuration / 1000),
    totalRequests,
    successfulRequests,
    failedRequests
  };
}

function generatePerformanceReport(metrics: PerformanceMetrics[]) {
  return {
    summary: {
      totalTests: metrics.length,
      timestamp: new Date().toISOString(),
      overallMetrics: calculateOverallMetrics(metrics)
    },
    details: metrics,
    recommendations: generateRecommendations(metrics)
  };
}

function calculateOverallMetrics(metrics: PerformanceMetrics[]) {
  const totalRequests = metrics.reduce((sum, m) => sum + m.totalRequests, 0);
  const totalSuccessful = metrics.reduce((sum, m) => sum + m.successfulRequests, 0);
  const totalFailed = metrics.reduce((sum, m) => sum + m.failedRequests, 0);
  const totalDuration = metrics.reduce((sum, m) => sum + m.duration, 0);
  
  const avgResponseTime = metrics.reduce((sum, m) => sum + m.avgResponseTime, 0) / metrics.length;
  const errorRate = totalRequests > 0 ? (totalFailed / totalRequests) * 100 : 0;
  const throughput = totalRequests / (totalDuration / 1000);

  return {
    avgResponseTime,
    errorRate,
    throughput,
    totalRequests,
    successfulRequests: totalSuccessful,
    failedRequests: totalFailed
  };
}

function generateRecommendations(metrics: PerformanceMetrics[]): string[] {
  const recommendations = [];
  const overall = calculateOverallMetrics(metrics);

  if (overall.avgResponseTime > 2000) {
    recommendations.push('⚠️ Tempo de resposta alto - considere otimizar queries ou cache');
  }

  if (overall.errorRate > 2) {
    recommendations.push('⚠️ Taxa de erro elevada - investigue falhas de sistema');
  }

  if (overall.throughput < 5) {
    recommendations.push('⚠️ Throughput baixo - considere escalar recursos');
  }

  if (recommendations.length === 0) {
    recommendations.push('✅ Performance dentro dos parâmetros aceitáveis');
  }

  return recommendations;
} 