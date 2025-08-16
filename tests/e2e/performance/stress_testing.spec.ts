/**
 * Testes E2E de Stress - Omni Writer
 * - Testes de stress para cenários extremos
 * - Validação de limites do sistema
 * - Análise de comportamento sob carga extrema
 * 
 * 📐 CoCoT: Baseado em cenários extremos de uso da aplicação
 * 🌲 ToT: Múltiplas estratégias de stress implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de falha
 *
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T15:00:00Z
 * **Tracing ID:** E2E_STRESS_TESTING_md1ppfhs
 * **Origem:** Necessidade de validação de limites do sistema
 */

import { test, expect, chromium } from '@playwright/test';
import { PerformanceValidator, PerformanceMetrics } from '../utils/performance-validator';

// Configuração para testes de stress
const STRESS_CONFIG = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  maxUsers: 100,
  stressLevels: [10, 25, 50, 75, 100],
  testDuration: 300, // 5 minutos
  recoveryTime: 60, // 1 minuto
  thresholds: {
    maxResponseTime: 10000, // 10 segundos
    maxErrorRate: 20, // 20%
    minThroughput: 1 // 1 req/s mínimo
  }
};

// Métricas de stress coletadas
const stressMetrics: PerformanceMetrics[] = [];

test.describe('🔥 Testes E2E de Stress', () => {
  let browser;
  let validator: PerformanceValidator;

  test.beforeAll(async () => {
    // Inicializar browser para testes de stress
    browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--max-old-space-size=4096'
      ]
    });

    // Inicializar validador de performance
    validator = new PerformanceValidator({
      baseUrl: STRESS_CONFIG.baseUrl,
      concurrentUsers: STRESS_CONFIG.maxUsers,
      rampUpTime: 30,
      testDuration: STRESS_CONFIG.testDuration,
      thresholds: {
        responseTime: STRESS_CONFIG.thresholds.maxResponseTime,
        errorRate: STRESS_CONFIG.thresholds.maxErrorRate,
        throughput: STRESS_CONFIG.thresholds.minThroughput
      },
      scenarios: {}
    });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('Stress Progressivo - Aumento Gradual de Carga', async () => {
    console.log('🔥 Iniciando teste de stress progressivo...');

    for (const userCount of STRESS_CONFIG.stressLevels) {
      console.log(`📊 Testando com ${userCount} usuários concorrentes...`);
      
      const startTime = Date.now();
      const results = [];
      const contexts = [];
      const pages = [];

      // Criar usuários para este nível de stress
      for (let i = 0; i < userCount; i++) {
        const context = await browser.newContext({
          viewport: { width: 1280, height: 720 },
          userAgent: `StressTest-User-${i + 1}`
        });
        contexts.push(context);
        
        const page = await context.newPage();
        pages.push(page);
        
        // Interceptar responses
        page.on('response', (response) => {
          const url = response.url();
          const status = response.status();
          const timing = response.timing();
          
          if (url.includes(STRESS_CONFIG.baseUrl)) {
            results.push({
              url,
              status,
              responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
              timestamp: Date.now(),
              userIndex: i
            });
          }
        });
      }

      // Executar cenário de stress
      const stressPromises = pages.map(async (page, index) => {
        const userResults = [];
        
        try {
          // Navegar para página inicial
          await page.goto(STRESS_CONFIG.baseUrl, { timeout: 30000 });
          
          // Executar operações de stress
          for (let j = 0; j < 10; j++) {
            const operationStart = Date.now();
            
            try {
              // Geração de conteúdo (operação mais pesada)
              const payload = {
                api_key: `sk-stress-${index}-${j}`,
                model_type: 'openai',
                prompts: [
                  { text: `Prompt de stress ${j} do usuário ${index} - ${Date.now()}`, index: 0 }
                ]
              };
              
              const response = await page.request.post(`${STRESS_CONFIG.baseUrl}/generate`, {
                data: payload,
                timeout: 30000
              });
              
              userResults.push({
                action: 'generate_content',
                responseTime: Date.now() - operationStart,
                status: response.status(),
                success: response.ok()
              });
              
              // Download de conteúdo
              const downloadResponse = await page.request.get(`${STRESS_CONFIG.baseUrl}/download`, {
                timeout: 30000
              });
              
              userResults.push({
                action: 'download_content',
                responseTime: Date.now() - operationStart,
                status: downloadResponse.status(),
                success: downloadResponse.ok()
              });
              
            } catch (error) {
              userResults.push({
                action: 'stress_operation',
                responseTime: Date.now() - operationStart,
                status: 0,
                success: false,
                error: error.message
              });
            }
          }
        } catch (error) {
          console.error(`Erro no usuário ${index}:`, error.message);
        }
        
        return userResults;
      });

      // Aguardar conclusão
      const allResults = await Promise.all(stressPromises);
      const totalDuration = Date.now() - startTime;

      // Analisar resultados
      const analysis = analyzeStressResults(allResults, totalDuration, userCount);
      
      // Salvar métricas
      const metric: PerformanceMetrics = {
        testName: `Stress Progressivo - ${userCount} Usuários`,
        timestamp: new Date().toISOString(),
        duration: totalDuration,
        concurrentUsers: userCount,
        avgResponseTime: analysis.avgResponseTime,
        maxResponseTime: analysis.maxResponseTime,
        minResponseTime: analysis.minResponseTime,
        errorRate: analysis.errorRate,
        throughput: analysis.throughput,
        totalRequests: analysis.totalRequests,
        successfulRequests: analysis.successfulRequests,
        failedRequests: analysis.failedRequests
      };

      stressMetrics.push(metric);

      // Validar resultados
      const validation = validator.validateMetrics(metric);
      
      console.log(`📊 Resultados para ${userCount} usuários:`);
      console.log(`  Tempo Médio: ${analysis.avgResponseTime}ms`);
      console.log(`  Taxa de Erro: ${analysis.errorRate}%`);
      console.log(`  Throughput: ${analysis.throughput} req/s`);
      console.log(`  Score: ${validation.score}/100`);

      // Limpar recursos
      for (const page of pages) {
        await page.close();
      }
      for (const context of contexts) {
        await context.close();
      }

      // Aguardar recuperação entre níveis
      if (userCount < STRESS_CONFIG.stressLevels[STRESS_CONFIG.stressLevels.length - 1]) {
        console.log(`⏳ Aguardando ${STRESS_CONFIG.recoveryTime}s para recuperação...`);
        await new Promise(resolve => setTimeout(resolve, STRESS_CONFIG.recoveryTime * 1000));
      }
    }

    // Validar que o sistema não quebrou completamente
    const finalValidation = validator.validateMetrics(stressMetrics[stressMetrics.length - 1]);
    expect(finalValidation.score).toBeGreaterThan(0);
  });

  test('Teste de Break Point - Encontrar Limite do Sistema', async () => {
    console.log('🔥 Iniciando teste de break point...');
    
    let currentUsers = 50;
    let breakPointFound = false;
    const breakPointMetrics: PerformanceMetrics[] = [];

    while (!breakPointFound && currentUsers <= 200) {
      console.log(`🔍 Testando break point com ${currentUsers} usuários...`);
      
      const startTime = Date.now();
      const results = [];
      const contexts = [];
      const pages = [];

      // Criar usuários para teste
      for (let i = 0; i < currentUsers; i++) {
        const context = await browser.newContext({
          viewport: { width: 1280, height: 720 },
          userAgent: `BreakPoint-User-${i + 1}`
        });
        contexts.push(context);
        
        const page = await context.newPage();
        pages.push(page);
        
        page.on('response', (response) => {
          const url = response.url();
          const status = response.status();
          const timing = response.timing();
          
          if (url.includes(STRESS_CONFIG.baseUrl)) {
            results.push({
              url,
              status,
              responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
              timestamp: Date.now()
            });
          }
        });
      }

      // Executar teste de break point
      const breakPointPromises = pages.map(async (page, index) => {
        const userResults = [];
        
        try {
          await page.goto(STRESS_CONFIG.baseUrl, { timeout: 30000 });
          
          // Executar operações intensivas
          for (let j = 0; j < 5; j++) {
            const start = Date.now();
            
            try {
              const payload = {
                api_key: `sk-breakpoint-${index}-${j}`,
                model_type: 'openai',
                prompts: [
                  { text: `Break point test ${j} user ${index}`, index: 0 }
                ]
              };
              
              const response = await page.request.post(`${STRESS_CONFIG.baseUrl}/generate`, {
                data: payload,
                timeout: 60000
              });
              
              userResults.push({
                action: 'breakpoint_generate',
                responseTime: Date.now() - start,
                status: response.status(),
                success: response.ok()
              });
              
            } catch (error) {
              userResults.push({
                action: 'breakpoint_generate',
                responseTime: Date.now() - start,
                status: 0,
                success: false,
                error: error.message
              });
            }
          }
        } catch (error) {
          console.error(`Erro no break point usuário ${index}:`, error.message);
        }
        
        return userResults;
      });

      const allResults = await Promise.all(breakPointPromises);
      const totalDuration = Date.now() - startTime;

      // Analisar resultados
      const analysis = analyzeStressResults(allResults, totalDuration, currentUsers);
      
      const metric: PerformanceMetrics = {
        testName: `Break Point - ${currentUsers} Usuários`,
        timestamp: new Date().toISOString(),
        duration: totalDuration,
        concurrentUsers: currentUsers,
        avgResponseTime: analysis.avgResponseTime,
        maxResponseTime: analysis.maxResponseTime,
        minResponseTime: analysis.minResponseTime,
        errorRate: analysis.errorRate,
        throughput: analysis.throughput,
        totalRequests: analysis.totalRequests,
        successfulRequests: analysis.successfulRequests,
        failedRequests: analysis.failedRequests
      };

      breakPointMetrics.push(metric);

      // Verificar se encontrou break point
      if (analysis.errorRate > 50 || analysis.avgResponseTime > 30000) {
        breakPointFound = true;
        console.log(`🚨 Break point encontrado em ${currentUsers} usuários!`);
        console.log(`  Taxa de Erro: ${analysis.errorRate}%`);
        console.log(`  Tempo Médio: ${analysis.avgResponseTime}ms`);
      } else {
        currentUsers += 25; // Aumentar carga
      }

      // Limpar recursos
      for (const page of pages) {
        await page.close();
      }
      for (const context of contexts) {
        await context.close();
      }

      // Aguardar entre testes
      await new Promise(resolve => setTimeout(resolve, 30000));
    }

    // Validar que encontrou break point
    expect(breakPointFound).toBe(true);
    expect(breakPointMetrics.length).toBeGreaterThan(0);
  });

  test('Teste de Recuperação - Sistema Após Stress', async () => {
    console.log('🔄 Iniciando teste de recuperação...');
    
    // Primeiro, aplicar stress
    const stressStartTime = Date.now();
    const stressContexts = [];
    const stressPages = [];

    for (let i = 0; i < 50; i++) {
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: `Recovery-Stress-User-${i + 1}`
      });
      stressContexts.push(context);
      
      const page = await context.newPage();
      stressPages.push(page);
    }

    // Aplicar stress por 2 minutos
    const stressPromises = stressPages.map(async (page, index) => {
      try {
        await page.goto(STRESS_CONFIG.baseUrl);
        
        for (let j = 0; j < 10; j++) {
          try {
            const payload = {
              api_key: `sk-recovery-stress-${index}-${j}`,
              model_type: 'openai',
              prompts: [{ text: `Recovery stress ${j}`, index: 0 }]
            };
            
            await page.request.post(`${STRESS_CONFIG.baseUrl}/generate`, {
              data: payload,
              timeout: 30000
            });
          } catch (error) {
            // Ignorar erros durante stress
          }
        }
      } catch (error) {
        // Ignorar erros durante stress
      }
    });

    await Promise.all(stressPromises);
    const stressDuration = Date.now() - stressStartTime;

    // Limpar stress
    for (const page of stressPages) {
      await page.close();
    }
    for (const context of stressContexts) {
      await context.close();
    }

    console.log(`🔥 Stress aplicado por ${stressDuration}ms`);

    // Aguardar recuperação
    console.log('⏳ Aguardando recuperação do sistema...');
    await new Promise(resolve => setTimeout(resolve, 60000)); // 1 minuto

    // Testar recuperação
    const recoveryStartTime = Date.now();
    const recoveryResults = [];

    const recoveryContext = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent: 'Recovery-Test-User'
    });
    const recoveryPage = await recoveryContext.newPage();

    recoveryPage.on('response', (response) => {
      const url = response.url();
      const status = response.status();
      const timing = response.timing();
      
      if (url.includes(STRESS_CONFIG.baseUrl)) {
        recoveryResults.push({
          url,
          status,
          responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
          timestamp: Date.now()
        });
      }
    });

    // Testar operações normais
    await recoveryPage.goto(STRESS_CONFIG.baseUrl);
    
    const testOperations = [
      async () => {
        const payload = {
          api_key: 'sk-recovery-test',
          model_type: 'openai',
          prompts: [{ text: 'Teste de recuperação', index: 0 }]
        };
        return await recoveryPage.request.post(`${STRESS_CONFIG.baseUrl}/generate`, {
          data: payload,
          timeout: 30000
        });
      },
      async () => {
        return await recoveryPage.request.get(`${STRESS_CONFIG.baseUrl}/download`, {
          timeout: 30000
        });
      },
      async () => {
        return await recoveryPage.request.get(`${STRESS_CONFIG.baseUrl}/status/test-recovery`, {
          timeout: 30000
        });
      }
    ];

    const operationResults = [];
    for (const operation of testOperations) {
      const start = Date.now();
      try {
        const response = await operation();
        operationResults.push({
          success: true,
          responseTime: Date.now() - start,
          status: response.status()
        });
      } catch (error) {
        operationResults.push({
          success: false,
          responseTime: Date.now() - start,
          error: error.message
        });
      }
    }

    const recoveryDuration = Date.now() - recoveryStartTime;
    await recoveryContext.close();

    // Analisar recuperação
    const successfulOperations = operationResults.filter(r => r.success).length;
    const avgRecoveryTime = operationResults.reduce((sum, r) => sum + r.responseTime, 0) / operationResults.length;
    const recoverySuccessRate = (successfulOperations / operationResults.length) * 100;

    console.log('📊 Resultados da Recuperação:');
    console.log(`  Operações Bem-sucedidas: ${successfulOperations}/${operationResults.length}`);
    console.log(`  Taxa de Sucesso: ${recoverySuccessRate}%`);
    console.log(`  Tempo Médio: ${avgRecoveryTime}ms`);

    // Validar recuperação
    expect(recoverySuccessRate).toBeGreaterThan(80);
    expect(avgRecoveryTime).toBeLessThan(5000);
  });

  test('Geração de Relatório de Stress', async () => {
    // Gerar relatório consolidado
    const report = validator.generateReport(stressMetrics);
    
    // Salvar relatório
    const fs = require('fs');
    const path = require('path');
    
    const reportDir = 'test-results/stress';
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    const reportPath = path.join(reportDir, `stress-test-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log(`📊 Relatório de stress salvo em: ${reportPath}`);
    
    // Validar métricas gerais
    expect(report.summary.totalTests).toBeGreaterThan(0);
    expect(report.summary.averageScore).toBeGreaterThan(0);
    
    console.log('📊 Resumo do Relatório de Stress:');
    console.log(`  Total de Testes: ${report.summary.totalTests}`);
    console.log(`  Testes Aprovados: ${report.summary.passedTests}`);
    console.log(`  Score Médio: ${report.summary.averageScore.toFixed(1)}/100`);
    console.log(`  Tendência: ${report.summary.overallTrend}`);
  });
});

// Função auxiliar para análise de resultados de stress
function analyzeStressResults(results: any[], totalDuration: number, userCount: number) {
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
    failedRequests,
    userCount
  };
} 