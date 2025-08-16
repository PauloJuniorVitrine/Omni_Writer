/**
 * Testes E2E de Concorrência - Omni Writer
 * - Testes de concorrência para múltiplos usuários
 * - Validação de operações simultâneas
 * - Análise de comportamento concorrente
 * 
 * 📐 CoCoT: Baseado em cenários reais de concorrência
 * 🌲 ToT: Múltiplas estratégias de concorrência implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de concorrência
 *
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T15:30:00Z
 * **Tracing ID:** E2E_CONCURRENCY_TESTING_md1ppfhs
 * **Origem:** Necessidade de validação de operações concorrentes
 */

import { test, expect, chromium } from '@playwright/test';
import { PerformanceValidator, PerformanceMetrics } from '../utils/performance-validator';

// Configuração para testes de concorrência
const CONCURRENCY_CONFIG = {
  baseUrl: process.env.E2E_BASE_URL || 'http://localhost:5000',
  userCounts: [5, 10, 20, 30],
  testDuration: 120, // 2 minutos
  operationTypes: [
    'generate_content',
    'download_content',
    'check_status',
    'send_feedback',
    'register_webhook'
  ]
};

// Métricas de concorrência coletadas
const concurrencyMetrics: PerformanceMetrics[] = [];

test.describe('🔄 Testes E2E de Concorrência', () => {
  let browser;
  let validator: PerformanceValidator;

  test.beforeAll(async () => {
    // Inicializar browser para testes de concorrência
    browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    // Inicializar validador de performance
    validator = new PerformanceValidator({
      baseUrl: CONCURRENCY_CONFIG.baseUrl,
      concurrentUsers: Math.max(...CONCURRENCY_CONFIG.userCounts),
      rampUpTime: 10,
      testDuration: CONCURRENCY_CONFIG.testDuration,
      thresholds: {
        responseTime: 5000,
        errorRate: 10,
        throughput: 5
      },
      scenarios: {}
    });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test('Concorrência de Geração de Conteúdo', async () => {
    console.log('🔄 Iniciando teste de concorrência de geração...');

    for (const userCount of CONCURRENCY_CONFIG.userCounts) {
      console.log(`📊 Testando concorrência com ${userCount} usuários...`);
      
      const startTime = Date.now();
      const results = [];
      const contexts = [];
      const pages = [];

      // Criar usuários concorrentes
      for (let i = 0; i < userCount; i++) {
        const context = await browser.newContext({
          viewport: { width: 1280, height: 720 },
          userAgent: `Concurrency-User-${i + 1}`
        });
        contexts.push(context);
        
        const page = await context.newPage();
        pages.push(page);
        
        // Interceptar responses
        page.on('response', (response) => {
          const url = response.url();
          const status = response.status();
          const timing = response.timing();
          
          if (url.includes(CONCURRENCY_CONFIG.baseUrl)) {
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

      // Executar gerações concorrentes
      const concurrentPromises = pages.map(async (page, index) => {
        const userResults = [];
        
        try {
          // Navegar para página inicial
          await page.goto(CONCURRENCY_CONFIG.baseUrl);
          
          // Executar múltiplas gerações simultaneamente
          const generationPromises = [];
          
          for (let j = 0; j < 3; j++) {
            const generationPromise = (async () => {
              const start = Date.now();
              
              try {
                const payload = {
                  api_key: `sk-concurrent-${index}-${j}`,
                  model_type: 'openai',
                  prompts: [
                    { text: `Concorrência ${j} usuário ${index} - ${Date.now()}`, index: 0 }
                  ]
                };
                
                const response = await page.request.post(`${CONCURRENCY_CONFIG.baseUrl}/generate`, {
                  data: payload,
                  timeout: 30000
                });
                
                return {
                  action: 'generate_content',
                  responseTime: Date.now() - start,
                  status: response.status(),
                  success: response.ok(),
                  userIndex: index,
                  operationIndex: j
                };
              } catch (error) {
                return {
                  action: 'generate_content',
                  responseTime: Date.now() - start,
                  status: 0,
                  success: false,
                  error: error.message,
                  userIndex: index,
                  operationIndex: j
                };
              }
            })();
            
            generationPromises.push(generationPromise);
          }
          
          // Aguardar todas as gerações
          const generationResults = await Promise.all(generationPromises);
          userResults.push(...generationResults);
          
        } catch (error) {
          console.error(`Erro no usuário ${index}:`, error.message);
        }
        
        return userResults;
      });

      // Aguardar conclusão de todos os usuários
      const allResults = await Promise.all(concurrentPromises);
      const totalDuration = Date.now() - startTime;

      // Analisar resultados
      const analysis = analyzeConcurrencyResults(allResults, totalDuration, userCount);
      
      // Salvar métricas
      const metric: PerformanceMetrics = {
        testName: `Concorrência de Geração - ${userCount} Usuários`,
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

      concurrencyMetrics.push(metric);

      // Validar resultados
      const validation = validator.validateMetrics(metric);
      
      console.log(`📊 Resultados para ${userCount} usuários concorrentes:`);
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

      // Aguardar entre testes
      await new Promise(resolve => setTimeout(resolve, 10000));
    }
  });

  test('Concorrência de Operações Mistas', async () => {
    console.log('🔄 Iniciando teste de concorrência de operações mistas...');
    
    const userCount = 15; // Número fixo para teste de operações mistas
    const startTime = Date.now();
    const results = [];
    const contexts = [];
    const pages = [];

    // Criar usuários
    for (let i = 0; i < userCount; i++) {
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: `MixedOps-User-${i + 1}`
      });
      contexts.push(context);
      
      const page = await context.newPage();
      pages.push(page);
      
      page.on('response', (response) => {
        const url = response.url();
        const status = response.status();
        const timing = response.timing();
        
        if (url.includes(CONCURRENCY_CONFIG.baseUrl)) {
          results.push({
            url,
            status,
            responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
            timestamp: Date.now()
          });
        }
      });
    }

    // Executar operações mistas concorrentes
    const mixedOperationsPromises = pages.map(async (page, index) => {
      const userResults = [];
      
      try {
        await page.goto(CONCURRENCY_CONFIG.baseUrl);
        
        // Definir operações para este usuário
        const operations = [
          // Geração de conteúdo
          async () => {
            const start = Date.now();
            const payload = {
              api_key: `sk-mixed-${index}`,
              model_type: 'openai',
              prompts: [{ text: `Operação mista ${index}`, index: 0 }]
            };
            
            const response = await page.request.post(`${CONCURRENCY_CONFIG.baseUrl}/generate`, {
              data: payload,
              timeout: 30000
            });
            
            return {
              action: 'generate_content',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Download de conteúdo
          async () => {
            const start = Date.now();
            const response = await page.request.get(`${CONCURRENCY_CONFIG.baseUrl}/download`, {
              timeout: 30000
            });
            
            return {
              action: 'download_content',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Verificação de status
          async () => {
            const start = Date.now();
            const response = await page.request.get(`${CONCURRENCY_CONFIG.baseUrl}/status/test-mixed-${index}`, {
              timeout: 30000
            });
            
            return {
              action: 'check_status',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Envio de feedback
          async () => {
            const start = Date.now();
            const payload = {
              article_id: index + 1,
              feedback: ['positivo', 'negativo', 'neutro'][index % 3],
              comentario: `Feedback concorrente ${index}`
            };
            
            const response = await page.request.post(`${CONCURRENCY_CONFIG.baseUrl}/feedback`, {
              data: payload,
              timeout: 30000
            });
            
            return {
              action: 'send_feedback',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Registro de webhook
          async () => {
            const start = Date.now();
            const payload = {
              url: `http://localhost:8080/webhook-${index}`
            };
            
            const response = await page.request.post(`${CONCURRENCY_CONFIG.baseUrl}/webhook`, {
              data: payload,
              timeout: 30000
            });
            
            return {
              action: 'register_webhook',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          }
        ];

        // Executar operações em paralelo
        const operationPromises = operations.map(op => op());
        const operationResults = await Promise.all(operationPromises);
        userResults.push(...operationResults);
        
      } catch (error) {
        console.error(`Erro no usuário ${index}:`, error.message);
      }
      
      return userResults;
    });

    // Aguardar conclusão
    const allResults = await Promise.all(mixedOperationsPromises);
    const totalDuration = Date.now() - startTime;

    // Analisar resultados
    const analysis = analyzeConcurrencyResults(allResults, totalDuration, userCount);
    
    // Salvar métricas
    const metric: PerformanceMetrics = {
      testName: 'Concorrência de Operações Mistas',
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

    concurrencyMetrics.push(metric);

    // Validar resultados
    const validation = validator.validateMetrics(metric);
    
    console.log('📊 Resultados de Operações Mistas:');
    console.log(`  Usuários Concorrentes: ${userCount}`);
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
  });

  test('Concorrência de Acesso a Recursos Compartilhados', async () => {
    console.log('🔄 Iniciando teste de concorrência de recursos compartilhados...');
    
    const userCount = 10;
    const startTime = Date.now();
    const results = [];
    const contexts = [];
    const pages = [];

    // Criar usuários
    for (let i = 0; i < userCount; i++) {
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: `SharedResource-User-${i + 1}`
      });
      contexts.push(context);
      
      const page = await context.newPage();
      pages.push(page);
      
      page.on('response', (response) => {
        const url = response.url();
        const status = response.status();
        const timing = response.timing();
        
        if (url.includes(CONCURRENCY_CONFIG.baseUrl)) {
          results.push({
            url,
            status,
            responseTime: timing ? timing.responseEnd - timing.requestStart : 0,
            timestamp: Date.now()
          });
        }
      });
    }

    // Executar acesso concorrente a recursos compartilhados
    const sharedResourcePromises = pages.map(async (page, index) => {
      const userResults = [];
      
      try {
        await page.goto(CONCURRENCY_CONFIG.baseUrl);
        
        // Simular acesso concorrente ao mesmo recurso
        const sharedResourceId = 'shared-resource-1';
        
        const operations = [
          // Acesso simultâneo ao mesmo arquivo
          async () => {
            const start = Date.now();
            const response = await page.request.get(`${CONCURRENCY_CONFIG.baseUrl}/download?file=${sharedResourceId}`, {
              timeout: 30000
            });
            
            return {
              action: 'access_shared_file',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Verificação simultânea do mesmo status
          async () => {
            const start = Date.now();
            const response = await page.request.get(`${CONCURRENCY_CONFIG.baseUrl}/status/${sharedResourceId}`, {
              timeout: 30000
            });
            
            return {
              action: 'check_shared_status',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          },
          
          // Modificação simultânea do mesmo recurso
          async () => {
            const start = Date.now();
            const payload = {
              resource_id: sharedResourceId,
              modification: `modification-${index}-${Date.now()}`
            };
            
            const response = await page.request.post(`${CONCURRENCY_CONFIG.baseUrl}/modify-resource`, {
              data: payload,
              timeout: 30000
            });
            
            return {
              action: 'modify_shared_resource',
              responseTime: Date.now() - start,
              status: response.status(),
              success: response.ok()
            };
          }
        ];

        // Executar operações em paralelo
        const operationPromises = operations.map(op => op());
        const operationResults = await Promise.all(operationPromises);
        userResults.push(...operationResults);
        
      } catch (error) {
        console.error(`Erro no usuário ${index}:`, error.message);
      }
      
      return userResults;
    });

    // Aguardar conclusão
    const allResults = await Promise.all(sharedResourcePromises);
    const totalDuration = Date.now() - startTime;

    // Analisar resultados
    const analysis = analyzeConcurrencyResults(allResults, totalDuration, userCount);
    
    // Salvar métricas
    const metric: PerformanceMetrics = {
      testName: 'Concorrência de Recursos Compartilhados',
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

    concurrencyMetrics.push(metric);

    // Validar resultados
    const validation = validator.validateMetrics(metric);
    
    console.log('📊 Resultados de Recursos Compartilhados:');
    console.log(`  Usuários Concorrentes: ${userCount}`);
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
  });

  test('Geração de Relatório de Concorrência', async () => {
    // Gerar relatório consolidado
    const report = validator.generateReport(concurrencyMetrics);
    
    // Salvar relatório
    const fs = require('fs');
    const path = require('path');
    
    const reportDir = 'test-results/concurrency';
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    const reportPath = path.join(reportDir, `concurrency-test-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log(`📊 Relatório de concorrência salvo em: ${reportPath}`);
    
    // Validar métricas gerais
    expect(report.summary.totalTests).toBeGreaterThan(0);
    expect(report.summary.averageScore).toBeGreaterThan(0);
    
    console.log('📊 Resumo do Relatório de Concorrência:');
    console.log(`  Total de Testes: ${report.summary.totalTests}`);
    console.log(`  Testes Aprovados: ${report.summary.passedTests}`);
    console.log(`  Score Médio: ${report.summary.averageScore.toFixed(1)}/100`);
    console.log(`  Tendência: ${report.summary.overallTrend}`);
  });
});

// Função auxiliar para análise de resultados de concorrência
function analyzeConcurrencyResults(results: any[], totalDuration: number, userCount: number) {
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