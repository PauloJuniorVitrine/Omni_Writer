/**
 * Global Setup para Testes E2E
 * - Health checks do sistema
 * - Preparação do ambiente de teste
 * - Validação de dependências
 * 
 * 📐 CoCoT: Baseado em boas práticas de setup de testes E2E
 * 🌲 ToT: Múltiplas estratégias de validação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de falha
 */

import { chromium, FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

async function globalSetup(config: FullConfig) {
  console.log('🚀 Iniciando Global Setup para E2E...');
  
  // Configurações do ambiente
  const baseUrl = config.projects[0]?.use?.baseURL || 'http://localhost:5000';
  const environment = process.env.E2E_ENV || 'dev';
  
  console.log(`📍 Ambiente: ${environment}`);
  console.log(`🌐 Base URL: ${baseUrl}`);
  
  // Cria diretórios necessários
  const directories = [
    'test-results',
    'test-results/html-report',
    'test-results/allure-results',
    'tests/e2e/snapshots',
    'tests/e2e/snapshots/generate_content',
    'logs/e2e'
  ];
  
  for (const dir of directories) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`📁 Diretório criado: ${dir}`);
    }
  }
  
  // Health check do sistema
  console.log('🏥 Executando health check...');
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();
  
  try {
    // Tenta acessar a aplicação
    await page.goto(baseUrl, { timeout: 30000 });
    
    // Verifica se a página carregou corretamente
    const title = await page.title();
    console.log(`📄 Título da página: ${title}`);
    
    // Verifica elementos críticos
    const criticalSelectors = [
      '[data-testid="instance-name"]',
      '[data-testid="model-type"]',
      '[data-testid="api-key"]',
      '[data-testid="prompts"]',
      '[data-testid="submit-btn"]'
    ];
    
    for (const selector of criticalSelectors) {
      try {
        await page.waitForSelector(selector, { timeout: 5000 });
        console.log(`✅ Elemento encontrado: ${selector}`);
      } catch (error) {
        console.error(`❌ Elemento não encontrado: ${selector}`);
        throw new Error(`Health check falhou: elemento ${selector} não disponível`);
      }
    }
    
    // Verifica se há erros no console
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    // Aguarda um pouco para capturar erros
    await page.waitForTimeout(2000);
    
    if (consoleErrors.length > 0) {
      console.warn('⚠️ Erros no console detectados:');
      consoleErrors.forEach(error => console.warn(`  - ${error}`));
    }
    
    // Verifica status da API
    try {
      const response = await page.request.get(`${baseUrl}/health`);
      if (response.status() === 200) {
        console.log('✅ Health check da API: OK');
      } else {
        console.warn(`⚠️ Health check da API: Status ${response.status()}`);
      }
    } catch (error) {
      console.warn('⚠️ Health check da API: Endpoint não disponível');
    }
    
    console.log('✅ Health check concluído com sucesso');
    
  } catch (error) {
    console.error('❌ Health check falhou:', error);
    
    // Salva screenshot de erro
    await page.screenshot({ 
      path: 'test-results/health-check-failed.png',
      fullPage: true 
    });
    
    // Salva HTML da página
    const html = await page.content();
    fs.writeFileSync('test-results/health-check-failed.html', html);
    
    throw new Error(`Sistema não está pronto para testes E2E: ${error}`);
  } finally {
    await browser.close();
  }
  
  // Validação de variáveis de ambiente
  console.log('🔧 Validando variáveis de ambiente...');
  const requiredEnvVars = ['TEST_API_KEY'];
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    console.warn(`⚠️ Variáveis de ambiente ausentes: ${missingVars.join(', ')}`);
    console.warn('💡 Usando valores padrão para testes');
  }
  
  // Limpeza de arquivos temporários
  console.log('🧹 Limpando arquivos temporários...');
  const tempFiles = [
    'diagnostico_inicial.html',
    'diagnostico_pos_envio.html',
    'diagnostico_erro_envio.html',
    'diagnostico_logs_fluxo_principal.log',
    'diagnostico_logs_fluxo_erro.log',
    'diagnostico_e2e_fluxo_real.log'
  ];
  
  for (const file of tempFiles) {
    if (fs.existsSync(file)) {
      fs.unlinkSync(file);
      console.log(`🗑️ Arquivo removido: ${file}`);
    }
  }
  
  // Cria arquivo de log inicial
  const logEntry = `\n[${new Date().toISOString()}] [GLOBAL_SETUP] Setup concluído com sucesso - Ambiente: ${environment}`;
  fs.appendFileSync('tests/e2e/E2E_LOG.md', logEntry);
  
  console.log('✅ Global Setup concluído com sucesso!');
}

export default globalSetup; 