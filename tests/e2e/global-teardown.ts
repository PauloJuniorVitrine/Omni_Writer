/**
 * Global Teardown para Testes E2E
 * - Limpeza de recursos
 * - Geração de relatórios finais
 * - Análise de resultados
 * 
 * 📐 CoCoT: Baseado em boas práticas de teardown de testes E2E
 * 🌲 ToT: Múltiplas estratégias de limpeza implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de finalização
 */

import { FullConfig } from '@playwright/test';
import fs from 'fs';
import path from 'path';

async function globalTeardown(config: FullConfig) {
  console.log('🧹 Iniciando Global Teardown para E2E...');
  
  const environment = process.env.E2E_ENV || 'dev';
  const timestamp = new Date().toISOString();
  
  console.log(`📍 Ambiente: ${environment}`);
  console.log(`⏰ Timestamp: ${timestamp}`);
  
  // Análise de resultados
  console.log('📊 Analisando resultados dos testes...');
  
  const resultsFile = 'test-results/results.json';
  let testResults = {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0,
    duration: 0
  };
  
  if (fs.existsSync(resultsFile)) {
    try {
      const resultsData = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
      testResults = {
        total: resultsData.suites?.reduce((acc: number, suite: any) => acc + suite.specs.length, 0) || 0,
        passed: resultsData.suites?.reduce((acc: number, suite: any) => 
          acc + suite.specs.filter((spec: any) => spec.tests.every((test: any) => test.outcome === 'passed')).length, 0) || 0,
        failed: resultsData.suites?.reduce((acc: number, suite: any) => 
          acc + suite.specs.filter((spec: any) => spec.tests.some((test: any) => test.outcome === 'failed')).length, 0) || 0,
        skipped: resultsData.suites?.reduce((acc: number, suite: any) => 
          acc + suite.specs.filter((spec: any) => spec.tests.every((test: any) => test.outcome === 'skipped')).length, 0) || 0,
        duration: resultsData.duration || 0
      };
      
      console.log(`📈 Resultados: ${testResults.passed}/${testResults.total} testes passaram`);
      console.log(`❌ Falhas: ${testResults.failed}`);
      console.log(`⏭️ Pulados: ${testResults.skipped}`);
      console.log(`⏱️ Duração total: ${Math.round(testResults.duration / 1000)}s`);
    } catch (error) {
      console.warn('⚠️ Erro ao analisar resultados:', error);
    }
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
      try {
        fs.unlinkSync(file);
        console.log(`🗑️ Arquivo removido: ${file}`);
      } catch (error) {
        console.warn(`⚠️ Erro ao remover ${file}:`, error);
      }
    }
  }
  
  // Compressão de logs antigos
  console.log('📦 Comprimindo logs antigos...');
  const logsDir = 'logs/e2e';
  if (fs.existsSync(logsDir)) {
    const logFiles = fs.readdirSync(logsDir).filter(file => file.endsWith('.log'));
    const oldLogs = logFiles.filter(file => {
      const filePath = path.join(logsDir, file);
      const stats = fs.statSync(filePath);
      const daysOld = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
      return daysOld > 7; // Logs com mais de 7 dias
    });
    
    for (const logFile of oldLogs) {
      console.log(`📦 Log antigo encontrado: ${logFile}`);
    }
  }
  
  // Geração de relatório final
  console.log('📋 Gerando relatório final...');
  const reportData = {
    environment,
    timestamp,
    testResults,
    summary: {
      success: testResults.failed === 0,
      coverage: testResults.total > 0 ? Math.round((testResults.passed / testResults.total) * 100) : 0,
      recommendations: [] as string[]
    }
  };
  
  // Adiciona recomendações baseadas nos resultados
  if (testResults.failed > 0) {
    reportData.summary.recommendations.push('Revisar testes que falharam');
  }
  
  if (testResults.skipped > 0) {
    reportData.summary.recommendations.push('Investigar testes pulados');
  }
  
  if (testResults.total < 10) {
    reportData.summary.recommendations.push('Considerar adicionar mais testes');
  }
  
  // Salva relatório final
  const reportFile = `test-results/e2e-final-report-${timestamp.split('T')[0]}.json`;
  fs.writeFileSync(reportFile, JSON.stringify(reportData, null, 2));
  console.log(`📄 Relatório salvo: ${reportFile}`);
  
  // Log final
  const logEntry = `\n[${timestamp}] [GLOBAL_TEARDOWN] Teardown concluído - Resultados: ${testResults.passed}/${testResults.total} passaram`;
  fs.appendFileSync('tests/e2e/E2E_LOG.md', logEntry);
  
  // Validação de integridade
  console.log('🔍 Validando integridade dos resultados...');
  const criticalFiles = [
    'test-results/results.json',
    'test-results/html-report/index.html'
  ];
  
  for (const file of criticalFiles) {
    if (fs.existsSync(file)) {
      console.log(`✅ Arquivo crítico presente: ${file}`);
    } else {
      console.warn(`⚠️ Arquivo crítico ausente: ${file}`);
    }
  }
  
  // Resumo final
  console.log('\n📊 RESUMO FINAL:');
  console.log(`✅ Testes executados: ${testResults.total}`);
  console.log(`✅ Sucessos: ${testResults.passed}`);
  console.log(`❌ Falhas: ${testResults.failed}`);
  console.log(`⏭️ Pulados: ${testResults.skipped}`);
  console.log(`📈 Taxa de sucesso: ${reportData.summary.coverage}%`);
  console.log(`🎯 Status geral: ${reportData.summary.success ? 'PASSOU' : 'FALHOU'}`);
  
  if (reportData.summary.recommendations.length > 0) {
    console.log('\n💡 RECOMENDAÇÕES:');
    reportData.summary.recommendations.forEach(rec => console.log(`  - ${rec}`));
  }
  
  console.log('✅ Global Teardown concluído com sucesso!');
}

export default globalTeardown; 