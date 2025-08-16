/**
 * Script de Validação de Configuração
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - TEST-005
 * Data/Hora: 2025-01-28T02:25:00Z
 * Tracing ID: VALIDATE_CONFIG_20250128_001
 * 
 * Validação de configuração de ambientes para shadow testing
 * Baseado em código real da aplicação Omni Writer
 */

import { loadEnvironmentConfig, validateEnvironmentConfig, generateEnvTemplate } from '../config/environment-config';

/**
 * Executa validação de configuração
 */
async function validateConfig() {
  console.log('🔧 Validando configuração de ambientes...\n');

  try {
    // Carrega configuração
    const config = loadEnvironmentConfig();
    
    // Valida configuração
    const validation = validateEnvironmentConfig(config);
    
    // Exibe resultados
    console.log('📊 RESULTADO DA VALIDAÇÃO:\n');
    
    if (validation.isValid) {
      console.log('✅ Configuração válida!');
    } else {
      console.log('❌ Configuração inválida!');
    }
    
    // Exibe erros
    if (validation.errors.length > 0) {
      console.log('\n🚨 ERROS:');
      validation.errors.forEach(error => {
        console.log(`  - ${error}`);
      });
    }
    
    // Exibe warnings
    if (validation.warnings.length > 0) {
      console.log('\n⚠️ WARNINGS:');
      validation.warnings.forEach(warning => {
        console.log(`  - ${warning}`);
      });
    }
    
    // Exibe recomendações
    if (validation.recommendations.length > 0) {
      console.log('\n💡 RECOMENDAÇÕES:');
      validation.recommendations.forEach(recommendation => {
        console.log(`  - ${recommendation}`);
      });
    }
    
    // Exibe configuração atual
    console.log('\n📋 CONFIGURAÇÃO ATUAL:');
    console.log(`  Produção: ${config.prod.url} (timeout: ${config.prod.timeout}ms)`);
    console.log(`  Canary: ${config.canary.url} (timeout: ${config.canary.timeout}ms)`);
    console.log(`  Staging: ${config.staging.url} (timeout: ${config.staging.timeout}ms)`);
    console.log(`  Dev: ${config.dev.url} (timeout: ${config.dev.timeout}ms)`);
    console.log(`  Similaridade: ${config.global.similarityThreshold}`);
    console.log(`  Shadow Testing: ${config.global.enableShadowTesting ? 'Habilitado' : 'Desabilitado'}`);
    
    // Gera template se necessário
    if (!validation.isValid || validation.recommendations.length > 0) {
      console.log('\n📝 TEMPLATE DE CONFIGURAÇÃO:');
      console.log('Copie o template abaixo para .env e configure conforme necessário:\n');
      console.log(generateEnvTemplate());
    }
    
    console.log('\n🎯 Validação concluída!');
    
    return validation.isValid;
    
  } catch (error) {
    console.error('❌ Erro na validação:', error.message);
    return false;
  }
}

/**
 * Executa validação se chamado diretamente
 */
if (require.main === module) {
  validateConfig()
    .then(isValid => {
      process.exit(isValid ? 0 : 1);
    })
    .catch(error => {
      console.error('Erro fatal:', error);
      process.exit(1);
    });
}

export { validateConfig }; 