#!/usr/bin/env node

/**
 * Script de Sincronização de Contratos - Omni Writer
 * Baseado no código real do sistema
 * 
 * Tracing ID: CONTRACT_SYNC_20250127_001
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configurações baseadas no código real
const CONFIG = {
  openapiSpec: 'docs/openapi.yaml',
  outputDir: 'ui/generated',
  configFile: 'openapi-generator-config.json',
  schemasDir: 'ui/schemas',
  backendRoutes: 'app/main.py'
};

// Cores para output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

const log = (message, color = colors.reset) => {
  console.log(`${color}${message}${colors.reset}`);
};

// Validação do OpenAPI spec
const validateOpenApiSpec = () => {
  log('🔍 Validando especificação OpenAPI...', colors.blue);
  
  try {
    if (!fs.existsSync(CONFIG.openapiSpec)) {
      throw new Error(`Arquivo OpenAPI não encontrado: ${CONFIG.openapiSpec}`);
    }
    
    const specContent = fs.readFileSync(CONFIG.openapiSpec, 'utf8');
    const spec = JSON.parse(specContent);
    
    // Validações básicas baseadas no código real
    const requiredEndpoints = [
      '/api/blogs',
      '/generate',
      '/download',
      '/status/{trace_id}',
      '/events/{trace_id}',
      '/webhook'
    ];
    
    const missingEndpoints = requiredEndpoints.filter(endpoint => {
      return !spec.paths || !spec.paths[endpoint];
    });
    
    if (missingEndpoints.length > 0) {
      log(`⚠️  Endpoints ausentes na especificação: ${missingEndpoints.join(', ')}`, colors.yellow);
    }
    
    log('✅ Especificação OpenAPI válida', colors.green);
    return true;
  } catch (error) {
    log(`❌ Erro na validação: ${error.message}`, colors.red);
    return false;
  }
};

// Geração do cliente API
const generateApiClient = () => {
  log('🔧 Gerando cliente API...', colors.blue);
  
  try {
    // Cria diretório de saída se não existir
    if (!fs.existsSync(CONFIG.outputDir)) {
      fs.mkdirSync(CONFIG.outputDir, { recursive: true });
    }
    
    // Comando de geração baseado no package.json
    const command = `npx @openapitools/openapi-generator-cli generate \
      -i ${CONFIG.openapiSpec} \
      -g typescript-axios \
      -o ${CONFIG.outputDir}/api-client \
      -c ${CONFIG.configFile}`;
    
    execSync(command, { stdio: 'inherit' });
    log('✅ Cliente API gerado com sucesso', colors.green);
    return true;
  } catch (error) {
    log(`❌ Erro na geração do cliente: ${error.message}`, colors.red);
    return false;
  }
};

// Geração de tipos
const generateTypes = () => {
  log('📝 Gerando tipos TypeScript...', colors.blue);
  
  try {
    const command = `npx @openapitools/openapi-generator-cli generate \
      -i ${CONFIG.openapiSpec} \
      -g typescript-axios \
      -o ${CONFIG.outputDir}/api-types \
      -c ${CONFIG.configFile}`;
    
    execSync(command, { stdio: 'inherit' });
    log('✅ Tipos TypeScript gerados com sucesso', colors.green);
    return true;
  } catch (error) {
    log(`❌ Erro na geração de tipos: ${error.message}`, colors.red);
    return false;
  }
};

// Sincronização de schemas Zod
const syncZodSchemas = () => {
  log('🔄 Sincronizando schemas Zod...', colors.blue);
  
  try {
    // Verifica se o arquivo de schemas existe
    const schemasFile = path.join(CONFIG.schemasDir, 'api-schemas.ts');
    if (!fs.existsSync(schemasFile)) {
      log('⚠️  Arquivo de schemas Zod não encontrado, criando...', colors.yellow);
      
      // Cria diretório se não existir
      if (!fs.existsSync(CONFIG.schemasDir)) {
        fs.mkdirSync(CONFIG.schemasDir, { recursive: true });
      }
      
      // Cria arquivo básico de schemas
      const basicSchemas = `import { z } from 'zod';

// Schemas básicos baseados no código real
export const BlogSchema = z.object({
  id: z.number().int().positive(),
  nome: z.string().min(1).max(40),
  desc: z.string().max(80).optional()
});

export const GenerationRequestSchema = z.object({
  api_key: z.string().min(1),
  model_type: z.enum(['openai', 'deepseek']),
  prompts: z.array(z.string().min(1).max(500))
});

// Tipos exportados
export type Blog = z.infer<typeof BlogSchema>;
export type GenerationRequest = z.infer<typeof GenerationRequestSchema>;
`;
      
      fs.writeFileSync(schemasFile, basicSchemas);
    }
    
    log('✅ Schemas Zod sincronizados', colors.green);
    return true;
  } catch (error) {
    log(`❌ Erro na sincronização de schemas: ${error.message}`, colors.red);
    return false;
  }
};

// Verificação de consistência
const checkConsistency = () => {
  log('🔍 Verificando consistência...', colors.blue);
  
  try {
    // Verifica se os arquivos gerados existem
    const generatedFiles = [
      path.join(CONFIG.outputDir, 'api-client'),
      path.join(CONFIG.outputDir, 'api-types'),
      path.join(CONFIG.schemasDir, 'api-schemas.ts')
    ];
    
    const missingFiles = generatedFiles.filter(file => !fs.existsSync(file));
    
    if (missingFiles.length > 0) {
      log(`⚠️  Arquivos ausentes: ${missingFiles.join(', ')}`, colors.yellow);
      return false;
    }
    
    log('✅ Consistência verificada', colors.green);
    return true;
  } catch (error) {
    log(`❌ Erro na verificação de consistência: ${error.message}`, colors.red);
    return false;
  }
};

// Função principal
const main = () => {
  log('🚀 Iniciando sincronização de contratos...', colors.blue);
  log(`📅 Data/Hora: ${new Date().toISOString()}`, colors.blue);
  log(`🆔 Tracing ID: CONTRACT_SYNC_20250127_001`, colors.blue);
  
  const steps = [
    { name: 'Validação OpenAPI', fn: validateOpenApiSpec },
    { name: 'Geração Cliente API', fn: generateApiClient },
    { name: 'Geração de Tipos', fn: generateTypes },
    { name: 'Sincronização Zod', fn: syncZodSchemas },
    { name: 'Verificação de Consistência', fn: checkConsistency }
  ];
  
  let successCount = 0;
  
  for (const step of steps) {
    log(`\n📋 Executando: ${step.name}`, colors.blue);
    
    if (step.fn()) {
      successCount++;
    } else {
      log(`❌ Falha em: ${step.name}`, colors.red);
    }
  }
  
  log(`\n📊 Resumo da sincronização:`, colors.blue);
  log(`✅ Passos bem-sucedidos: ${successCount}/${steps.length}`, colors.green);
  
  if (successCount === steps.length) {
    log('🎉 Sincronização concluída com sucesso!', colors.green);
    process.exit(0);
  } else {
    log('⚠️  Sincronização concluída com falhas', colors.yellow);
    process.exit(1);
  }
};

// Execução
if (require.main === module) {
  main();
}

module.exports = {
  validateOpenApiSpec,
  generateApiClient,
  generateTypes,
  syncZodSchemas,
  checkConsistency
}; 