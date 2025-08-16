#!/usr/bin/env node

/**
 * Script Simples de Validação de Testes E2E
 * - Demonstração da validação de testes sintéticos
 * - Versão simplificada para execução imediata
 * 
 * 📐 CoCoT: Baseado em boas práticas de validação
 * 🌲 ToT: Múltiplas estratégias implementadas
 * ♻️ ReAct: Simulado para diferentes cenários
 */

import fs from 'fs';
import path from 'path';

// Padrões proibidos em testes
const FORBIDDEN_PATTERNS = {
  syntheticData: [
    /\bfoo\b/i,
    /\bbar\b/i,
    /\blorem\b/i,
    /\bipsum\b/i,
    /\bdummy\b/i,
    /\bfake\b/i,
    /\brandom\b/i,
    /\btest.*data\b/i,
    /\bsample.*data\b/i,
    /\bplaceholder\b/i
  ],
  
  genericNames: [
    /\btest.*user\b/i,
    /\btest.*article\b/i,
    /\btest.*blog\b/i,
    /\btest.*category\b/i,
    /\btest.*prompt\b/i
  ]
};

// Padrões obrigatórios
const REQUIRED_PATTERNS = {
  realData: [
    /\bomni.*writer\b/i,
    /\barticle.*generation\b/i,
    /\bblog.*management\b/i,
    /\bcategory.*management\b/i,
    /\bprompt.*management\b/i,
    /\bapi.*key\b/i,
    /\bwebhook\b/i,
    /\bgeneration\b/i,
    /\bdownload\b/i,
    /\bexport\b/i
  ],
  
  traceability: [
    /\*\*Prompt:\s*\w+/i,
    /\*\*Data\/Hora:\s*\d{4}-\d{2}-\d{2}/i,
    /\*\*Tracing ID:\s*\w+/i,
    /\*\*Origem:\s*\w+/i
  ]
};

// Cores para output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

class SimpleValidator {
  constructor() {
    this.results = [];
  }

  /**
   * Valida um arquivo de teste
   */
  validateTestFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const violations = [];
      const warnings = [];
      let score = 100;

      // Verificar padrões proibidos
      for (const [category, patterns] of Object.entries(FORBIDDEN_PATTERNS)) {
        for (const pattern of patterns) {
          const matches = content.match(pattern);
          if (matches) {
            violations.push(`Dados sintéticos (${category}): ${matches.join(', ')}`);
            score -= 20;
          }
        }
      }

      // Verificar padrões obrigatórios
      for (const [category, patterns] of Object.entries(REQUIRED_PATTERNS)) {
        let found = false;
        for (const pattern of patterns) {
          if (pattern.test(content)) {
            found = true;
            break;
          }
        }
        if (!found) {
          warnings.push(`Padrão obrigatório ausente (${category})`);
          score -= 10;
        }
      }

      // Verificar rastreabilidade
      const hasPrompt = /\*\*Prompt:/.test(content);
      const hasTracingId = /\*\*Tracing ID:/.test(content);
      
      if (!hasPrompt && !hasTracingId) {
        violations.push('Origem do teste não documentada');
        score -= 20;
      }

      // Bônus por dados reais
      if (content.includes('omni') && content.includes('writer')) {
        score += 5;
      }

      score = Math.max(0, Math.min(100, score));

      const result = {
        file: filePath,
        isValid: violations.length === 0,
        violations,
        warnings,
        score
      };

      this.results.push(result);
      return result;

    } catch (error) {
      console.error(`${colors.red}Erro ao ler arquivo ${filePath}:${colors.reset}`, error.message);
      return {
        file: filePath,
        isValid: false,
        violations: ['Erro ao ler arquivo'],
        warnings: [],
        score: 0
      };
    }
  }

  /**
   * Obtém lista de arquivos de teste
   */
  getTestFiles(dir) {
    const files = [];
    
    if (fs.existsSync(dir)) {
      const items = fs.readdirSync(dir);
      
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          files.push(...this.getTestFiles(fullPath));
        } else if (item.endsWith('.spec.ts') || item.endsWith('.test.ts')) {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  /**
   * Valida toda a suite de testes
   */
  validateTestSuite(testDir = './tests/e2e') {
    console.log(`${colors.cyan}${colors.bold}🔍 Iniciando Validação de Testes E2E${colors.reset}\n`);
    
    const files = this.getTestFiles(testDir);
    console.log(`${colors.blue}Encontrados ${files.length} arquivos de teste${colors.reset}\n`);
    
    for (const file of files) {
      this.validateTestFile(file);
    }

    return this.results;
  }

  /**
   * Exibe resumo da validação
   */
  displaySummary() {
    const totalFiles = this.results.length;
    const validFiles = this.results.filter(r => r.isValid).length;
    const avgScore = this.results.reduce((sum, r) => sum + r.score, 0) / totalFiles;
    const violations = this.results.reduce((sum, r) => sum + r.violations.length, 0);
    const warnings = this.results.reduce((sum, r) => sum + r.warnings.length, 0);

    console.log(`${colors.bold}📈 Resumo da Validação:${colors.reset}\n`);
    console.log(`  📁 Total de arquivos: ${totalFiles}`);
    console.log(`  ✅ Arquivos válidos: ${validFiles}/${totalFiles} (${((validFiles/totalFiles)*100).toFixed(1)}%)`);
    console.log(`  📊 Score médio: ${avgScore.toFixed(1)}/100`);
    console.log(`  🚨 Violações: ${violations}`);
    console.log(`  ⚠️  Avisos: ${warnings}\n`);

    // Detalhes por arquivo
    if (this.results.length > 0) {
      console.log(`${colors.bold}📋 Detalhes por Arquivo:${colors.reset}\n`);
      
      for (const result of this.results) {
        const status = result.isValid ? `${colors.green}✅${colors.reset}` : `${colors.red}❌${colors.reset}`;
        const scoreColor = result.score >= 80 ? colors.green : result.score >= 60 ? colors.yellow : colors.red;
        
        console.log(`${status} ${path.basename(result.file)}`);
        console.log(`    Score: ${scoreColor}${result.score}/100${colors.reset}`);
        
        if (result.violations.length > 0) {
          console.log(`    ${colors.red}Violations: ${result.violations.length}${colors.reset}`);
          result.violations.forEach(v => console.log(`      - ${v}`));
        }
        
        if (result.warnings.length > 0) {
          console.log(`    ${colors.yellow}Warnings: ${result.warnings.length}${colors.reset}`);
          result.warnings.forEach(w => console.log(`      - ${w}`));
        }
        
        console.log('');
      }
    }

    // Status final
    const isPassing = validFiles === totalFiles && avgScore >= 80;
    if (isPassing) {
      console.log(`${colors.green}${colors.bold}✅ Validação aprovada!${colors.reset}`);
    } else {
      console.log(`${colors.red}${colors.bold}❌ Validação falhou!${colors.reset}`);
    }
  }

  /**
   * Gera relatório em arquivo
   */
  saveReport(outputPath = 'test-results/synthetic-test-validation-simple.md') {
    const totalFiles = this.results.length;
    const validFiles = this.results.filter(r => r.isValid).length;
    const avgScore = this.results.reduce((sum, r) => sum + r.score, 0) / totalFiles;

    let report = `# 📊 Relatório de Validação - Testes Sintéticos (Simples)\n\n`;
    report += `**Data**: ${new Date().toISOString()}\n`;
    report += `**Total de arquivos**: ${totalFiles}\n`;
    report += `**Arquivos válidos**: ${validFiles}/${totalFiles} (${((validFiles/totalFiles)*100).toFixed(1)}%)\n`;
    report += `**Score médio**: ${avgScore.toFixed(1)}/100\n\n`;

    // Arquivos com problemas
    const problematicFiles = this.results.filter(r => !r.isValid || r.violations.length > 0);
    if (problematicFiles.length > 0) {
      report += `## 🚨 Arquivos com Problemas\n\n`;
      
      for (const result of problematicFiles) {
        report += `### ${result.file}\n`;
        report += `- **Score**: ${result.score}/100\n`;
        
        if (result.violations.length > 0) {
          report += `- **Violações**:\n`;
          for (const violation of result.violations) {
            report += `  - ${violation}\n`;
          }
        }
        
        if (result.warnings.length > 0) {
          report += `- **Avisos**:\n`;
          for (const warning of result.warnings) {
            report += `  - ${warning}\n`;
          }
        }
        
        report += `\n`;
      }
    }

    // Criar diretório se não existir
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(outputPath, report);
    console.log(`${colors.blue}📊 Relatório salvo em: ${outputPath}${colors.reset}\n`);
  }
}

// Função principal
async function main() {
  const validator = new SimpleValidator();
  
  // Verificar argumentos
  const args = process.argv.slice(2);
  
  if (args.length > 0) {
    const command = args[0];
    
    switch (command) {
      case '--help':
        console.log(`
Uso: node scripts/validate_e2e_simple.js [opções]

Opções:
  --file <caminho>        Valida arquivo específico
  --help                  Exibe esta ajuda

Exemplos:
  node scripts/validate_e2e_simple.js
  node scripts/validate_e2e_simple.js --file tests/e2e/test_example.spec.ts
        `);
        break;
        
      case '--file':
        if (args[1]) {
          const result = validator.validateTestFile(args[1]);
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.error('Especifique o arquivo: --file <caminho>');
          process.exit(1);
        }
        break;
        
      default:
        console.error(`Comando desconhecido: ${command}`);
        console.error('Use --help para ver as opções disponíveis');
        process.exit(1);
    }
  } else {
    // Execução padrão: validação completa
    validator.validateTestSuite();
    validator.displaySummary();
    validator.saveReport();
  }
}

// Executar se chamado diretamente
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(error => {
    console.error(`${colors.red}Erro fatal:${colors.reset}`, error);
    process.exit(1);
  });
}

export default SimpleValidator; 