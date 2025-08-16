#!/usr/bin/env ts-node

/**
 * Script de Validação de Testes E2E
 * - Executa validação automática de testes sintéticos
 * - Gera relatórios detalhados
 * - Integra com CI/CD pipeline
 * 
 * 📐 CoCoT: Baseado em boas práticas de automação de validação
 * 🌲 ToT: Múltiplas estratégias de validação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de execução
 */

import { SyntheticTestDetector, ValidationResult } from '../tests/e2e/utils/synthetic-test-detector';
import fs from 'fs';
import path from 'path';

// Configurações
const CONFIG = {
  testDir: './tests/e2e',
  outputDir: './test-results',
  reportFile: 'synthetic-test-validation.md',
  jsonReportFile: 'synthetic-test-validation.json',
  threshold: 80, // Score mínimo para aprovação
  failOnViolations: process.env.FAIL_ON_VIOLATIONS === 'true'
};

// Cores para output no terminal
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

class E2EValidator {
  private detector: SyntheticTestDetector;
  private results: ValidationResult[] = [];

  constructor() {
    this.detector = new SyntheticTestDetector();
  }

  /**
   * Executa validação completa
   */
  async run(): Promise<boolean> {
    console.log(`${colors.cyan}${colors.bold}🔍 Iniciando Validação de Testes E2E${colors.reset}\n`);

    try {
      // Validar suite de testes
      this.results = this.detector.validateTestSuite(CONFIG.testDir);
      
      // Gerar relatórios
      this.generateReports();
      
      // Exibir resumo
      this.displaySummary();
      
      // Verificar se deve falhar
      const shouldFail = this.shouldFailValidation();
      
      if (shouldFail) {
        console.log(`${colors.red}${colors.bold}❌ Validação falhou!${colors.reset}`);
        process.exit(1);
      } else {
        console.log(`${colors.green}${colors.bold}✅ Validação aprovada!${colors.reset}`);
        return true;
      }

    } catch (error) {
      console.error(`${colors.red}Erro durante validação:${colors.reset}`, error);
      process.exit(1);
    }
  }

  /**
   * Gera relatórios detalhados
   */
  private generateReports(): void {
    // Criar diretório de output se não existir
    if (!fs.existsSync(CONFIG.outputDir)) {
      fs.mkdirSync(CONFIG.outputDir, { recursive: true });
    }

    // Relatório em Markdown
    const markdownPath = path.join(CONFIG.outputDir, CONFIG.reportFile);
    this.detector.saveReport(markdownPath);

    // Relatório em JSON
    const jsonPath = path.join(CONFIG.outputDir, CONFIG.jsonReportFile);
    const jsonReport = {
      timestamp: new Date().toISOString(),
      config: CONFIG,
      summary: this.generateSummary(),
      results: this.results,
      metadata: {
        totalFiles: this.results.length,
        validFiles: this.results.filter(r => r.isValid).length,
        averageScore: this.results.reduce((sum, r) => sum + r.score, 0) / this.results.length,
        violationsCount: this.results.reduce((sum, r) => sum + r.violations.length, 0),
        warningsCount: this.results.reduce((sum, r) => sum + r.warnings.length, 0)
      }
    };

    fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));
    console.log(`${colors.blue}📊 Relatórios gerados:${colors.reset}`);
    console.log(`  - Markdown: ${markdownPath}`);
    console.log(`  - JSON: ${jsonPath}\n`);
  }

  /**
   * Exibe resumo no terminal
   */
  private displaySummary(): void {
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
        }
        
        if (result.warnings.length > 0) {
          console.log(`    ${colors.yellow}Warnings: ${result.warnings.length}${colors.reset}`);
        }
        
        console.log('');
      }
    }
  }

  /**
   * Gera resumo para relatórios
   */
  private generateSummary() {
    const totalFiles = this.results.length;
    const validFiles = this.results.filter(r => r.isValid).length;
    const avgScore = this.results.reduce((sum, r) => sum + r.score, 0) / totalFiles;
    const violations = this.results.reduce((sum, r) => sum + r.violations.length, 0);
    const warnings = this.results.reduce((sum, r) => sum + r.warnings.length, 0);

    return {
      totalFiles,
      validFiles,
      invalidFiles: totalFiles - validFiles,
      averageScore: avgScore,
      violations,
      warnings,
      passRate: (validFiles / totalFiles) * 100,
      isPassing: validFiles === totalFiles && avgScore >= CONFIG.threshold
    };
  }

  /**
   * Verifica se a validação deve falhar
   */
  private shouldFailValidation(): boolean {
    const summary = this.generateSummary();
    
    // Falhar se há arquivos inválidos
    if (summary.invalidFiles > 0) {
      return true;
    }
    
    // Falhar se score médio está abaixo do threshold
    if (summary.averageScore < CONFIG.threshold) {
      return true;
    }
    
    // Falhar se há violações e FAIL_ON_VIOLATIONS está ativo
    if (CONFIG.failOnViolations && summary.violations > 0) {
      return true;
    }
    
    return false;
  }

  /**
   * Valida arquivo específico
   */
  validateSingleFile(filePath: string): ValidationResult {
    console.log(`${colors.cyan}Validando arquivo: ${filePath}${colors.reset}`);
    return this.detector.validateTestFile(filePath);
  }

  /**
   * Lista arquivos que precisam de atenção
   */
  listProblematicFiles(): ValidationResult[] {
    return this.results.filter(r => !r.isValid || r.score < CONFIG.threshold);
  }
}

// Função principal
async function main() {
  const validator = new E2EValidator();
  
  // Verificar argumentos da linha de comando
  const args = process.argv.slice(2);
  
  if (args.length > 0) {
    const command = args[0];
    
    switch (command) {
      case '--file':
        if (args[1]) {
          const result = validator.validateSingleFile(args[1]);
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.error('Especifique o arquivo: --file <caminho>');
          process.exit(1);
        }
        break;
        
      case '--list-problems':
        await validator.run();
        const problems = validator.listProblematicFiles();
        console.log('\n🚨 Arquivos com problemas:');
        problems.forEach(p => console.log(`  - ${p.file} (Score: ${p.score}/100)`));
        break;
        
      case '--help':
        console.log(`
Uso: ts-node scripts/validate_e2e_tests.ts [opções]

Opções:
  --file <caminho>        Valida arquivo específico
  --list-problems         Lista arquivos com problemas
  --help                  Exibe esta ajuda

Variáveis de ambiente:
  FAIL_ON_VIOLATIONS=true  Falha se há violações (padrão: false)
  E2E_ENV=dev|staging|prod Ambiente de teste (padrão: dev)
        `);
        break;
        
      default:
        console.error(`Comando desconhecido: ${command}`);
        console.error('Use --help para ver as opções disponíveis');
        process.exit(1);
    }
  } else {
    // Execução padrão: validação completa
    await validator.run();
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  main().catch(error => {
    console.error(`${colors.red}Erro fatal:${colors.reset}`, error);
    process.exit(1);
  });
}

export default E2EValidator; 