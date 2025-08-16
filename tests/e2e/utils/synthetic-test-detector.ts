/**
 * Detector de Testes Sintéticos
 * - Valida que todos os testes são baseados em código real
 * - Proíbe dados fictícios (foo, bar, lorem, random)
 * - Exige rastreabilidade da origem dos testes
 * 
 * 📐 CoCoT: Baseado em boas práticas de validação de testes
 * 🌲 ToT: Múltiplas estratégias de detecção implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de validação
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
  ],
  
  meaninglessContent: [
    /\bcontent.*here\b/i,
    /\btext.*here\b/i,
    /\bdescription.*here\b/i,
    /\btitle.*here\b/i
  ]
};

// Padrões obrigatórios (devem estar presentes)
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

export interface ValidationResult {
  file: string;
  isValid: boolean;
  violations: string[];
  warnings: string[];
  suggestions: string[];
  score: number; // 0-100
}

export interface TestOrigin {
  file: string;
  prompt?: string;
  date?: string;
  tracingId?: string;
  sourceCode?: string;
  functionality?: string;
}

export class SyntheticTestDetector {
  private results: ValidationResult[] = [];
  private origins: Map<string, TestOrigin> = new Map();

  /**
   * Valida um arquivo de teste individual
   */
  validateTestFile(filePath: string): ValidationResult {
    const content = fs.readFileSync(filePath, 'utf-8');
    const violations: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];

    // Verificar padrões proibidos
    for (const [category, patterns] of Object.entries(FORBIDDEN_PATTERNS)) {
      for (const pattern of patterns) {
        const matches = content.match(pattern);
        if (matches) {
          violations.push(`Dados sintéticos detectados (${category}): ${matches.join(', ')}`);
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
        warnings.push(`Padrão obrigatório ausente (${category}): dados reais do sistema`);
      }
    }

    // Verificar rastreabilidade
    const origin = this.extractTestOrigin(content, filePath);
    if (!origin.prompt && !origin.sourceCode) {
      violations.push('Origem do teste não documentada');
    }

    // Calcular score
    const score = this.calculateScore(violations, warnings, content);

    // Gerar sugestões
    if (violations.length > 0) {
      suggestions.push('Substitua dados sintéticos por dados reais do sistema');
    }
    if (warnings.length > 0) {
      suggestions.push('Adicione documentação de origem do teste');
    }

    const result: ValidationResult = {
      file: filePath,
      isValid: violations.length === 0,
      violations,
      warnings,
      suggestions,
      score
    };

    this.results.push(result);
    this.origins.set(filePath, origin);

    return result;
  }

  /**
   * Valida toda a suite de testes E2E
   */
  validateTestSuite(testDir: string = './tests/e2e'): ValidationResult[] {
    const files = this.getTestFiles(testDir);
    
    for (const file of files) {
      this.validateTestFile(file);
    }

    return this.results;
  }

  /**
   * Extrai informações de origem do teste
   */
  private extractTestOrigin(content: string, filePath: string): TestOrigin {
    const origin: TestOrigin = { file: filePath };

    // Extrair prompt
    const promptMatch = content.match(/\*\*Prompt:\s*(.+)/i);
    if (promptMatch) {
      origin.prompt = promptMatch[1].trim();
    }

    // Extrair data/hora
    const dateMatch = content.match(/\*\*Data\/Hora:\s*(.+)/i);
    if (dateMatch) {
      origin.date = dateMatch[1].trim();
    }

    // Extrair tracing ID
    const tracingMatch = content.match(/\*\*Tracing ID:\s*(.+)/i);
    if (tracingMatch) {
      origin.tracingId = tracingMatch[1].trim();
    }

    // Extrair código fonte referenciado
    const sourceMatch = content.match(/\*\*Origem:\s*(.+)/i);
    if (sourceMatch) {
      origin.sourceCode = sourceMatch[1].trim();
    }

    // Inferir funcionalidade baseada no nome do arquivo
    const fileName = path.basename(filePath, '.ts');
    if (fileName.includes('generate')) {
      origin.functionality = 'Geração de Artigos';
    } else if (fileName.includes('webhook')) {
      origin.functionality = 'Webhooks';
    } else if (fileName.includes('blog')) {
      origin.functionality = 'Gestão de Blogs';
    } else if (fileName.includes('category')) {
      origin.functionality = 'Gestão de Categorias';
    } else if (fileName.includes('prompt')) {
      origin.functionality = 'Gestão de Prompts';
    }

    return origin;
  }

  /**
   * Calcula score de qualidade do teste
   */
  private calculateScore(violations: string[], warnings: string[], content: string): number {
    let score = 100;

    // Penalizar violações
    score -= violations.length * 20;

    // Penalizar warnings
    score -= warnings.length * 10;

    // Bônus por rastreabilidade
    if (content.includes('**Prompt:') && content.includes('**Tracing ID:')) {
      score += 10;
    }

    // Bônus por dados reais
    if (content.includes('omni') && content.includes('writer')) {
      score += 5;
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Obtém lista de arquivos de teste
   */
  private getTestFiles(dir: string): string[] {
    const files: string[] = [];
    
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
   * Gera relatório de validação
   */
  generateReport(): string {
    const totalFiles = this.results.length;
    const validFiles = this.results.filter(r => r.isValid).length;
    const avgScore = this.results.reduce((sum, r) => sum + r.score, 0) / totalFiles;

    let report = `# 📊 Relatório de Validação - Testes Sintéticos\n\n`;
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
        
        if (result.suggestions.length > 0) {
          report += `- **Sugestões**:\n`;
          for (const suggestion of result.suggestions) {
            report += `  - ${suggestion}\n`;
          }
        }
        
        report += `\n`;
      }
    }

    // Arquivos válidos
    const validFilesList = this.results.filter(r => r.isValid && r.score >= 80);
    if (validFilesList.length > 0) {
      report += `## ✅ Arquivos Válidos\n\n`;
      
      for (const result of validFilesList) {
        const origin = this.origins.get(result.file);
        report += `### ${result.file}\n`;
        report += `- **Score**: ${result.score}/100\n`;
        if (origin?.functionality) {
          report += `- **Funcionalidade**: ${origin.functionality}\n`;
        }
        if (origin?.tracingId) {
          report += `- **Tracing ID**: ${origin.tracingId}\n`;
        }
        report += `\n`;
      }
    }

    return report;
  }

  /**
   * Salva relatório em arquivo
   */
  saveReport(outputPath: string = 'test-results/synthetic-test-validation.md'): void {
    const report = this.generateReport();
    
    // Criar diretório se não existir
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(outputPath, report);
    console.log(`📊 Relatório salvo em: ${outputPath}`);
  }
}

// Utilitário para uso em scripts
export function validateTestFile(filePath: string): ValidationResult {
  const detector = new SyntheticTestDetector();
  return detector.validateTestFile(filePath);
}

export function validateTestSuite(testDir?: string): ValidationResult[] {
  const detector = new SyntheticTestDetector();
  return detector.validateTestSuite(testDir);
}

// Exportar para uso em outros módulos
export default SyntheticTestDetector; 