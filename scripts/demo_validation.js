#!/usr/bin/env node

/**
 * Demonstração de Validação de Testes E2E
 * - Validação de testes sintéticos
 * - Versão simplificada para demonstração
 */

import fs from 'fs';
import path from 'path';

// Padrões proibidos
const FORBIDDEN = [
  /\bfoo\b/i, /\bbar\b/i, /\blorem\b/i, /\bipsum\b/i,
  /\bdummy\b/i, /\bfake\b/i, /\brandom\b/i
];

// Padrões obrigatórios
const REQUIRED = [
  /\bomni.*writer\b/i, /\barticle.*generation\b/i,
  /\bapi.*key\b/i, /\bwebhook\b/i
];

// Cores
const colors = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', reset: '\x1b[0m', bold: '\x1b[1m'
};

function validateFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const violations = [];
    const warnings = [];
    let score = 100;

    // Verificar proibidos
    FORBIDDEN.forEach(pattern => {
      if (pattern.test(content)) {
        violations.push(`Dados sintéticos: ${pattern.source}`);
        score -= 20;
      }
    });

    // Verificar obrigatórios
    let hasRequired = false;
    REQUIRED.forEach(pattern => {
      if (pattern.test(content)) {
        hasRequired = true;
      }
    });

    if (!hasRequired) {
      warnings.push('Dados reais do sistema ausentes');
      score -= 10;
    }

    // Verificar rastreabilidade
    if (!content.includes('**Prompt:') && !content.includes('**Tracing ID:')) {
      violations.push('Origem não documentada');
      score -= 20;
    }

    score = Math.max(0, Math.min(100, score));

    return {
      file: path.basename(filePath),
      isValid: violations.length === 0,
      violations,
      warnings,
      score
    };

  } catch (error) {
    return {
      file: path.basename(filePath),
      isValid: false,
      violations: ['Erro ao ler arquivo'],
      warnings: [],
      score: 0
    };
  }
}

function getTestFiles(dir) {
  const files = [];
  
  if (fs.existsSync(dir)) {
    const items = fs.readdirSync(dir);
    
    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...getTestFiles(fullPath));
      } else if (item.endsWith('.spec.ts') || item.endsWith('.test.ts')) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

// Execução principal
console.log(`${colors.cyan}${colors.bold}🔍 Validação de Testes E2E - Demonstração${colors.reset}\n`);

const testDir = './tests/e2e';
const files = getTestFiles(testDir);

console.log(`${colors.blue}Encontrados ${files.length} arquivos de teste${colors.reset}\n`);

const results = [];
for (const file of files) {
  const result = validateFile(file);
  results.push(result);
}

// Exibir resultados
console.log(`${colors.bold}📋 Resultados da Validação:${colors.reset}\n`);

results.forEach(result => {
  const status = result.isValid ? `${colors.green}✅${colors.reset}` : `${colors.red}❌${colors.reset}`;
  const scoreColor = result.score >= 80 ? colors.green : result.score >= 60 ? colors.yellow : colors.red;
  
  console.log(`${status} ${result.file}`);
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
});

// Resumo final
const totalFiles = results.length;
const validFiles = results.filter(r => r.isValid).length;
const avgScore = results.reduce((sum, r) => sum + r.score, 0) / totalFiles;

console.log(`${colors.bold}📈 Resumo Final:${colors.reset}`);
console.log(`  📁 Total: ${totalFiles}`);
console.log(`  ✅ Válidos: ${validFiles}/${totalFiles} (${((validFiles/totalFiles)*100).toFixed(1)}%)`);
console.log(`  📊 Score médio: ${avgScore.toFixed(1)}/100`);

if (validFiles === totalFiles && avgScore >= 80) {
  console.log(`\n${colors.green}${colors.bold}✅ Validação aprovada!${colors.reset}`);
} else {
  console.log(`\n${colors.red}${colors.bold}❌ Validação falhou!${colors.reset}`);
}

console.log(`\n${colors.blue}📊 Relatório salvo em: test-results/validation-demo.md${colors.reset}`);

// Salvar relatório
const report = `# Validação de Testes E2E - Demonstração

**Data**: ${new Date().toISOString()}
**Total de arquivos**: ${totalFiles}
**Arquivos válidos**: ${validFiles}/${totalFiles} (${((validFiles/totalFiles)*100).toFixed(1)}%)
**Score médio**: ${avgScore.toFixed(1)}/100

## Resultados Detalhados

${results.map(r => `
### ${r.file}
- **Score**: ${r.score}/100
- **Válido**: ${r.isValid ? 'Sim' : 'Não'}
${r.violations.length > 0 ? `- **Violações**: ${r.violations.join(', ')}` : ''}
${r.warnings.length > 0 ? `- **Avisos**: ${r.warnings.join(', ')}` : ''}
`).join('')}
`;

if (!fs.existsSync('test-results')) {
  fs.mkdirSync('test-results', { recursive: true });
}

fs.writeFileSync('test-results/validation-demo.md', report); 