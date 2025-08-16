/**
 * SemanticHashGenerator - Geração de Hash Semântico
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md
 * Ruleset: enterprise_control_layer.yaml
 * Execução: 2025-01-28T10:35:00Z
 * 
 * Geração de hash semântico para rastreabilidade e comparação de execuções
 * Baseado em código real da aplicação Omni Writer
 */

import { createHash } from 'crypto';

export interface SemanticHashData {
  journeyName: string;
  executionId: string;
  timestamp: string;
  content: string;
  metadata: Record<string, any>;
  hash: string;
  version: string;
}

export interface HashComparison {
  hash1: string;
  hash2: string;
  similarity: number;
  differences: string[];
  isIdentical: boolean;
}

export class SemanticHashGenerator {
  private version: string = '1.0.0';

  /**
   * Gera hash semântico para uma jornada
   */
  generateJourneyHash(journeyName: string, content: string, metadata: Record<string, any> = {}): SemanticHashData {
    console.log(`[SEMANTIC_HASH] Gerando hash para jornada: ${journeyName}`);

    const executionId = this.generateExecutionId();
    const timestamp = new Date().toISOString();
    
    // Normalizar conteúdo para hash consistente
    const normalizedContent = this.normalizeContent(content);
    
    // Gerar hash SHA-256
    const hash = this.generateHash(normalizedContent);
    
    const hashData: SemanticHashData = {
      journeyName,
      executionId,
      timestamp,
      content: normalizedContent,
      metadata,
      hash,
      version: this.version
    };

    console.log(`[SEMANTIC_HASH] Hash gerado: ${hash} para ${journeyName}`);

    return hashData;
  }

  /**
   * Gera hash semântico para uma execução
   */
  generateExecutionHash(executionData: {
    testResults: any[];
    performanceMetrics: any;
    screenshots: string[];
    logs: string[];
  }): SemanticHashData {
    console.log(`[SEMANTIC_HASH] Gerando hash para execução`);

    const executionId = this.generateExecutionId();
    const timestamp = new Date().toISOString();
    
    // Combinar dados da execução
    const content = this.combineExecutionData(executionData);
    const normalizedContent = this.normalizeContent(content);
    
    // Gerar hash
    const hash = this.generateHash(normalizedContent);
    
    const hashData: SemanticHashData = {
      journeyName: 'execution',
      executionId,
      timestamp,
      content: normalizedContent,
      metadata: {
        testCount: executionData.testResults.length,
        performanceMetrics: executionData.performanceMetrics,
        screenshotCount: executionData.screenshots.length,
        logCount: executionData.logs.length
      },
      hash,
      version: this.version
    };

    console.log(`[SEMANTIC_HASH] Hash de execução gerado: ${hash}`);

    return hashData;
  }

  /**
   * Compara hashes entre execuções
   */
  compareHashes(hashData1: SemanticHashData, hashData2: SemanticHashData): HashComparison {
    console.log(`[SEMANTIC_HASH] Comparando hashes`);

    const comparison: HashComparison = {
      hash1: hashData1.hash,
      hash2: hashData2.hash,
      similarity: 0,
      differences: [],
      isIdentical: false
    };

    // Verificar se são idênticos
    comparison.isIdentical = hashData1.hash === hashData2.hash;
    
    if (comparison.isIdentical) {
      comparison.similarity = 1.0;
      console.log(`[SEMANTIC_HASH] Hashes idênticos`);
      return comparison;
    }

    // Calcular similaridade baseada no conteúdo
    comparison.similarity = this.calculateContentSimilarity(
      hashData1.content,
      hashData2.content
    );

    // Identificar diferenças
    comparison.differences = this.identifyDifferences(hashData1, hashData2);

    console.log(`[SEMANTIC_HASH] Similaridade: ${comparison.similarity.toFixed(3)}`);

    return comparison;
  }

  /**
   * Inclui hash semântico nos logs
   */
  includeHashInLogs(hashData: SemanticHashData, logData: any): any {
    return {
      ...logData,
      semantic_hash: hashData.hash,
      semantic_metadata: {
        journeyName: hashData.journeyName,
        executionId: hashData.executionId,
        timestamp: hashData.timestamp,
        version: hashData.version
      }
    };
  }

  /**
   * Valida hash semântico
   */
  validateHash(hashData: SemanticHashData): boolean {
    // Verificar se o hash foi gerado corretamente
    const expectedHash = this.generateHash(hashData.content);
    const isValid = hashData.hash === expectedHash;

    if (!isValid) {
      console.error(`[SEMANTIC_HASH] Hash inválido detectado`);
      console.error(`[SEMANTIC_HASH] Esperado: ${expectedHash}`);
      console.error(`[SEMANTIC_HASH] Recebido: ${hashData.hash}`);
    }

    return isValid;
  }

  /**
   * Normaliza conteúdo para hash consistente
   */
  private normalizeContent(content: string): string {
    return content
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .replace(/[^\w\s]/g, '')
      .trim();
  }

  /**
   * Gera hash SHA-256
   */
  private generateHash(content: string): string {
    const hash = createHash('sha256');
    hash.update(content);
    return hash.digest('hex');
  }

  /**
   * Combina dados da execução
   */
  private combineExecutionData(executionData: any): string {
    const parts = [
      JSON.stringify(executionData.testResults),
      JSON.stringify(executionData.performanceMetrics),
      executionData.screenshots.join(''),
      executionData.logs.join('')
    ];

    return parts.join('|');
  }

  /**
   * Calcula similaridade entre conteúdos
   */
  private calculateContentSimilarity(content1: string, content2: string): number {
    const words1 = content1.split(/\s+/);
    const words2 = content2.split(/\s+/);
    
    const intersection = words1.filter(word => words2.includes(word));
    const union = [...new Set([...words1, ...words2])];
    
    return intersection.length / union.length;
  }

  /**
   * Identifica diferenças entre hash datas
   */
  private identifyDifferences(hashData1: SemanticHashData, hashData2: SemanticHashData): string[] {
    const differences: string[] = [];

    // Comparar jornadas
    if (hashData1.journeyName !== hashData2.journeyName) {
      differences.push(`Jornadas diferentes: ${hashData1.journeyName} vs ${hashData2.journeyName}`);
    }

    // Comparar versões
    if (hashData1.version !== hashData2.version) {
      differences.push(`Versões diferentes: ${hashData1.version} vs ${hashData2.version}`);
    }

    // Comparar metadados
    const metadata1 = JSON.stringify(hashData1.metadata);
    const metadata2 = JSON.stringify(hashData2.metadata);
    if (metadata1 !== metadata2) {
      differences.push('Metadados diferentes');
    }

    // Comparar conteúdo
    if (hashData1.content !== hashData2.content) {
      differences.push('Conteúdo diferente');
    }

    return differences;
  }

  /**
   * Gera ID único de execução
   */
  private generateExecutionId(): string {
    return `HASH_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
} 