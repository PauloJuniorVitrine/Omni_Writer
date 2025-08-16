/**
 * SemanticValidator - Validação Semântica
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md
 * Ruleset: enterprise_control_layer.yaml
 * Execução: 2025-01-28T10:30:00Z
 * 
 * Validação semântica para detectar testes sintéticos e garantir alinhamento com código real
 * Baseado em código real da aplicação Omni Writer
 */

import { createHash } from 'crypto';

export interface SemanticValidationResult {
  isValid: boolean;
  semanticSimilarity: number;
  semanticHash: string;
  syntheticTestDetected: boolean;
  realCodeAlignment: boolean;
  issues: string[];
  recommendations: string[];
}

export interface SemanticComparison {
  description: string;
  execution: string;
  similarity: number;
  hash1: string;
  hash2: string;
  alignmentScore: number;
}

export interface EmbeddingComparison {
  embedding1: number[];
  embedding2: number[];
  cosineSimilarity: number;
  euclideanDistance: number;
  semanticScore: number;
}

export class SemanticValidator {
  private execId: string;
  private syntheticPatterns: string[];
  private realCodePatterns: string[];

  constructor() {
    this.execId = this.generateExecId();
    this.syntheticPatterns = this.initializeSyntheticPatterns();
    this.realCodePatterns = this.initializeRealCodePatterns();
  }

  /**
   * Valida similaridade semântica entre descrição e execução
   */
  validateSemanticSimilarity(description: string, execution: string): SemanticValidationResult {
    console.log(`[SEMANTIC] Validando similaridade semântica`);

    const result: SemanticValidationResult = {
      isValid: false,
      semanticSimilarity: 0,
      semanticHash: '',
      syntheticTestDetected: false,
      realCodeAlignment: false,
      issues: [],
      recommendations: []
    };

    try {
      // Gerar hash semântico
      result.semanticHash = this.generateSemanticHash(description + execution);
      
      // Calcular similaridade semântica
      result.semanticSimilarity = this.calculateSemanticSimilarity(description, execution);
      
      // Detectar testes sintéticos
      result.syntheticTestDetected = this.detectSyntheticTests(description, execution);
      
      // Validar alinhamento com código real
      result.realCodeAlignment = this.validateRealCodeAlignment(description, execution);
      
      // Determinar validade
      result.isValid = this.determineValidity(result);
      
      // Coletar issues
      result.issues = this.collectIssues(result);
      
      // Gerar recomendações
      result.recommendations = this.generateRecommendations(result);

      console.log(`[SEMANTIC] Validação concluída. Similaridade: ${result.semanticSimilarity.toFixed(2)}`);

      return result;
    } catch (error) {
      console.error(`[SEMANTIC] Erro na validação: ${error.message}`);
      result.issues.push(`Erro na validação semântica: ${error.message}`);
      return result;
    }
  }

  /**
   * Gera hash semântico do conteúdo
   */
  generateSemanticHash(content: string): string {
    // Normalizar conteúdo para hash consistente
    const normalizedContent = content
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .replace(/[^\w\s]/g, '')
      .trim();

    // Gerar hash SHA-256
    const hash = createHash('sha256');
    hash.update(normalizedContent);
    
    return hash.digest('hex').substring(0, 16);
  }

  /**
   * Compara embeddings para similaridade semântica
   */
  compareEmbeddings(embedding1: number[], embedding2: number[]): EmbeddingComparison {
    console.log(`[SEMANTIC] Comparando embeddings`);

    const comparison: EmbeddingComparison = {
      embedding1,
      embedding2,
      cosineSimilarity: 0,
      euclideanDistance: 0,
      semanticScore: 0
    };

    try {
      // Calcular similaridade do cosseno
      comparison.cosineSimilarity = this.calculateCosineSimilarity(embedding1, embedding2);
      
      // Calcular distância euclidiana
      comparison.euclideanDistance = this.calculateEuclideanDistance(embedding1, embedding2);
      
      // Calcular score semântico combinado
      comparison.semanticScore = this.calculateSemanticScore(comparison);

      console.log(`[SEMANTIC] Similaridade do cosseno: ${comparison.cosineSimilarity.toFixed(3)}`);

      return comparison;
    } catch (error) {
      console.error(`[SEMANTIC] Erro na comparação de embeddings: ${error.message}`);
      return comparison;
    }
  }

  /**
   * Valida alinhamento entre descrição e execução
   */
  validateDescriptionExecutionAlignment(): SemanticValidationResult {
    console.log(`[SEMANTIC] Validando alinhamento descrição-execução`);

    // Esta função seria chamada com dados reais de descrição e execução
    // Por enquanto, retorna uma validação simulada
    const mockDescription = "Teste de geração de artigos com dados reais";
    const mockExecution = "Execução real de geração de artigos";

    return this.validateSemanticSimilarity(mockDescription, mockExecution);
  }

  /**
   * Detecta testes sintéticos/genéricos
   */
  detectSyntheticTests(description: string, execution: string): boolean {
    console.log(`[SEMANTIC] Detectando testes sintéticos`);

    const content = (description + ' ' + execution).toLowerCase();
    
    // Verificar padrões sintéticos
    for (const pattern of this.syntheticPatterns) {
      if (content.includes(pattern)) {
        console.log(`[SEMANTIC] Padrão sintético detectado: ${pattern}`);
        return true;
      }
    }

    // Verificar dados fictícios
    const syntheticDataPatterns = [
      'foo', 'bar', 'baz', 'qux', 'quux',
      'lorem ipsum', 'dolor sit amet',
      'test data', 'dummy data', 'fake data',
      'random', 'randomly', 'randomize',
      'sample', 'example', 'mock'
    ];

    for (const pattern of syntheticDataPatterns) {
      if (content.includes(pattern)) {
        console.log(`[SEMANTIC] Dados sintéticos detectados: ${pattern}`);
        return true;
      }
    }

    return false;
  }

  /**
   * Valida alinhamento com código real
   */
  validateRealCodeAlignment(description: string, execution: string): boolean {
    console.log(`[SEMANTIC] Validando alinhamento com código real`);

    const content = (description + ' ' + execution).toLowerCase();
    
    // Verificar padrões de código real
    let realCodeMatches = 0;
    for (const pattern of this.realCodePatterns) {
      if (content.includes(pattern)) {
        realCodeMatches++;
      }
    }

    // Calcular score de alinhamento
    const alignmentScore = realCodeMatches / this.realCodePatterns.length;
    const isValid = alignmentScore >= 0.7; // 70% de alinhamento mínimo

    console.log(`[SEMANTIC] Score de alinhamento: ${alignmentScore.toFixed(2)} (${isValid ? 'VÁLIDO' : 'INVÁLIDO'})`);

    return isValid;
  }

  /**
   * Calcula similaridade semântica entre dois textos
   */
  private calculateSemanticSimilarity(text1: string, text2: string): number {
    // Simulação de cálculo de similaridade semântica
    // Em implementação real, usaria embeddings ou análise de texto avançada
    
    const words1 = this.extractKeywords(text1);
    const words2 = this.extractKeywords(text2);
    
    const intersection = words1.filter(word => words2.includes(word));
    const union = [...new Set([...words1, ...words2])];
    
    const jaccardSimilarity = intersection.length / union.length;
    
    // Ajustar para similaridade semântica (mais rigorosa)
    return Math.min(jaccardSimilarity * 1.2, 1.0);
  }

  /**
   * Extrai palavras-chave do texto
   */
  private extractKeywords(text: string): string[] {
    const stopWords = ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'];
    
    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, '')
      .split(/\s+/)
      .filter(word => word.length > 2 && !stopWords.includes(word));
  }

  /**
   * Calcula similaridade do cosseno
   */
  private calculateCosineSimilarity(vec1: number[], vec2: number[]): number {
    if (vec1.length !== vec2.length) {
      throw new Error('Vetores devem ter o mesmo tamanho');
    }

    let dotProduct = 0;
    let norm1 = 0;
    let norm2 = 0;

    for (let i = 0; i < vec1.length; i++) {
      dotProduct += vec1[i] * vec2[i];
      norm1 += vec1[i] * vec1[i];
      norm2 += vec2[i] * vec2[i];
    }

    if (norm1 === 0 || norm2 === 0) {
      return 0;
    }

    return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
  }

  /**
   * Calcula distância euclidiana
   */
  private calculateEuclideanDistance(vec1: number[], vec2: number[]): number {
    if (vec1.length !== vec2.length) {
      throw new Error('Vetores devem ter o mesmo tamanho');
    }

    let sum = 0;
    for (let i = 0; i < vec1.length; i++) {
      sum += Math.pow(vec1[i] - vec2[i], 2);
    }

    return Math.sqrt(sum);
  }

  /**
   * Calcula score semântico combinado
   */
  private calculateSemanticScore(comparison: EmbeddingComparison): number {
    // Combinar similaridade do cosseno e distância euclidiana
    const normalizedDistance = Math.max(0, 1 - comparison.euclideanDistance / 10);
    return (comparison.cosineSimilarity + normalizedDistance) / 2;
  }

  /**
   * Determina validade baseada nos critérios
   */
  private determineValidity(result: SemanticValidationResult): boolean {
    const criteria = [
      result.semanticSimilarity >= 0.7,
      !result.syntheticTestDetected,
      result.realCodeAlignment
    ];

    return criteria.every(criterion => criterion);
  }

  /**
   * Coleta issues da validação
   */
  private collectIssues(result: SemanticValidationResult): string[] {
    const issues: string[] = [];

    if (result.semanticSimilarity < 0.7) {
      issues.push(`Similaridade semântica baixa: ${result.semanticSimilarity.toFixed(2)} (mínimo: 0.7)`);
    }

    if (result.syntheticTestDetected) {
      issues.push('Teste sintético/genérico detectado');
    }

    if (!result.realCodeAlignment) {
      issues.push('Alinhamento com código real insuficiente');
    }

    return issues;
  }

  /**
   * Gera recomendações baseadas nos issues
   */
  private generateRecommendations(result: SemanticValidationResult): string[] {
    const recommendations: string[] = [];

    if (result.semanticSimilarity < 0.7) {
      recommendations.push('Melhorar descrição do teste para maior alinhamento semântico');
      recommendations.push('Usar terminologia específica da aplicação');
    }

    if (result.syntheticTestDetected) {
      recommendations.push('Remover dados sintéticos (foo, bar, lorem, etc.)');
      recommendations.push('Usar dados reais da aplicação');
      recommendations.push('Basear testes em funcionalidades reais');
    }

    if (!result.realCodeAlignment) {
      recommendations.push('Incluir referências a componentes reais da aplicação');
      recommendations.push('Usar nomes de funções e classes reais');
      recommendations.push('Referenciar endpoints e rotas reais');
    }

    return recommendations;
  }

  /**
   * Inicializa padrões sintéticos
   */
  private initializeSyntheticPatterns(): string[] {
    return [
      'should return something',
      'should work correctly',
      'should handle the case',
      'should process the data',
      'should validate the input',
      'should generate output',
      'should perform operation',
      'should manage state',
      'should handle errors',
      'should complete successfully'
    ];
  }

  /**
   * Inicializa padrões de código real
   */
  private initializeRealCodePatterns(): string[] {
    return [
      // Componentes reais da aplicação
      'article generation',
      'blog management',
      'user authentication',
      'webhook handling',
      'api endpoints',
      'database operations',
      'file upload',
      'email notification',
      'cache management',
      'logging system',
      
      // Funções reais
      'generateArticle',
      'createBlog',
      'authenticateUser',
      'sendWebhook',
      'validateInput',
      'processRequest',
      'saveToDatabase',
      'sendNotification',
      'updateCache',
      'logActivity',
      
      // Endpoints reais
      '/api/articles',
      '/api/blogs',
      '/api/auth',
      '/api/webhooks',
      '/api/users',
      '/api/categories',
      '/api/notifications',
      '/api/metrics',
      '/api/health',
      '/api/status'
    ];
  }

  /**
   * Gera ID único de execução
   */
  private generateExecId(): string {
    return `SEMANTIC_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
} 