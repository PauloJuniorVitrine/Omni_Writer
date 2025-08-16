/**
 * AntiSyntheticValidator - Validação Anti-Sintética
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md
 * Ruleset: enterprise_control_layer.yaml
 * Execução: 2025-01-28T10:40:00Z
 * 
 * Detecção e rejeição de testes sintéticos/genéricos
 * Baseado em código real da aplicação Omni Writer
 */

export interface AntiSyntheticValidationResult {
  isValid: boolean;
  syntheticTestDetected: boolean;
  syntheticPatterns: string[];
  realCodeAlignment: boolean;
  alignmentScore: number;
  issues: string[];
  recommendations: string[];
  rejectionReason?: string;
}

export interface SyntheticPattern {
  pattern: string;
  type: 'data' | 'function' | 'description' | 'variable';
  severity: 'critical' | 'warning' | 'info';
  description: string;
}

export class AntiSyntheticValidator {
  private syntheticPatterns: SyntheticPattern[];
  private realCodePatterns: string[];
  private criticalThreshold: number = 0.8;
  private warningThreshold: number = 0.6;

  constructor() {
    this.syntheticPatterns = this.initializeSyntheticPatterns();
    this.realCodePatterns = this.initializeRealCodePatterns();
  }

  /**
   * Valida se o teste não é sintético
   */
  validateAntiSynthetic(testContent: string): AntiSyntheticValidationResult {
    console.log(`[ANTI_SYNTHETIC] Validando conteúdo anti-sintético`);

    const result: AntiSyntheticValidationResult = {
      isValid: false,
      syntheticTestDetected: false,
      syntheticPatterns: [],
      realCodeAlignment: false,
      alignmentScore: 0,
      issues: [],
      recommendations: []
    };

    try {
      // Detectar padrões sintéticos
      result.syntheticPatterns = this.detectSyntheticPatterns(testContent);
      result.syntheticTestDetected = result.syntheticPatterns.length > 0;

      // Validar alinhamento com código real
      result.alignmentScore = this.calculateRealCodeAlignment(testContent);
      result.realCodeAlignment = result.alignmentScore >= this.criticalThreshold;

      // Determinar validade
      result.isValid = this.determineValidity(result);

      // Coletar issues
      result.issues = this.collectIssues(result);

      // Gerar recomendações
      result.recommendations = this.generateRecommendations(result);

      // Definir motivo de rejeição se aplicável
      if (!result.isValid) {
        result.rejectionReason = this.generateRejectionReason(result);
      }

      console.log(`[ANTI_SYNTHETIC] Validação concluída. Sintético: ${result.syntheticTestDetected}, Alinhamento: ${result.alignmentScore.toFixed(2)}`);

      return result;
    } catch (error) {
      console.error(`[ANTI_SYNTHETIC] Erro na validação: ${error.message}`);
      result.issues.push(`Erro na validação anti-sintética: ${error.message}`);
      return result;
    }
  }

  /**
   * Detecta uso de dados fictícios
   */
  detectFictitiousData(testContent: string): string[] {
    console.log(`[ANTI_SYNTHETIC] Detectando dados fictícios`);

    const fictitiousPatterns = [
      'foo', 'bar', 'baz', 'qux', 'quux', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud',
      'lorem ipsum', 'dolor sit amet', 'consectetur adipiscing elit',
      'test data', 'dummy data', 'fake data', 'mock data', 'sample data',
      'random', 'randomly', 'randomize', 'randomized',
      'example', 'sample', 'mock', 'stub', 'fake', 'dummy',
      'user123', 'testuser', 'demo', 'placeholder',
      'password123', 'testpass', 'secret123',
      'email@test.com', 'test@example.com', 'user@test.com'
    ];

    const detected: string[] = [];
    const content = testContent.toLowerCase();

    for (const pattern of fictitiousPatterns) {
      if (content.includes(pattern)) {
        detected.push(pattern);
        console.log(`[ANTI_SYNTHETIC] Dados fictícios detectados: ${pattern}`);
      }
    }

    return detected;
  }

  /**
   * Detecta cenários genéricos não representativos
   */
  detectGenericScenarios(testContent: string): string[] {
    console.log(`[ANTI_SYNTHETIC] Detectando cenários genéricos`);

    const genericPatterns = [
      'should work correctly',
      'should handle the case',
      'should process the data',
      'should validate the input',
      'should generate output',
      'should perform operation',
      'should manage state',
      'should handle errors',
      'should complete successfully',
      'should return something',
      'should be defined',
      'should not be null',
      'should have the correct value',
      'should match the expected result'
    ];

    const detected: string[] = [];
    const content = testContent.toLowerCase();

    for (const pattern of genericPatterns) {
      if (content.includes(pattern)) {
        detected.push(pattern);
        console.log(`[ANTI_SYNTHETIC] Cenário genérico detectado: ${pattern}`);
      }
    }

    return detected;
  }

  /**
   * Valida que testes usam código real da aplicação
   */
  validateRealCodeUsage(testContent: string): boolean {
    console.log(`[ANTI_SYNTHETIC] Validando uso de código real`);

    const content = testContent.toLowerCase();
    let realCodeMatches = 0;

    for (const pattern of this.realCodePatterns) {
      if (content.includes(pattern)) {
        realCodeMatches++;
      }
    }

    const alignmentScore = realCodeMatches / this.realCodePatterns.length;
    const isValid = alignmentScore >= this.criticalThreshold;

    console.log(`[ANTI_SYNTHETIC] Score de alinhamento: ${alignmentScore.toFixed(2)} (${isValid ? 'VÁLIDO' : 'INVÁLIDO'})`);

    return isValid;
  }

  /**
   * Rejeita testes que não passem na validação semântica
   */
  rejectInvalidTests(validationResult: AntiSyntheticValidationResult): void {
    if (!validationResult.isValid) {
      console.error(`[ANTI_SYNTHETIC] Teste rejeitado: ${validationResult.rejectionReason}`);
      console.error(`[ANTI_SYNTHETIC] Issues encontradas:`, validationResult.issues);
      console.error(`[ANTI_SYNTHETIC] Recomendações:`, validationResult.recommendations);
      
      throw new Error(`Teste sintético/genérico rejeitado: ${validationResult.rejectionReason}`);
    }
  }

  /**
   * Detecta padrões sintéticos no conteúdo
   */
  private detectSyntheticPatterns(testContent: string): string[] {
    const detected: string[] = [];
    const content = testContent.toLowerCase();

    for (const pattern of this.syntheticPatterns) {
      if (content.includes(pattern.pattern)) {
        detected.push(pattern.pattern);
        console.log(`[ANTI_SYNTHETIC] Padrão sintético detectado: ${pattern.pattern} (${pattern.type})`);
      }
    }

    return detected;
  }

  /**
   * Calcula alinhamento com código real
   */
  private calculateRealCodeAlignment(testContent: string): number {
    const content = testContent.toLowerCase();
    let realCodeMatches = 0;

    for (const pattern of this.realCodePatterns) {
      if (content.includes(pattern)) {
        realCodeMatches++;
      }
    }

    return realCodeMatches / this.realCodePatterns.length;
  }

  /**
   * Determina validade baseada nos critérios
   */
  private determineValidity(result: AntiSyntheticValidationResult): boolean {
    const criteria = [
      !result.syntheticTestDetected,
      result.realCodeAlignment,
      result.alignmentScore >= this.criticalThreshold
    ];

    return criteria.every(criterion => criterion);
  }

  /**
   * Coleta issues da validação
   */
  private collectIssues(result: AntiSyntheticValidationResult): string[] {
    const issues: string[] = [];

    if (result.syntheticTestDetected) {
      issues.push(`Teste sintético detectado com ${result.syntheticPatterns.length} padrões`);
      issues.push(`Padrões detectados: ${result.syntheticPatterns.join(', ')}`);
    }

    if (!result.realCodeAlignment) {
      issues.push(`Alinhamento com código real insuficiente: ${result.alignmentScore.toFixed(2)} (mínimo: ${this.criticalThreshold})`);
    }

    if (result.alignmentScore < this.warningThreshold) {
      issues.push(`Alinhamento muito baixo: ${result.alignmentScore.toFixed(2)} (recomendado: ${this.warningThreshold})`);
    }

    return issues;
  }

  /**
   * Gera recomendações baseadas nos issues
   */
  private generateRecommendations(result: AntiSyntheticValidationResult): string[] {
    const recommendations: string[] = [];

    if (result.syntheticTestDetected) {
      recommendations.push('Remover todos os dados sintéticos (foo, bar, lorem, etc.)');
      recommendations.push('Usar dados reais da aplicação Omni Writer');
      recommendations.push('Referenciar funcionalidades específicas da aplicação');
      recommendations.push('Basear testes em casos de uso reais');
    }

    if (!result.realCodeAlignment) {
      recommendations.push('Incluir referências a componentes reais da aplicação');
      recommendations.push('Usar nomes de funções e classes reais');
      recommendations.push('Referenciar endpoints e rotas reais');
      recommendations.push('Incluir validações específicas do domínio');
    }

    if (result.alignmentScore < this.warningThreshold) {
      recommendations.push('Aumentar alinhamento com código real');
      recommendations.push('Usar terminologia específica da aplicação');
      recommendations.push('Incluir mais referências a funcionalidades reais');
    }

    return recommendations;
  }

  /**
   * Gera motivo de rejeição
   */
  private generateRejectionReason(result: AntiSyntheticValidationResult): string {
    if (result.syntheticTestDetected) {
      return `Teste sintético detectado com ${result.syntheticPatterns.length} padrões proibidos`;
    }

    if (!result.realCodeAlignment) {
      return `Alinhamento com código real insuficiente (${result.alignmentScore.toFixed(2)})`;
    }

    return 'Validação anti-sintética falhou';
  }

  /**
   * Inicializa padrões sintéticos
   */
  private initializeSyntheticPatterns(): SyntheticPattern[] {
    return [
      // Dados fictícios
      { pattern: 'foo', type: 'data', severity: 'critical', description: 'Dados fictícios proibidos' },
      { pattern: 'bar', type: 'data', severity: 'critical', description: 'Dados fictícios proibidos' },
      { pattern: 'lorem ipsum', type: 'data', severity: 'critical', description: 'Texto Lorem Ipsum proibido' },
      { pattern: 'test data', type: 'data', severity: 'critical', description: 'Dados de teste genéricos' },
      { pattern: 'dummy data', type: 'data', severity: 'critical', description: 'Dados dummy proibidos' },
      { pattern: 'random', type: 'data', severity: 'critical', description: 'Dados aleatórios proibidos' },
      
      // Funções genéricas
      { pattern: 'should work correctly', type: 'function', severity: 'critical', description: 'Descrição genérica proibida' },
      { pattern: 'should handle the case', type: 'function', severity: 'critical', description: 'Descrição genérica proibida' },
      { pattern: 'should process the data', type: 'function', severity: 'critical', description: 'Descrição genérica proibida' },
      { pattern: 'should validate the input', type: 'function', severity: 'critical', description: 'Descrição genérica proibida' },
      
      // Variáveis genéricas
      { pattern: 'testuser', type: 'variable', severity: 'critical', description: 'Usuário de teste genérico' },
      { pattern: 'password123', type: 'variable', severity: 'critical', description: 'Senha de teste genérica' },
      { pattern: 'test@example.com', type: 'variable', severity: 'critical', description: 'Email de teste genérico' },
      
      // Descrições genéricas
      { pattern: 'should be defined', type: 'description', severity: 'warning', description: 'Validação genérica' },
      { pattern: 'should not be null', type: 'description', severity: 'warning', description: 'Validação genérica' },
      { pattern: 'should have the correct value', type: 'description', severity: 'warning', description: 'Validação genérica' }
    ];
  }

  /**
   * Inicializa padrões de código real
   */
  private initializeRealCodePatterns(): string[] {
    return [
      // Componentes reais da aplicação Omni Writer
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
      'content optimization',
      'seo analysis',
      'keyword research',
      'plagiarism check',
      'grammar check',
      'tone analysis',
      'readability score',
      'word count',
      'reading time',
      'meta description',
      
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
      'optimizeContent',
      'analyzeSEO',
      'checkPlagiarism',
      'checkGrammar',
      'analyzeTone',
      'calculateReadability',
      'countWords',
      'estimateReadingTime',
      'generateMetaDescription',
      
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
      '/api/status',
      '/api/optimize',
      '/api/seo',
      '/api/plagiarism',
      '/api/grammar',
      '/api/tone',
      '/api/readability',
      
      // Elementos de UI reais
      'article-generation-form',
      'blog-management-panel',
      'user-dashboard',
      'webhook-configuration',
      'api-documentation',
      'database-schema',
      'file-upload-zone',
      'email-templates',
      'cache-controls',
      'log-viewer',
      'content-editor',
      'seo-analyzer',
      'plagiarism-checker',
      'grammar-checker',
      'tone-analyzer',
      'readability-calculator',
      'word-counter',
      'reading-time-estimator',
      'meta-description-generator'
    ];
  }
} 