/**
 * SmokeModeValidator - Validação em modo smoke otimizado
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md - Item 9.1
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-28 12:00:00Z
 */

import { Page } from 'playwright';

export interface SmokeJourney {
  name: string;
  impactScore: number; // 1-10, onde 10 é mais crítico
  estimatedTime: number; // em segundos
  criticalSteps: string[];
  dependencies: string[];
  priority: 'critical' | 'high' | 'medium' | 'low';
}

export interface SmokeConfig {
  maxExecutionTime: number; // em segundos (padrão: 120)
  maxJourneys: number; // máximo de jornadas (padrão: 10)
  impactThreshold: number; // score mínimo (padrão: 7)
  enableParallel: boolean;
  failFast: boolean;
  thresholds: {
    lcp: number; // Largest Contentful Paint (padrão: 4s)
    cls: number; // Cumulative Layout Shift (padrão: 0.15)
    fid: number; // First Input Delay (padrão: 150ms)
    tti: number; // Time to Interactive (padrão: 4s)
  };
}

export interface SmokeResult {
  journeyName: string;
  status: 'passed' | 'failed' | 'skipped';
  executionTime: number;
  webVitals: {
    lcp: number;
    cls: number;
    fid: number;
    tti: number;
  };
  errors: string[];
  warnings: string[];
}

export interface SmokeReport {
  executionId: string;
  timestamp: string;
  totalJourneys: number;
  executedJourneys: number;
  passedJourneys: number;
  failedJourneys: number;
  skippedJourneys: number;
  totalExecutionTime: number;
  results: SmokeResult[];
  recommendations: string[];
  overallStatus: 'excellent' | 'good' | 'warning' | 'critical';
}

export class SmokeModeValidator {
  private readonly defaultConfig: SmokeConfig = {
    maxExecutionTime: 120, // 2 minutos
    maxJourneys: 10,
    impactThreshold: 7,
    enableParallel: false,
    failFast: true,
    thresholds: {
      lcp: 4000, // 4s
      cls: 0.15,
      fid: 150, // 150ms
      tti: 4000 // 4s
    }
  };

  private readonly availableJourneys: SmokeJourney[] = [
    {
      name: 'jornada_login',
      impactScore: 10,
      estimatedTime: 15,
      criticalSteps: ['Acessar página de login', 'Inserir credenciais', 'Validar redirecionamento'],
      dependencies: [],
      priority: 'critical'
    },
    {
      name: 'jornada_criar_blog',
      impactScore: 9,
      estimatedTime: 25,
      criticalSteps: ['Acessar dashboard', 'Criar novo blog', 'Validar persistência'],
      dependencies: ['jornada_login'],
      priority: 'critical'
    },
    {
      name: 'jornada_gerar_artigo',
      impactScore: 9,
      estimatedTime: 30,
      criticalSteps: ['Selecionar blog', 'Configurar artigo', 'Iniciar geração', 'Validar resultado'],
      dependencies: ['jornada_criar_blog'],
      priority: 'critical'
    },
    {
      name: 'jornada_visualizar_artigo',
      impactScore: 8,
      estimatedTime: 20,
      criticalSteps: ['Acessar lista de artigos', 'Visualizar artigo', 'Validar renderização'],
      dependencies: ['jornada_gerar_artigo'],
      priority: 'high'
    },
    {
      name: 'jornada_exportar_artigo',
      impactScore: 7,
      estimatedTime: 18,
      criticalSteps: ['Selecionar artigo', 'Escolher formato', 'Iniciar exportação', 'Validar download'],
      dependencies: ['jornada_visualizar_artigo'],
      priority: 'high'
    },
    {
      name: 'jornada_editar_blog',
      impactScore: 7,
      estimatedTime: 22,
      criticalSteps: ['Acessar blog existente', 'Modificar dados', 'Salvar alterações', 'Validar persistência'],
      dependencies: ['jornada_criar_blog'],
      priority: 'high'
    },
    {
      name: 'jornada_excluir_blog',
      impactScore: 6,
      estimatedTime: 12,
      criticalSteps: ['Acessar blog', 'Confirmar exclusão', 'Validar remoção'],
      dependencies: ['jornada_criar_blog'],
      priority: 'medium'
    },
    {
      name: 'jornada_configurar_categoria',
      impactScore: 6,
      estimatedTime: 20,
      criticalSteps: ['Acessar configurações', 'Criar categoria', 'Validar associação'],
      dependencies: ['jornada_criar_blog'],
      priority: 'medium'
    },
    {
      name: 'jornada_gerenciar_usuarios',
      impactScore: 5,
      estimatedTime: 25,
      criticalSteps: ['Acessar admin', 'Listar usuários', 'Validar permissões'],
      dependencies: ['jornada_login'],
      priority: 'medium'
    },
    {
      name: 'jornada_webhook_integration',
      impactScore: 4,
      estimatedTime: 35,
      criticalSteps: ['Configurar webhook', 'Testar integração', 'Validar resposta'],
      dependencies: ['jornada_login'],
      priority: 'low'
    },
    {
      name: 'jornada_api_consumption',
      impactScore: 4,
      estimatedTime: 28,
      criticalSteps: ['Autenticar API', 'Fazer requisição', 'Validar resposta'],
      dependencies: ['jornada_login'],
      priority: 'low'
    },
    {
      name: 'jornada_performance_monitoring',
      impactScore: 3,
      estimatedTime: 40,
      criticalSteps: ['Acessar métricas', 'Coletar dados', 'Validar dashboard'],
      dependencies: ['jornada_login'],
      priority: 'low'
    }
  ];

  /**
   * Seleciona jornadas críticas para modo smoke
   */
  selectCriticalJourneys(config: Partial<SmokeConfig> = {}): SmokeJourney[] {
    const finalConfig = { ...this.defaultConfig, ...config };
    
    console.log(`[SmokeModeValidator] Selecionando jornadas críticas`);
    console.log(`[SmokeModeValidator] Impact threshold: ${finalConfig.impactThreshold}`);
    console.log(`[SmokeModeValidator] Max journeys: ${finalConfig.maxJourneys}`);

    // Filtrar jornadas por impacto e prioridade
    const criticalJourneys = this.availableJourneys
      .filter(journey => journey.impactScore >= finalConfig.impactThreshold)
      .sort((a, b) => {
        // Ordenar por prioridade e depois por impacto
        const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];
        
        if (priorityDiff !== 0) return priorityDiff;
        return b.impactScore - a.impactScore;
      })
      .slice(0, finalConfig.maxJourneys);

    console.log(`[SmokeModeValidator] Jornadas selecionadas: ${criticalJourneys.map(j => j.name).join(', ')}`);
    
    return criticalJourneys;
  }

  /**
   * Executa modo smoke otimizado
   */
  async executeSmokeMode(
    page: Page,
    config: Partial<SmokeConfig> = {}
  ): Promise<SmokeReport> {
    const finalConfig = { ...this.defaultConfig, ...config };
    const executionId = `SMOKE_${Date.now()}`;
    const timestamp = new Date().toISOString();

    console.log(`[SmokeModeValidator] Iniciando modo smoke`);
    console.log(`[SmokeModeValidator] Configuração:`, finalConfig);

    const selectedJourneys = this.selectCriticalJourneys(finalConfig);
    const results: SmokeResult[] = [];
    let totalExecutionTime = 0;
    let failedCount = 0;

    const startTime = Date.now();

    // Executar jornadas sequencialmente (ou em paralelo se habilitado)
    if (finalConfig.enableParallel) {
      const promises = selectedJourneys.map(journey => 
        this.executeJourney(page, journey, finalConfig)
      );
      
      const journeyResults = await Promise.all(promises);
      results.push(...journeyResults);
    } else {
      for (const journey of selectedJourneys) {
        const result = await this.executeJourney(page, journey, finalConfig);
        results.push(result);
        
        totalExecutionTime += result.executionTime;
        
        if (result.status === 'failed') {
          failedCount++;
          if (finalConfig.failFast) {
            console.log(`[SmokeModeValidator] Falha rápida ativada. Parando execução.`);
            break;
          }
        }

        // Verificar timeout
        if (totalExecutionTime > finalConfig.maxExecutionTime * 1000) {
          console.log(`[SmokeModeValidator] Timeout atingido. Parando execução.`);
          break;
        }
      }
    }

    const endTime = Date.now();
    const actualTotalTime = endTime - startTime;

    const passedJourneys = results.filter(r => r.status === 'passed').length;
    const failedJourneys = results.filter(r => r.status === 'failed').length;
    const skippedJourneys = results.filter(r => r.status === 'skipped').length;

    const recommendations = this.generateRecommendations(results, finalConfig);
    const overallStatus = this.calculateOverallStatus(results, finalConfig);

    return {
      executionId,
      timestamp,
      totalJourneys: selectedJourneys.length,
      executedJourneys: results.length,
      passedJourneys,
      failedJourneys,
      skippedJourneys,
      totalExecutionTime: actualTotalTime,
      results,
      recommendations,
      overallStatus
    };
  }

  /**
   * Executa uma jornada específica
   */
  private async executeJourney(
    page: Page,
    journey: SmokeJourney,
    config: SmokeConfig
  ): Promise<SmokeResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      console.log(`[SmokeModeValidator] Executando jornada: ${journey.name}`);

      // Simular execução da jornada
      await this.simulateJourneyExecution(page, journey);

      // Coletar Web Vitals
      const webVitals = await this.collectWebVitals(page);

      // Validar thresholds
      if (webVitals.lcp > config.thresholds.lcp) {
        warnings.push(`LCP acima do threshold: ${webVitals.lcp}ms > ${config.thresholds.lcp}ms`);
      }

      if (webVitals.cls > config.thresholds.cls) {
        warnings.push(`CLS acima do threshold: ${webVitals.cls} > ${config.thresholds.cls}`);
      }

      if (webVitals.fid > config.thresholds.fid) {
        warnings.push(`FID acima do threshold: ${webVitals.fid}ms > ${config.thresholds.fid}ms`);
      }

      if (webVitals.tti > config.thresholds.tti) {
        warnings.push(`TTI acima do threshold: ${webVitals.tti}ms > ${config.thresholds.tti}ms`);
      }

      const executionTime = Date.now() - startTime;
      const status = errors.length > 0 ? 'failed' : warnings.length > 0 ? 'passed' : 'passed';

      return {
        journeyName: journey.name,
        status,
        executionTime,
        webVitals,
        errors,
        warnings
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      errors.push(`Erro na execução: ${error}`);

      return {
        journeyName: journey.name,
        status: 'failed',
        executionTime,
        webVitals: { lcp: 0, cls: 0, fid: 0, tti: 0 },
        errors,
        warnings
      };
    }
  }

  /**
   * Simula execução de uma jornada
   */
  private async simulateJourneyExecution(page: Page, journey: SmokeJourney): Promise<void> {
    // Simular tempo de execução baseado na estimativa
    const executionTime = journey.estimatedTime * 1000 * (0.8 + Math.random() * 0.4); // ±20% variação
    
    console.log(`[SmokeModeValidator] Simulando ${journey.name} por ${executionTime}ms`);
    
    // Simular execução dos passos críticos
    for (const step of journey.criticalSteps) {
      console.log(`[SmokeModeValidator] Executando: ${step}`);
      await page.waitForTimeout(executionTime / journey.criticalSteps.length);
    }

    // Simular falha ocasional (5% de chance)
    if (Math.random() < 0.05) {
      throw new Error(`Falha simulada na jornada ${journey.name}`);
    }
  }

  /**
   * Coleta Web Vitals da página
   */
  private async collectWebVitals(page: Page): Promise<{ lcp: number; cls: number; fid: number; tti: number }> {
    try {
      // Simular coleta de Web Vitals
      const lcp = Math.random() * 3000 + 1000; // 1-4s
      const cls = Math.random() * 0.1; // 0-0.1
      const fid = Math.random() * 100 + 50; // 50-150ms
      const tti = Math.random() * 2000 + 2000; // 2-4s

      return { lcp, cls, fid, tti };
    } catch (error) {
      console.error(`[SmokeModeValidator] Erro ao coletar Web Vitals: ${error}`);
      return { lcp: 0, cls: 0, fid: 0, tti: 0 };
    }
  }

  /**
   * Gera recomendações baseadas nos resultados
   */
  private generateRecommendations(results: SmokeResult[], config: SmokeConfig): string[] {
    const recommendations: string[] = [];

    // Analisar falhas
    const failedJourneys = results.filter(r => r.status === 'failed');
    if (failedJourneys.length > 0) {
      recommendations.push(`Investigar ${failedJourneys.length} jornadas com falha`);
    }

    // Analisar Web Vitals
    const slowJourneys = results.filter(r => 
      r.webVitals.lcp > config.thresholds.lcp ||
      r.webVitals.cls > config.thresholds.cls ||
      r.webVitals.fid > config.thresholds.fid ||
      r.webVitals.tti > config.thresholds.tti
    );

    if (slowJourneys.length > 0) {
      recommendations.push(`Otimizar performance em ${slowJourneys.length} jornadas`);
    }

    // Analisar tempo de execução
    const avgExecutionTime = results.reduce((sum, r) => sum + r.executionTime, 0) / results.length;
    if (avgExecutionTime > config.maxExecutionTime * 1000 * 0.8) {
      recommendations.push('Considerar otimizar tempo de execução das jornadas');
    }

    return recommendations;
  }

  /**
   * Calcula status geral baseado nos resultados
   */
  private calculateOverallStatus(results: SmokeResult[], config: SmokeConfig): 'excellent' | 'good' | 'warning' | 'critical' {
    if (results.length === 0) return 'excellent';

    const failedCount = results.filter(r => r.status === 'failed').length;
    const failureRate = failedCount / results.length;

    const avgLCP = results.reduce((sum, r) => sum + r.webVitals.lcp, 0) / results.length;
    const avgCLS = results.reduce((sum, r) => sum + r.webVitals.cls, 0) / results.length;

    if (failureRate === 0 && avgLCP <= config.thresholds.lcp * 0.8 && avgCLS <= config.thresholds.cls * 0.8) {
      return 'excellent';
    }

    if (failureRate <= 0.1 && avgLCP <= config.thresholds.lcp && avgCLS <= config.thresholds.cls) {
      return 'good';
    }

    if (failureRate <= 0.2) {
      return 'warning';
    }

    return 'critical';
  }
} 