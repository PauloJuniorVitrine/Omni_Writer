/**
 * Validador de Performance para Testes E2E
 * - Validação de métricas de performance
 * - Análise de resultados de carga
 * - Geração de relatórios de performance
 * 
 * 📐 CoCoT: Baseado em boas práticas de validação de performance
 * 🌲 ToT: Múltiplas estratégias de análise implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de performance
 *
 * **Prompt:** Interface Gráfica v3.5 Enterprise+ - TEST-001
 * **Data/Hora:** 2025-01-28T14:30:00Z
 * **Tracing ID:** PERFORMANCE_VALIDATOR_md1ppfhs
 * **Origem:** Necessidade de validação de performance em testes E2E
 */

export interface PerformanceMetrics {
  testName: string;
  timestamp: string;
  duration: number;
  concurrentUsers: number;
  avgResponseTime: number;
  maxResponseTime: number;
  minResponseTime: number;
  errorRate: number;
  throughput: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  memoryUsage?: number;
  cpuUsage?: number;
  networkLatency?: number;
}

export interface LoadTestConfig {
  baseUrl: string;
  concurrentUsers: number;
  rampUpTime: number;
  testDuration: number;
  thresholds: {
    responseTime: number;
    errorRate: number;
    throughput: number;
  };
  scenarios: {
    [key: string]: {
      weight: number;
      endpoint: string;
      method: string;
    };
  };
}

export interface PerformanceThresholds {
  responseTime: {
    warning: number;
    critical: number;
  };
  errorRate: {
    warning: number;
    critical: number;
  };
  throughput: {
    warning: number;
    critical: number;
  };
  memoryUsage: {
    warning: number;
    critical: number;
  };
  cpuUsage: {
    warning: number;
    critical: number;
  };
}

export class PerformanceValidator {
  private config: LoadTestConfig;
  private thresholds: PerformanceThresholds;
  private metrics: PerformanceMetrics[] = [];

  constructor(config: LoadTestConfig, thresholds?: PerformanceThresholds) {
    this.config = config;
    this.thresholds = thresholds || this.getDefaultThresholds();
  }

  /**
   * Valida métricas de performance
   */
  validateMetrics(metrics: PerformanceMetrics): {
    passed: boolean;
    warnings: string[];
    errors: string[];
    score: number;
  } {
    const warnings: string[] = [];
    const errors: string[] = [];
    let score = 100;

    // Validar tempo de resposta
    if (metrics.avgResponseTime > this.thresholds.responseTime.critical) {
      errors.push(`Tempo de resposta crítico: ${metrics.avgResponseTime}ms > ${this.thresholds.responseTime.critical}ms`);
      score -= 30;
    } else if (metrics.avgResponseTime > this.thresholds.responseTime.warning) {
      warnings.push(`Tempo de resposta alto: ${metrics.avgResponseTime}ms > ${this.thresholds.responseTime.warning}ms`);
      score -= 10;
    }

    // Validar taxa de erro
    if (metrics.errorRate > this.thresholds.errorRate.critical) {
      errors.push(`Taxa de erro crítica: ${metrics.errorRate}% > ${this.thresholds.errorRate.critical}%`);
      score -= 40;
    } else if (metrics.errorRate > this.thresholds.errorRate.warning) {
      warnings.push(`Taxa de erro alta: ${metrics.errorRate}% > ${this.thresholds.errorRate.warning}%`);
      score -= 15;
    }

    // Validar throughput
    if (metrics.throughput < this.thresholds.throughput.critical) {
      errors.push(`Throughput crítico: ${metrics.throughput} req/s < ${this.thresholds.throughput.critical} req/s`);
      score -= 25;
    } else if (metrics.throughput < this.thresholds.throughput.warning) {
      warnings.push(`Throughput baixo: ${metrics.throughput} req/s < ${this.thresholds.throughput.warning} req/s`);
      score -= 10;
    }

    // Validar uso de memória (se disponível)
    if (metrics.memoryUsage && metrics.memoryUsage > this.thresholds.memoryUsage.critical) {
      errors.push(`Uso de memória crítico: ${metrics.memoryUsage}MB > ${this.thresholds.memoryUsage.critical}MB`);
      score -= 20;
    } else if (metrics.memoryUsage && metrics.memoryUsage > this.thresholds.memoryUsage.warning) {
      warnings.push(`Uso de memória alto: ${metrics.memoryUsage}MB > ${this.thresholds.memoryUsage.warning}MB`);
      score -= 5;
    }

    // Validar uso de CPU (se disponível)
    if (metrics.cpuUsage && metrics.cpuUsage > this.thresholds.cpuUsage.critical) {
      errors.push(`Uso de CPU crítico: ${metrics.cpuUsage}% > ${this.thresholds.cpuUsage.critical}%`);
      score -= 20;
    } else if (metrics.cpuUsage && metrics.cpuUsage > this.thresholds.cpuUsage.warning) {
      warnings.push(`Uso de CPU alto: ${metrics.cpuUsage}% > ${this.thresholds.cpuUsage.warning}%`);
      score -= 5;
    }

    // Garantir score mínimo
    score = Math.max(0, score);

    return {
      passed: errors.length === 0,
      warnings,
      errors,
      score
    };
  }

  /**
   * Analisa tendências de performance
   */
  analyzeTrends(metrics: PerformanceMetrics[]): {
    trend: 'improving' | 'stable' | 'degrading';
    confidence: number;
    recommendations: string[];
  } {
    if (metrics.length < 3) {
      return {
        trend: 'stable',
        confidence: 0.5,
        recommendations: ['Dados insuficientes para análise de tendência']
      };
    }

    // Calcular tendência baseada nos últimos 3 testes
    const recentMetrics = metrics.slice(-3);
    const responseTimeTrend = this.calculateTrend(
      recentMetrics.map(m => m.avgResponseTime)
    );
    const errorRateTrend = this.calculateTrend(
      recentMetrics.map(m => m.errorRate)
    );
    const throughputTrend = this.calculateTrend(
      recentMetrics.map(m => m.throughput)
    );

    // Determinar tendência geral
    let improvingCount = 0;
    let degradingCount = 0;

    if (responseTimeTrend < -0.1) improvingCount++;
    else if (responseTimeTrend > 0.1) degradingCount++;

    if (errorRateTrend < -0.1) improvingCount++;
    else if (errorRateTrend > 0.1) degradingCount++;

    if (throughputTrend > 0.1) improvingCount++;
    else if (throughputTrend < -0.1) degradingCount++;

    let trend: 'improving' | 'stable' | 'degrading';
    let confidence: number;

    if (improvingCount >= 2) {
      trend = 'improving';
      confidence = 0.8;
    } else if (degradingCount >= 2) {
      trend = 'degrading';
      confidence = 0.8;
    } else {
      trend = 'stable';
      confidence = 0.6;
    }

    // Gerar recomendações
    const recommendations = this.generateTrendRecommendations(
      responseTimeTrend,
      errorRateTrend,
      throughputTrend
    );

    return { trend, confidence, recommendations };
  }

  /**
   * Gera relatório de performance
   */
  generateReport(metrics: PerformanceMetrics[]): {
    summary: {
      totalTests: number;
      passedTests: number;
      failedTests: number;
      averageScore: number;
      overallTrend: string;
    };
    details: {
      testName: string;
      validation: any;
      trend: any;
    }[];
    recommendations: string[];
  } {
    const validations = metrics.map(m => this.validateMetrics(m));
    const trends = metrics.map(m => this.analyzeTrends([m]));

    const passedTests = validations.filter(v => v.passed).length;
    const averageScore = validations.reduce((sum, v) => sum + v.score, 0) / validations.length;
    const overallTrend = this.analyzeTrends(metrics);

    const details = metrics.map((metric, index) => ({
      testName: metric.testName,
      validation: validations[index],
      trend: trends[index]
    }));

    const recommendations = this.generateOverallRecommendations(validations, overallTrend);

    return {
      summary: {
        totalTests: metrics.length,
        passedTests,
        failedTests: metrics.length - passedTests,
        averageScore,
        overallTrend: overallTrend.trend
      },
      details,
      recommendations
    };
  }

  /**
   * Monitora performance em tempo real
   */
  async monitorPerformance(
    duration: number,
    interval: number = 1000
  ): Promise<PerformanceMetrics[]> {
    const metrics: PerformanceMetrics[] = [];
    const startTime = Date.now();
    const endTime = startTime + duration;

    while (Date.now() < endTime) {
      const metric = await this.collectCurrentMetrics();
      metrics.push(metric);
      
      await new Promise(resolve => setTimeout(resolve, interval));
    }

    return metrics;
  }

  /**
   * Coleta métricas atuais do sistema
   */
  private async collectCurrentMetrics(): Promise<PerformanceMetrics> {
    // Implementação básica - pode ser expandida
    return {
      testName: 'Real-time Monitoring',
      timestamp: new Date().toISOString(),
      duration: 0,
      concurrentUsers: 0,
      avgResponseTime: 0,
      maxResponseTime: 0,
      minResponseTime: 0,
      errorRate: 0,
      throughput: 0,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0
    };
  }

  /**
   * Calcula tendência de uma série de valores
   */
  private calculateTrend(values: number[]): number {
    if (values.length < 2) return 0;

    const n = values.length;
    const sumX = (n * (n - 1)) / 2;
    const sumY = values.reduce((sum, val) => sum + val, 0);
    const sumXY = values.reduce((sum, val, index) => sum + (index * val), 0);
    const sumX2 = values.reduce((sum, _, index) => sum + (index * index), 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope;
  }

  /**
   * Gera recomendações baseadas em tendências
   */
  private generateTrendRecommendations(
    responseTimeTrend: number,
    errorRateTrend: number,
    throughputTrend: number
  ): string[] {
    const recommendations: string[] = [];

    if (responseTimeTrend > 0.1) {
      recommendations.push('📈 Tempo de resposta aumentando - investigue gargalos');
    }

    if (errorRateTrend > 0.1) {
      recommendations.push('📈 Taxa de erro aumentando - verifique logs de erro');
    }

    if (throughputTrend < -0.1) {
      recommendations.push('📉 Throughput diminuindo - considere otimizações');
    }

    if (responseTimeTrend < -0.1 && errorRateTrend < -0.1 && throughputTrend > 0.1) {
      recommendations.push('✅ Performance melhorando - mantenha as otimizações');
    }

    return recommendations;
  }

  /**
   * Gera recomendações gerais
   */
  private generateOverallRecommendations(
    validations: any[],
    overallTrend: any
  ): string[] {
    const recommendations: string[] = [];

    const criticalIssues = validations.filter(v => v.errors.length > 0).length;
    const warnings = validations.filter(v => v.warnings.length > 0).length;

    if (criticalIssues > 0) {
      recommendations.push(`🚨 ${criticalIssues} testes com problemas críticos - ação imediata necessária`);
    }

    if (warnings > 0) {
      recommendations.push(`⚠️ ${warnings} testes com avisos - monitoramento recomendado`);
    }

    if (overallTrend.trend === 'degrading') {
      recommendations.push('📉 Tendência de degradação detectada - investigação urgente');
    }

    if (overallTrend.trend === 'improving') {
      recommendations.push('📈 Tendência de melhoria detectada - mantenha as otimizações');
    }

    return recommendations;
  }

  /**
   * Retorna thresholds padrão
   */
  private getDefaultThresholds(): PerformanceThresholds {
    return {
      responseTime: {
        warning: 2000,
        critical: 5000
      },
      errorRate: {
        warning: 2,
        critical: 5
      },
      throughput: {
        warning: 5,
        critical: 2
      },
      memoryUsage: {
        warning: 512,
        critical: 1024
      },
      cpuUsage: {
        warning: 70,
        critical: 90
      }
    };
  }
}

/**
 * Utilitários de performance
 */
export class PerformanceUtils {
  /**
   * Calcula percentil de uma série de valores
   */
  static calculatePercentile(values: number[], percentile: number): number {
    const sorted = values.sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[index] || 0;
  }

  /**
   * Formata tempo em formato legível
   */
  static formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  }

  /**
   * Calcula taxa de sucesso
   */
  static calculateSuccessRate(successful: number, total: number): number {
    return total > 0 ? (successful / total) * 100 : 0;
  }

  /**
   * Valida se métricas estão dentro dos limites aceitáveis
   */
  static validateThresholds(
    metrics: PerformanceMetrics,
    thresholds: PerformanceThresholds
  ): boolean {
    return (
      metrics.avgResponseTime <= thresholds.responseTime.critical &&
      metrics.errorRate <= thresholds.errorRate.critical &&
      metrics.throughput >= thresholds.throughput.critical
    );
  }
} 