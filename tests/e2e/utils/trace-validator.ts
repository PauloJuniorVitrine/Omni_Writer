/**
 * Sistema de Traces para Debugging de Testes E2E
 * - Captura informações detalhadas durante execução
 * - Rastreia operações, erros e performance
 * - Gera relatórios estruturados para análise
 * 
 * 📐 CoCoT: Baseado em boas práticas de observabilidade e debugging
 * 🌲 ToT: Múltiplas estratégias de rastreamento implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de debugging
 */

import { Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

export interface TraceEvent {
  id: string;
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';
  category: 'NAVIGATION' | 'INTERACTION' | 'VALIDATION' | 'PERFORMANCE' | 'ERROR' | 'CUSTOM';
  message: string;
  details?: any;
  duration?: number;
  screenshot?: string;
  html?: string;
  console?: string[];
  network?: NetworkEvent[];
  errors?: ErrorEvent[];
}

export interface NetworkEvent {
  method: string;
  url: string;
  status: number;
  duration: number;
  timestamp: string;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: any;
  responseBody?: any;
}

export interface ErrorEvent {
  type: string;
  message: string;
  stack?: string;
  timestamp: string;
  context?: any;
}

export interface PerformanceMetrics {
  pageLoadTime: number;
  domContentLoaded: number;
  firstContentfulPaint: number;
  largestContentfulPaint: number;
  cumulativeLayoutShift: number;
  firstInputDelay: number;
}

export interface TraceReport {
  testId: string;
  testName: string;
  startTime: string;
  endTime: string;
  duration: number;
  events: TraceEvent[];
  performance: PerformanceMetrics;
  summary: {
    totalEvents: number;
    errors: number;
    warnings: number;
    screenshots: number;
    networkRequests: number;
  };
  recommendations: string[];
}

export class TraceValidator {
  private page: Page;
  private events: TraceEvent[] = [];
  private networkEvents: NetworkEvent[] = [];
  private errorEvents: ErrorEvent[] = [];
  private consoleLogs: string[] = [];
  private startTime: number;
  private testId: string;
  private testName: string;
  private screenshotDir: string;
  private reportDir: string;

  constructor(page: Page, testName: string) {
    this.page = page;
    this.testName = testName;
    this.testId = `${testName}_${Date.now()}`;
    this.startTime = Date.now();
    this.screenshotDir = `test-results/traces/${this.testId}/screenshots`;
    this.reportDir = `test-results/traces/${this.testId}`;
    
    this.setupEventListeners();
    this.createDirectories();
  }

  /**
   * Configura listeners para capturar eventos automaticamente
   */
  private setupEventListeners(): void {
    // Console logs
    this.page.on('console', msg => {
      this.consoleLogs.push(`[${msg.type()}] ${msg.text()}`);
      this.addEvent('DEBUG', 'CUSTOM', `Console: ${msg.type()} - ${msg.text()}`, {
        type: msg.type(),
        text: msg.text(),
        location: msg.location()
      });
    });

    // Network requests
    this.page.on('request', request => {
      const networkEvent: NetworkEvent = {
        method: request.method(),
        url: request.url(),
        status: 0,
        duration: 0,
        timestamp: new Date().toISOString(),
        requestHeaders: request.headers(),
        requestBody: request.postData()
      };
      this.networkEvents.push(networkEvent);
    });

    this.page.on('response', response => {
      const request = response.request();
      const networkEvent = this.networkEvents.find(e => e.url === request.url());
      if (networkEvent) {
        networkEvent.status = response.status();
        networkEvent.responseHeaders = response.headers();
        networkEvent.duration = Date.now() - new Date(networkEvent.timestamp).getTime();
      }
    });

    // Page errors
    this.page.on('pageerror', error => {
      this.errorEvents.push({
        type: 'PageError',
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
      this.addEvent('ERROR', 'ERROR', `Page Error: ${error.message}`, {
        stack: error.stack
      });
    });

    // Request failures
    this.page.on('requestfailed', request => {
      this.errorEvents.push({
        type: 'RequestFailed',
        message: `Request failed: ${request.method()} ${request.url()}`,
        timestamp: new Date().toISOString(),
        context: {
          method: request.method(),
          url: request.url(),
          failure: request.failure()
        }
      });
      this.addEvent('ERROR', 'ERROR', `Request failed: ${request.method()} ${request.url()}`, {
        failure: request.failure()
      });
    });
  }

  /**
   * Cria diretórios necessários
   */
  private createDirectories(): void {
    const dirs = [this.screenshotDir, this.reportDir];
    for (const dir of dirs) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
  }

  /**
   * Adiciona evento ao trace
   */
  addEvent(
    level: TraceEvent['level'],
    category: TraceEvent['category'],
    message: string,
    details?: any,
    takeScreenshot: boolean = false
  ): void {
    const event: TraceEvent = {
      id: `${this.testId}_${this.events.length}`,
      timestamp: new Date().toISOString(),
      level,
      category,
      message,
      details,
      console: [...this.consoleLogs],
      network: [...this.networkEvents],
      errors: [...this.errorEvents]
    };

    if (takeScreenshot) {
      const screenshotPath = `${this.screenshotDir}/event_${this.events.length}.png`;
      this.page.screenshot({ path: screenshotPath, fullPage: true }).catch(() => {
        // Ignora erros de screenshot
      });
      event.screenshot = screenshotPath;
    }

    this.events.push(event);
    console.log(`[TRACE] [${level}] [${category}] ${message}`);
  }

  /**
   * Captura métricas de performance
   */
  async capturePerformanceMetrics(): Promise<PerformanceMetrics> {
    try {
      const metrics = await this.page.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
        const paint = performance.getEntriesByType('paint');
        
        return {
          pageLoadTime: navigation.loadEventEnd - navigation.loadEventStart,
          domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
          firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
          largestContentfulPaint: 0, // Será calculado via observer
          cumulativeLayoutShift: 0, // Será calculado via observer
          firstInputDelay: 0 // Será calculado via observer
        };
      });

      return metrics;
    } catch (error) {
      console.warn('Erro ao capturar métricas de performance:', error);
      return {
        pageLoadTime: 0,
        domContentLoaded: 0,
        firstContentfulPaint: 0,
        largestContentfulPaint: 0,
        cumulativeLayoutShift: 0,
        firstInputDelay: 0
      };
    }
  }

  /**
   * Captura HTML da página atual
   */
  async captureHTML(): Promise<string> {
    try {
      return await this.page.content();
    } catch (error) {
      console.warn('Erro ao capturar HTML:', error);
      return '';
    }
  }

  /**
   * Adiciona evento de navegação
   */
  async traceNavigation(url: string, description: string): Promise<void> {
    const startTime = Date.now();
    
    try {
      await this.page.goto(url);
      const duration = Date.now() - startTime;
      
      this.addEvent('INFO', 'NAVIGATION', `Navegação: ${description}`, {
        url,
        duration,
        status: 'success'
      }, true);
    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.addEvent('ERROR', 'NAVIGATION', `Falha na navegação: ${description}`, {
        url,
        duration,
        error: error.message
      }, true);
    }
  }

  /**
   * Adiciona evento de interação
   */
  async traceInteraction(
    action: string,
    selector: string,
    description: string,
    takeScreenshot: boolean = true
  ): Promise<void> {
    const startTime = Date.now();
    
    try {
      switch (action) {
        case 'click':
          await this.page.click(selector);
          break;
        case 'fill':
          await this.page.fill(selector, description);
          break;
        case 'select':
          await this.page.selectOption(selector, description);
          break;
        case 'wait':
          await this.page.waitForSelector(selector);
          break;
        default:
          throw new Error(`Ação não suportada: ${action}`);
      }
      
      const duration = Date.now() - startTime;
      
      this.addEvent('INFO', 'INTERACTION', `Interação: ${action} ${selector}`, {
        action,
        selector,
        description,
        duration,
        status: 'success'
      }, takeScreenshot);
    } catch (error) {
      const duration = Date.now() - startTime;
      
      this.addEvent('ERROR', 'INTERACTION', `Falha na interação: ${action} ${selector}`, {
        action,
        selector,
        description,
        duration,
        error: error.message
      }, takeScreenshot);
    }
  }

  /**
   * Adiciona evento de validação
   */
  traceValidation(
    validation: string,
    expected: any,
    actual: any,
    success: boolean
  ): void {
    this.addEvent(
      success ? 'INFO' : 'ERROR',
      'VALIDATION',
      `Validação: ${validation}`,
      {
        expected,
        actual,
        success,
        diff: success ? undefined : this.generateDiff(expected, actual)
      }
    );
  }

  /**
   * Adiciona evento de performance
   */
  tracePerformance(metric: string, value: number, threshold?: number): void {
    const level = threshold && value > threshold ? 'WARN' : 'INFO';
    
    this.addEvent(level, 'PERFORMANCE', `Performance: ${metric} = ${value}ms`, {
      metric,
      value,
      threshold,
      withinThreshold: threshold ? value <= threshold : true
    });
  }

  /**
   * Gera diff entre valores esperado e atual
   */
  private generateDiff(expected: any, actual: any): string {
    try {
      return JSON.stringify({
        expected,
        actual,
        differences: this.findDifferences(expected, actual)
      }, null, 2);
    } catch (error) {
      return `Erro ao gerar diff: ${error.message}`;
    }
  }

  /**
   * Encontra diferenças entre objetos
   */
  private findDifferences(expected: any, actual: any, path: string = ''): any[] {
    const differences: any[] = [];
    
    if (typeof expected !== typeof actual) {
      differences.push({
        path,
        expected: typeof expected,
        actual: typeof actual,
        message: 'Tipos diferentes'
      });
      return differences;
    }
    
    if (typeof expected === 'object' && expected !== null) {
      const expectedKeys = Object.keys(expected);
      const actualKeys = Object.keys(actual);
      
      // Chaves que existem apenas em expected
      for (const key of expectedKeys) {
        if (!actualKeys.includes(key)) {
          differences.push({
            path: path ? `${path}.${key}` : key,
            expected: expected[key],
            actual: undefined,
            message: 'Chave ausente em actual'
          });
        }
      }
      
      // Chaves que existem apenas em actual
      for (const key of actualKeys) {
        if (!expectedKeys.includes(key)) {
          differences.push({
            path: path ? `${path}.${key}` : key,
            expected: undefined,
            actual: actual[key],
            message: 'Chave extra em actual'
          });
        }
      }
      
      // Compara valores das chaves comuns
      for (const key of expectedKeys) {
        if (actualKeys.includes(key)) {
          const newPath = path ? `${path}.${key}` : key;
          const nestedDifferences = this.findDifferences(expected[key], actual[key], newPath);
          differences.push(...nestedDifferences);
        }
      }
    } else if (expected !== actual) {
      differences.push({
        path,
        expected,
        actual,
        message: 'Valores diferentes'
      });
    }
    
    return differences;
  }

  /**
   * Gera relatório final do trace
   */
  async generateTraceReport(): Promise<TraceReport> {
    const endTime = Date.now();
    const duration = endTime - this.startTime;
    const performance = await this.capturePerformanceMetrics();
    
    const summary = {
      totalEvents: this.events.length,
      errors: this.events.filter(e => e.level === 'ERROR').length,
      warnings: this.events.filter(e => e.level === 'WARN').length,
      screenshots: this.events.filter(e => e.screenshot).length,
      networkRequests: this.networkEvents.length
    };

    const recommendations = this.generateRecommendations(summary, performance);

    const report: TraceReport = {
      testId: this.testId,
      testName: this.testName,
      startTime: new Date(this.startTime).toISOString(),
      endTime: new Date(endTime).toISOString(),
      duration,
      events: this.events,
      performance,
      summary,
      recommendations
    };

    // Salva relatório em arquivo
    const reportPath = `${this.reportDir}/trace-report.json`;
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    // Salva HTML da página final
    const finalHTML = await this.captureHTML();
    const htmlPath = `${this.reportDir}/final-page.html`;
    fs.writeFileSync(htmlPath, finalHTML);

    console.log(`📊 Relatório de trace salvo em: ${reportPath}`);
    return report;
  }

  /**
   * Gera recomendações baseadas no trace
   */
  private generateRecommendations(summary: any, performance: PerformanceMetrics): string[] {
    const recommendations: string[] = [];

    if (summary.errors > 0) {
      recommendations.push(`Investigar ${summary.errors} erros encontrados durante o teste`);
    }

    if (summary.warnings > 0) {
      recommendations.push(`Revisar ${summary.warnings} warnings para otimização`);
    }

    if (performance.pageLoadTime > 5000) {
      recommendations.push('Tempo de carregamento da página alto (>5s) - otimizar performance');
    }

    if (performance.firstContentfulPaint > 2000) {
      recommendations.push('First Contentful Paint alto (>2s) - otimizar renderização');
    }

    if (summary.networkRequests > 50) {
      recommendations.push('Muitas requisições de rede - considerar otimização');
    }

    if (summary.screenshots === 0) {
      recommendations.push('Nenhum screenshot capturado - habilitar captura para debugging');
    }

    return recommendations;
  }

  /**
   * Limpa dados do trace
   */
  clear(): void {
    this.events = [];
    this.networkEvents = [];
    this.errorEvents = [];
    this.consoleLogs = [];
  }
} 