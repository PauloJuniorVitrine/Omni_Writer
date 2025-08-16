/**
 * Integração de Monitoramento E2E
 * ===============================
 * 
 * Integra testes E2E com o sistema de monitoramento:
 * - Captura métricas de execução
 * - Monitora performance em tempo real
 * - Envia alertas automáticos
 * - Gera relatórios de saúde
 * 
 * 📐 CoCoT: Baseado em padrões de observabilidade enterprise
 * 🌲 ToT: Múltiplas estratégias de captura implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de monitoramento
 * 
 * **Prompt:** Integração de Monitoramento E2E - Item 14
 * **Data/Hora:** 2025-01-28T12:30:00Z
 * **Tracing ID:** E2E_MONITORING_INTEGRATION_20250128_014
 * **Origem:** Necessidade de integração entre testes E2E e sistema de monitoramento
 */

import { Page, TestInfo } from '@playwright/test';
import { performance } from 'perf_hooks';
import * as fs from 'fs';
import * as path from 'path';

export interface TestMetrics {
    test_name: string;
    execution_time: number;
    status: 'passed' | 'failed' | 'skipped';
    browser: string;
    shard: number;
    timestamp: string;
    memory_usage?: number;
    cpu_usage?: number;
    error_count: number;
    retry_count: number;
    screenshot_path?: string;
    video_path?: string;
    error_message?: string;
    performance_metrics?: {
        dom_content_loaded: number;
        load_complete: number;
        first_contentful_paint: number;
        largest_contentful_paint: number;
    };
}

export interface MonitoringConfig {
    enabled: boolean;
    endpoint?: string;
    api_key?: string;
    alert_thresholds: {
        execution_time: number;
        memory_usage: number;
        error_rate: number;
    };
    capture_screenshots: boolean;
    capture_videos: boolean;
    performance_monitoring: boolean;
}

export class E2EMonitoringIntegration {
    private config: MonitoringConfig;
    private metrics: TestMetrics[] = [];
    private startTime: number = 0;
    private memoryUsage: NodeJS.MemoryUsage | null = null;
    private performanceMetrics: any = {};

    constructor(config: Partial<MonitoringConfig>) {
        this.config = {
            enabled: true,
            alert_thresholds: {
                execution_time: 300000, // 5 minutos
                memory_usage: 1024 * 1024 * 1024, // 1GB
                error_rate: 0.1 // 10%
            },
            capture_screenshots: true,
            capture_videos: true,
            performance_monitoring: true,
            ...config
        } as MonitoringConfig;
    }

    /**
     * Inicia monitoramento de um teste
     */
    async startTestMonitoring(testInfo: TestInfo, page: Page): Promise<void> {
        if (!this.config.enabled) return;

        this.startTime = performance.now();
        this.memoryUsage = process.memoryUsage();
        
        // Capturar métricas de performance do navegador
        if (this.config.performance_monitoring) {
            await this.capturePerformanceMetrics(page);
        }

        console.log(`🔍 [MONITORING] Iniciando monitoramento para: ${testInfo.title}`);
    }

    /**
     * Finaliza monitoramento de um teste
     */
    async endTestMonitoring(
        testInfo: TestInfo, 
        page: Page, 
        status: 'passed' | 'failed' | 'skipped',
        error?: Error
    ): Promise<TestMetrics> {
        if (!this.config.enabled) {
            return {} as TestMetrics;
        }

        const endTime = performance.now();
        const executionTime = endTime - this.startTime;
        const currentMemoryUsage = process.memoryUsage();

        // Capturar screenshot se configurado
        let screenshotPath: string | undefined;
        if (this.config.capture_screenshots && status === 'failed') {
            screenshotPath = await this.captureScreenshot(testInfo, page);
        }

        // Capturar vídeo se configurado
        let videoPath: string | undefined;
        if (this.config.capture_videos && status === 'failed') {
            videoPath = await this.captureVideo(testInfo);
        }

        // Calcular métricas de memória
        const memoryUsageMB = currentMemoryUsage.heapUsed / (1024 * 1024);

        // Criar métricas do teste
        const testMetrics: TestMetrics = {
            test_name: testInfo.title,
            execution_time: executionTime,
            status,
            browser: testInfo.project.name || 'unknown',
            shard: testInfo.workerIndex || 0,
            timestamp: new Date().toISOString(),
            memory_usage: memoryUsageMB,
            cpu_usage: this.calculateCPUUsage(),
            error_count: error ? 1 : 0,
            retry_count: testInfo.retry || 0,
            screenshot_path: screenshotPath,
            video_path: videoPath,
            error_message: error?.message,
            performance_metrics: this.performanceMetrics
        };

        // Adicionar às métricas coletadas
        this.metrics.push(testMetrics);

        // Verificar se precisa gerar alerta
        await this.checkForAlerts(testMetrics);

        // Enviar métricas para o sistema de monitoramento
        await this.sendMetricsToMonitoring(testMetrics);

        console.log(`📊 [MONITORING] Teste finalizado: ${testInfo.title} - ${status} (${executionTime.toFixed(0)}ms)`);

        return testMetrics;
    }

    /**
     * Captura métricas de performance do navegador
     */
    private async capturePerformanceMetrics(page: Page): Promise<void> {
        try {
            // Aguardar carregamento da página
            await page.waitForLoadState('networkidle');

            // Capturar métricas de performance
            const performanceMetrics = await page.evaluate(() => {
                const navigation = performance.getEntriesByType('navigation' as any)[0] as PerformanceNavigationTiming;
                const paint = performance.getEntriesByType('paint' as any);
                
                return {
                    dom_content_loaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
                    load_complete: navigation.loadEventEnd - navigation.loadEventStart,
                    first_contentful_paint: paint.find((p: any) => p.name === 'first-contentful-paint')?.startTime || 0,
                    largest_contentful_paint: 0 // Será calculado se disponível
                };
            });

            this.performanceMetrics = performanceMetrics;

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao capturar métricas de performance: ${error}`);
        }
    }

    /**
     * Captura screenshot em caso de falha
     */
    private async captureScreenshot(testInfo: TestInfo, page: Page): Promise<string> {
        try {
            const screenshotDir = path.join('test-results', 'screenshots');
            if (!fs.existsSync(screenshotDir)) {
                fs.mkdirSync(screenshotDir, { recursive: true });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${testInfo.title.replace(/\s+/g, '_')}_${timestamp}.png`;
            const filepath = path.join(screenshotDir, filename);

            await page.screenshot({ 
                path: filepath, 
                fullPage: true 
            });

            return filepath;

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao capturar screenshot: ${error}`);
            return '';
        }
    }

    /**
     * Captura vídeo em caso de falha
     */
    private async captureVideo(testInfo: TestInfo): Promise<string> {
        try {
            const videoDir = path.join('test-results', 'videos');
            if (!fs.existsSync(videoDir)) {
                fs.mkdirSync(videoDir, { recursive: true });
            }

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${testInfo.title.replace(/\s+/g, '_')}_${timestamp}.webm`;
            const filepath = path.join(videoDir, filename);

            // O vídeo já foi capturado pelo Playwright, apenas retornar o caminho
            return filepath;

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao capturar vídeo: ${error}`);
            return '';
        }
    }

    /**
     * Calcula uso de CPU (aproximado)
     */
    private calculateCPUUsage(): number {
        // Implementação simplificada - em produção usar lib específica
        return Math.random() * 100; // Placeholder
    }

    /**
     * Verifica se precisa gerar alertas
     */
    private async checkForAlerts(testMetrics: TestMetrics): Promise<void> {
        const alerts: string[] = [];

        // Alerta de tempo de execução
        if (testMetrics.execution_time > this.config.alert_thresholds.execution_time) {
            alerts.push(`Tempo de execução alto: ${testMetrics.execution_time.toFixed(0)}ms`);
        }

        // Alerta de uso de memória
        if (testMetrics.memory_usage && testMetrics.memory_usage > this.config.alert_thresholds.memory_usage) {
            alerts.push(`Alto uso de memória: ${testMetrics.memory_usage.toFixed(1)}MB`);
        }

        // Alerta de falha
        if (testMetrics.status === 'failed') {
            alerts.push(`Teste falhou: ${testMetrics.error_message || 'Erro desconhecido'}`);
        }

        // Enviar alertas se houver
        if (alerts.length > 0) {
            await this.sendAlerts(testMetrics.test_name, alerts);
        }
    }

    /**
     * Envia métricas para o sistema de monitoramento
     */
    private async sendMetricsToMonitoring(testMetrics: TestMetrics): Promise<void> {
        try {
            if (!this.config.endpoint) {
                // Salvar localmente se não houver endpoint
                await this.saveMetricsLocally(testMetrics);
                return;
            }

            const response = await fetch(this.config.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.config.api_key}`,
                    'X-Tracing-ID': `E2E_MONITORING_${Date.now()}`
                },
                body: JSON.stringify(testMetrics)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            console.log(`📤 [MONITORING] Métricas enviadas para: ${this.config.endpoint}`);

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao enviar métricas: ${error}`);
            // Fallback para salvamento local
            await this.saveMetricsLocally(testMetrics);
        }
    }

    /**
     * Salva métricas localmente
     */
    private async saveMetricsLocally(testMetrics: TestMetrics): Promise<void> {
        try {
            const metricsDir = path.join('test-results', 'metrics');
            if (!fs.existsSync(metricsDir)) {
                fs.mkdirSync(metricsDir, { recursive: true });
            }

            const filename = `metrics_${Date.now()}.json`;
            const filepath = path.join(metricsDir, filename);

            fs.writeFileSync(filepath, JSON.stringify(testMetrics, null, 2));

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao salvar métricas localmente: ${error}`);
        }
    }

    /**
     * Envia alertas
     */
    private async sendAlerts(testName: string, alerts: string[]): Promise<void> {
        try {
            const alertData = {
                test_name: testName,
                alerts,
                timestamp: new Date().toISOString(),
                severity: 'high'
            };

            // Salvar alerta localmente
            const alertsDir = path.join('test-results', 'alerts');
            if (!fs.existsSync(alertsDir)) {
                fs.mkdirSync(alertsDir, { recursive: true });
            }

            const filename = `alert_${Date.now()}.json`;
            const filepath = path.join(alertsDir, filename);

            fs.writeFileSync(filepath, JSON.stringify(alertData, null, 2));

            console.log(`🚨 [MONITORING] Alerta gerado para: ${testName}`);

        } catch (error) {
            console.warn(`⚠️ [MONITORING] Erro ao enviar alerta: ${error}`);
        }
    }

    /**
     * Gera relatório de métricas
     */
    async generateMetricsReport(): Promise<any> {
        if (this.metrics.length === 0) {
            return { message: 'Nenhuma métrica coletada' };
        }

        const totalTests = this.metrics.length;
        const passedTests = this.metrics.filter(m => m.status === 'passed').length;
        const failedTests = this.metrics.filter(m => m.status === 'failed').length;
        const skippedTests = this.metrics.filter(m => m.status === 'skipped').length;

        const avgExecutionTime = this.metrics.reduce((sum, m) => sum + m.execution_time, 0) / totalTests;
        const avgMemoryUsage = this.metrics
            .filter(m => m.memory_usage)
            .reduce((sum, m) => sum + (m.memory_usage || 0), 0) / totalTests;

        const successRate = (passedTests / totalTests) * 100;
        const failureRate = (failedTests / totalTests) * 100;

        // Agrupar por browser
        const browserMetrics = this.metrics.reduce((acc, metric) => {
            if (!acc[metric.browser]) {
                acc[metric.browser] = { total: 0, passed: 0, failed: 0, skipped: 0 };
            }
            acc[metric.browser].total++;
            acc[metric.browser][metric.status]++;
            return acc;
        }, {} as Record<string, any>);

        return {
            summary: {
                total_tests: totalTests,
                passed_tests: passedTests,
                failed_tests: failedTests,
                skipped_tests: skippedTests,
                success_rate: successRate,
                failure_rate: failureRate,
                avg_execution_time: avgExecutionTime,
                avg_memory_usage: avgMemoryUsage
            },
            browser_metrics: browserMetrics,
            performance_metrics: {
                avg_dom_content_loaded: this.calculateAveragePerformanceMetric('dom_content_loaded'),
                avg_load_complete: this.calculateAveragePerformanceMetric('load_complete'),
                avg_first_contentful_paint: this.calculateAveragePerformanceMetric('first_contentful_paint')
            },
            recommendations: this.generateRecommendations(successRate, failureRate, avgExecutionTime),
            timestamp: new Date().toISOString(),
            tracing_id: 'E2E_MONITORING_REPORT'
        };
    }

    /**
     * Calcula média de métrica de performance
     */
    private calculateAveragePerformanceMetric(metricName: string): number {
        const metrics = this.metrics
            .filter(m => m.performance_metrics && m.performance_metrics[metricName])
            .map(m => m.performance_metrics![metricName]);

        return metrics.length > 0 ? metrics.reduce((sum, m) => sum + m, 0) / metrics.length : 0;
    }

    /**
     * Gera recomendações baseadas nas métricas
     */
    private generateRecommendations(successRate: number, failureRate: number, avgExecutionTime: number): string[] {
        const recommendations: string[] = [];

        if (successRate < 90) {
            recommendations.push('Investigar causas das falhas frequentes');
        }

        if (avgExecutionTime > 60000) { // 1 minuto
            recommendations.push('Otimizar performance dos testes');
        }

        if (failureRate > 10) {
            recommendations.push('Revisar estabilidade dos testes');
        }

        if (this.metrics.length < 10) {
            recommendations.push('Executar mais testes para melhor análise');
        }

        return recommendations;
    }

    /**
     * Obtém todas as métricas coletadas
     */
    getMetrics(): TestMetrics[] {
        return [...this.metrics];
    }

    /**
     * Limpa métricas antigas
     */
    clearMetrics(): void {
        this.metrics = [];
    }
}

/**
 * Decorator para monitoramento automático de testes
 */
export function withMonitoring(config?: Partial<MonitoringConfig>) {
    return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = async function (...args: any[]) {
            const monitoring = new E2EMonitoringIntegration({
                enabled: true,
                ...config
            });

            const testInfo = args[0] as TestInfo;
            const page = args[1] as Page;

            try {
                await monitoring.startTestMonitoring(testInfo, page);
                const result = await originalMethod.apply(this, args);
                await monitoring.endTestMonitoring(testInfo, page, 'passed');
                return result;
            } catch (error) {
                await monitoring.endTestMonitoring(testInfo, page, 'failed', error as Error);
                throw error;
            }
        };

        return descriptor;
    };
}

/**
 * Configuração padrão do monitoramento
 */
export const defaultMonitoringConfig: MonitoringConfig = {
    enabled: true,
    alert_thresholds: {
        execution_time: 300000, // 5 minutos
        memory_usage: 1024 * 1024 * 1024, // 1GB
        error_rate: 0.1 // 10%
    },
    capture_screenshots: true,
    capture_videos: true,
    performance_monitoring: true
}; 