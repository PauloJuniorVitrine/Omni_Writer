/**
 * Página de Monitoramento - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-012
 * Tracing ID: UI_IMPLEMENTATION_20250127_012
 * Data: 2025-01-27T23:50:00Z
 * 
 * Funcionalidades:
 * - Métricas Prometheus em tempo real
 * - Status de circuit breakers
 * - Performance analytics
 * - Sistema de alertas
 * - Dashboards interativos
 * - Análise de tendências
 */

import React, { useState, useEffect, useRef } from 'react';
import Card from '../components/base/Card';
import Button from '../components/base/Button';
import Input from '../components/base/Input';
import Select from '../components/base/Select';
import Modal from '../components/base/Modal';
import Toast from '../components/base/Toast';
import Loading from '../components/base/Loading';
import { useNavigation } from '../hooks/useNavigation';

// Componentes de dashboard
import PerformanceChart from '../components/dashboard/PerformanceChart';
import ServiceStatus from '../components/dashboard/ServiceStatus';
import MetricsCard from '../components/dashboard/MetricsCard';

interface PrometheusMetric {
  name: string;
  value: number;
  labels: Record<string, string>;
  timestamp: number;
}

interface CircuitBreakerStatus {
  name: string;
  state: 'closed' | 'open' | 'half_open';
  failureRate: number;
  healthScore: number;
  totalRequests: number;
  failedRequests: number;
  consecutiveFailures: number;
  lastStateChange: Date;
  alerts: Alert[];
}

interface Alert {
  id: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  message: string;
  timestamp: Date;
  acknowledged: boolean;
  resolved: boolean;
  source: string;
  labels: Record<string, string>;
}

interface PerformanceData {
  responseTime: number[];
  throughput: number[];
  errorRate: number[];
  labels: string[];
}

interface ServiceHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  responseTime: number;
  availability: number;
  lastCheck: Date;
  metrics: {
    requestsPerSecond: number;
    errorRate: number;
    avgResponseTime: number;
  };
}

interface MonitoringConfig {
  refreshInterval: number;
  alertThresholds: {
    errorRate: number;
    responseTime: number;
    availability: number;
  };
  enabledMetrics: string[];
  autoRefresh: boolean;
}

/**
 * Página principal de Monitoramento
 */
const Monitoring: React.FC = () => {
  const navigation = useNavigation();
  const [config, setConfig] = useState<MonitoringConfig>({
    refreshInterval: 30,
    alertThresholds: {
      errorRate: 5.0,
      responseTime: 2000,
      availability: 99.5
    },
    enabledMetrics: ['response_time', 'error_rate', 'throughput', 'availability'],
    autoRefresh: true
  });

  const [prometheusMetrics, setPrometheusMetrics] = useState<PrometheusMetric[]>([]);
  const [circuitBreakers, setCircuitBreakers] = useState<CircuitBreakerStatus[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [performanceData, setPerformanceData] = useState<PerformanceData>({
    responseTime: [],
    throughput: [],
    errorRate: [],
    labels: []
  });
  const [services, setServices] = useState<ServiceHealth[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showAlertsModal, setShowAlertsModal] = useState(false);
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [selectedMetric, setSelectedMetric] = useState('response_time');

  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Simula dados de métricas Prometheus
  useEffect(() => {
    setPrometheusMetrics([
      {
        name: 'omni_writer_requests_total',
        value: 1247,
        labels: { method: 'POST', endpoint: '/generate', status: '200' },
        timestamp: Date.now()
      },
      {
        name: 'omni_writer_request_duration_seconds',
        value: 1.2,
        labels: { method: 'POST', endpoint: '/generate' },
        timestamp: Date.now()
      },
      {
        name: 'omni_writer_errors_total',
        value: 23,
        labels: { error_type: 'api_error', endpoint: '/generate' },
        timestamp: Date.now()
      },
      {
        name: 'omni_writer_generations_total',
        value: 1189,
        labels: { model_type: 'openai', status: 'success' },
        timestamp: Date.now()
      }
    ]);
  }, []);

  // Simula dados de circuit breakers
  useEffect(() => {
    setCircuitBreakers([
      {
        name: 'ai_providers',
        state: 'closed',
        failureRate: 2.1,
        healthScore: 0.95,
        totalRequests: 1247,
        failedRequests: 26,
        consecutiveFailures: 0,
        lastStateChange: new Date(Date.now() - 3600000),
        alerts: []
      },
      {
        name: 'external_api',
        state: 'half_open',
        failureRate: 15.3,
        healthScore: 0.65,
        totalRequests: 89,
        failedRequests: 14,
        consecutiveFailures: 3,
        lastStateChange: new Date(Date.now() - 300000),
        alerts: [
          {
            id: 'alert_1',
            severity: 'warning',
            title: 'High Failure Rate',
            message: 'Failure rate above threshold (15.3% > 10%)',
            timestamp: new Date(Date.now() - 300000),
            acknowledged: false,
            resolved: false,
            source: 'circuit_breaker',
            labels: { circuit_breaker: 'external_api' }
          }
        ]
      },
      {
        name: 'database_connection',
        state: 'closed',
        failureRate: 0.5,
        healthScore: 0.98,
        totalRequests: 2156,
        failedRequests: 11,
        consecutiveFailures: 0,
        lastStateChange: new Date(Date.now() - 7200000),
        alerts: []
      }
    ]);
  }, []);

  // Simula dados de performance
  useEffect(() => {
    const now = new Date();
    const labels = [];
    const responseTime = [];
    const throughput = [];
    const errorRate = [];

    for (let i = 11; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 300000); // 5 minutos atrás
      labels.push(time.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }));
      
      // Simula dados realistas
      responseTime.push(Math.random() * 2000 + 500);
      throughput.push(Math.random() * 50 + 20);
      errorRate.push(Math.random() * 5);
    }

    setPerformanceData({
      responseTime,
      throughput,
      errorRate,
      labels
    });
  }, []);

  // Simula dados de serviços
  useEffect(() => {
    setServices([
      {
        name: 'API Gateway',
        status: 'healthy',
        responseTime: 45,
        availability: 99.9,
        lastCheck: new Date(),
        metrics: {
          requestsPerSecond: 12.5,
          errorRate: 0.1,
          avgResponseTime: 45
        }
      },
      {
        name: 'Article Generator',
        status: 'healthy',
        responseTime: 1200,
        availability: 99.7,
        lastCheck: new Date(),
        metrics: {
          requestsPerSecond: 8.2,
          errorRate: 2.1,
          avgResponseTime: 1200
        }
      },
      {
        name: 'Database',
        status: 'degraded',
        responseTime: 350,
        availability: 98.5,
        lastCheck: new Date(),
        metrics: {
          requestsPerSecond: 45.8,
          errorRate: 1.5,
          avgResponseTime: 350
        }
      },
      {
        name: 'Redis Cache',
        status: 'healthy',
        responseTime: 12,
        availability: 99.8,
        lastCheck: new Date(),
        metrics: {
          requestsPerSecond: 125.3,
          errorRate: 0.2,
          avgResponseTime: 12
        }
      }
    ]);
  }, []);

  // Simula alertas
  useEffect(() => {
    setAlerts([
      {
        id: 'alert_1',
        severity: 'warning',
        title: 'High Error Rate',
        message: 'Error rate for external API is above threshold (15.3% > 10%)',
        timestamp: new Date(Date.now() - 300000),
        acknowledged: false,
        resolved: false,
        source: 'circuit_breaker',
        labels: { service: 'external_api' }
      },
      {
        id: 'alert_2',
        severity: 'error',
        title: 'Service Degraded',
        message: 'Database response time is above normal (350ms > 200ms)',
        timestamp: new Date(Date.now() - 600000),
        acknowledged: true,
        resolved: false,
        source: 'performance',
        labels: { service: 'database' }
      },
      {
        id: 'alert_3',
        severity: 'info',
        title: 'High Throughput',
        message: 'Article generation throughput is high (8.2 req/s)',
        timestamp: new Date(Date.now() - 900000),
        acknowledged: false,
        resolved: true,
        source: 'performance',
        labels: { service: 'article_generator' }
      }
    ]);
  }, []);

  // Auto-refresh
  useEffect(() => {
    if (config.autoRefresh) {
      refreshIntervalRef.current = setInterval(() => {
        refreshMetrics();
      }, config.refreshInterval * 1000);
    }

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [config.autoRefresh, config.refreshInterval]);

  const refreshMetrics = async () => {
    setIsLoading(true);
    try {
      // Simula refresh das métricas
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Atualiza dados simulados
      const now = new Date();
      const newLabels = [];
      const newResponseTime = [];
      const newThroughput = [];
      const newErrorRate = [];

      for (let i = 11; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 300000);
        newLabels.push(time.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }));
        
        newResponseTime.push(Math.random() * 2000 + 500);
        newThroughput.push(Math.random() * 50 + 20);
        newErrorRate.push(Math.random() * 5);
      }

      setPerformanceData({
        responseTime: newResponseTime,
        throughput: newThroughput,
        errorRate: newErrorRate,
        labels: newLabels
      });

      setError(null);
    } catch (err) {
      setError('Erro ao atualizar métricas');
    } finally {
      setIsLoading(false);
    }
  };

  const acknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, acknowledged: true } : alert
    ));
  };

  const resolveAlert = (alertId: string) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, resolved: true } : alert
    ));
  };

  const getAlertSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'error': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'warning': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'info': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getAlertSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return '🚨';
      case 'error': return '❌';
      case 'warning': return '⚠️';
      case 'info': return 'ℹ️';
      default: return '📋';
    }
  };

  const getCircuitBreakerStateColor = (state: string) => {
    switch (state) {
      case 'closed': return 'text-green-600 bg-green-100';
      case 'open': return 'text-red-600 bg-red-100';
      case 'half_open': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getCircuitBreakerStateIcon = (state: string) => {
    switch (state) {
      case 'closed': return '🟢';
      case 'open': return '🔴';
      case 'half_open': return '🟡';
      default: return '⚪';
    }
  };

  const getSelectedMetricData = () => {
    switch (selectedMetric) {
      case 'response_time':
        return {
          labels: performanceData.labels,
          datasets: [{
            label: 'Tempo de Resposta (ms)',
            data: performanceData.responseTime,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)'
          }]
        };
      case 'throughput':
        return {
          labels: performanceData.labels,
          datasets: [{
            label: 'Throughput (req/s)',
            data: performanceData.throughput,
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)'
          }]
        };
      case 'error_rate':
        return {
          labels: performanceData.labels,
          datasets: [{
            label: 'Taxa de Erro (%)',
            data: performanceData.errorRate,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)'
          }]
        };
      default:
        return {
          labels: performanceData.labels,
          datasets: [{
            label: 'Tempo de Resposta (ms)',
            data: performanceData.responseTime,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)'
          }]
        };
    }
  };

  const exportMetrics = () => {
    const data = {
      timestamp: new Date().toISOString(),
      prometheusMetrics,
      circuitBreakers,
      performanceData,
      services,
      alerts
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `monitoring_metrics_${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeAlerts = alerts.filter(alert => !alert.resolved);
  const unacknowledgedAlerts = alerts.filter(alert => !alert.acknowledged && !alert.resolved);

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                Monitoramento
              </h1>
              <p className="text-gray-600">
                Métricas em tempo real, circuit breakers e alertas do sistema
              </p>
            </div>
            <div className="flex space-x-3">
              <Button
                variant="outline"
                onClick={refreshMetrics}
                disabled={isLoading}
              >
                {isLoading ? <Loading size="sm" /> : '🔄 Atualizar'}
              </Button>
              <Button
                variant="outline"
                onClick={() => setShowConfigModal(true)}
              >
                ⚙️ Configurar
              </Button>
              <Button
                variant="outline"
                onClick={exportMetrics}
              >
                📊 Exportar
              </Button>
            </div>
          </div>
        </div>

        {/* Alertas Críticos */}
        {unacknowledgedAlerts.length > 0 && (
          <div className="mb-6">
            <Card className="p-4 border-l-4 border-red-500 bg-red-50">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">🚨</span>
                  <div>
                    <h3 className="font-semibold text-red-900">
                      {unacknowledgedAlerts.length} Alerta(s) Não Reconhecido(s)
                    </h3>
                    <p className="text-red-700">
                      Ação requerida para {unacknowledgedAlerts.length} alerta(s)
                    </p>
                  </div>
                </div>
                <Button
                  variant="outline"
                  onClick={() => setShowAlertsModal(true)}
                  className="text-red-700 border-red-300 hover:bg-red-100"
                >
                  Ver Alertas
                </Button>
              </div>
            </Card>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Métricas Principais */}
          <div className="lg:col-span-2">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-semibold text-gray-900">Performance Analytics</h2>
                <div className="flex space-x-2">
                  <Select
                    value={selectedTimeRange}
                    onChange={(e) => setSelectedTimeRange(e.target.value)}
                    className="w-32"
                  >
                    <option value="15m">15 min</option>
                    <option value="1h">1 hora</option>
                    <option value="6h">6 horas</option>
                    <option value="24h">24 horas</option>
                  </Select>
                  <Select
                    value={selectedMetric}
                    onChange={(e) => setSelectedMetric(e.target.value)}
                    className="w-40"
                  >
                    <option value="response_time">Tempo de Resposta</option>
                    <option value="throughput">Throughput</option>
                    <option value="error_rate">Taxa de Erro</option>
                  </Select>
                </div>
              </div>

              <PerformanceChart
                data={getSelectedMetricData()}
                height={300}
              />
            </Card>

            {/* Circuit Breakers */}
            <Card className="p-6 mt-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-6">Circuit Breakers</h2>
              <div className="space-y-4">
                {circuitBreakers.map((cb, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <span className="text-lg">{getCircuitBreakerStateIcon(cb.state)}</span>
                        <h3 className="font-medium text-gray-900">{cb.name}</h3>
                        <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCircuitBreakerStateColor(cb.state)}`}>
                          {cb.state.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-600">Health Score</p>
                        <p className="text-lg font-bold text-gray-900">
                          {(cb.healthScore * 100).toFixed(1)}%
                        </p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-gray-600">Taxa de Falha</p>
                        <p className="font-medium">{cb.failureRate.toFixed(1)}%</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Total Requests</p>
                        <p className="font-medium">{cb.totalRequests}</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Falhas Consecutivas</p>
                        <p className="font-medium">{cb.consecutiveFailures}</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Última Mudança</p>
                        <p className="font-medium">
                          {cb.lastStateChange.toLocaleTimeString('pt-BR')}
                        </p>
                      </div>
                    </div>

                    {cb.alerts.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-gray-200">
                        <p className="text-sm text-gray-600 mb-2">Alertas Ativos:</p>
                        {cb.alerts.map((alert, alertIndex) => (
                          <div key={alertIndex} className="flex items-center space-x-2 text-sm">
                            <span>{getAlertSeverityIcon(alert.severity)}</span>
                            <span className="text-gray-700">{alert.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Métricas Rápidas */}
            <div className="grid grid-cols-1 gap-4">
              <MetricsCard
                title="Requests/min"
                value="745"
                change="+12.5%"
                trend="up"
                icon="📈"
              />
              <MetricsCard
                title="Error Rate"
                value="2.1%"
                change="-0.5%"
                trend="down"
                icon="📉"
              />
              <MetricsCard
                title="Avg Response"
                value="1.2s"
                change="+0.1s"
                trend="up"
                icon="⏱️"
              />
              <MetricsCard
                title="Active Alerts"
                value={activeAlerts.length.toString()}
                change={unacknowledgedAlerts.length > 0 ? `${unacknowledgedAlerts.length} unack` : "All clear"}
                trend={unacknowledgedAlerts.length > 0 ? "up" : "down"}
                icon="🚨"
              />
            </div>

            {/* Status dos Serviços */}
            <Card className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Status dos Serviços</h3>
              <ServiceStatus
                services={services.map(service => ({
                  name: service.name,
                  status: service.status === 'healthy' ? 'online' : 
                         service.status === 'degraded' ? 'warning' : 'offline',
                  responseTime: service.responseTime,
                  lastCheck: service.lastCheck
                }))}
              />
            </Card>

            {/* Métricas Prometheus */}
            <Card className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Métricas Prometheus</h3>
              <div className="space-y-3">
                {prometheusMetrics.map((metric, index) => (
                  <div key={index} className="flex justify-between items-center p-2 bg-gray-50 rounded">
                    <div>
                      <p className="text-sm font-medium text-gray-900">{metric.name}</p>
                      <p className="text-xs text-gray-500">
                        {Object.entries(metric.labels).map(([k, v]) => `${k}=${v}`).join(', ')}
                      </p>
                    </div>
                    <span className="text-sm font-bold text-gray-900">{metric.value}</span>
                  </div>
                ))}
              </div>
            </Card>

            {/* Alertas Recentes */}
            <Card className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Alertas Recentes</h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAlertsModal(true)}
                >
                  Ver Todos
                </Button>
              </div>
              <div className="space-y-3">
                {alerts.slice(0, 3).map((alert) => (
                  <div
                    key={alert.id}
                    className={`p-3 rounded-lg border ${getAlertSeverityColor(alert.severity)}`}
                  >
                    <div className="flex items-start space-x-2">
                      <span className="text-lg">{getAlertSeverityIcon(alert.severity)}</span>
                      <div className="flex-1">
                        <p className="text-sm font-medium">{alert.title}</p>
                        <p className="text-xs opacity-75">{alert.message}</p>
                        <p className="text-xs opacity-75 mt-1">
                          {alert.timestamp.toLocaleTimeString('pt-BR')}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        {/* Modal de Configuração */}
        <Modal
          isOpen={showConfigModal}
          onClose={() => setShowConfigModal(false)}
          title="Configurar Monitoramento"
          size="lg"
        >
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Intervalo de Atualização (segundos)
              </label>
              <Input
                type="number"
                value={config.refreshInterval}
                onChange={(e) => setConfig(prev => ({ ...prev, refreshInterval: parseInt(e.target.value) }))}
                min="5"
                max="300"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Thresholds de Alerta
              </label>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-gray-600 mb-1">Taxa de Erro (%)</label>
                  <Input
                    type="number"
                    value={config.alertThresholds.errorRate}
                    onChange={(e) => setConfig(prev => ({
                      ...prev,
                      alertThresholds: { ...prev.alertThresholds, errorRate: parseFloat(e.target.value) }
                    }))}
                    step="0.1"
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-600 mb-1">Tempo de Resposta (ms)</label>
                  <Input
                    type="number"
                    value={config.alertThresholds.responseTime}
                    onChange={(e) => setConfig(prev => ({
                      ...prev,
                      alertThresholds: { ...prev.alertThresholds, responseTime: parseInt(e.target.value) }
                    }))}
                  />
                </div>
                <div>
                  <label className="block text-xs text-gray-600 mb-1">Disponibilidade (%)</label>
                  <Input
                    type="number"
                    value={config.alertThresholds.availability}
                    onChange={(e) => setConfig(prev => ({
                      ...prev,
                      alertThresholds: { ...prev.alertThresholds, availability: parseFloat(e.target.value) }
                    }))}
                    step="0.1"
                  />
                </div>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Métricas Habilitadas
              </label>
              <div className="space-y-2">
                {['response_time', 'error_rate', 'throughput', 'availability'].map((metric) => (
                  <label key={metric} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={config.enabledMetrics.includes(metric)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setConfig(prev => ({
                            ...prev,
                            enabledMetrics: [...prev.enabledMetrics, metric]
                          }));
                        } else {
                          setConfig(prev => ({
                            ...prev,
                            enabledMetrics: prev.enabledMetrics.filter(m => m !== metric)
                          }));
                        }
                      }}
                      className="mr-2"
                    />
                    <span className="text-sm text-gray-700 capitalize">
                      {metric.replace('_', ' ')}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={config.autoRefresh}
                  onChange={(e) => setConfig(prev => ({ ...prev, autoRefresh: e.target.checked }))}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">Atualização Automática</span>
              </label>
            </div>

            <div className="flex justify-end space-x-3">
              <Button
                variant="outline"
                onClick={() => setShowConfigModal(false)}
              >
                Cancelar
              </Button>
              <Button
                onClick={() => setShowConfigModal(false)}
              >
                Salvar
              </Button>
            </div>
          </div>
        </Modal>

        {/* Modal de Alertas */}
        <Modal
          isOpen={showAlertsModal}
          onClose={() => setShowAlertsModal(false)}
          title="Sistema de Alertas"
          size="xl"
        >
          <div className="space-y-4">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 rounded-lg border ${getAlertSeverityColor(alert.severity)}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <span className="text-2xl">{getAlertSeverityIcon(alert.severity)}</span>
                    <div className="flex-1">
                      <h4 className="font-medium">{alert.title}</h4>
                      <p className="text-sm opacity-75 mt-1">{alert.message}</p>
                      <div className="flex items-center space-x-4 mt-2 text-xs opacity-75">
                        <span>Fonte: {alert.source}</span>
                        <span>{alert.timestamp.toLocaleString('pt-BR')}</span>
                        {Object.entries(alert.labels).map(([k, v]) => (
                          <span key={k}>{k}: {v}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    {!alert.acknowledged && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => acknowledgeAlert(alert.id)}
                      >
                        Reconhecer
                      </Button>
                    )}
                    {!alert.resolved && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => resolveAlert(alert.id)}
                      >
                        Resolver
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Modal>

        {/* Toast de Erro */}
        {error && (
          <Toast
            type="error"
            message={error}
            onClose={() => setError(null)}
          />
        )}
      </div>
    </div>
  );
};

export default Monitoring; 