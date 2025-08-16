/**
 * Página de Métricas de Qualidade - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - COV-001, COV-002, COV-003
 * Data/Hora: 2025-01-28T02:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_005
 * 
 * Funcionalidades:
 * - Cobertura mínima 85%
 * - Testes de regressão
 * - Testes de performance
 */

import React, { useState, useEffect } from 'react';
import { useI18n } from '../hooks/use_i18n';
import { useTheme } from '../hooks/use_theme';
import { Card } from '../components/base/Card';
import { Button } from '../components/base/Button';
import { Select } from '../components/base/Select';
import { Modal } from '../components/base/Modal';
import { Toast } from '../components/base/Toast';
import { Loading } from '../components/base/Loading';
import { DataTable } from '../components/DataTable';
import { Charts } from '../components/Charts';

// ===== TIPOS =====

interface CoverageMetrics {
  total: number;
  covered: number;
  uncovered: number;
  percentage: number;
  threshold: number;
  status: 'pass' | 'fail' | 'warning';
  details: {
    statements: { total: number; covered: number; percentage: number };
    branches: { total: number; covered: number; percentage: number };
    functions: { total: number; covered: number; percentage: number };
    lines: { total: number; covered: number; percentage: number };
  };
}

interface RegressionTest {
  id: string;
  name: string;
  category: 'unit' | 'integration' | 'e2e' | 'visual';
  status: 'pass' | 'fail' | 'running' | 'pending';
  duration: number;
  lastRun: Date;
  failureRate: number;
  flakiness: number;
  critical: boolean;
  description: string;
  errorMessage?: string;
}

interface PerformanceTest {
  id: string;
  name: string;
  type: 'load' | 'stress' | 'spike' | 'endurance';
  status: 'pass' | 'fail' | 'running' | 'pending';
  metrics: {
    responseTime: { avg: number; p95: number; p99: number };
    throughput: { rps: number; total: number };
    errorRate: number;
    cpuUsage: number;
    memoryUsage: number;
  };
  threshold: {
    maxResponseTime: number;
    maxErrorRate: number;
    minThroughput: number;
  };
  lastRun: Date;
  duration: number;
  users: number;
}

interface QualityReport {
  id: string;
  timestamp: Date;
  coverage: CoverageMetrics;
  regressionTests: RegressionTest[];
  performanceTests: PerformanceTest[];
  overallScore: number;
  status: 'excellent' | 'good' | 'warning' | 'critical';
  recommendations: string[];
}

// ===== DADOS MOCK =====

const mockCoverage: CoverageMetrics = {
  total: 1250,
  covered: 1187,
  uncovered: 63,
  percentage: 95.0,
  threshold: 85,
  status: 'pass',
  details: {
    statements: { total: 1250, covered: 1187, percentage: 95.0 },
    branches: { total: 450, covered: 420, percentage: 93.3 },
    functions: { total: 180, covered: 175, percentage: 97.2 },
    lines: { total: 1200, covered: 1150, percentage: 95.8 }
  }
};

const mockRegressionTests: RegressionTest[] = [
  {
    id: 'reg-001',
    name: 'Teste de Autenticação',
    category: 'unit',
    status: 'pass',
    duration: 0.5,
    lastRun: new Date('2025-01-28T01:30:00Z'),
    failureRate: 0.0,
    flakiness: 0.0,
    critical: true,
    description: 'Testa fluxo completo de autenticação'
  },
  {
    id: 'reg-002',
    name: 'Teste de Geração de Artigos',
    category: 'integration',
    status: 'pass',
    duration: 2.3,
    lastRun: new Date('2025-01-28T01:25:00Z'),
    failureRate: 0.0,
    flakiness: 0.0,
    critical: true,
    description: 'Testa integração com APIs de geração'
  },
  {
    id: 'reg-003',
    name: 'Teste de Interface Responsiva',
    category: 'visual',
    status: 'fail',
    duration: 1.8,
    lastRun: new Date('2025-01-28T01:20:00Z'),
    failureRate: 15.0,
    flakiness: 8.0,
    critical: false,
    description: 'Testa responsividade em diferentes dispositivos',
    errorMessage: 'Diferença de 5px detectada em mobile'
  },
  {
    id: 'reg-004',
    name: 'Teste de Performance de Carregamento',
    category: 'e2e',
    status: 'running',
    duration: 0,
    lastRun: new Date('2025-01-28T01:35:00Z'),
    failureRate: 0.0,
    flakiness: 0.0,
    critical: true,
    description: 'Testa tempo de carregamento da aplicação'
  }
];

const mockPerformanceTests: PerformanceTest[] = [
  {
    id: 'perf-001',
    name: 'Teste de Carga - 100 Usuários',
    type: 'load',
    status: 'pass',
    metrics: {
      responseTime: { avg: 250, p95: 450, p99: 800 },
      throughput: { rps: 45, total: 4500 },
      errorRate: 0.2,
      cpuUsage: 65,
      memoryUsage: 512
    },
    threshold: {
      maxResponseTime: 1000,
      maxErrorRate: 1.0,
      minThroughput: 40
    },
    lastRun: new Date('2025-01-28T01:00:00Z'),
    duration: 300,
    users: 100
  },
  {
    id: 'perf-002',
    name: 'Teste de Stress - 500 Usuários',
    type: 'stress',
    status: 'fail',
    metrics: {
      responseTime: { avg: 1200, p95: 2500, p99: 5000 },
      throughput: { rps: 35, total: 3500 },
      errorRate: 5.2,
      cpuUsage: 95,
      memoryUsage: 1024
    },
    threshold: {
      maxResponseTime: 2000,
      maxErrorRate: 2.0,
      minThroughput: 30
    },
    lastRun: new Date('2025-01-28T00:30:00Z'),
    duration: 600,
    users: 500
  },
  {
    id: 'perf-003',
    name: 'Teste de Spike - 1000 Usuários',
    type: 'spike',
    status: 'running',
    metrics: {
      responseTime: { avg: 0, p95: 0, p99: 0 },
      throughput: { rps: 0, total: 0 },
      errorRate: 0,
      cpuUsage: 0,
      memoryUsage: 0
    },
    threshold: {
      maxResponseTime: 3000,
      maxErrorRate: 5.0,
      minThroughput: 20
    },
    lastRun: new Date('2025-01-28T01:40:00Z'),
    duration: 0,
    users: 1000
  }
];

// ===== COMPONENTE PRINCIPAL =====

export const QualityMetrics: React.FC = () => {
  const { t } = useI18n();
  const { colors } = useTheme();
  const [activeTab, setActiveTab] = useState<'coverage' | 'regression' | 'performance'>('coverage');
  const [coverage, setCoverage] = useState<CoverageMetrics>(mockCoverage);
  const [regressionTests, setRegressionTests] = useState<RegressionTest[]>(mockRegressionTests);
  const [performanceTests, setPerformanceTests] = useState<PerformanceTest[]>(mockPerformanceTests);
  const [loading, setLoading] = useState(false);
  const [showRunTestsModal, setShowRunTestsModal] = useState(false);
  const [selectedTestType, setSelectedTestType] = useState<'regression' | 'performance'>('regression');
  const [testConfig, setTestConfig] = useState({
    category: 'all',
    users: 100,
    duration: 300,
    threshold: 85
  });

  // Carregar métricas
  useEffect(() => {
    const loadMetrics = async () => {
      setLoading(true);
      try {
        // Simular chamada API
        await new Promise(resolve => setTimeout(resolve, 1000));
        setCoverage(mockCoverage);
        setRegressionTests(mockRegressionTests);
        setPerformanceTests(mockPerformanceTests);
      } catch (error) {
        console.error('Erro ao carregar métricas:', error);
        Toast.error('Erro ao carregar métricas de qualidade');
      } finally {
        setLoading(false);
      }
    };

    loadMetrics();
  }, []);

  // Executar testes
  const handleRunTests = async () => {
    setLoading(true);
    try {
      // Simular execução de testes
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      if (selectedTestType === 'regression') {
        // Atualizar testes de regressão
        const updatedTests = regressionTests.map(test => ({
          ...test,
          status: Math.random() > 0.1 ? 'pass' : 'fail',
          lastRun: new Date(),
          duration: Math.random() * 5 + 0.5
        }));
        setRegressionTests(updatedTests);
        Toast.success('Testes de regressão executados com sucesso!');
      } else {
        // Atualizar testes de performance
        const updatedTests = performanceTests.map(test => ({
          ...test,
          status: Math.random() > 0.2 ? 'pass' : 'fail',
          lastRun: new Date(),
          metrics: {
            responseTime: {
              avg: Math.random() * 1000 + 200,
              p95: Math.random() * 2000 + 400,
              p99: Math.random() * 4000 + 800
            },
            throughput: {
              rps: Math.random() * 50 + 20,
              total: Math.random() * 5000 + 2000
            },
            errorRate: Math.random() * 5,
            cpuUsage: Math.random() * 100,
            memoryUsage: Math.random() * 1024 + 256
          }
        }));
        setPerformanceTests(updatedTests);
        Toast.success('Testes de performance executados com sucesso!');
      }
      
      setShowRunTestsModal(false);
    } catch (error) {
      Toast.error('Erro ao executar testes');
    } finally {
      setLoading(false);
    }
  };

  // Gerar relatório
  const handleGenerateReport = async () => {
    setLoading(true);
    try {
      // Simular geração de relatório
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const overallScore = Math.round(
        (coverage.percentage * 0.4) +
        (regressionTests.filter(t => t.status === 'pass').length / regressionTests.length * 100 * 0.3) +
        (performanceTests.filter(t => t.status === 'pass').length / performanceTests.length * 100 * 0.3)
      );
      
      const status = overallScore >= 90 ? 'excellent' :
                    overallScore >= 80 ? 'good' :
                    overallScore >= 70 ? 'warning' : 'critical';
      
      const recommendations = [];
      if (coverage.percentage < 85) {
        recommendations.push('Aumentar cobertura de testes para pelo menos 85%');
      }
      if (regressionTests.some(t => t.status === 'fail')) {
        recommendations.push('Corrigir testes de regressão que falharam');
      }
      if (performanceTests.some(t => t.status === 'fail')) {
        recommendations.push('Otimizar performance dos endpoints');
      }
      
      Toast.success(`Relatório gerado! Score: ${overallScore}%`);
      
      // Aqui você poderia abrir o relatório em uma nova aba ou modal
      console.log('Relatório gerado:', { overallScore, status, recommendations });
    } catch (error) {
      Toast.error('Erro ao gerar relatório');
    } finally {
      setLoading(false);
    }
  };

  // Renderizar métricas de cobertura
  const renderCoverageMetrics = () => {
    const coverageData = [
      { name: 'Statements', covered: coverage.details.statements.covered, total: coverage.details.statements.total },
      { name: 'Branches', covered: coverage.details.branches.covered, total: coverage.details.branches.total },
      { name: 'Functions', covered: coverage.details.functions.covered, total: coverage.details.functions.total },
      { name: 'Lines', covered: coverage.details.lines.covered, total: coverage.details.lines.total }
    ];

    return (
      <div className="space-y-6">
        {/* Resumo */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{coverage.percentage}%</div>
              <div className="text-sm text-gray-600">Cobertura Total</div>
              <div className={`text-xs mt-1 px-2 py-1 rounded ${
                coverage.status === 'pass' ? 'bg-green-100 text-green-800' :
                coverage.status === 'warning' ? 'bg-yellow-100 text-yellow-800' :
                'bg-red-100 text-red-800'
              }`}>
                {coverage.status === 'pass' ? '✅ Aprovado' :
                 coverage.status === 'warning' ? '⚠️ Atenção' : '❌ Reprovado'}
              </div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{coverage.covered}</div>
              <div className="text-sm text-gray-600">Linhas Cobertas</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">{coverage.uncovered}</div>
              <div className="text-sm text-gray-600">Linhas Não Cobertas</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">{coverage.threshold}%</div>
              <div className="text-sm text-gray-600">Threshold Mínimo</div>
            </div>
          </Card>
        </div>

        {/* Gráfico de cobertura */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Detalhamento por Tipo</h3>
          <div className="h-64">
            <Charts
              type="bar"
              data={coverageData.map(item => ({
                name: item.name,
                value: Math.round((item.covered / item.total) * 100),
                color: Math.round((item.covered / item.total) * 100) >= 85 ? '#10B981' : '#EF4444'
              }))}
              options={{
                legend: true,
                grid: true,
                tooltip: true,
                animate: true
              }}
            />
          </div>
        </Card>

        {/* Tabela detalhada */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Detalhamento Completo</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2">Tipo</th>
                  <th className="text-right py-2">Coberto</th>
                  <th className="text-right py-2">Total</th>
                  <th className="text-right py-2">Porcentagem</th>
                  <th className="text-center py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(coverage.details).map(([key, detail]) => (
                  <tr key={key} className="border-b">
                    <td className="py-2 capitalize">{key}</td>
                    <td className="text-right py-2">{detail.covered}</td>
                    <td className="text-right py-2">{detail.total}</td>
                    <td className="text-right py-2">{detail.percentage}%</td>
                    <td className="text-center py-2">
                      <span className={`px-2 py-1 rounded text-xs ${
                        detail.percentage >= 85 ? 'bg-green-100 text-green-800' :
                        detail.percentage >= 70 ? 'bg-yellow-100 text-yellow-800' :
                        'bg-red-100 text-red-800'
                      }`}>
                        {detail.percentage >= 85 ? '✅' : detail.percentage >= 70 ? '⚠️' : '❌'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    );
  };

  // Renderizar testes de regressão
  const renderRegressionTests = () => {
    const columns = [
      { key: 'name', label: 'Nome', sortable: true },
      { key: 'category', label: 'Categoria', sortable: true },
      { key: 'status', label: 'Status', sortable: true },
      { key: 'duration', label: 'Duração (s)', sortable: true },
      { key: 'lastRun', label: 'Última Execução', sortable: true },
      { key: 'failureRate', label: 'Taxa de Falha (%)', sortable: true },
      { key: 'flakiness', label: 'Flakiness (%)', sortable: true },
      { key: 'critical', label: 'Crítico', sortable: true },
      { key: 'actions', label: 'Ações', sortable: false }
    ];

    const data = regressionTests.map(test => ({
      ...test,
      category: test.category === 'unit' ? 'Unitário' :
                test.category === 'integration' ? 'Integração' :
                test.category === 'e2e' ? 'E2E' : 'Visual',
      status: test.status === 'pass' ? '✅ Passou' :
              test.status === 'fail' ? '❌ Falhou' :
              test.status === 'running' ? '🔄 Executando' : '⏳ Pendente',
      lastRun: test.lastRun.toLocaleString(),
      critical: test.critical ? '🔴 Sim' : '⚪ Não',
      actions: (
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              Toast.info(`Executando ${test.name}...`);
            }}
            disabled={test.status === 'running'}
          >
            Executar
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              Toast.info(`Visualizando detalhes de ${test.name}`);
            }}
          >
            Detalhes
          </Button>
        </div>
      )
    }));

    return (
      <div className="space-y-6">
        {/* Resumo */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {regressionTests.filter(t => t.status === 'pass').length}
              </div>
              <div className="text-sm text-gray-600">Testes Passando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">
                {regressionTests.filter(t => t.status === 'fail').length}
              </div>
              <div className="text-sm text-gray-600">Testes Falhando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {regressionTests.filter(t => t.status === 'running').length}
              </div>
              <div className="text-sm text-gray-600">Executando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">
                {regressionTests.filter(t => t.critical).length}
              </div>
              <div className="text-sm text-gray-600">Testes Críticos</div>
            </div>
          </Card>
        </div>

        {/* Tabela */}
        <Card className="p-6">
          <DataTable
            data={data}
            columns={columns}
            pagination={{ enabled: true, pageSize: 10 }}
            search={{ enabled: true }}
            filters={{ enabled: true }}
          />
        </Card>
      </div>
    );
  };

  // Renderizar testes de performance
  const renderPerformanceTests = () => {
    const columns = [
      { key: 'name', label: 'Nome', sortable: true },
      { key: 'type', label: 'Tipo', sortable: true },
      { key: 'status', label: 'Status', sortable: true },
      { key: 'responseTime', label: 'Tempo de Resposta (ms)', sortable: true },
      { key: 'throughput', label: 'Throughput (RPS)', sortable: true },
      { key: 'errorRate', label: 'Taxa de Erro (%)', sortable: true },
      { key: 'users', label: 'Usuários', sortable: true },
      { key: 'lastRun', label: 'Última Execução', sortable: true },
      { key: 'actions', label: 'Ações', sortable: false }
    ];

    const data = performanceTests.map(test => ({
      ...test,
      type: test.type === 'load' ? 'Carga' :
            test.type === 'stress' ? 'Stress' :
            test.type === 'spike' ? 'Spike' : 'Endurance',
      status: test.status === 'pass' ? '✅ Passou' :
              test.status === 'fail' ? '❌ Falhou' :
              test.status === 'running' ? '🔄 Executando' : '⏳ Pendente',
      responseTime: test.metrics.responseTime.avg.toFixed(0),
      throughput: test.metrics.throughput.rps.toFixed(1),
      errorRate: test.metrics.errorRate.toFixed(1),
      lastRun: test.lastRun.toLocaleString(),
      actions: (
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              Toast.info(`Executando ${test.name}...`);
            }}
            disabled={test.status === 'running'}
          >
            Executar
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              Toast.info(`Visualizando métricas de ${test.name}`);
            }}
          >
            Métricas
          </Button>
        </div>
      )
    }));

    return (
      <div className="space-y-6">
        {/* Resumo */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {performanceTests.filter(t => t.status === 'pass').length}
              </div>
              <div className="text-sm text-gray-600">Testes Passando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">
                {performanceTests.filter(t => t.status === 'fail').length}
              </div>
              <div className="text-sm text-gray-600">Testes Falhando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {performanceTests.filter(t => t.status === 'running').length}
              </div>
              <div className="text-sm text-gray-600">Executando</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-600">
                {performanceTests.reduce((sum, t) => sum + t.users, 0)}
              </div>
              <div className="text-sm text-gray-600">Total de Usuários</div>
            </div>
          </Card>
        </div>

        {/* Gráfico de performance */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Métricas de Performance</h3>
          <div className="h-64">
            <Charts
              type="line"
              data={performanceTests.map(test => ({
                name: test.name,
                value: test.metrics.responseTime.avg,
                color: test.status === 'pass' ? '#10B981' : '#EF4444'
              }))}
              options={{
                legend: true,
                grid: true,
                tooltip: true,
                animate: true
              }}
            />
          </div>
        </Card>

        {/* Tabela */}
        <Card className="p-6">
          <DataTable
            data={data}
            columns={columns}
            pagination={{ enabled: true, pageSize: 10 }}
            search={{ enabled: true }}
            filters={{ enabled: true }}
          />
        </Card>
      </div>
    );
  };

  if (loading) {
    return <Loading type="spinner" text="Carregando métricas de qualidade..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Métricas de Qualidade</h1>
          <p className="text-gray-600">Monitoramento e análise da qualidade do código</p>
        </div>
        
        <div className="flex space-x-3">
          <Button
            variant="outline"
            onClick={() => setShowRunTestsModal(true)}
          >
            Executar Testes
          </Button>
          
          <Button
            variant="primary"
            onClick={handleGenerateReport}
          >
            Gerar Relatório
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'coverage', label: 'Cobertura', icon: '📊' },
            { id: 'regression', label: 'Regressão', icon: '🔄' },
            { id: 'performance', label: 'Performance', icon: '⚡' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span>{tab.icon}</span>
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <div className="mt-6">
        {activeTab === 'coverage' && renderCoverageMetrics()}
        {activeTab === 'regression' && renderRegressionTests()}
        {activeTab === 'performance' && renderPerformanceTests()}
      </div>

      {/* Modal de execução de testes */}
      <Modal
        isOpen={showRunTestsModal}
        onClose={() => setShowRunTestsModal(false)}
        title="Executar Testes"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Tipo de Teste
            </label>
            <Select
              value={selectedTestType}
              onChange={(value) => setSelectedTestType(value as any)}
              options={[
                { value: 'regression', label: 'Testes de Regressão' },
                { value: 'performance', label: 'Testes de Performance' }
              ]}
            />
          </div>
          
          {selectedTestType === 'regression' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Categoria
              </label>
              <Select
                value={testConfig.category}
                onChange={(value) => setTestConfig(prev => ({ ...prev, category: value }))}
                options={[
                  { value: 'all', label: 'Todos' },
                  { value: 'unit', label: 'Unitários' },
                  { value: 'integration', label: 'Integração' },
                  { value: 'e2e', label: 'E2E' },
                  { value: 'visual', label: 'Visual' }
                ]}
              />
            </div>
          )}
          
          {selectedTestType === 'performance' && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Número de Usuários
                </label>
                <input
                  type="number"
                  value={testConfig.users}
                  onChange={(e) => setTestConfig(prev => ({ ...prev, users: parseInt(e.target.value) }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="1"
                  max="10000"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Duração (segundos)
                </label>
                <input
                  type="number"
                  value={testConfig.duration}
                  onChange={(e) => setTestConfig(prev => ({ ...prev, duration: parseInt(e.target.value) }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  min="60"
                  max="3600"
                />
              </div>
            </>
          )}
        </div>
        
        <div className="flex justify-end space-x-3 mt-6">
          <Button
            variant="outline"
            onClick={() => setShowRunTestsModal(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            onClick={handleRunTests}
            disabled={loading}
          >
            {loading ? 'Executando...' : 'Executar'}
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default QualityMetrics; 