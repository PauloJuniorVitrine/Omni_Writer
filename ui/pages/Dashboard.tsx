/**
 * Dashboard Principal - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Métricas em tempo real
 * - Gráficos de performance
 * - Status dos serviços
 * - Ações rápidas
 * - Layout responsivo
 */

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Card from '../components/base/Card';
import Button from '../components/base/Button';
import Loading from '../components/base/Loading';
import { useNavigation } from '../hooks/useNavigation';

// Componentes do Dashboard
import MetricsCard from '../components/dashboard/MetricsCard';
import PerformanceChart from '../components/dashboard/PerformanceChart';
import ServiceStatus from '../components/dashboard/ServiceStatus';
import QuickActions from '../components/dashboard/QuickActions';
import RecentActivity from '../components/dashboard/RecentActivity';

interface DashboardMetrics {
  totalArticles: number;
  totalBlogs: number;
  totalCategories: number;
  generationSuccess: number;
  generationPending: number;
  generationFailed: number;
}

interface ServiceStatus {
  name: string;
  status: 'online' | 'offline' | 'warning';
  responseTime: number;
  lastCheck: Date;
}

/**
 * Dashboard principal da aplicação
 */
const Dashboard: React.FC = () => {
  const navigation = useNavigation();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Simulação de carregamento de dados
  useEffect(() => {
    const loadDashboardData = async () => {
      setIsLoading(true);
      
      // Simula delay de carregamento
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Dados simulados
      setMetrics({
        totalArticles: 1247,
        totalBlogs: 23,
        totalCategories: 156,
        generationSuccess: 89,
        generationPending: 3,
        generationFailed: 2
      });

      setServices([
        {
          name: 'API de Geração',
          status: 'online',
          responseTime: 245,
          lastCheck: new Date()
        },
        {
          name: 'Banco de Dados',
          status: 'online',
          responseTime: 12,
          lastCheck: new Date()
        },
        {
          name: 'Cache Redis',
          status: 'warning',
          responseTime: 89,
          lastCheck: new Date()
        },
        {
          name: 'Pipeline Multi',
          status: 'online',
          responseTime: 156,
          lastCheck: new Date()
        }
      ]);

      setIsLoading(false);
    };

    loadDashboardData();
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loading size="large" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header do Dashboard */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">
            Dashboard
          </h1>
          <p className="text-gray-600 mt-1">
            Visão geral do sistema Omni Writer
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <Button 
            variant="primary"
            onClick={() => navigation.navigateTo('/article-generation')}
          >
            Gerar Novo Artigo
          </Button>
        </div>
      </div>

      {/* Métricas Principais */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricsCard
          title="Total de Artigos"
          value={metrics?.totalArticles || 0}
          change="+12%"
          changeType="positive"
          icon="article"
        />
        <MetricsCard
          title="Blogs Ativos"
          value={metrics?.totalBlogs || 0}
          change="+2"
          changeType="positive"
          icon="blog"
        />
        <MetricsCard
          title="Categorias"
          value={metrics?.totalCategories || 0}
          change="+8"
          changeType="positive"
          icon="category"
        />
        <MetricsCard
          title="Taxa de Sucesso"
          value={`${metrics?.generationSuccess || 0}%`}
          change="+3%"
          changeType="positive"
          icon="success"
        />
      </div>

      {/* Gráficos e Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gráfico de Performance */}
        <div className="lg:col-span-2">
          <Card>
            <div className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Performance de Geração
              </h3>
              <PerformanceChart
                data={{
                  labels: ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun'],
                  datasets: [
                    {
                      label: 'Artigos Gerados',
                      data: [120, 190, 300, 500, 200, 300],
                      borderColor: '#3B82F6',
                      backgroundColor: 'rgba(59, 130, 246, 0.1)'
                    }
                  ]
                }}
              />
            </div>
          </Card>
        </div>

        {/* Status dos Serviços */}
        <div>
          <Card>
            <div className="p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Status dos Serviços
              </h3>
              <ServiceStatus services={services} />
            </div>
          </Card>
        </div>
      </div>

      {/* Ações Rápidas e Atividade Recente */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Ações Rápidas */}
        <Card>
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Ações Rápidas
            </h3>
            <QuickActions />
          </div>
        </Card>

        {/* Atividade Recente */}
        <Card>
          <div className="p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Atividade Recente
            </h3>
            <RecentActivity />
          </div>
        </Card>
      </div>

      {/* Status de Geração */}
      <Card>
        <div className="p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Status de Geração
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">
                {metrics?.generationSuccess || 0}
              </div>
              <div className="text-sm text-green-600">Sucessos</div>
            </div>
            <div className="text-center p-4 bg-yellow-50 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600">
                {metrics?.generationPending || 0}
              </div>
              <div className="text-sm text-yellow-600">Pendentes</div>
            </div>
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {metrics?.generationFailed || 0}
              </div>
              <div className="text-sm text-red-600">Falhas</div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Dashboard; 