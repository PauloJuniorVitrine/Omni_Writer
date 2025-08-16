/**
 * Componente RecentActivity - Dashboard
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Lista de atividades recentes
 * - Indicadores de status
 * - Timestamps relativos
 * - Scroll automático
 */

import React from 'react';

interface Activity {
  id: string;
  type: 'article_generated' | 'blog_created' | 'category_added' | 'prompt_updated' | 'error';
  title: string;
  description: string;
  timestamp: Date;
  status: 'success' | 'pending' | 'error';
}

/**
 * Componente de atividade recente
 */
const RecentActivity: React.FC = () => {
  // Dados simulados de atividade
  const activities: Activity[] = [
    {
      id: '1',
      type: 'article_generated',
      title: 'Artigo gerado com sucesso',
      description: '"Como melhorar a produtividade no trabalho remoto" foi gerado para o blog Tech Tips',
      timestamp: new Date(Date.now() - 5 * 60 * 1000), // 5 minutos atrás
      status: 'success'
    },
    {
      id: '2',
      type: 'blog_created',
      title: 'Novo blog criado',
      description: 'Blog "Saúde e Bem-estar" foi adicionado ao sistema',
      timestamp: new Date(Date.now() - 15 * 60 * 1000), // 15 minutos atrás
      status: 'success'
    },
    {
      id: '3',
      type: 'category_added',
      title: 'Categoria adicionada',
      description: 'Categoria "Fitness" foi criada no blog Saúde e Bem-estar',
      timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 minutos atrás
      status: 'success'
    },
    {
      id: '4',
      type: 'prompt_updated',
      title: 'Prompt atualizado',
      description: 'Prompt "Introdução de artigos" foi modificado',
      timestamp: new Date(Date.now() - 45 * 60 * 1000), // 45 minutos atrás
      status: 'success'
    },
    {
      id: '5',
      type: 'error',
      title: 'Erro na geração',
      description: 'Falha ao gerar artigo "Dicas de investimento" - API timeout',
      timestamp: new Date(Date.now() - 60 * 60 * 1000), // 1 hora atrás
      status: 'error'
    }
  ];

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'article_generated':
        return '📝';
      case 'blog_created':
        return '📄';
      case 'category_added':
        return '📁';
      case 'prompt_updated':
        return '💬';
      case 'error':
        return '❌';
      default:
        return '📋';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success':
        return 'text-green-600 bg-green-100';
      case 'pending':
        return 'text-yellow-600 bg-yellow-100';
      case 'error':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
        return '✅';
      case 'pending':
        return '⏳';
      case 'error':
        return '❌';
      default:
        return '⚪';
    }
  };

  const formatTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Agora';
    if (minutes < 60) return `${minutes}m atrás`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h atrás`;
    
    const days = Math.floor(hours / 24);
    return `${days}d atrás`;
  };

  return (
    <div className="space-y-3 max-h-80 overflow-y-auto">
      {activities.map((activity) => (
        <div
          key={activity.id}
          className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
        >
          <div className="flex-shrink-0">
            <span className="text-lg">{getActivityIcon(activity.type)}</span>
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-gray-900 truncate">
                {activity.title}
              </h4>
              <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(activity.status)}`}>
                {getStatusIcon(activity.status)}
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-1">
              {activity.description}
            </p>
            <p className="text-xs text-gray-500 mt-2">
              {formatTime(activity.timestamp)}
            </p>
          </div>
        </div>
      ))}
      
      {/* Botão para ver mais */}
      <div className="text-center pt-2">
        <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
          Ver todas as atividades →
        </button>
      </div>
    </div>
  );
};

export default RecentActivity; 