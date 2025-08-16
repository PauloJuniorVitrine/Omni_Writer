/**
 * Componente QuickActions - Dashboard
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Ações rápidas para navegação
 * - Ícones intuitivos
 * - Hover effects
 * - Responsivo
 */

import React from 'react';
import { useNavigation } from '../../hooks/useNavigation';

interface QuickAction {
  id: string;
  title: string;
  description: string;
  icon: string;
  path: string;
  color: string;
}

/**
 * Componente de ações rápidas
 */
const QuickActions: React.FC = () => {
  const navigation = useNavigation();

  const actions: QuickAction[] = [
    {
      id: 'generate-article',
      title: 'Gerar Artigo',
      description: 'Criar novo artigo',
      icon: '📝',
      path: '/article-generation',
      color: 'bg-blue-500 hover:bg-blue-600'
    },
    {
      id: 'manage-blogs',
      title: 'Gerenciar Blogs',
      description: 'Ver todos os blogs',
      icon: '📄',
      path: '/blogs',
      color: 'bg-green-500 hover:bg-green-600'
    },
    {
      id: 'manage-categories',
      title: 'Categorias',
      description: 'Organizar categorias',
      icon: '📁',
      path: '/categories',
      color: 'bg-purple-500 hover:bg-purple-600'
    },
    {
      id: 'manage-prompts',
      title: 'Prompts',
      description: 'Editar prompts',
      icon: '💬',
      path: '/prompts',
      color: 'bg-orange-500 hover:bg-orange-600'
    },
    {
      id: 'pipeline',
      title: 'Pipeline',
      description: 'Monitorar pipeline',
      icon: '⚙️',
      path: '/pipeline',
      color: 'bg-indigo-500 hover:bg-indigo-600'
    },
    {
      id: 'monitoring',
      title: 'Monitoramento',
      description: 'Ver métricas',
      icon: '📊',
      path: '/monitoring',
      color: 'bg-red-500 hover:bg-red-600'
    }
  ];

  const handleActionClick = (action: QuickAction) => {
    navigation.navigateTo(action.path);
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {actions.map((action) => (
        <button
          key={action.id}
          onClick={() => handleActionClick(action)}
          className={`${action.color} text-white p-4 rounded-lg transition-all duration-200 transform hover:scale-105 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500`}
        >
          <div className="text-center">
            <div className="text-2xl mb-2">{action.icon}</div>
            <h4 className="font-semibold text-sm mb-1">{action.title}</h4>
            <p className="text-xs opacity-90">{action.description}</p>
          </div>
        </button>
      ))}
    </div>
  );
};

export default QuickActions; 