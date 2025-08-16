/**
 * Componente MetricsCard - Dashboard
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Exibição de métricas com ícone
 * - Indicador de mudança (positivo/negativo)
 * - Design responsivo
 * - Animações suaves
 */

import React from 'react';
import Card from '../base/Card';

interface MetricsCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  icon?: string;
  onClick?: () => void;
}

/**
 * Componente de card de métricas
 */
const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  change,
  changeType = 'neutral',
  icon,
  onClick
}) => {
  const getChangeColor = () => {
    switch (changeType) {
      case 'positive':
        return 'text-green-600';
      case 'negative':
        return 'text-red-600';
      default:
        return 'text-gray-600';
    }
  };

  const getChangeIcon = () => {
    switch (changeType) {
      case 'positive':
        return '↗';
      case 'negative':
        return '↘';
      default:
        return '→';
    }
  };

  const getIconColor = () => {
    switch (icon) {
      case 'article':
        return 'text-blue-600 bg-blue-100';
      case 'blog':
        return 'text-green-600 bg-green-100';
      case 'category':
        return 'text-purple-600 bg-purple-100';
      case 'success':
        return 'text-emerald-600 bg-emerald-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <Card 
      className={`transition-all duration-200 hover:shadow-lg ${
        onClick ? 'cursor-pointer hover:scale-105' : ''
      }`}
      onClick={onClick}
    >
      <div className="p-6">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-600 mb-1">
              {title}
            </p>
            <div className="flex items-baseline">
              <p className="text-2xl font-bold text-gray-900">
                {value}
              </p>
              {change && (
                <span className={`ml-2 text-sm font-medium ${getChangeColor()}`}>
                  {getChangeIcon()} {change}
                </span>
              )}
            </div>
          </div>
          {icon && (
            <div className={`p-3 rounded-lg ${getIconColor()}`}>
              <span className="text-xl">
                {icon === 'article' && '📄'}
                {icon === 'blog' && '📝'}
                {icon === 'category' && '📁'}
                {icon === 'success' && '✅'}
              </span>
            </div>
          )}
        </div>
      </div>
    </Card>
  );
};

export default MetricsCard; 