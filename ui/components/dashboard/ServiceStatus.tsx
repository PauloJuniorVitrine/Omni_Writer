/**
 * Componente ServiceStatus - Dashboard
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Status visual dos serviços
 * - Tempo de resposta
 * - Indicadores de saúde
 * - Atualização em tempo real
 */

import React from 'react';

interface ServiceStatusProps {
  services: Array<{
    name: string;
    status: 'online' | 'offline' | 'warning';
    responseTime: number;
    lastCheck: Date;
  }>;
}

/**
 * Componente de status dos serviços
 */
const ServiceStatus: React.FC<ServiceStatusProps> = ({ services }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'text-green-600 bg-green-100';
      case 'offline':
        return 'text-red-600 bg-red-100';
      case 'warning':
        return 'text-yellow-600 bg-yellow-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return '🟢';
      case 'offline':
        return '🔴';
      case 'warning':
        return '🟡';
      default:
        return '⚪';
    }
  };

  const getResponseTimeColor = (time: number) => {
    if (time < 100) return 'text-green-600';
    if (time < 300) return 'text-yellow-600';
    return 'text-red-600';
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
    <div className="space-y-3">
      {services.map((service, index) => (
        <div
          key={index}
          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
        >
          <div className="flex items-center space-x-3">
            <span className="text-lg">{getStatusIcon(service.status)}</span>
            <div>
              <p className="font-medium text-gray-900">{service.name}</p>
              <p className="text-sm text-gray-500">
                Última verificação: {formatTime(service.lastCheck)}
              </p>
            </div>
          </div>
          
          <div className="text-right">
            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(service.status)}`}>
              {service.status === 'online' && 'Online'}
              {service.status === 'offline' && 'Offline'}
              {service.status === 'warning' && 'Atenção'}
            </span>
            <p className={`text-sm font-medium mt-1 ${getResponseTimeColor(service.responseTime)}`}>
              {service.responseTime}ms
            </p>
          </div>
        </div>
      ))}
      
      {/* Resumo geral */}
      <div className="mt-4 pt-4 border-t border-gray-200">
        <div className="flex justify-between text-sm">
          <span className="text-gray-600">Serviços online:</span>
          <span className="font-medium text-green-600">
            {services.filter(s => s.status === 'online').length}/{services.length}
          </span>
        </div>
        <div className="flex justify-between text-sm mt-1">
          <span className="text-gray-600">Tempo médio:</span>
          <span className="font-medium">
            {Math.round(services.reduce((acc, s) => acc + s.responseTime, 0) / services.length)}ms
          </span>
        </div>
      </div>
    </div>
  );
};

export default ServiceStatus; 