import React, { useState } from 'react';
import { useFeatureFlags } from '../hooks/useFeatureFlags';
import { FeatureFlagConfig } from '../../shared/types/api_types';

/**
 * Componente para gerenciamento e visualização de feature flags.
 * 
 * Tracing ID: FEATURE_FLAGS_UI_20250127_001
 * Data/Hora: 2025-01-27T22:45:00Z
 * Prompt: Implementar features flags de API pendentes
 * Ruleset: Enterprise+ Standards
 */

interface FeatureFlagsManagerProps {
  showAdminPanel?: boolean;
  showStatus?: boolean;
  className?: string;
}

interface FlagStatusProps {
  flagName: string;
  config: FeatureFlagConfig;
  enabled: boolean;
}

const FlagStatus: React.FC<FlagStatusProps> = ({ flagName, config, enabled }) => {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ENABLED': return 'text-green-600 bg-green-100';
      case 'DISABLED': return 'text-red-600 bg-red-100';
      case 'PARTIAL': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'RELEASE': return 'bg-blue-100 text-blue-800';
      case 'OPERATIONAL': return 'bg-purple-100 text-purple-800';
      case 'EXPERIMENTAL': return 'bg-orange-100 text-orange-800';
      case 'PERMISSION': return 'bg-indigo-100 text-indigo-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="border rounded-lg p-4 mb-4 bg-white shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-lg font-semibold text-gray-900">{flagName}</h3>
        <div className="flex items-center space-x-2">
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(config.status)}`}>
            {config.status}
          </span>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getTypeColor(config.type)}`}>
            {config.type}
          </span>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
            {enabled ? 'ATIVO' : 'INATIVO'}
          </span>
        </div>
      </div>
      
      {config.description && (
        <p className="text-sm text-gray-600 mb-3">{config.description}</p>
      )}
      
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="font-medium text-gray-700">Criado:</span>
          <span className="ml-2 text-gray-600">
            {new Date(config.created_at).toLocaleDateString('pt-BR')}
          </span>
        </div>
        <div>
          <span className="font-medium text-gray-700">Atualizado:</span>
          <span className="ml-2 text-gray-600">
            {new Date(config.updated_at).toLocaleDateString('pt-BR')}
          </span>
        </div>
        {config.percentage !== undefined && (
          <div>
            <span className="font-medium text-gray-700">Porcentagem:</span>
            <span className="ml-2 text-gray-600">{config.percentage}%</span>
          </div>
        )}
        {config.start_date && (
          <div>
            <span className="font-medium text-gray-700">Início:</span>
            <span className="ml-2 text-gray-600">
              {new Date(config.start_date).toLocaleDateString('pt-BR')}
            </span>
          </div>
        )}
        {config.end_date && (
          <div>
            <span className="font-medium text-gray-700">Fim:</span>
            <span className="ml-2 text-gray-600">
              {new Date(config.end_date).toLocaleDateString('pt-BR')}
            </span>
          </div>
        )}
      </div>
      
      {config.conditions && Object.keys(config.conditions).length > 0 && (
        <div className="mt-3">
          <span className="font-medium text-gray-700 text-sm">Condições:</span>
          <pre className="mt-1 text-xs bg-gray-50 p-2 rounded border overflow-x-auto">
            {JSON.stringify(config.conditions, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export const FeatureFlagsManager: React.FC<FeatureFlagsManagerProps> = ({
  showAdminPanel = false,
  showStatus = true,
  className = ''
}) => {
  const {
    flags,
    loading,
    error,
    lastUpdated,
    refresh,
    isEnabled,
    getFlagConfig
  } = useFeatureFlags();

  const [filterType, setFilterType] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Filtra flags baseado no tipo e termo de busca
  const filteredFlags = Object.entries(flags).filter(([flagName, flagData]) => {
    const matchesType = filterType === 'all' || flagData.config.type === filterType;
    const matchesSearch = flagName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (flagData.config.description || '').toLowerCase().includes(searchTerm.toLowerCase());
    return matchesType && matchesSearch;
  });

  // Agrupa flags por tipo
  const flagsByType = filteredFlags.reduce((acc, [flagName, flagData]) => {
    const type = flagData.config.type;
    if (!acc[type]) acc[type] = [];
    acc[type].push([flagName, flagData]);
    return acc;
  }, {} as Record<string, [string, any][]>);

  if (loading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-3 text-gray-600">Carregando feature flags...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center">
          <svg className="w-5 h-5 text-red-400 mr-2" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
          <span className="text-red-800 font-medium">Erro ao carregar feature flags</span>
        </div>
        <p className="text-red-700 mt-2 text-sm">{error}</p>
        <button
          onClick={refresh}
          className="mt-3 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
        >
          Tentar novamente
        </button>
      </div>
    );
  }

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Feature Flags</h2>
          {lastUpdated && (
            <p className="text-sm text-gray-600">
              Última atualização: {lastUpdated.toLocaleString('pt-BR')}
            </p>
          )}
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={refresh}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Atualizar
          </button>
        </div>
      </div>

      {/* Filtros */}
      <div className="flex items-center space-x-4">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Buscar feature flags..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="all">Todos os tipos</option>
          <option value="RELEASE">Release</option>
          <option value="OPERATIONAL">Operacional</option>
          <option value="EXPERIMENTAL">Experimental</option>
          <option value="PERMISSION">Permissão</option>
        </select>
      </div>

      {/* Estatísticas */}
      {showStatus && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded-lg border shadow-sm">
            <div className="text-2xl font-bold text-blue-600">
              {Object.keys(flags).length}
            </div>
            <div className="text-sm text-gray-600">Total de Flags</div>
          </div>
          <div className="bg-white p-4 rounded-lg border shadow-sm">
            <div className="text-2xl font-bold text-green-600">
              {Object.values(flags).filter(flag => flag.enabled).length}
            </div>
            <div className="text-sm text-gray-600">Ativas</div>
          </div>
          <div className="bg-white p-4 rounded-lg border shadow-sm">
            <div className="text-2xl font-bold text-red-600">
              {Object.values(flags).filter(flag => !flag.enabled).length}
            </div>
            <div className="text-sm text-gray-600">Inativas</div>
          </div>
          <div className="bg-white p-4 rounded-lg border shadow-sm">
            <div className="text-2xl font-bold text-yellow-600">
              {Object.values(flags).filter(flag => flag.config.status === 'PARTIAL').length}
            </div>
            <div className="text-sm text-gray-600">Parciais</div>
          </div>
        </div>
      )}

      {/* Lista de Flags */}
      <div className="space-y-4">
        {Object.keys(flagsByType).length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            Nenhuma feature flag encontrada com os filtros aplicados.
          </div>
        ) : (
          Object.entries(flagsByType).map(([type, typeFlags]) => (
            <div key={type}>
              <h3 className="text-lg font-semibold text-gray-800 mb-3 capitalize">
                {type.toLowerCase()} ({typeFlags.length})
              </h3>
              <div className="space-y-4">
                {typeFlags.map(([flagName, flagData]) => (
                  <FlagStatus
                    key={flagName}
                    flagName={flagName}
                    config={flagData.config}
                    enabled={flagData.enabled}
                  />
                ))}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Painel de Administração */}
      {showAdminPanel && (
        <div className="bg-gray-50 border rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Painel de Administração</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="font-medium text-gray-700 mb-2">Ações Rápidas</h4>
              <div className="space-y-2">
                <button className="w-full px-3 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors">
                  Habilitar Todas
                </button>
                <button className="w-full px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                  Desabilitar Todas
                </button>
              </div>
            </div>
            <div>
              <h4 className="font-medium text-gray-700 mb-2">Exportar</h4>
              <div className="space-y-2">
                <button className="w-full px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Exportar Configuração
                </button>
                <button className="w-full px-3 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors">
                  Relatório de Uso
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}; 