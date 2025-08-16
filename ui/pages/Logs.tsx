/**
 * Página de Logs e Auditoria - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-019
 * Data/Hora: 2025-01-27T23:30:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Visualização de logs em tempo real
 * - Filtros avançados e busca
 * - Exportação em múltiplos formatos
 * - Análise de padrões e métricas
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, Button, Input, Select, Switch, Toast } from '../components/base';
import { useApi } from '../hooks/use_api';
import { useI18n } from '../hooks/use_i18n';

interface LogEntry {
  id: string;
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  service: string;
  message: string;
  tracing_id?: string;
  user_id?: string;
  ip_address?: string;
  user_agent?: string;
  metadata?: {
    [key: string]: any;
  };
  audit_data?: {
    action?: string;
    resource_type?: string;
    resource_id?: string;
    old_value?: any;
    new_value?: any;
    reason?: string;
  };
}

interface LogFilters {
  level: string[];
  service: string[];
  search: string;
  tracing_id: string;
  user_id: string;
  start_date: string;
  end_date: string;
  include_audit: boolean;
  include_metadata: boolean;
}

interface LogMetrics {
  total_logs: number;
  logs_by_level: { [key: string]: number };
  logs_by_service: { [key: string]: number };
  logs_by_hour: { [key: string]: number };
  error_rate: number;
  avg_response_time: number;
  top_errors: Array<{ message: string; count: number }>;
  top_services: Array<{ service: string; count: number }>;
}

interface ExportOptions {
  format: 'json' | 'csv' | 'txt';
  include_metadata: boolean;
  include_audit: boolean;
  date_range: 'all' | 'today' | 'week' | 'month' | 'custom';
  custom_start?: string;
  custom_end?: string;
}

const Logs: React.FC = () => {
  const { t } = useI18n();
  const { apiCall } = useApi();
  
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<LogEntry[]>([]);
  const [metrics, setMetrics] = useState<LogMetrics | null>(null);
  const [filters, setFilters] = useState<LogFilters>({
    level: [],
    service: [],
    search: '',
    tracing_id: '',
    user_id: '',
    start_date: '',
    end_date: '',
    include_audit: true,
    include_metadata: true,
  });
  const [exportOptions, setExportOptions] = useState<ExportOptions>({
    format: 'json',
    include_metadata: true,
    include_audit: true,
    date_range: 'all',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [showMetrics, setShowMetrics] = useState(true);
  const [showFilters, setShowFilters] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [hasMore, setHasMore] = useState(true);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error'>('success');
  const [selectedLogs, setSelectedLogs] = useState<string[]>([]);
  const [logViewMode, setLogViewMode] = useState<'table' | 'json' | 'compact'>('table');
  
  const logsEndRef = useRef<HTMLDivElement>(null);
  const autoRefreshRef = useRef<NodeJS.Timeout | null>(null);

  // Carregar logs iniciais
  useEffect(() => {
    loadLogs();
    loadMetrics();
  }, []);

  // Auto-refresh
  useEffect(() => {
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(() => {
        loadLogs();
        loadMetrics();
      }, refreshInterval * 1000);
    } else {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
    }

    return () => {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
    };
  }, [autoRefresh, refreshInterval]);

  // Aplicar filtros
  useEffect(() => {
    applyFilters();
  }, [logs, filters]);

  // Auto-scroll para logs mais recentes
  useEffect(() => {
    if (autoRefresh && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const loadLogs = useCallback(async (pageNum = 1, append = false) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: pageNum.toString(),
        page_size: pageSize.toString(),
        ...(filters.level.length > 0 && { level: filters.level.join(',') }),
        ...(filters.service.length > 0 && { service: filters.service.join(',') }),
        ...(filters.search && { search: filters.search }),
        ...(filters.tracing_id && { tracing_id: filters.tracing_id }),
        ...(filters.user_id && { user_id: filters.user_id }),
        ...(filters.start_date && { start_date: filters.start_date }),
        ...(filters.end_date && { end_date: filters.end_date }),
        ...(filters.include_audit && { include_audit: 'true' }),
        ...(filters.include_metadata && { include_metadata: 'true' }),
      });

      const response = await apiCall(`/api/logs?${params}`, 'GET');
      if (response.success) {
        if (append) {
          setLogs(prev => [...prev, ...response.logs]);
        } else {
          setLogs(response.logs);
        }
        setHasMore(response.logs.length === pageSize);
      }
    } catch (error) {
      console.error('Erro ao carregar logs:', error);
      setToastMessage('Erro ao carregar logs');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsLoading(false);
    }
  }, [apiCall, pageSize, filters]);

  const loadMetrics = useCallback(async () => {
    try {
      const response = await apiCall('/api/logs/metrics', 'GET');
      if (response.success) {
        setMetrics(response.metrics);
      }
    } catch (error) {
      console.error('Erro ao carregar métricas:', error);
    }
  }, [apiCall]);

  const applyFilters = useCallback(() => {
    let filtered = [...logs];

    // Filtro por nível
    if (filters.level.length > 0) {
      filtered = filtered.filter(log => filters.level.includes(log.level));
    }

    // Filtro por serviço
    if (filters.service.length > 0) {
      filtered = filtered.filter(log => filters.service.includes(log.service));
    }

    // Filtro por busca textual
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(log =>
        log.message.toLowerCase().includes(searchLower) ||
        log.service.toLowerCase().includes(searchLower) ||
        (log.tracing_id && log.tracing_id.toLowerCase().includes(searchLower)) ||
        (log.user_id && log.user_id.toLowerCase().includes(searchLower))
      );
    }

    // Filtro por tracing ID
    if (filters.tracing_id) {
      filtered = filtered.filter(log => log.tracing_id === filters.tracing_id);
    }

    // Filtro por user ID
    if (filters.user_id) {
      filtered = filtered.filter(log => log.user_id === filters.user_id);
    }

    // Filtro por data
    if (filters.start_date) {
      filtered = filtered.filter(log => log.timestamp >= filters.start_date);
    }
    if (filters.end_date) {
      filtered = filtered.filter(log => log.timestamp <= filters.end_date);
    }

    setFilteredLogs(filtered);
  }, [logs, filters]);

  const handleFilterChange = (field: keyof LogFilters, value: any) => {
    setFilters(prev => ({
      ...prev,
      [field]: value,
    }));
    setPage(1);
  };

  const handleLevelFilter = (level: string, checked: boolean) => {
    setFilters(prev => ({
      ...prev,
      level: checked
        ? [...prev.level, level]
        : prev.level.filter(l => l !== level),
    }));
    setPage(1);
  };

  const handleServiceFilter = (service: string, checked: boolean) => {
    setFilters(prev => ({
      ...prev,
      service: checked
        ? [...prev.service, service]
        : prev.service.filter(s => s !== service),
    }));
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({
      level: [],
      service: [],
      search: '',
      tracing_id: '',
      user_id: '',
      start_date: '',
      end_date: '',
      include_audit: true,
      include_metadata: true,
    });
    setPage(1);
  };

  const loadMoreLogs = () => {
    const nextPage = page + 1;
    setPage(nextPage);
    loadLogs(nextPage, true);
  };

  const exportLogs = async () => {
    setIsExporting(true);
    try {
      const params = new URLSearchParams({
        format: exportOptions.format,
        include_metadata: exportOptions.include_metadata.toString(),
        include_audit: exportOptions.include_audit.toString(),
        date_range: exportOptions.date_range,
        ...(exportOptions.custom_start && { custom_start: exportOptions.custom_start }),
        ...(exportOptions.custom_end && { custom_end: exportOptions.custom_end }),
      });

      const response = await apiCall(`/api/logs/export?${params}`, 'GET');
      if (response.success) {
        // Download do arquivo
        const blob = new Blob([response.data], { 
          type: exportOptions.format === 'json' ? 'application/json' : 
                exportOptions.format === 'csv' ? 'text/csv' : 'text/plain' 
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `logs_${new Date().toISOString()}.${exportOptions.format}`;
        a.click();
        URL.revokeObjectURL(url);

        setToastMessage('Logs exportados com sucesso');
        setToastType('success');
        setShowToast(true);
      }
    } catch (error) {
      console.error('Erro ao exportar logs:', error);
      setToastMessage('Erro ao exportar logs');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsExporting(false);
    }
  };

  const handleLogSelection = (logId: string, checked: boolean) => {
    setSelectedLogs(prev =>
      checked
        ? [...prev, logId]
        : prev.filter(id => id !== logId)
    );
  };

  const selectAllLogs = () => {
    setSelectedLogs(filteredLogs.map(log => log.id));
  };

  const clearSelection = () => {
    setSelectedLogs([]);
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'ERROR': return 'text-red-500 bg-red-50';
      case 'WARNING': return 'text-yellow-600 bg-yellow-100';
      case 'INFO': return 'text-blue-600 bg-blue-100';
      case 'DEBUG': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Agora mesmo';
    if (diffInMinutes < 60) return `${diffInMinutes}m atrás`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h atrás`;
    return date.toLocaleDateString('pt-BR') + ' ' + date.toLocaleTimeString('pt-BR');
  };

  const truncateMessage = (message: string, maxLength = 100) => {
    return message.length > maxLength ? message.substring(0, maxLength) + '...' : message;
  };

  const renderLogTable = () => (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              <input
                type="checkbox"
                checked={selectedLogs.length === filteredLogs.length && filteredLogs.length > 0}
                onChange={(e) => e.target.checked ? selectAllLogs() : clearSelection()}
                className="rounded border-gray-300"
              />
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Timestamp
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Nível
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Serviço
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Mensagem
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Tracing ID
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Usuário
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Ações
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {filteredLogs.map((log) => (
            <tr key={log.id} className="hover:bg-gray-50">
              <td className="px-6 py-4 whitespace-nowrap">
                <input
                  type="checkbox"
                  checked={selectedLogs.includes(log.id)}
                  onChange={(e) => handleLogSelection(log.id, e.target.checked)}
                  className="rounded border-gray-300"
                />
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {formatTimestamp(log.timestamp)}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getLevelColor(log.level)}`}>
                  {log.level}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {log.service}
              </td>
              <td className="px-6 py-4 text-sm text-gray-900">
                <div className="max-w-md">
                  <div>{truncateMessage(log.message)}</div>
                  {log.audit_data && (
                    <div className="text-xs text-gray-500 mt-1">
                      Ação: {log.audit_data.action} | Recurso: {log.audit_data.resource_type}
                    </div>
                  )}
                </div>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {log.tracing_id ? (
                  <span className="font-mono text-xs">{log.tracing_id.substring(0, 8)}...</span>
                ) : '-'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {log.user_id || '-'}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <button
                  onClick={() => {
                    console.log('Log completo:', log);
                    setToastMessage('Log detalhado exibido no console');
                    setToastType('success');
                    setShowToast(true);
                  }}
                  className="text-blue-600 hover:text-blue-900"
                >
                  Detalhes
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  const renderLogJson = () => (
    <div className="space-y-2">
      {filteredLogs.map((log) => (
        <div key={log.id} className="bg-gray-50 p-4 rounded-lg">
          <pre className="text-sm overflow-x-auto">
            {JSON.stringify(log, null, 2)}
          </pre>
        </div>
      ))}
    </div>
  );

  const renderLogCompact = () => (
    <div className="space-y-1">
      {filteredLogs.map((log) => (
        <div key={log.id} className="flex items-center space-x-2 text-sm font-mono">
          <span className="text-gray-500">[{formatTimestamp(log.timestamp)}]</span>
          <span className={`px-2 py-1 rounded text-xs font-semibold ${getLevelColor(log.level)}`}>
            {log.level}
          </span>
          <span className="text-blue-600">[{log.service}]</span>
          <span className="text-gray-900">{log.message}</span>
          {log.tracing_id && (
            <span className="text-purple-600">#{log.tracing_id.substring(0, 8)}</span>
          )}
        </div>
      ))}
    </div>
  );

  const renderMetrics = () => {
    if (!metrics) return null;

    return (
      <Card>
        <h3 className="text-lg font-semibold mb-4">Métricas dos Logs</h3>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">{metrics.total_logs.toLocaleString()}</div>
            <div className="text-sm text-gray-600">Total de Logs</div>
          </div>
          
          <div className="text-center p-4 bg-red-50 rounded-lg">
            <div className="text-2xl font-bold text-red-600">{metrics.error_rate.toFixed(1)}%</div>
            <div className="text-sm text-gray-600">Taxa de Erro</div>
          </div>
          
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="text-2xl font-bold text-green-600">{metrics.avg_response_time.toFixed(0)}ms</div>
            <div className="text-sm text-gray-600">Tempo Médio</div>
          </div>
          
          <div className="text-center p-4 bg-purple-50 rounded-lg">
            <div className="text-2xl font-bold text-purple-600">{Object.keys(metrics.logs_by_service).length}</div>
            <div className="text-sm text-gray-600">Serviços</div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-medium mb-2">Logs por Nível</h4>
            <div className="space-y-2">
              {Object.entries(metrics.logs_by_level).map(([level, count]) => (
                <div key={level} className="flex justify-between items-center">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${getLevelColor(level)}`}>
                    {level}
                  </span>
                  <span className="text-sm text-gray-600">{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div>
            <h4 className="font-medium mb-2">Top Serviços</h4>
            <div className="space-y-2">
              {metrics.top_services.slice(0, 5).map((service) => (
                <div key={service.service} className="flex justify-between items-center">
                  <span className="text-sm text-gray-900">{service.service}</span>
                  <span className="text-sm text-gray-600">{service.count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Card>
    );
  };

  const renderFilters = () => (
    <Card>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Filtros Avançados</h3>
        <Button variant="secondary" onClick={clearFilters}>
          Limpar Filtros
        </Button>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Busca</label>
          <Input
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            placeholder="Buscar em mensagens, serviços..."
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Tracing ID</label>
          <Input
            value={filters.tracing_id}
            onChange={(e) => handleFilterChange('tracing_id', e.target.value)}
            placeholder="ID de rastreamento"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">User ID</label>
          <Input
            value={filters.user_id}
            onChange={(e) => handleFilterChange('user_id', e.target.value)}
            placeholder="ID do usuário"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Data Inicial</label>
          <Input
            type="datetime-local"
            value={filters.start_date}
            onChange={(e) => handleFilterChange('start_date', e.target.value)}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Data Final</label>
          <Input
            type="datetime-local"
            value={filters.end_date}
            onChange={(e) => handleFilterChange('end_date', e.target.value)}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Modo de Visualização</label>
          <Select
            value={logViewMode}
            onChange={(value) => setLogViewMode(value)}
            options={[
              { value: 'table', label: 'Tabela' },
              { value: 'json', label: 'JSON' },
              { value: 'compact', label: 'Compacto' },
            ]}
          />
        </div>
      </div>
      
      <div className="mt-4">
        <h4 className="font-medium mb-2">Níveis de Log</h4>
        <div className="flex flex-wrap gap-2">
          {['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].map((level) => (
            <label key={level} className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={filters.level.includes(level)}
                onChange={(e) => handleLevelFilter(level, e.target.checked)}
                className="rounded border-gray-300"
              />
              <span className={`px-2 py-1 text-xs font-semibold rounded ${getLevelColor(level)}`}>
                {level}
              </span>
            </label>
          ))}
        </div>
      </div>
      
      <div className="mt-4">
        <h4 className="font-medium mb-2">Serviços</h4>
        <div className="flex flex-wrap gap-2">
          {metrics?.top_services.slice(0, 10).map((service) => (
            <label key={service.service} className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={filters.service.includes(service.service)}
                onChange={(e) => handleServiceFilter(service.service, e.target.checked)}
                className="rounded border-gray-300"
              />
              <span className="text-sm text-gray-700">{service.service}</span>
            </label>
          ))}
        </div>
      </div>
      
      <div className="mt-4 flex items-center space-x-4">
        <label className="flex items-center space-x-2">
          <Switch
            checked={filters.include_audit}
            onChange={(checked) => handleFilterChange('include_audit', checked)}
          />
          <span className="text-sm">Incluir dados de auditoria</span>
        </label>
        
        <label className="flex items-center space-x-2">
          <Switch
            checked={filters.include_metadata}
            onChange={(checked) => handleFilterChange('include_metadata', checked)}
          />
          <span className="text-sm">Incluir metadados</span>
        </label>
      </div>
    </Card>
  );

  const renderExportOptions = () => (
    <Card>
      <h3 className="text-lg font-semibold mb-4">Exportar Logs</h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Formato</label>
          <Select
            value={exportOptions.format}
            onChange={(value) => setExportOptions(prev => ({ ...prev, format: value }))}
            options={[
              { value: 'json', label: 'JSON' },
              { value: 'csv', label: 'CSV' },
              { value: 'txt', label: 'Texto' },
            ]}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Período</label>
          <Select
            value={exportOptions.date_range}
            onChange={(value) => setExportOptions(prev => ({ ...prev, date_range: value }))}
            options={[
              { value: 'all', label: 'Todos' },
              { value: 'today', label: 'Hoje' },
              { value: 'week', label: 'Última Semana' },
              { value: 'month', label: 'Último Mês' },
              { value: 'custom', label: 'Personalizado' },
            ]}
          />
        </div>
        
        {exportOptions.date_range === 'custom' && (
          <>
            <div>
              <label className="block text-sm font-medium mb-2">Data Inicial</label>
              <Input
                type="datetime-local"
                value={exportOptions.custom_start || ''}
                onChange={(e) => setExportOptions(prev => ({ ...prev, custom_start: e.target.value }))}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Data Final</label>
              <Input
                type="datetime-local"
                value={exportOptions.custom_end || ''}
                onChange={(e) => setExportOptions(prev => ({ ...prev, custom_end: e.target.value }))}
              />
            </div>
          </>
        )}
      </div>
      
      <div className="mt-4 flex items-center space-x-4">
        <label className="flex items-center space-x-2">
          <Switch
            checked={exportOptions.include_metadata}
            onChange={(checked) => setExportOptions(prev => ({ ...prev, include_metadata: checked }))}
          />
          <span className="text-sm">Incluir metadados</span>
        </label>
        
        <label className="flex items-center space-x-2">
          <Switch
            checked={exportOptions.include_audit}
            onChange={(checked) => setExportOptions(prev => ({ ...prev, include_audit: checked }))}
          />
          <span className="text-sm">Incluir dados de auditoria</span>
        </label>
      </div>
      
      <div className="mt-4">
        <Button
          onClick={exportLogs}
          disabled={isExporting}
        >
          {isExporting ? 'Exportando...' : 'Exportar Logs'}
        </Button>
      </div>
    </Card>
  );

  return (
    <div className="container mx-auto px-4 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Logs e Auditoria</h1>
        <p className="text-gray-600 mt-2">
          Visualize, filtre e analise logs do sistema em tempo real
        </p>
      </div>
      
      {/* Controles principais */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <Button
            variant="secondary"
            onClick={() => setShowMetrics(!showMetrics)}
          >
            {showMetrics ? 'Ocultar' : 'Mostrar'} Métricas
          </Button>
          
          <Button
            variant="secondary"
            onClick={() => setShowFilters(!showFilters)}
          >
            {showFilters ? 'Ocultar' : 'Mostrar'} Filtros
          </Button>
          
          <Button
            variant="secondary"
            onClick={() => setShowToast(true)}
          >
            Exportar
          </Button>
        </div>
        
        <div className="flex items-center space-x-4">
          <label className="flex items-center space-x-2">
            <Switch
              checked={autoRefresh}
              onChange={setAutoRefresh}
            />
            <span className="text-sm">Auto-refresh</span>
          </label>
          
          {autoRefresh && (
            <Select
              value={refreshInterval.toString()}
              onChange={(value) => setRefreshInterval(parseInt(value))}
              options={[
                { value: '10', label: '10s' },
                { value: '30', label: '30s' },
                { value: '60', label: '1min' },
                { value: '300', label: '5min' },
              ]}
            />
          )}
          
          <Button
            variant="primary"
            onClick={() => {
              loadLogs();
              loadMetrics();
            }}
            disabled={isLoading}
          >
            {isLoading ? 'Carregando...' : 'Atualizar'}
          </Button>
        </div>
      </div>
      
      {/* Métricas */}
      {showMetrics && renderMetrics()}
      
      {/* Filtros */}
      {showFilters && (
        <div className="mb-6">
          {renderFilters()}
        </div>
      )}
      
      {/* Opções de exportação */}
      <div className="mb-6">
        {renderExportOptions()}
      </div>
      
      {/* Logs */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">
            Logs ({filteredLogs.length.toLocaleString()})
          </h3>
          
          <div className="flex items-center space-x-2">
            {selectedLogs.length > 0 && (
              <span className="text-sm text-gray-600">
                {selectedLogs.length} selecionado(s)
              </span>
            )}
            
            <Select
              value={pageSize.toString()}
              onChange={(value) => setPageSize(parseInt(value))}
              options={[
                { value: '50', label: '50 por página' },
                { value: '100', label: '100 por página' },
                { value: '200', label: '200 por página' },
                { value: '500', label: '500 por página' },
              ]}
            />
          </div>
        </div>
        
        <div className="overflow-hidden">
          {logViewMode === 'table' && renderLogTable()}
          {logViewMode === 'json' && renderLogJson()}
          {logViewMode === 'compact' && renderLogCompact()}
        </div>
        
        {hasMore && (
          <div className="mt-4 text-center">
            <Button
              variant="secondary"
              onClick={loadMoreLogs}
              disabled={isLoading}
            >
              {isLoading ? 'Carregando...' : 'Carregar Mais'}
            </Button>
          </div>
        )}
        
        <div ref={logsEndRef} />
      </Card>
      
      {/* Toast */}
      {showToast && (
        <Toast
          message={toastMessage}
          type={toastType}
          onClose={() => setShowToast(false)}
        />
      )}
    </div>
  );
};

export default Logs; 