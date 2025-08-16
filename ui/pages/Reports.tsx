/**
 * Página de Exportação e Relatórios - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-023
 * Data/Hora: 2025-01-28T00:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_001
 * 
 * Funcionalidades:
 * - Geração de PDF
 * - Exportação Excel
 * - Relatórios customizados
 * - Relatórios agendados
 * - Templates de relatórios
 * - Preview de relatórios
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/base/Card';
import { Button } from '../components/base/Button';
import { Input } from '../components/base/Input';
import { Select } from '../components/base/Select';
import { Switch } from '../components/base/Switch';
import { Modal } from '../components/base/Modal';
import { Loading } from '../components/base/Loading';
import { Toast } from '../components/base/Toast';
import { useI18n } from '../hooks/use_i18n';
import { useApi } from '../hooks/use_api';

// ===== TIPOS =====

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: 'pdf' | 'excel' | 'custom';
  category: 'articles' | 'blogs' | 'prompts' | 'analytics' | 'system';
  fields: string[];
  filters: ReportFilter[];
  schedule?: ReportSchedule;
}

interface ReportFilter {
  field: string;
  label: string;
  type: 'date' | 'select' | 'text' | 'number' | 'boolean';
  options?: string[];
  required: boolean;
  defaultValue?: any;
}

interface ReportSchedule {
  enabled: boolean;
  frequency: 'daily' | 'weekly' | 'monthly' | 'custom';
  time: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
  recipients: string[];
  format: 'pdf' | 'excel' | 'both';
}

interface ReportData {
  id: string;
  name: string;
  type: 'pdf' | 'excel' | 'custom';
  status: 'pending' | 'generating' | 'completed' | 'failed';
  progress: number;
  createdAt: string;
  completedAt?: string;
  downloadUrl?: string;
  error?: string;
  size?: number;
}

interface ExportOptions {
  format: 'pdf' | 'excel' | 'csv' | 'json';
  includeCharts: boolean;
  includeMetadata: boolean;
  compression: boolean;
  password?: string;
  watermark?: string;
  customStyling: boolean;
}

// ===== DADOS MOCK =====

const mockTemplates: ReportTemplate[] = [
  {
    id: 'articles-summary',
    name: 'Resumo de Artigos',
    description: 'Relatório completo de artigos gerados com métricas e análises',
    type: 'pdf',
    category: 'articles',
    fields: ['title', 'content', 'category', 'created_at', 'word_count', 'seo_score'],
    filters: [
      { field: 'date_range', label: 'Período', type: 'date', required: true },
      { field: 'category', label: 'Categoria', type: 'select', options: ['Tecnologia', 'Marketing', 'Saúde'], required: false },
      { field: 'min_words', label: 'Mínimo de palavras', type: 'number', required: false, defaultValue: 500 }
    ]
  },
  {
    id: 'blogs-performance',
    name: 'Performance dos Blogs',
    description: 'Análise de performance e engajamento dos blogs',
    type: 'excel',
    category: 'blogs',
    fields: ['blog_name', 'articles_count', 'total_views', 'avg_engagement', 'seo_score'],
    filters: [
      { field: 'date_range', label: 'Período', type: 'date', required: true },
      { field: 'min_views', label: 'Mínimo de visualizações', type: 'number', required: false }
    ]
  },
  {
    id: 'prompts-analysis',
    name: 'Análise de Prompts',
    description: 'Relatório detalhado sobre eficácia dos prompts',
    type: 'custom',
    category: 'prompts',
    fields: ['prompt_name', 'usage_count', 'success_rate', 'avg_response_time', 'user_rating'],
    filters: [
      { field: 'category', label: 'Categoria', type: 'select', options: ['Marketing', 'Técnico', 'Criativo'], required: false },
      { field: 'min_usage', label: 'Mínimo de usos', type: 'number', required: false }
    ]
  },
  {
    id: 'system-analytics',
    name: 'Analytics do Sistema',
    description: 'Métricas de performance e uso do sistema',
    type: 'pdf',
    category: 'analytics',
    fields: ['metric_name', 'value', 'trend', 'timestamp', 'category'],
    filters: [
      { field: 'date_range', label: 'Período', type: 'date', required: true },
      { field: 'metric_type', label: 'Tipo de Métrica', type: 'select', options: ['Performance', 'Uso', 'Erros'], required: false }
    ]
  }
];

const mockReportData: ReportData[] = [
  {
    id: '1',
    name: 'Resumo de Artigos - Janeiro 2025',
    type: 'pdf',
    status: 'completed',
    progress: 100,
    createdAt: '2025-01-27T10:00:00Z',
    completedAt: '2025-01-27T10:05:00Z',
    downloadUrl: '/reports/1.pdf',
    size: 2048576
  },
  {
    id: '2',
    name: 'Performance dos Blogs - Dezembro 2024',
    type: 'excel',
    status: 'generating',
    progress: 65,
    createdAt: '2025-01-27T11:00:00Z'
  },
  {
    id: '3',
    name: 'Análise de Prompts - Q4 2024',
    type: 'custom',
    status: 'failed',
    progress: 0,
    createdAt: '2025-01-27T12:00:00Z',
    error: 'Erro na geração do relatório: dados insuficientes'
  }
];

// ===== COMPONENTE PRINCIPAL =====

export const Reports: React.FC = () => {
  const { t } = useI18n();
  const { apiCall } = useApi();
  
  // Estados principais
  const [templates, setTemplates] = useState<ReportTemplate[]>(mockTemplates);
  const [reports, setReports] = useState<ReportData[]>(mockReportData);
  const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplate | null>(null);
  const [selectedReport, setSelectedReport] = useState<ReportData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [activeTab, setActiveTab] = useState<'templates' | 'reports' | 'scheduled'>('templates');
  
  // Estados de filtros e opções
  const [filters, setFilters] = useState<Record<string, any>>({});
  const [exportOptions, setExportOptions] = useState<ExportOptions>({
    format: 'pdf',
    includeCharts: true,
    includeMetadata: true,
    compression: false,
    customStyling: false
  });
  
  // Estados de feedback
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error' | 'warning'>('success');

  // ===== FUNÇÕES PRINCIPAIS =====

  const generateReport = async () => {
    if (!selectedTemplate) return;
    
    setIsGenerating(true);
    try {
      const response = await apiCall('/api/reports/generate', 'POST', {
        template_id: selectedTemplate.id,
        filters,
        options: exportOptions
      });
      
      if (response.success) {
        const newReport: ReportData = {
          id: response.data.id,
          name: `${selectedTemplate.name} - ${new Date().toLocaleDateString()}`,
          type: selectedTemplate.type,
          status: 'generating',
          progress: 0,
          createdAt: new Date().toISOString()
        };
        
        setReports(prev => [newReport, ...prev]);
        setShowTemplateModal(false);
        setFilters({});
        
        setToastMessage('Relatório iniciado com sucesso');
        setToastType('success');
        setShowToast(true);
        
        // Simular progresso
        simulateReportProgress(newReport.id);
      }
    } catch (error) {
      console.error('Erro ao gerar relatório:', error);
      setToastMessage('Erro ao gerar relatório');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsGenerating(false);
    }
  };

  const simulateReportProgress = (reportId: string) => {
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 20;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        
        setReports(prev => prev.map(report => 
          report.id === reportId 
            ? { 
                ...report, 
                status: 'completed', 
                progress: 100, 
                completedAt: new Date().toISOString(),
                downloadUrl: `/reports/${reportId}.${report.type}`,
                size: Math.floor(Math.random() * 5000000) + 1000000
              }
            : report
        ));
      } else {
        setReports(prev => prev.map(report => 
          report.id === reportId 
            ? { ...report, progress: Math.min(progress, 99) }
            : report
        ));
      }
    }, 1000);
  };

  const downloadReport = async (report: ReportData) => {
    if (!report.downloadUrl) return;
    
    try {
      const response = await apiCall(report.downloadUrl, 'GET');
      if (response.success) {
        const blob = new Blob([response.data], { 
          type: report.type === 'pdf' ? 'application/pdf' : 
                report.type === 'excel' ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' :
                'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.name}.${report.type}`;
        a.click();
        URL.revokeObjectURL(url);
        
        setToastMessage('Relatório baixado com sucesso');
        setToastType('success');
        setShowToast(true);
      }
    } catch (error) {
      console.error('Erro ao baixar relatório:', error);
      setToastMessage('Erro ao baixar relatório');
      setToastType('error');
      setShowToast(true);
    }
  };

  const deleteReport = async (reportId: string) => {
    try {
      const response = await apiCall(`/api/reports/${reportId}`, 'DELETE');
      if (response.success) {
        setReports(prev => prev.filter(report => report.id !== reportId));
        setToastMessage('Relatório excluído com sucesso');
        setToastType('success');
        setShowToast(true);
      }
    } catch (error) {
      console.error('Erro ao excluir relatório:', error);
      setToastMessage('Erro ao excluir relatório');
      setToastType('error');
      setShowToast(true);
    }
  };

  const scheduleReport = async (schedule: ReportSchedule) => {
    if (!selectedTemplate) return;
    
    try {
      const response = await apiCall('/api/reports/schedule', 'POST', {
        template_id: selectedTemplate.id,
        schedule,
        filters,
        options: exportOptions
      });
      
      if (response.success) {
        setShowScheduleModal(false);
        setToastMessage('Relatório agendado com sucesso');
        setToastType('success');
        setShowToast(true);
      }
    } catch (error) {
      console.error('Erro ao agendar relatório:', error);
      setToastMessage('Erro ao agendar relatório');
      setToastType('error');
      setShowToast(true);
    }
  };

  // ===== RENDERIZAÇÃO =====

  const renderTemplateCard = (template: ReportTemplate) => (
    <Card key={template.id} className="hover:shadow-lg transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            {template.name}
          </h3>
          <p className="text-gray-600 text-sm mb-3">
            {template.description}
          </p>
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span className={`px-2 py-1 rounded-full ${
              template.type === 'pdf' ? 'bg-red-100 text-red-800' :
              template.type === 'excel' ? 'bg-green-100 text-green-800' :
              'bg-blue-100 text-blue-800'
            }`}>
              {template.type.toUpperCase()}
            </span>
            <span className="capitalize">{template.category}</span>
            <span>{template.fields.length} campos</span>
          </div>
        </div>
        <div className="flex space-x-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setSelectedTemplate(template);
              setShowPreviewModal(true);
            }}
          >
            👁️ Preview
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              setSelectedTemplate(template);
              setShowTemplateModal(true);
            }}
          >
            📊 Gerar
          </Button>
        </div>
      </div>
    </Card>
  );

  const renderReportCard = (report: ReportData) => (
    <Card key={report.id} className="hover:shadow-lg transition-shadow">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            {report.name}
          </h3>
          <div className="flex items-center space-x-4 text-sm text-gray-600 mb-3">
            <span className={`px-2 py-1 rounded-full ${
              report.type === 'pdf' ? 'bg-red-100 text-red-800' :
              report.type === 'excel' ? 'bg-green-100 text-green-800' :
              'bg-blue-100 text-blue-800'
            }`}>
              {report.type.toUpperCase()}
            </span>
            <span>{new Date(report.createdAt).toLocaleDateString()}</span>
            {report.size && (
              <span>{(report.size / 1024 / 1024).toFixed(1)} MB</span>
            )}
          </div>
          
          {/* Progresso */}
          {report.status === 'generating' && (
            <div className="mb-3">
              <div className="flex justify-between text-xs text-gray-600 mb-1">
                <span>Gerando...</span>
                <span>{report.progress}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div 
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${report.progress}%` }}
                />
              </div>
            </div>
          )}
          
          {/* Status */}
          <div className={`text-sm ${
            report.status === 'completed' ? 'text-green-600' :
            report.status === 'failed' ? 'text-red-600' :
            report.status === 'generating' ? 'text-blue-600' :
            'text-yellow-600'
          }`}>
            {report.status === 'completed' && '✅ Concluído'}
            {report.status === 'generating' && '⏳ Gerando...'}
            {report.status === 'failed' && '❌ Falhou'}
            {report.status === 'pending' && '⏸️ Pendente'}
          </div>
          
          {report.error && (
            <p className="text-red-600 text-xs mt-2">{report.error}</p>
          )}
        </div>
        
        <div className="flex space-x-2">
          {report.status === 'completed' && report.downloadUrl && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => downloadReport(report)}
            >
              📥 Baixar
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setSelectedReport(report);
              setShowReportModal(true);
            }}
          >
            ℹ️ Detalhes
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => deleteReport(report.id)}
          >
            🗑️ Excluir
          </Button>
        </div>
      </div>
    </Card>
  );

  const renderTemplateModal = () => (
    <Modal
      isOpen={showTemplateModal}
      onClose={() => setShowTemplateModal(false)}
      title={`Gerar Relatório: ${selectedTemplate?.name}`}
      size="xl"
    >
      {selectedTemplate && (
        <div className="space-y-6">
          {/* Filtros */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Filtros</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {selectedTemplate.filters.map((filter) => (
                <div key={filter.field}>
                  <label className="block text-sm font-medium mb-2">
                    {filter.label}
                    {filter.required && <span className="text-red-500">*</span>}
                  </label>
                  {filter.type === 'date' && (
                    <Input
                      type="date"
                      value={filters[filter.field] || ''}
                      onChange={(e) => setFilters(prev => ({ ...prev, [filter.field]: e.target.value }))}
                      required={filter.required}
                    />
                  )}
                  {filter.type === 'select' && (
                    <Select
                      value={filters[filter.field] || ''}
                      onChange={(value) => setFilters(prev => ({ ...prev, [filter.field]: value }))}
                      options={filter.options?.map(opt => ({ value: opt, label: opt })) || []}
                      placeholder={`Selecione ${filter.label.toLowerCase()}`}
                    />
                  )}
                  {filter.type === 'text' && (
                    <Input
                      type="text"
                      value={filters[filter.field] || ''}
                      onChange={(e) => setFilters(prev => ({ ...prev, [filter.field]: e.target.value }))}
                      placeholder={`Digite ${filter.label.toLowerCase()}`}
                      required={filter.required}
                    />
                  )}
                  {filter.type === 'number' && (
                    <Input
                      type="number"
                      value={filters[filter.field] || ''}
                      onChange={(e) => setFilters(prev => ({ ...prev, [filter.field]: e.target.value }))}
                      placeholder={`Digite ${filter.label.toLowerCase()}`}
                      required={filter.required}
                    />
                  )}
                  {filter.type === 'boolean' && (
                    <Switch
                      checked={filters[filter.field] || false}
                      onChange={(checked) => setFilters(prev => ({ ...prev, [filter.field]: checked }))}
                    />
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Opções de Exportação */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Opções de Exportação</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Formato</label>
                <Select
                  value={exportOptions.format}
                  onChange={(value) => setExportOptions(prev => ({ ...prev, format: value as any }))}
                  options={[
                    { value: 'pdf', label: 'PDF' },
                    { value: 'excel', label: 'Excel' },
                    { value: 'csv', label: 'CSV' },
                    { value: 'json', label: 'JSON' }
                  ]}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Senha (opcional)</label>
                <Input
                  type="password"
                  value={exportOptions.password || ''}
                  onChange={(e) => setExportOptions(prev => ({ ...prev, password: e.target.value }))}
                  placeholder="Senha para proteger o arquivo"
                />
              </div>
            </div>
            
            <div className="mt-4 space-y-3">
              <label className="flex items-center space-x-2">
                <Switch
                  checked={exportOptions.includeCharts}
                  onChange={(checked) => setExportOptions(prev => ({ ...prev, includeCharts: checked }))}
                />
                <span className="text-sm">Incluir gráficos</span>
              </label>
              
              <label className="flex items-center space-x-2">
                <Switch
                  checked={exportOptions.includeMetadata}
                  onChange={(checked) => setExportOptions(prev => ({ ...prev, includeMetadata: checked }))}
                />
                <span className="text-sm">Incluir metadados</span>
              </label>
              
              <label className="flex items-center space-x-2">
                <Switch
                  checked={exportOptions.compression}
                  onChange={(checked) => setExportOptions(prev => ({ ...prev, compression: checked }))}
                />
                <span className="text-sm">Comprimir arquivo</span>
              </label>
              
              <label className="flex items-center space-x-2">
                <Switch
                  checked={exportOptions.customStyling}
                  onChange={(checked) => setExportOptions(prev => ({ ...prev, customStyling: checked }))}
                />
                <span className="text-sm">Estilo personalizado</span>
              </label>
            </div>
          </div>

          {/* Ações */}
          <div className="flex justify-end space-x-3 pt-4 border-t">
            <Button
              variant="outline"
              onClick={() => setShowScheduleModal(true)}
            >
              📅 Agendar
            </Button>
            <Button
              variant="primary"
              onClick={generateReport}
              disabled={isGenerating}
            >
              {isGenerating ? (
                <>
                  <Loading size="sm" />
                  Gerando...
                </>
              ) : (
                'Gerar Relatório'
              )}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );

  const renderReportModal = () => (
    <Modal
      isOpen={showReportModal}
      onClose={() => setShowReportModal(false)}
      title={`Detalhes do Relatório: ${selectedReport?.name}`}
      size="lg"
    >
      {selectedReport && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Status:</span>
              <span className={`ml-2 ${
                selectedReport.status === 'completed' ? 'text-green-600' :
                selectedReport.status === 'failed' ? 'text-red-600' :
                selectedReport.status === 'generating' ? 'text-blue-600' :
                'text-yellow-600'
              }`}>
                {selectedReport.status}
              </span>
            </div>
            <div>
              <span className="font-medium">Tipo:</span>
              <span className="ml-2">{selectedReport.type.toUpperCase()}</span>
            </div>
            <div>
              <span className="font-medium">Criado em:</span>
              <span className="ml-2">{new Date(selectedReport.createdAt).toLocaleString()}</span>
            </div>
            {selectedReport.completedAt && (
              <div>
                <span className="font-medium">Concluído em:</span>
                <span className="ml-2">{new Date(selectedReport.completedAt).toLocaleString()}</span>
              </div>
            )}
            {selectedReport.size && (
              <div>
                <span className="font-medium">Tamanho:</span>
                <span className="ml-2">{(selectedReport.size / 1024 / 1024).toFixed(1)} MB</span>
              </div>
            )}
          </div>
          
          {selectedReport.error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-3">
              <h4 className="font-medium text-red-800 mb-2">Erro:</h4>
              <p className="text-red-700 text-sm">{selectedReport.error}</p>
            </div>
          )}
          
          {selectedReport.status === 'completed' && selectedReport.downloadUrl && (
            <div className="flex justify-end">
              <Button
                variant="primary"
                onClick={() => downloadReport(selectedReport)}
              >
                📥 Baixar Relatório
              </Button>
            </div>
          )}
        </div>
      )}
    </Modal>
  );

  const renderScheduleModal = () => (
    <Modal
      isOpen={showScheduleModal}
      onClose={() => setShowScheduleModal(false)}
      title="Agendar Relatório"
      size="lg"
    >
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2">Frequência</label>
          <Select
            value="weekly"
            onChange={() => {}}
            options={[
              { value: 'daily', label: 'Diário' },
              { value: 'weekly', label: 'Semanal' },
              { value: 'monthly', label: 'Mensal' },
              { value: 'custom', label: 'Personalizado' }
            ]}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Horário</label>
          <Input
            type="time"
            value="09:00"
            onChange={() => {}}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Destinatários (emails separados por vírgula)</label>
          <Input
            type="text"
            placeholder="usuario@exemplo.com, admin@exemplo.com"
            onChange={() => {}}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Formato</label>
          <Select
            value="pdf"
            onChange={() => {}}
            options={[
              { value: 'pdf', label: 'PDF' },
              { value: 'excel', label: 'Excel' },
              { value: 'both', label: 'Ambos' }
            ]}
          />
        </div>
        
        <div className="flex justify-end space-x-3 pt-4">
          <Button
            variant="outline"
            onClick={() => setShowScheduleModal(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              scheduleReport({
                enabled: true,
                frequency: 'weekly',
                time: '09:00',
                recipients: ['admin@exemplo.com'],
                format: 'pdf'
              });
            }}
          >
            Agendar
          </Button>
        </div>
      </div>
    </Modal>
  );

  const renderPreviewModal = () => (
    <Modal
      isOpen={showPreviewModal}
      onClose={() => setShowPreviewModal(false)}
      title={`Preview: ${selectedTemplate?.name}`}
      size="xl"
    >
      {selectedTemplate && (
        <div className="space-y-4">
          <div className="bg-gray-50 p-4 rounded-lg">
            <h4 className="font-medium mb-2">Campos incluídos:</h4>
            <div className="flex flex-wrap gap-2">
              {selectedTemplate.fields.map((field) => (
                <span key={field} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-sm">
                  {field}
                </span>
              ))}
            </div>
          </div>
          
          <div className="bg-gray-50 p-4 rounded-lg">
            <h4 className="font-medium mb-2">Filtros disponíveis:</h4>
            <div className="space-y-2">
              {selectedTemplate.filters.map((filter) => (
                <div key={filter.field} className="flex items-center justify-between">
                  <span className="text-sm">{filter.label}</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    filter.required ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {filter.required ? 'Obrigatório' : 'Opcional'}
                  </span>
                </div>
              ))}
            </div>
          </div>
          
          <div className="flex justify-end">
            <Button
              variant="primary"
              onClick={() => {
                setShowPreviewModal(false);
                setShowTemplateModal(true);
              }}
            >
              Gerar Relatório
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 mb-2">
                Exportação e Relatórios
              </h1>
              <p className="text-gray-600">
                Gere relatórios personalizados, exporte dados e agende relatórios automáticos
              </p>
            </div>
            <div className="flex space-x-3">
              <Button
                variant="outline"
                onClick={() => setActiveTab('templates')}
              >
                📊 Templates
              </Button>
              <Button
                variant="outline"
                onClick={() => setActiveTab('reports')}
              >
                📋 Relatórios
              </Button>
              <Button
                variant="outline"
                onClick={() => setActiveTab('scheduled')}
              >
                📅 Agendados
              </Button>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8">
              <button
                onClick={() => setActiveTab('templates')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'templates'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                📊 Templates ({templates.length})
              </button>
              <button
                onClick={() => setActiveTab('reports')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'reports'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                📋 Relatórios ({reports.length})
              </button>
              <button
                onClick={() => setActiveTab('scheduled')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'scheduled'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                📅 Agendados (0)
              </button>
            </nav>
          </div>
        </div>

        {/* Conteúdo das Tabs */}
        {activeTab === 'templates' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {templates.map(renderTemplateCard)}
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="space-y-6">
            {reports.length === 0 ? (
              <Card>
                <div className="text-center py-12">
                  <div className="text-6xl mb-4">📋</div>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">
                    Nenhum relatório encontrado
                  </h3>
                  <p className="text-gray-600 mb-4">
                    Gere seu primeiro relatório usando um dos templates disponíveis
                  </p>
                  <Button
                    variant="primary"
                    onClick={() => setActiveTab('templates')}
                  >
                    Ver Templates
                  </Button>
                </div>
              </Card>
            ) : (
              reports.map(renderReportCard)
            )}
          </div>
        )}

        {activeTab === 'scheduled' && (
          <Card>
            <div className="text-center py-12">
              <div className="text-6xl mb-4">📅</div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Nenhum relatório agendado
              </h3>
              <p className="text-gray-600 mb-4">
                Agende relatórios automáticos para receber atualizações regulares
              </p>
              <Button
                variant="primary"
                onClick={() => setActiveTab('templates')}
              >
                Agendar Relatório
              </Button>
            </div>
          </Card>
        )}

        {/* Modais */}
        {renderTemplateModal()}
        {renderReportModal()}
        {renderScheduleModal()}
        {renderPreviewModal()}

        {/* Toast */}
        {showToast && (
          <Toast
            type={toastType}
            message={toastMessage}
            onClose={() => setShowToast(false)}
          />
        )}
      </div>
    </div>
  );
};

export default Reports; 