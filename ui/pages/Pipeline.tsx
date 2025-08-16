/**
 * Página de Pipeline Multi-Instância - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-011
 * Tracing ID: UI_IMPLEMENTATION_20250127_011
 * Data: 2025-01-27T23:45:00Z
 * 
 * Funcionalidades:
 * - Configuração de instâncias múltiplas
 * - Monitoramento em tempo real
 * - Logs detalhados
 * - Controle de execução
 * - Métricas de performance
 * - Status de cada instância
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

interface Instance {
  id: string;
  name: string;
  apiKey: string;
  model: 'openai' | 'deepseek' | 'gemini' | 'claude';
  prompts: string[];
  status: 'idle' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  articlesGenerated: number;
  totalArticles: number;
  startTime?: Date;
  endTime?: Date;
  error?: string;
}

interface PipelineConfig {
  name: string;
  description: string;
  instances: Instance[];
  globalPrompts: string[];
  maxConcurrent: number;
  autoStart: boolean;
  notifications: boolean;
}

interface PipelineStatus {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  totalInstances: number;
  completedInstances: number;
  failedInstances: number;
  startTime?: Date;
  endTime?: Date;
  logs: LogEntry[];
}

interface LogEntry {
  id: string;
  timestamp: Date;
  level: 'info' | 'warning' | 'error' | 'success';
  instance?: string;
  message: string;
  details?: any;
}

interface Metric {
  name: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
}

/**
 * Página principal do Pipeline Multi-Instância
 */
const Pipeline: React.FC = () => {
  const navigation = useNavigation();
  const [config, setConfig] = useState<PipelineConfig>({
    name: '',
    description: '',
    instances: [],
    globalPrompts: [],
    maxConcurrent: 3,
    autoStart: false,
    notifications: true
  });

  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus>({
    id: '',
    status: 'idle',
    progress: 0,
    totalInstances: 0,
    completedInstances: 0,
    failedInstances: 0,
    logs: []
  });

  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [selectedInstance, setSelectedInstance] = useState<Instance | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Simula dados de métricas
  useEffect(() => {
    setMetrics([
      { name: 'Taxa de Sucesso', value: 95.2, unit: '%', trend: 'up' },
      { name: 'Tempo Médio', value: 2.3, unit: 'min', trend: 'down' },
      { name: 'Artigos Gerados', value: 1247, unit: '', trend: 'up' },
      { name: 'Erro Rate', value: 2.1, unit: '%', trend: 'stable' }
    ]);
  }, []);

  // Auto-scroll para logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [pipelineStatus.logs]);

  const addInstance = () => {
    const newInstance: Instance = {
      id: `inst_${Date.now()}`,
      name: `Instância ${config.instances.length + 1}`,
      apiKey: '',
      model: 'openai',
      prompts: [],
      status: 'idle',
      progress: 0,
      articlesGenerated: 0,
      totalArticles: 0
    };

    setConfig(prev => ({
      ...prev,
      instances: [...prev.instances, newInstance]
    }));
  };

  const updateInstance = (id: string, updates: Partial<Instance>) => {
    setConfig(prev => ({
      ...prev,
      instances: prev.instances.map(inst =>
        inst.id === id ? { ...inst, ...updates } : inst
      )
    }));
  };

  const removeInstance = (id: string) => {
    setConfig(prev => ({
      ...prev,
      instances: prev.instances.filter(inst => inst.id !== id)
    }));
  };

  const addGlobalPrompt = () => {
    const prompt = prompt('Digite o prompt global:');
    if (prompt) {
      setConfig(prev => ({
        ...prev,
        globalPrompts: [...prev.globalPrompts, prompt]
      }));
    }
  };

  const removeGlobalPrompt = (index: number) => {
    setConfig(prev => ({
      ...prev,
      globalPrompts: prev.globalPrompts.filter((_, i) => i !== index)
    }));
  };

  const addLog = (entry: Omit<LogEntry, 'id' | 'timestamp'>) => {
    const newEntry: LogEntry = {
      ...entry,
      id: `log_${Date.now()}_${Math.random()}`,
      timestamp: new Date()
    };

    setPipelineStatus(prev => ({
      ...prev,
      logs: [...prev.logs, newEntry]
    }));
  };

  const startPipeline = async () => {
    if (config.instances.length === 0) {
      setError('Adicione pelo menos uma instância');
      return;
    }

    setIsLoading(true);
    setError(null);

    // Simula início do pipeline
    setPipelineStatus(prev => ({
      ...prev,
      id: `pipeline_${Date.now()}`,
      status: 'running',
      startTime: new Date(),
      totalInstances: config.instances.length
    }));

    addLog({
      level: 'info',
      message: 'Pipeline iniciado',
      details: { instances: config.instances.length }
    });

    // Simula execução das instâncias
    for (let i = 0; i < config.instances.length; i++) {
      const instance = config.instances[i];
      
      addLog({
        level: 'info',
        instance: instance.name,
        message: 'Iniciando instância'
      });

      // Simula progresso da instância
      for (let progress = 0; progress <= 100; progress += 10) {
        await new Promise(resolve => setTimeout(resolve, 500));
        
        updateInstance(instance.id, { progress });
        
        if (progress % 30 === 0) {
          addLog({
            level: 'info',
            instance: instance.name,
            message: `Progresso: ${progress}%`
          });
        }
      }

      // Finaliza instância
      updateInstance(instance.id, {
        status: 'completed',
        progress: 100,
        endTime: new Date()
      });

      addLog({
        level: 'success',
        instance: instance.name,
        message: 'Instância concluída com sucesso'
      });

      // Atualiza status do pipeline
      setPipelineStatus(prev => ({
        ...prev,
        completedInstances: prev.completedInstances + 1,
        progress: ((prev.completedInstances + 1) / prev.totalInstances) * 100
      }));
    }

    // Finaliza pipeline
    setPipelineStatus(prev => ({
      ...prev,
      status: 'completed',
      endTime: new Date()
    }));

    addLog({
      level: 'success',
      message: 'Pipeline concluído com sucesso'
    });

    setIsLoading(false);
  };

  const pausePipeline = () => {
    setPipelineStatus(prev => ({ ...prev, status: 'paused' }));
    addLog({
      level: 'warning',
      message: 'Pipeline pausado pelo usuário'
    });
  };

  const resumePipeline = () => {
    setPipelineStatus(prev => ({ ...prev, status: 'running' }));
    addLog({
      level: 'info',
      message: 'Pipeline retomado'
    });
  };

  const stopPipeline = () => {
    setPipelineStatus(prev => ({ ...prev, status: 'idle' }));
    addLog({
      level: 'warning',
      message: 'Pipeline interrompido pelo usuário'
    });
  };

  const clearLogs = () => {
    setPipelineStatus(prev => ({ ...prev, logs: [] }));
  };

  const exportLogs = () => {
    const logsText = pipelineStatus.logs
      .map(log => `[${log.timestamp.toISOString()}] ${log.level.toUpperCase()}: ${log.message}`)
      .join('\n');
    
    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pipeline_logs_${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-blue-600';
      case 'completed': return 'text-green-600';
      case 'failed': return 'text-red-600';
      case 'paused': return 'text-yellow-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return '▶️';
      case 'completed': return '✅';
      case 'failed': return '❌';
      case 'paused': return '⏸️';
      default: return '⏹️';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Pipeline Multi-Instância
          </h1>
          <p className="text-gray-600">
            Configure e execute geração de artigos em múltiplas instâncias simultaneamente
          </p>
        </div>

        {/* Métricas */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          {metrics.map((metric, index) => (
            <Card key={index} className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">{metric.name}</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {metric.value}{metric.unit}
                  </p>
                </div>
                <div className={`text-2xl ${
                  metric.trend === 'up' ? 'text-green-500' :
                  metric.trend === 'down' ? 'text-red-500' : 'text-gray-500'
                }`}>
                  {metric.trend === 'up' ? '↗️' : metric.trend === 'down' ? '↘️' : '→'}
                </div>
              </div>
            </Card>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Configuração */}
          <div className="lg:col-span-1">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-semibold text-gray-900">Configuração</h2>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setShowConfigModal(true)}
                >
                  Editar
                </Button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome do Pipeline
                  </label>
                  <Input
                    value={config.name}
                    onChange={(e) => setConfig(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="Digite o nome do pipeline"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Descrição
                  </label>
                  <textarea
                    value={config.description}
                    onChange={(e) => setConfig(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="Descreva o propósito deste pipeline"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    rows={3}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Instâncias ({config.instances.length})
                  </label>
                  <div className="space-y-2">
                    {config.instances.map((instance) => (
                      <div key={instance.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <span className="text-sm font-medium">{instance.name}</span>
                        <span className={`text-xs px-2 py-1 rounded ${getStatusColor(instance.status)}`}>
                          {getStatusIcon(instance.status)} {instance.status}
                        </span>
                      </div>
                    ))}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={addInstance}
                    className="mt-2"
                  >
                    + Adicionar Instância
                  </Button>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Prompts Globais ({config.globalPrompts.length})
                  </label>
                  <div className="space-y-2">
                    {config.globalPrompts.map((prompt, index) => (
                      <div key={index} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <span className="text-sm truncate flex-1">{prompt}</span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => removeGlobalPrompt(index)}
                          className="text-red-600 hover:text-red-800"
                        >
                          ×
                        </Button>
                      </div>
                    ))}
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={addGlobalPrompt}
                    className="mt-2"
                  >
                    + Adicionar Prompt
                  </Button>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Máximo Concorrente
                  </label>
                  <Select
                    value={config.maxConcurrent.toString()}
                    onChange={(e) => setConfig(prev => ({ ...prev, maxConcurrent: parseInt(e.target.value) }))}
                  >
                    <option value="1">1 instância</option>
                    <option value="2">2 instâncias</option>
                    <option value="3">3 instâncias</option>
                    <option value="5">5 instâncias</option>
                    <option value="10">10 instâncias</option>
                  </Select>
                </div>
              </div>
            </Card>
          </div>

          {/* Status e Controles */}
          <div className="lg:col-span-2">
            <Card className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-semibold text-gray-900">Status do Pipeline</h2>
                <div className="flex items-center space-x-2">
                  <span className={`text-sm font-medium ${getStatusColor(pipelineStatus.status)}`}>
                    {getStatusIcon(pipelineStatus.status)} {pipelineStatus.status.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Progresso */}
              <div className="mb-6">
                <div className="flex justify-between text-sm text-gray-600 mb-2">
                  <span>Progresso Geral</span>
                  <span>{Math.round(pipelineStatus.progress)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${pipelineStatus.progress}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-gray-500 mt-2">
                  <span>{pipelineStatus.completedInstances} de {pipelineStatus.totalInstances} instâncias</span>
                  <span>{pipelineStatus.failedInstances} falharam</span>
                </div>
              </div>

              {/* Controles */}
              <div className="flex space-x-3 mb-6">
                <Button
                  onClick={startPipeline}
                  disabled={isLoading || pipelineStatus.status === 'running'}
                  className="flex-1"
                >
                  {isLoading ? <Loading size="sm" /> : 'Iniciar Pipeline'}
                </Button>
                
                {pipelineStatus.status === 'running' && (
                  <Button
                    variant="secondary"
                    onClick={pausePipeline}
                    className="flex-1"
                  >
                    Pausar
                  </Button>
                )}
                
                {pipelineStatus.status === 'paused' && (
                  <Button
                    variant="secondary"
                    onClick={resumePipeline}
                    className="flex-1"
                  >
                    Retomar
                  </Button>
                )}
                
                <Button
                  variant="outline"
                  onClick={stopPipeline}
                  disabled={pipelineStatus.status === 'idle'}
                  className="flex-1"
                >
                  Parar
                </Button>
              </div>

              {/* Instâncias */}
              <div className="mb-6">
                <h3 className="text-lg font-medium text-gray-900 mb-4">Instâncias</h3>
                <div className="space-y-3">
                  {config.instances.map((instance) => (
                    <div key={instance.id} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{instance.name}</h4>
                        <span className={`text-sm px-2 py-1 rounded ${getStatusColor(instance.status)}`}>
                          {getStatusIcon(instance.status)} {instance.status}
                        </span>
                      </div>
                      
                      <div className="mb-2">
                        <div className="flex justify-between text-sm text-gray-600 mb-1">
                          <span>Progresso</span>
                          <span>{instance.progress}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-1">
                          <div
                            className="bg-green-600 h-1 rounded-full transition-all duration-300"
                            style={{ width: `${instance.progress}%` }}
                          />
                        </div>
                      </div>
                      
                      <div className="flex justify-between text-xs text-gray-500">
                        <span>Modelo: {instance.model}</span>
                        <span>Artigos: {instance.articlesGenerated}/{instance.totalArticles}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Logs */}
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900">Logs Recentes</h3>
                  <div className="flex space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={clearLogs}
                    >
                      Limpar
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={exportLogs}
                    >
                      Exportar
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowLogsModal(true)}
                    >
                      Ver Todos
                    </Button>
                  </div>
                </div>
                
                <div className="bg-gray-900 text-green-400 p-4 rounded-lg h-64 overflow-y-auto font-mono text-sm">
                  {pipelineStatus.logs.slice(-10).map((log) => (
                    <div key={log.id} className="mb-1">
                      <span className="text-gray-500">[{log.timestamp.toLocaleTimeString()}]</span>
                      <span className={`ml-2 ${
                        log.level === 'error' ? 'text-red-400' :
                        log.level === 'warning' ? 'text-yellow-400' :
                        log.level === 'success' ? 'text-green-400' : 'text-blue-400'
                      }`}>
                        {log.level.toUpperCase()}
                      </span>
                      {log.instance && (
                        <span className="text-purple-400 ml-2">[{log.instance}]</span>
                      )}
                      <span className="ml-2">{log.message}</span>
                    </div>
                  ))}
                  <div ref={logsEndRef} />
                </div>
              </div>
            </Card>
          </div>
        </div>

        {/* Modal de Configuração */}
        <Modal
          isOpen={showConfigModal}
          onClose={() => setShowConfigModal(false)}
          title="Configurar Pipeline"
          size="lg"
        >
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Nome do Pipeline
              </label>
              <Input
                value={config.name}
                onChange={(e) => setConfig(prev => ({ ...prev, name: e.target.value }))}
                placeholder="Digite o nome do pipeline"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Descrição
              </label>
              <textarea
                value={config.description}
                onChange={(e) => setConfig(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Descreva o propósito deste pipeline"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                rows={3}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Instâncias
              </label>
              <div className="space-y-3">
                {config.instances.map((instance) => (
                  <div key={instance.id} className="border rounded-lg p-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Nome
                        </label>
                        <Input
                          value={instance.name}
                          onChange={(e) => updateInstance(instance.id, { name: e.target.value })}
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Modelo
                        </label>
                        <Select
                          value={instance.model}
                          onChange={(e) => updateInstance(instance.id, { model: e.target.value as any })}
                        >
                          <option value="openai">OpenAI</option>
                          <option value="deepseek">DeepSeek</option>
                          <option value="gemini">Gemini</option>
                          <option value="claude">Claude</option>
                        </Select>
                      </div>
                    </div>
                    <div className="mt-3">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        API Key
                      </label>
                      <Input
                        type="password"
                        value={instance.apiKey}
                        onChange={(e) => updateInstance(instance.id, { apiKey: e.target.value })}
                        placeholder="sk-..."
                      />
                    </div>
                    <div className="mt-3 flex justify-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeInstance(instance.id)}
                        className="text-red-600 hover:text-red-800"
                      >
                        Remover
                      </Button>
                    </div>
                  </div>
                ))}
                <Button
                  variant="outline"
                  onClick={addInstance}
                  className="w-full"
                >
                  + Adicionar Instância
                </Button>
              </div>
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

        {/* Modal de Logs */}
        <Modal
          isOpen={showLogsModal}
          onClose={() => setShowLogsModal(false)}
          title="Logs do Pipeline"
          size="xl"
        >
          <div className="bg-gray-900 text-green-400 p-4 rounded-lg h-96 overflow-y-auto font-mono text-sm">
            {pipelineStatus.logs.map((log) => (
              <div key={log.id} className="mb-1">
                <span className="text-gray-500">[{log.timestamp.toLocaleString()}]</span>
                <span className={`ml-2 ${
                  log.level === 'error' ? 'text-red-400' :
                  log.level === 'warning' ? 'text-yellow-400' :
                  log.level === 'success' ? 'text-green-400' : 'text-blue-400'
                }`}>
                  {log.level.toUpperCase()}
                </span>
                {log.instance && (
                  <span className="text-purple-400 ml-2">[{log.instance}]</span>
                )}
                <span className="ml-2">{log.message}</span>
              </div>
            ))}
          </div>
          <div className="flex justify-end mt-4">
            <Button
              variant="outline"
              onClick={exportLogs}
            >
              Exportar Logs
            </Button>
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

export default Pipeline; 