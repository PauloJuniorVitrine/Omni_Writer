/**
 * Página de Integrações - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-024
 * Data/Hora: 2025-01-28T01:15:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_002
 * 
 * Funcionalidades:
 * - WordPress plugin mode
 * - API documentation
 * - Webhook configuration
 * - Third-party integrations
 */

import React, { useState, useEffect } from 'react';
import { useI18n } from '../hooks/use_i18n';
import { useTheme } from '../hooks/use_theme';
import { Card } from '../components/base/Card';
import { Button } from '../components/base/Button';
import { Input } from '../components/base/Input';
import { Select } from '../components/base/Select';
import { Modal } from '../components/base/Modal';
import { Toast } from '../components/base/Toast';
import { Loading } from '../components/base/Loading';
import { DataTable } from '../components/DataTable';
import { FileUpload } from '../components/FileUpload';

// ===== TIPOS =====

interface Integration {
  id: string;
  name: string;
  type: 'wordpress' | 'api' | 'webhook' | 'third-party';
  status: 'active' | 'inactive' | 'error' | 'configuring';
  description: string;
  version: string;
  lastSync?: Date;
  config: Record<string, any>;
  health: {
    status: 'healthy' | 'warning' | 'error';
    message: string;
    lastCheck: Date;
  };
}

interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  events: string[];
  active: boolean;
  lastTriggered?: Date;
  successCount: number;
  errorCount: number;
}

interface APIDocumentation {
  endpoint: string;
  method: string;
  description: string;
  parameters: Array<{
    name: string;
    type: string;
    required: boolean;
    description: string;
  }>;
  response: {
    type: string;
    example: any;
  };
}

// ===== DADOS MOCK =====

const mockIntegrations: Integration[] = [
  {
    id: 'wordpress-1',
    name: 'WordPress Plugin',
    type: 'wordpress',
    status: 'active',
    description: 'Plugin oficial do Omni Writer para WordPress',
    version: '2.1.0',
    lastSync: new Date('2025-01-27T10:30:00Z'),
    config: {
      siteUrl: 'https://meublog.com',
      apiKey: 'wp_****_key',
      autoSync: true,
      categories: ['artigos', 'tecnologia']
    },
    health: {
      status: 'healthy',
      message: 'Conectado e sincronizado',
      lastCheck: new Date('2025-01-27T10:30:00Z')
    }
  },
  {
    id: 'webhook-1',
    name: 'Webhook Notifications',
    type: 'webhook',
    status: 'active',
    description: 'Webhook para notificações de novos artigos',
    version: '1.0.0',
    config: {
      url: 'https://api.exemplo.com/webhook',
      events: ['article.created', 'article.published'],
      retryAttempts: 3
    },
    health: {
      status: 'healthy',
      message: 'Funcionando corretamente',
      lastCheck: new Date('2025-01-27T10:25:00Z')
    }
  },
  {
    id: 'api-1',
    name: 'API REST',
    type: 'api',
    status: 'active',
    description: 'API REST para integração externa',
    version: '3.0.0',
    config: {
      baseUrl: 'https://api.omniwriter.com/v3',
      rateLimit: 1000,
      authentication: 'bearer'
    },
    health: {
      status: 'healthy',
      message: 'API disponível',
      lastCheck: new Date('2025-01-27T10:20:00Z')
    }
  }
];

const mockWebhooks: WebhookConfig[] = [
  {
    id: 'wh-1',
    name: 'Notificação de Artigos',
    url: 'https://api.exemplo.com/webhook/articles',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer token123'
    },
    events: ['article.created', 'article.published', 'article.updated'],
    active: true,
    lastTriggered: new Date('2025-01-27T10:30:00Z'),
    successCount: 145,
    errorCount: 2
  },
  {
    id: 'wh-2',
    name: 'Sincronização de Blogs',
    url: 'https://api.exemplo.com/webhook/blogs',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    events: ['blog.created', 'blog.updated'],
    active: true,
    lastTriggered: new Date('2025-01-27T09:15:00Z'),
    successCount: 23,
    errorCount: 0
  }
];

const mockAPIDocs: APIDocumentation[] = [
  {
    endpoint: '/api/v3/articles',
    method: 'GET',
    description: 'Lista todos os artigos com paginação',
    parameters: [
      {
        name: 'page',
        type: 'integer',
        required: false,
        description: 'Número da página (padrão: 1)'
      },
      {
        name: 'limit',
        type: 'integer',
        required: false,
        description: 'Itens por página (padrão: 20, máximo: 100)'
      },
      {
        name: 'category',
        type: 'string',
        required: false,
        description: 'Filtrar por categoria'
      }
    ],
    response: {
      type: 'object',
      example: {
        data: [
          {
            id: '1',
            title: 'Exemplo de Artigo',
            content: 'Conteúdo do artigo...',
            category: 'tecnologia',
            created_at: '2025-01-27T10:00:00Z'
          }
        ],
        pagination: {
          page: 1,
          limit: 20,
          total: 100,
          pages: 5
        }
      }
    }
  },
  {
    endpoint: '/api/v3/articles',
    method: 'POST',
    description: 'Cria um novo artigo',
    parameters: [
      {
        name: 'title',
        type: 'string',
        required: true,
        description: 'Título do artigo'
      },
      {
        name: 'content',
        type: 'string',
        required: true,
        description: 'Conteúdo do artigo'
      },
      {
        name: 'category',
        type: 'string',
        required: false,
        description: 'Categoria do artigo'
      }
    ],
    response: {
      type: 'object',
      example: {
        id: '1',
        title: 'Novo Artigo',
        content: 'Conteúdo...',
        category: 'tecnologia',
        created_at: '2025-01-27T10:00:00Z'
      }
    }
  }
];

// ===== COMPONENTE PRINCIPAL =====

export const Integrations: React.FC = () => {
  const { t } = useI18n();
  const { colors } = useTheme();
  const [activeTab, setActiveTab] = useState<'wordpress' | 'api' | 'webhooks' | 'third-party'>('wordpress');
  const [integrations, setIntegrations] = useState<Integration[]>(mockIntegrations);
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>(mockWebhooks);
  const [apiDocs] = useState<APIDocumentation[]>(mockAPIDocs);
  const [loading, setLoading] = useState(false);
  const [showWordPressModal, setShowWordPressModal] = useState(false);
  const [showWebhookModal, setShowWebhookModal] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null);
  const [selectedWebhook, setSelectedWebhook] = useState<WebhookConfig | null>(null);

  // Estados para formulários
  const [wordPressConfig, setWordPressConfig] = useState({
    siteUrl: '',
    apiKey: '',
    autoSync: true,
    categories: [] as string[]
  });

  const [webhookConfig, setWebhookConfig] = useState({
    name: '',
    url: '',
    method: 'POST' as const,
    headers: {} as Record<string, string>,
    events: [] as string[]
  });

  // Carregar integrações
  useEffect(() => {
    const loadIntegrations = async () => {
      setLoading(true);
      try {
        // Simular chamada API
        await new Promise(resolve => setTimeout(resolve, 1000));
        setIntegrations(mockIntegrations);
      } catch (error) {
        console.error('Erro ao carregar integrações:', error);
      } finally {
        setLoading(false);
      }
    };

    loadIntegrations();
  }, []);

  // Configurar WordPress
  const handleWordPressSetup = async () => {
    setLoading(true);
    try {
      // Simular configuração
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const newIntegration: Integration = {
        id: `wordpress-${Date.now()}`,
        name: 'WordPress Plugin',
        type: 'wordpress',
        status: 'active',
        description: 'Plugin oficial do Omni Writer para WordPress',
        version: '2.1.0',
        lastSync: new Date(),
        config: wordPressConfig,
        health: {
          status: 'healthy',
          message: 'Conectado e sincronizado',
          lastCheck: new Date()
        }
      };

      setIntegrations(prev => [...prev, newIntegration]);
      setShowWordPressModal(false);
      setWordPressConfig({ siteUrl: '', apiKey: '', autoSync: true, categories: [] });
      
      Toast.success('WordPress configurado com sucesso!');
    } catch (error) {
      Toast.error('Erro ao configurar WordPress');
    } finally {
      setLoading(false);
    }
  };

  // Configurar Webhook
  const handleWebhookSetup = async () => {
    setLoading(true);
    try {
      // Simular configuração
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const newWebhook: WebhookConfig = {
        id: `wh-${Date.now()}`,
        name: webhookConfig.name,
        url: webhookConfig.url,
        method: webhookConfig.method,
        headers: webhookConfig.headers,
        events: webhookConfig.events,
        active: true,
        successCount: 0,
        errorCount: 0
      };

      setWebhooks(prev => [...prev, newWebhook]);
      setShowWebhookModal(false);
      setWebhookConfig({ name: '', url: '', method: 'POST', headers: {}, events: [] });
      
      Toast.success('Webhook configurado com sucesso!');
    } catch (error) {
      Toast.error('Erro ao configurar webhook');
    } finally {
      setLoading(false);
    }
  };

  // Testar integração
  const handleTestIntegration = async (integration: Integration) => {
    setLoading(true);
    try {
      // Simular teste
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const updatedIntegration = {
        ...integration,
        health: {
          status: 'healthy' as const,
          message: 'Teste realizado com sucesso',
          lastCheck: new Date()
        }
      };

      setIntegrations(prev => 
        prev.map(i => i.id === integration.id ? updatedIntegration : i)
      );
      
      Toast.success('Teste realizado com sucesso!');
    } catch (error) {
      Toast.error('Erro no teste da integração');
    } finally {
      setLoading(false);
    }
  };

  // Desativar integração
  const handleToggleIntegration = async (integration: Integration) => {
    setLoading(true);
    try {
      const newStatus = integration.status === 'active' ? 'inactive' : 'active';
      const updatedIntegration = { ...integration, status: newStatus };
      
      setIntegrations(prev => 
        prev.map(i => i.id === integration.id ? updatedIntegration : i)
      );
      
      Toast.success(`Integração ${newStatus === 'active' ? 'ativada' : 'desativada'}!`);
    } catch (error) {
      Toast.error('Erro ao alterar status da integração');
    } finally {
      setLoading(false);
    }
  };

  // Renderizar tabela de integrações
  const renderIntegrationsTable = () => {
    const columns = [
      { key: 'name', label: 'Nome', sortable: true },
      { key: 'type', label: 'Tipo', sortable: true },
      { key: 'status', label: 'Status', sortable: true },
      { key: 'version', label: 'Versão', sortable: true },
      { key: 'lastSync', label: 'Última Sincronização', sortable: true },
      { key: 'health', label: 'Saúde', sortable: true },
      { key: 'actions', label: 'Ações', sortable: false }
    ];

    const data = integrations.map(integration => ({
      ...integration,
      type: integration.type === 'wordpress' ? 'WordPress' :
            integration.type === 'api' ? 'API' :
            integration.type === 'webhook' ? 'Webhook' : 'Terceiros',
      status: integration.status === 'active' ? 'Ativo' :
              integration.status === 'inactive' ? 'Inativo' :
              integration.status === 'error' ? 'Erro' : 'Configurando',
      lastSync: integration.lastSync ? integration.lastSync.toLocaleString() : 'Nunca',
      health: integration.health.status === 'healthy' ? 'Saudável' :
              integration.health.status === 'warning' ? 'Atenção' : 'Erro',
      actions: (
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleTestIntegration(integration)}
            disabled={loading}
          >
            Testar
          </Button>
          <Button
            size="sm"
            variant={integration.status === 'active' ? 'secondary' : 'primary'}
            onClick={() => handleToggleIntegration(integration)}
            disabled={loading}
          >
            {integration.status === 'active' ? 'Desativar' : 'Ativar'}
          </Button>
        </div>
      )
    }));

    return (
      <DataTable
        data={data}
        columns={columns}
        pagination={{ enabled: true, pageSize: 10 }}
        search={{ enabled: true }}
        filters={{ enabled: true }}
      />
    );
  };

  // Renderizar tabela de webhooks
  const renderWebhooksTable = () => {
    const columns = [
      { key: 'name', label: 'Nome', sortable: true },
      { key: 'url', label: 'URL', sortable: true },
      { key: 'method', label: 'Método', sortable: true },
      { key: 'events', label: 'Eventos', sortable: true },
      { key: 'active', label: 'Ativo', sortable: true },
      { key: 'lastTriggered', label: 'Último Trigger', sortable: true },
      { key: 'stats', label: 'Estatísticas', sortable: true },
      { key: 'actions', label: 'Ações', sortable: false }
    ];

    const data = webhooks.map(webhook => ({
      ...webhook,
      events: webhook.events.join(', '),
      active: webhook.active ? 'Sim' : 'Não',
      lastTriggered: webhook.lastTriggered ? webhook.lastTriggered.toLocaleString() : 'Nunca',
      stats: `${webhook.successCount} sucessos, ${webhook.errorCount} erros`,
      actions: (
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setSelectedWebhook(webhook);
              setShowWebhookModal(true);
            }}
          >
            Editar
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => {
              // Simular teste de webhook
              Toast.info('Testando webhook...');
            }}
          >
            Testar
          </Button>
        </div>
      )
    }));

    return (
      <DataTable
        data={data}
        columns={columns}
        pagination={{ enabled: true, pageSize: 10 }}
        search={{ enabled: true }}
        filters={{ enabled: true }}
      />
    );
  };

  // Renderizar documentação da API
  const renderAPIDocumentation = () => {
    return (
      <div className="space-y-6">
        <div className="bg-gray-50 p-4 rounded-lg">
          <h3 className="text-lg font-semibold mb-2">Base URL</h3>
          <code className="bg-white px-3 py-2 rounded border text-sm">
            https://api.omniwriter.com/v3
          </code>
        </div>

        <div className="space-y-4">
          {apiDocs.map((doc, index) => (
            <Card key={index} className="p-6">
              <div className="flex items-center space-x-3 mb-4">
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  doc.method === 'GET' ? 'bg-green-100 text-green-800' :
                  doc.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                  doc.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-red-100 text-red-800'
                }`}>
                  {doc.method}
                </span>
                <code className="text-sm font-mono">{doc.endpoint}</code>
              </div>

              <p className="text-gray-600 mb-4">{doc.description}</p>

              {doc.parameters.length > 0 && (
                <div className="mb-4">
                  <h4 className="font-medium mb-2">Parâmetros</h4>
                  <div className="bg-gray-50 rounded p-3">
                    {doc.parameters.map((param, paramIndex) => (
                      <div key={paramIndex} className="flex justify-between items-center py-1">
                        <div>
                          <span className="font-mono text-sm">{param.name}</span>
                          <span className="text-gray-500 text-xs ml-2">({param.type})</span>
                          {param.required && <span className="text-red-500 text-xs ml-1">*</span>}
                        </div>
                        <span className="text-xs text-gray-600">{param.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <h4 className="font-medium mb-2">Resposta</h4>
                <pre className="bg-gray-50 rounded p-3 text-xs overflow-x-auto">
                  {JSON.stringify(doc.response.example, null, 2)}
                </pre>
              </div>
            </Card>
          ))}
        </div>
      </div>
    );
  };

  // Renderizar integrações de terceiros
  const renderThirdPartyIntegrations = () => {
    const thirdPartyServices = [
      {
        name: 'Slack',
        description: 'Envie notificações para canais do Slack',
        icon: '💬',
        status: 'available',
        config: { webhookUrl: '', channel: '' }
      },
      {
        name: 'Discord',
        description: 'Integração com servidores do Discord',
        icon: '🎮',
        status: 'available',
        config: { webhookUrl: '', channel: '' }
      },
      {
        name: 'Email',
        description: 'Envio de emails automáticos',
        icon: '📧',
        status: 'available',
        config: { smtp: '', port: '', username: '', password: '' }
      },
      {
        name: 'Google Drive',
        description: 'Backup automático para Google Drive',
        icon: '☁️',
        status: 'coming-soon',
        config: {}
      }
    ];

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {thirdPartyServices.map((service, index) => (
          <Card key={index} className="p-6">
            <div className="flex items-center space-x-3 mb-4">
              <span className="text-2xl">{service.icon}</span>
              <div>
                <h3 className="font-semibold">{service.name}</h3>
                <p className="text-sm text-gray-600">{service.description}</p>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className={`px-2 py-1 rounded text-xs ${
                service.status === 'available' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
              }`}>
                {service.status === 'available' ? 'Disponível' : 'Em breve'}
              </span>
              
              {service.status === 'available' ? (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => {
                    Toast.info(`Configurando ${service.name}...`);
                  }}
                >
                  Configurar
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="outline"
                  disabled
                >
                  Em breve
                </Button>
              )}
            </div>
          </Card>
        ))}
      </div>
    );
  };

  if (loading) {
    return <Loading type="spinner" text="Carregando integrações..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Integrações</h1>
          <p className="text-gray-600">Gerencie integrações com sistemas externos</p>
        </div>
        
        <div className="flex space-x-3">
          {activeTab === 'wordpress' && (
            <Button
              variant="primary"
              onClick={() => setShowWordPressModal(true)}
            >
              Configurar WordPress
            </Button>
          )}
          
          {activeTab === 'webhooks' && (
            <Button
              variant="primary"
              onClick={() => setShowWebhookModal(true)}
            >
              Novo Webhook
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'wordpress', label: 'WordPress', icon: '🔌' },
            { id: 'api', label: 'API', icon: '📚' },
            { id: 'webhooks', label: 'Webhooks', icon: '🔗' },
            { id: 'third-party', label: 'Terceiros', icon: '🔌' }
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
        {activeTab === 'wordpress' && (
          <div className="space-y-6">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h3 className="font-medium text-blue-900 mb-2">Plugin WordPress</h3>
              <p className="text-blue-700 text-sm mb-3">
                Instale o plugin oficial do Omni Writer no seu WordPress para sincronização automática de artigos.
              </p>
              <div className="flex space-x-3">
                <Button size="sm" variant="primary">
                  Download Plugin
                </Button>
                <Button size="sm" variant="outline">
                  Ver Documentação
                </Button>
              </div>
            </div>
            
            {renderIntegrationsTable()}
          </div>
        )}

        {activeTab === 'api' && (
          <div className="space-y-6">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <h3 className="font-medium text-green-900 mb-2">API REST</h3>
              <p className="text-green-700 text-sm">
                Use nossa API REST para integrar o Omni Writer com seus sistemas personalizados.
              </p>
            </div>
            
            {renderAPIDocumentation()}
          </div>
        )}

        {activeTab === 'webhooks' && (
          <div className="space-y-6">
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <h3 className="font-medium text-purple-900 mb-2">Webhooks</h3>
              <p className="text-purple-700 text-sm">
                Configure webhooks para receber notificações em tempo real sobre eventos do sistema.
              </p>
            </div>
            
            {renderWebhooksTable()}
          </div>
        )}

        {activeTab === 'third-party' && (
          <div className="space-y-6">
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <h3 className="font-medium text-orange-900 mb-2">Integrações de Terceiros</h3>
              <p className="text-orange-700 text-sm">
                Conecte o Omni Writer com suas ferramentas favoritas.
              </p>
            </div>
            
            {renderThirdPartyIntegrations()}
          </div>
        )}
      </div>

      {/* Modal WordPress */}
      <Modal
        isOpen={showWordPressModal}
        onClose={() => setShowWordPressModal(false)}
        title="Configurar WordPress"
        size="lg"
      >
        <div className="space-y-4">
          <Input
            label="URL do Site"
            placeholder="https://meublog.com"
            value={wordPressConfig.siteUrl}
            onChange={(e) => setWordPressConfig(prev => ({ ...prev, siteUrl: e.target.value }))}
            required
          />
          
          <Input
            label="Chave da API"
            placeholder="wp_****_key"
            value={wordPressConfig.apiKey}
            onChange={(e) => setWordPressConfig(prev => ({ ...prev, apiKey: e.target.value }))}
            type="password"
            required
          />
          
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              id="autoSync"
              checked={wordPressConfig.autoSync}
              onChange={(e) => setWordPressConfig(prev => ({ ...prev, autoSync: e.target.checked }))}
            />
            <label htmlFor="autoSync" className="text-sm">Sincronização automática</label>
          </div>
        </div>
        
        <div className="flex justify-end space-x-3 mt-6">
          <Button
            variant="outline"
            onClick={() => setShowWordPressModal(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            onClick={handleWordPressSetup}
            disabled={loading || !wordPressConfig.siteUrl || !wordPressConfig.apiKey}
          >
            {loading ? 'Configurando...' : 'Configurar'}
          </Button>
        </div>
      </Modal>

      {/* Modal Webhook */}
      <Modal
        isOpen={showWebhookModal}
        onClose={() => setShowWebhookModal(false)}
        title={selectedWebhook ? 'Editar Webhook' : 'Novo Webhook'}
        size="lg"
      >
        <div className="space-y-4">
          <Input
            label="Nome"
            placeholder="Nome do webhook"
            value={webhookConfig.name}
            onChange={(e) => setWebhookConfig(prev => ({ ...prev, name: e.target.value }))}
            required
          />
          
          <Input
            label="URL"
            placeholder="https://api.exemplo.com/webhook"
            value={webhookConfig.url}
            onChange={(e) => setWebhookConfig(prev => ({ ...prev, url: e.target.value }))}
            required
          />
          
          <Select
            label="Método"
            value={webhookConfig.method}
            onChange={(value) => setWebhookConfig(prev => ({ ...prev, method: value as any }))}
            options={[
              { value: 'GET', label: 'GET' },
              { value: 'POST', label: 'POST' },
              { value: 'PUT', label: 'PUT' },
              { value: 'DELETE', label: 'DELETE' }
            ]}
          />
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Eventos
            </label>
            <div className="space-y-2">
              {[
                'article.created',
                'article.published',
                'article.updated',
                'blog.created',
                'blog.updated'
              ].map((event) => (
                <div key={event} className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id={event}
                    checked={webhookConfig.events.includes(event)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setWebhookConfig(prev => ({
                          ...prev,
                          events: [...prev.events, event]
                        }));
                      } else {
                        setWebhookConfig(prev => ({
                          ...prev,
                          events: prev.events.filter(e => e !== event)
                        }));
                      }
                    }}
                  />
                  <label htmlFor={event} className="text-sm">{event}</label>
                </div>
              ))}
            </div>
          </div>
        </div>
        
        <div className="flex justify-end space-x-3 mt-6">
          <Button
            variant="outline"
            onClick={() => setShowWebhookModal(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            onClick={handleWebhookSetup}
            disabled={loading || !webhookConfig.name || !webhookConfig.url}
          >
            {loading ? 'Configurando...' : 'Salvar'}
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default Integrations; 