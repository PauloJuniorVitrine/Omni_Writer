/**
 * Página de Configurações - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-017
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Configurações gerais do sistema
 * - Configurações de API e provedores
 * - Configurações de segurança
 * - Backup e restauração
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, Button, Input, Select, Switch, Textarea, Toast } from '../components/base';
import { useApi } from '../hooks/use_api';
import { useI18n } from '../hooks/use_i18n';

interface SettingsData {
  general: {
    language: string;
    theme: 'light' | 'dark' | 'auto';
    autoSave: boolean;
    notifications: boolean;
    maxWorkers: number;
    enableCache: boolean;
  };
  api: {
    openaiApiKey: string;
    deepseekApiKey: string;
    openaiEndpoint: string;
    deepseekEndpoint: string;
    timeout: number;
    maxRetries: number;
    enableRateLimiting: boolean;
  };
  security: {
    enableAuditLog: boolean;
    sessionTimeout: number;
    maxLoginAttempts: number;
    enable2FA: boolean;
    dataEncryption: boolean;
    secureHeaders: boolean;
  };
  backup: {
    autoBackup: boolean;
    backupInterval: number;
    maxBackups: number;
    backupLocation: string;
    enableCompression: boolean;
  };
}

interface ValidationErrors {
  [key: string]: string;
}

const Settings: React.FC = () => {
  const { t } = useI18n();
  const { apiCall } = useApi();
  
  const [activeTab, setActiveTab] = useState<'general' | 'api' | 'security' | 'backup'>('general');
  const [settings, setSettings] = useState<SettingsData>({
    general: {
      language: 'pt-BR',
      theme: 'auto',
      autoSave: true,
      notifications: true,
      maxWorkers: 5,
      enableCache: true,
    },
    api: {
      openaiApiKey: '',
      deepseekApiKey: '',
      openaiEndpoint: 'https://api.openai.com/v1/chat/completions',
      deepseekEndpoint: 'https://api.deepseek.com/v1/chat/completions',
      timeout: 30,
      maxRetries: 3,
      enableRateLimiting: true,
    },
    security: {
      enableAuditLog: true,
      sessionTimeout: 3600,
      maxLoginAttempts: 5,
      enable2FA: false,
      dataEncryption: true,
      secureHeaders: true,
    },
    backup: {
      autoBackup: true,
      backupInterval: 24,
      maxBackups: 7,
      backupLocation: './backups',
      enableCompression: true,
    },
  });
  
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error'>('success');

  // Carregar configurações iniciais
  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await apiCall('/api/settings', 'GET');
      if (response.success) {
        setSettings(response.data);
      }
    } catch (error) {
      console.error('Erro ao carregar configurações:', error);
      setToastMessage('Erro ao carregar configurações');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsLoading(false);
    }
  }, [apiCall]);

  const validateField = (section: keyof SettingsData, field: string, value: any): string => {
    switch (section) {
      case 'general':
        if (field === 'maxWorkers' && (value < 1 || value > 20)) {
          return 'Número de workers deve estar entre 1 e 20';
        }
        break;
      case 'api':
        if (field === 'openaiApiKey' && value && !value.startsWith('sk-')) {
          return 'Chave da API OpenAI deve começar com "sk-"';
        }
        if (field === 'deepseekApiKey' && value && !value.startsWith('sk-')) {
          return 'Chave da API DeepSeek deve começar com "sk-"';
        }
        if (field === 'timeout' && (value < 5 || value > 300)) {
          return 'Timeout deve estar entre 5 e 300 segundos';
        }
        if (field === 'maxRetries' && (value < 0 || value > 10)) {
          return 'Número de tentativas deve estar entre 0 e 10';
        }
        break;
      case 'security':
        if (field === 'sessionTimeout' && (value < 300 || value > 86400)) {
          return 'Timeout de sessão deve estar entre 5 minutos e 24 horas';
        }
        if (field === 'maxLoginAttempts' && (value < 1 || value > 20)) {
          return 'Tentativas de login deve estar entre 1 e 20';
        }
        break;
      case 'backup':
        if (field === 'backupInterval' && (value < 1 || value > 168)) {
          return 'Intervalo de backup deve estar entre 1 hora e 1 semana';
        }
        if (field === 'maxBackups' && (value < 1 || value > 100)) {
          return 'Número máximo de backups deve estar entre 1 e 100';
        }
        break;
    }
    return '';
  };

  const handleFieldChange = (section: keyof SettingsData, field: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value,
      },
    }));

    // Validar campo
    const error = validateField(section, field, value);
    setErrors(prev => ({
      ...prev,
      [`${section}.${field}`]: error,
    }));
  };

  const saveSettings = async () => {
    // Verificar se há erros
    const hasErrors = Object.values(errors).some(error => error !== '');
    if (hasErrors) {
      setToastMessage('Corrija os erros antes de salvar');
      setToastType('error');
      setShowToast(true);
      return;
    }

    setIsSaving(true);
    try {
      const response = await apiCall('/api/settings', 'PUT', settings);
      if (response.success) {
        setToastMessage('Configurações salvas com sucesso');
        setToastType('success');
        setShowToast(true);
      } else {
        throw new Error(response.message || 'Erro ao salvar configurações');
      }
    } catch (error) {
      console.error('Erro ao salvar configurações:', error);
      setToastMessage('Erro ao salvar configurações');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsSaving(false);
    }
  };

  const testApiConnection = async (provider: 'openai' | 'deepseek') => {
    try {
      const response = await apiCall(`/api/settings/test-connection`, 'POST', {
        provider,
        apiKey: settings.api[`${provider}ApiKey` as keyof typeof settings.api] as string,
        endpoint: settings.api[`${provider}Endpoint` as keyof typeof settings.api] as string,
      });
      
      if (response.success) {
        setToastMessage(`Conexão com ${provider} testada com sucesso`);
        setToastType('success');
      } else {
        setToastMessage(`Erro na conexão com ${provider}: ${response.message}`);
        setToastType('error');
      }
      setShowToast(true);
    } catch (error) {
      setToastMessage(`Erro ao testar conexão com ${provider}`);
      setToastType('error');
      setShowToast(true);
    }
  };

  const createBackup = async () => {
    try {
      const response = await apiCall('/api/settings/backup', 'POST');
      if (response.success) {
        setToastMessage('Backup criado com sucesso');
        setToastType('success');
      } else {
        throw new Error(response.message || 'Erro ao criar backup');
      }
    } catch (error) {
      setToastMessage('Erro ao criar backup');
      setToastType('error');
    }
    setShowToast(true);
  };

  const restoreBackup = async (file: File) => {
    try {
      const formData = new FormData();
      formData.append('backup', file);
      
      const response = await apiCall('/api/settings/restore', 'POST', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      if (response.success) {
        setToastMessage('Backup restaurado com sucesso');
        setToastType('success');
        loadSettings(); // Recarregar configurações
      } else {
        throw new Error(response.message || 'Erro ao restaurar backup');
      }
    } catch (error) {
      setToastMessage('Erro ao restaurar backup');
      setToastType('error');
    }
    setShowToast(true);
  };

  const tabs = [
    { id: 'general', label: 'Geral', icon: '⚙️' },
    { id: 'api', label: 'API', icon: '🔌' },
    { id: 'security', label: 'Segurança', icon: '🔒' },
    { id: 'backup', label: 'Backup', icon: '💾' },
  ] as const;

  const renderGeneralTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Configurações Gerais</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-2">Idioma</label>
            <Select
              value={settings.general.language}
              onChange={(value) => handleFieldChange('general', 'language', value)}
              options={[
                { value: 'pt-BR', label: 'Português (Brasil)' },
                { value: 'en-US', label: 'English (US)' },
                { value: 'es-ES', label: 'Español' },
              ]}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Tema</label>
            <Select
              value={settings.general.theme}
              onChange={(value) => handleFieldChange('general', 'theme', value)}
              options={[
                { value: 'light', label: 'Claro' },
                { value: 'dark', label: 'Escuro' },
                { value: 'auto', label: 'Automático' },
              ]}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Número de Workers</label>
            <Input
              type="number"
              value={settings.general.maxWorkers}
              onChange={(e) => handleFieldChange('general', 'maxWorkers', parseInt(e.target.value))}
              min={1}
              max={20}
              error={errors['general.maxWorkers']}
            />
          </div>
        </div>
        
        <div className="mt-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Salvamento Automático</label>
              <p className="text-xs text-gray-500">Salvar alterações automaticamente</p>
            </div>
            <Switch
              checked={settings.general.autoSave}
              onChange={(checked) => handleFieldChange('general', 'autoSave', checked)}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Notificações</label>
              <p className="text-xs text-gray-500">Receber notificações do sistema</p>
            </div>
            <Switch
              checked={settings.general.notifications}
              onChange={(checked) => handleFieldChange('general', 'notifications', checked)}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Cache</label>
              <p className="text-xs text-gray-500">Habilitar cache para melhor performance</p>
            </div>
            <Switch
              checked={settings.general.enableCache}
              onChange={(checked) => handleFieldChange('general', 'enableCache', checked)}
            />
          </div>
        </div>
      </Card>
    </div>
  );

  const renderApiTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Configurações de API</h3>
        
        <div className="space-y-6">
          {/* OpenAI */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-medium">OpenAI</h4>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => testApiConnection('openai')}
                disabled={!settings.api.openaiApiKey}
              >
                Testar Conexão
              </Button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Chave da API</label>
                <Input
                  type="password"
                  value={settings.api.openaiApiKey}
                  onChange={(e) => handleFieldChange('api', 'openaiApiKey', e.target.value)}
                  placeholder="sk-..."
                  error={errors['api.openaiApiKey']}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Endpoint</label>
                <Input
                  value={settings.api.openaiEndpoint}
                  onChange={(e) => handleFieldChange('api', 'openaiEndpoint', e.target.value)}
                  placeholder="https://api.openai.com/v1/chat/completions"
                />
              </div>
            </div>
          </div>
          
          {/* DeepSeek */}
          <div className="border rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-medium">DeepSeek</h4>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => testApiConnection('deepseek')}
                disabled={!settings.api.deepseekApiKey}
              >
                Testar Conexão
              </Button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Chave da API</label>
                <Input
                  type="password"
                  value={settings.api.deepseekApiKey}
                  onChange={(e) => handleFieldChange('api', 'deepseekApiKey', e.target.value)}
                  placeholder="sk-..."
                  error={errors['api.deepseekApiKey']}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Endpoint</label>
                <Input
                  value={settings.api.deepseekEndpoint}
                  onChange={(e) => handleFieldChange('api', 'deepseekEndpoint', e.target.value)}
                  placeholder="https://api.deepseek.com/v1/chat/completions"
                />
              </div>
            </div>
          </div>
          
          {/* Configurações Gerais */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Timeout (segundos)</label>
              <Input
                type="number"
                value={settings.api.timeout}
                onChange={(e) => handleFieldChange('api', 'timeout', parseInt(e.target.value))}
                min={5}
                max={300}
                error={errors['api.timeout']}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Tentativas Máximas</label>
              <Input
                type="number"
                value={settings.api.maxRetries}
                onChange={(e) => handleFieldChange('api', 'maxRetries', parseInt(e.target.value))}
                min={0}
                max={10}
                error={errors['api.maxRetries']}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Rate Limiting</label>
                <p className="text-xs text-gray-500">Limitar requisições</p>
              </div>
              <Switch
                checked={settings.api.enableRateLimiting}
                onChange={(checked) => handleFieldChange('api', 'enableRateLimiting', checked)}
              />
            </div>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderSecurityTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Configurações de Segurança</h3>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Timeout de Sessão (segundos)</label>
              <Input
                type="number"
                value={settings.security.sessionTimeout}
                onChange={(e) => handleFieldChange('security', 'sessionTimeout', parseInt(e.target.value))}
                min={300}
                max={86400}
                error={errors['security.sessionTimeout']}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Tentativas de Login</label>
              <Input
                type="number"
                value={settings.security.maxLoginAttempts}
                onChange={(e) => handleFieldChange('security', 'maxLoginAttempts', parseInt(e.target.value))}
                min={1}
                max={20}
                error={errors['security.maxLoginAttempts']}
              />
            </div>
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Log de Auditoria</label>
                <p className="text-xs text-gray-500">Registrar todas as ações do usuário</p>
              </div>
              <Switch
                checked={settings.security.enableAuditLog}
                onChange={(checked) => handleFieldChange('security', 'enableAuditLog', checked)}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Autenticação 2FA</label>
                <p className="text-xs text-gray-500">Requer autenticação de dois fatores</p>
              </div>
              <Switch
                checked={settings.security.enable2FA}
                onChange={(checked) => handleFieldChange('security', 'enable2FA', checked)}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Criptografia de Dados</label>
                <p className="text-xs text-gray-500">Criptografar dados sensíveis</p>
              </div>
              <Switch
                checked={settings.security.dataEncryption}
                onChange={(checked) => handleFieldChange('security', 'dataEncryption', checked)}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Headers de Segurança</label>
                <p className="text-xs text-gray-500">Aplicar headers de segurança HTTP</p>
              </div>
              <Switch
                checked={settings.security.secureHeaders}
                onChange={(checked) => handleFieldChange('security', 'secureHeaders', checked)}
              />
            </div>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderBackupTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Configurações de Backup</h3>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Intervalo de Backup (horas)</label>
              <Input
                type="number"
                value={settings.backup.backupInterval}
                onChange={(e) => handleFieldChange('backup', 'backupInterval', parseInt(e.target.value))}
                min={1}
                max={168}
                error={errors['backup.backupInterval']}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Máximo de Backups</label>
              <Input
                type="number"
                value={settings.backup.maxBackups}
                onChange={(e) => handleFieldChange('backup', 'maxBackups', parseInt(e.target.value))}
                min={1}
                max={100}
                error={errors['backup.maxBackups']}
              />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-2">Local de Backup</label>
            <Input
              value={settings.backup.backupLocation}
              onChange={(e) => handleFieldChange('backup', 'backupLocation', e.target.value)}
              placeholder="./backups"
            />
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Backup Automático</label>
                <p className="text-xs text-gray-500">Criar backups automaticamente</p>
              </div>
              <Switch
                checked={settings.backup.autoBackup}
                onChange={(checked) => handleFieldChange('backup', 'autoBackup', checked)}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Compressão</label>
                <p className="text-xs text-gray-500">Comprimir arquivos de backup</p>
              </div>
              <Switch
                checked={settings.backup.enableCompression}
                onChange={(checked) => handleFieldChange('backup', 'enableCompression', checked)}
              />
            </div>
          </div>
        </div>
      </Card>
      
      <Card>
        <h3 className="text-lg font-semibold mb-4">Ações de Backup</h3>
        
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <Button
              onClick={createBackup}
              disabled={isSaving}
            >
              Criar Backup Manual
            </Button>
            
            <div className="flex items-center gap-2">
              <input
                type="file"
                accept=".zip,.json"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    restoreBackup(file);
                  }
                }}
                className="hidden"
                id="restore-file"
              />
              <label htmlFor="restore-file">
                <Button variant="secondary" as="span">
                  Restaurar Backup
                </Button>
              </label>
            </div>
          </div>
          
          <div className="text-sm text-gray-600">
            <p>• Backups automáticos são criados conforme o intervalo configurado</p>
            <p>• Backups manuais podem ser criados a qualquer momento</p>
            <p>• Apenas arquivos .zip e .json são aceitos para restauração</p>
          </div>
        </div>
      </Card>
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'general':
        return renderGeneralTab();
      case 'api':
        return renderApiTab();
      case 'security':
        return renderSecurityTab();
      case 'backup':
        return renderBackupTab();
      default:
        return null;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando configurações...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Configurações</h1>
        <p className="text-gray-600 mt-2">
          Gerencie as configurações do sistema, APIs, segurança e backup
        </p>
      </div>
      
      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-2 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>
      
      {/* Conteúdo da Tab */}
      <div className="mb-6">
        {renderTabContent()}
      </div>
      
      {/* Botões de Ação */}
      <div className="flex justify-end gap-4">
        <Button
          variant="secondary"
          onClick={loadSettings}
          disabled={isSaving}
        >
          Cancelar
        </Button>
        
        <Button
          onClick={saveSettings}
          disabled={isSaving || Object.values(errors).some(error => error !== '')}
        >
          {isSaving ? 'Salvando...' : 'Salvar Configurações'}
        </Button>
      </div>
      
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

export default Settings; 