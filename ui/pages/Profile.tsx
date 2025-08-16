/**
 * Página de Perfil do Usuário - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-018
 * Data/Hora: 2025-01-27T23:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Informações pessoais do usuário
 * - Preferências e configurações
 * - Histórico de atividades
 * - Métricas e estatísticas
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card, Button, Input, Select, Switch, Toast } from '../components/base';
import { useApi } from '../hooks/use_api';
import { useI18n } from '../hooks/use_i18n';
import { useAuth } from '../context/AuthContext';

interface UserProfile {
  id: string;
  name: string;
  email: string;
  avatar?: string;
  bio?: string;
  website?: string;
  location?: string;
  joinedAt: string;
  lastLogin: string;
}

interface UserMetrics {
  totalArticles: number;
  totalBlogs: number;
  averageQuality: number;
  tokensUsed: number;
  lastActivity: string;
  articlesThisMonth: number;
  blogsThisMonth: number;
  averageGenerationTime: number;
  successRate: number;
}

interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  privacy: {
    profileVisibility: 'public' | 'private' | 'friends';
    showMetrics: boolean;
    showActivity: boolean;
  };
  generation: {
    defaultModel: 'openai' | 'deepseek';
    defaultLanguage: string;
    autoSave: boolean;
  };
}

interface ActivityItem {
  id: string;
  type: 'article_generated' | 'blog_created' | 'prompt_uploaded' | 'backup_created' | 'settings_changed';
  title: string;
  description: string;
  timestamp: string;
  metadata?: {
    articleId?: string;
    blogId?: string;
    promptCount?: number;
    quality?: number;
  };
}

interface ValidationErrors {
  [key: string]: string;
}

const Profile: React.FC = () => {
  const { t } = useI18n();
  const { apiCall } = useApi();
  const { user } = useAuth();
  
  const [activeTab, setActiveTab] = useState<'personal' | 'preferences' | 'history'>('personal');
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [metrics, setMetrics] = useState<UserMetrics | null>(null);
  const [preferences, setPreferences] = useState<UserPreferences>({
    theme: 'auto',
    language: 'pt-BR',
    notifications: {
      email: true,
      push: false,
      sms: false,
    },
    privacy: {
      profileVisibility: 'private',
      showMetrics: true,
      showActivity: true,
    },
    generation: {
      defaultModel: 'openai',
      defaultLanguage: 'pt-BR',
      autoSave: true,
    },
  });
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error'>('success');
  const [activityFilter, setActivityFilter] = useState<string>('all');
  const [activityPage, setActivityPage] = useState(1);
  const [hasMoreActivities, setHasMoreActivities] = useState(true);

  // Carregar dados do perfil
  useEffect(() => {
    if (user) {
      loadProfile();
      loadMetrics();
      loadPreferences();
      loadActivities();
    }
  }, [user]);

  const loadProfile = useCallback(async () => {
    if (!user) return;
    
    setIsLoading(true);
    try {
      const response = await apiCall(`/api/users/${user}`, 'GET');
      if (response.success) {
        setProfile(response.user);
      }
    } catch (error) {
      console.error('Erro ao carregar perfil:', error);
      setToastMessage('Erro ao carregar perfil');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsLoading(false);
    }
  }, [user, apiCall]);

  const loadMetrics = useCallback(async () => {
    if (!user) return;
    
    try {
      const response = await apiCall(`/api/users/${user}/metrics`, 'GET');
      if (response.success) {
        setMetrics(response.metrics);
      }
    } catch (error) {
      console.error('Erro ao carregar métricas:', error);
    }
  }, [user, apiCall]);

  const loadPreferences = useCallback(async () => {
    if (!user) return;
    
    try {
      const response = await apiCall(`/api/users/${user}/preferences`, 'GET');
      if (response.success) {
        setPreferences(response.preferences);
      }
    } catch (error) {
      console.error('Erro ao carregar preferências:', error);
    }
  }, [user, apiCall]);

  const loadActivities = useCallback(async (page = 1, filter = 'all') => {
    if (!user) return;
    
    try {
      const response = await apiCall(`/api/users/${user}/activities`, 'GET', null, {
        params: { page, filter, limit: 20 }
      });
      if (response.success) {
        if (page === 1) {
          setActivities(response.activities);
        } else {
          setActivities(prev => [...prev, ...response.activities]);
        }
        setHasMoreActivities(response.activities.length === 20);
      }
    } catch (error) {
      console.error('Erro ao carregar atividades:', error);
    }
  }, [user, apiCall]);

  const validateField = (section: string, field: string, value: any): string => {
    switch (section) {
      case 'personal':
        if (field === 'name' && (!value || value.trim().length < 2)) {
          return 'Nome deve ter pelo menos 2 caracteres';
        }
        if (field === 'email' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          return 'Email deve ter formato válido';
        }
        if (field === 'website' && value && !/^https?:\/\/.+/.test(value)) {
          return 'Website deve começar com http:// ou https://';
        }
        break;
    }
    return '';
  };

  const handleProfileChange = (field: string, value: any) => {
    if (!profile) return;
    
    setProfile(prev => prev ? { ...prev, [field]: value } : null);
    
    // Validar campo
    const error = validateField('personal', field, value);
    setErrors(prev => ({
      ...prev,
      [`personal.${field}`]: error,
    }));
  };

  const handlePreferencesChange = (section: keyof UserPreferences, field: string, value: any) => {
    setPreferences(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value,
      },
    }));
  };

  const saveProfile = async () => {
    if (!profile || !user) return;
    
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
      const response = await apiCall(`/api/users/${user}`, 'PUT', profile);
      if (response.success) {
        setToastMessage('Perfil atualizado com sucesso');
        setToastType('success');
        setShowToast(true);
      } else {
        throw new Error(response.message || 'Erro ao atualizar perfil');
      }
    } catch (error) {
      console.error('Erro ao atualizar perfil:', error);
      setToastMessage('Erro ao atualizar perfil');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsSaving(false);
    }
  };

  const savePreferences = async () => {
    if (!user) return;
    
    setIsSaving(true);
    try {
      const response = await apiCall(`/api/users/${user}/preferences`, 'PUT', preferences);
      if (response.success) {
        setToastMessage('Preferências salvas com sucesso');
        setToastType('success');
        setShowToast(true);
      } else {
        throw new Error(response.message || 'Erro ao salvar preferências');
      }
    } catch (error) {
      console.error('Erro ao salvar preferências:', error);
      setToastMessage('Erro ao salvar preferências');
      setToastType('error');
      setShowToast(true);
    } finally {
      setIsSaving(false);
    }
  };

  const loadMoreActivities = () => {
    const nextPage = activityPage + 1;
    setActivityPage(nextPage);
    loadActivities(nextPage, activityFilter);
  };

  const filterActivities = (filter: string) => {
    setActivityFilter(filter);
    setActivityPage(1);
    loadActivities(1, filter);
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'article_generated': return '📝';
      case 'blog_created': return '📚';
      case 'prompt_uploaded': return '📤';
      case 'backup_created': return '💾';
      case 'settings_changed': return '⚙️';
      default: return '📋';
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return 'Agora mesmo';
    if (diffInHours < 24) return `${diffInHours}h atrás`;
    if (diffInHours < 168) return `${Math.floor(diffInHours / 24)}d atrás`;
    return date.toLocaleDateString('pt-BR');
  };

  const tabs = [
    { id: 'personal', label: 'Informações Pessoais', icon: '👤' },
    { id: 'preferences', label: 'Preferências', icon: '⚙️' },
    { id: 'history', label: 'Histórico', icon: '📋' },
  ] as const;

  const renderPersonalTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Informações Pessoais</h3>
        
        {profile && (
          <div className="space-y-4">
            <div className="flex items-center space-x-4 mb-6">
              <div className="w-20 h-20 bg-gray-200 rounded-full flex items-center justify-center text-2xl">
                {profile.avatar ? (
                  <img src={profile.avatar} alt="Avatar" className="w-full h-full rounded-full object-cover" />
                ) : (
                  <span>{profile.name.charAt(0).toUpperCase()}</span>
                )}
              </div>
              <div>
                <h4 className="text-xl font-semibold">{profile.name}</h4>
                <p className="text-gray-600">{profile.email}</p>
                <p className="text-sm text-gray-500">Membro desde {new Date(profile.joinedAt).toLocaleDateString('pt-BR')}</p>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Nome Completo</label>
                <Input
                  value={profile.name}
                  onChange={(e) => handleProfileChange('name', e.target.value)}
                  error={errors['personal.name']}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Email</label>
                <Input
                  type="email"
                  value={profile.email}
                  onChange={(e) => handleProfileChange('email', e.target.value)}
                  error={errors['personal.email']}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Website</label>
                <Input
                  value={profile.website || ''}
                  onChange={(e) => handleProfileChange('website', e.target.value)}
                  placeholder="https://meusite.com"
                  error={errors['personal.website']}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Localização</label>
                <Input
                  value={profile.location || ''}
                  onChange={(e) => handleProfileChange('location', e.target.value)}
                  placeholder="Cidade, País"
                />
              </div>
              
              <div className="md:col-span-2">
                <label className="block text-sm font-medium mb-2">Biografia</label>
                <textarea
                  value={profile.bio || ''}
                  onChange={(e) => handleProfileChange('bio', e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  rows={3}
                  placeholder="Conte um pouco sobre você..."
                />
              </div>
            </div>
          </div>
        )}
      </Card>
      
      {metrics && (
        <Card>
          <h3 className="text-lg font-semibold mb-4">Estatísticas</h3>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{metrics.totalArticles}</div>
              <div className="text-sm text-gray-600">Artigos</div>
            </div>
            
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{metrics.totalBlogs}</div>
              <div className="text-sm text-gray-600">Blogs</div>
            </div>
            
            <div className="text-center p-4 bg-purple-50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">{metrics.averageQuality.toFixed(1)}</div>
              <div className="text-sm text-gray-600">Qualidade Média</div>
            </div>
            
            <div className="text-center p-4 bg-orange-50 rounded-lg">
              <div className="text-2xl font-bold text-orange-600">{metrics.successRate.toFixed(0)}%</div>
              <div className="text-sm text-gray-600">Taxa de Sucesso</div>
            </div>
          </div>
          
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-600">Tokens Utilizados:</span>
              <span className="ml-2 font-medium">{metrics.tokensUsed.toLocaleString()}</span>
            </div>
            <div>
              <span className="text-gray-600">Tempo Médio de Geração:</span>
              <span className="ml-2 font-medium">{metrics.averageGenerationTime.toFixed(1)}s</span>
            </div>
            <div>
              <span className="text-gray-600">Artigos este mês:</span>
              <span className="ml-2 font-medium">{metrics.articlesThisMonth}</span>
            </div>
            <div>
              <span className="text-gray-600">Última atividade:</span>
              <span className="ml-2 font-medium">{formatDate(metrics.lastActivity)}</span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );

  const renderPreferencesTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Preferências de Interface</h3>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Tema</label>
              <Select
                value={preferences.theme}
                onChange={(value) => handlePreferencesChange('theme', 'theme', value)}
                options={[
                  { value: 'light', label: 'Claro' },
                  { value: 'dark', label: 'Escuro' },
                  { value: 'auto', label: 'Automático' },
                ]}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Idioma</label>
              <Select
                value={preferences.language}
                onChange={(value) => handlePreferencesChange('language', 'language', value)}
                options={[
                  { value: 'pt-BR', label: 'Português (Brasil)' },
                  { value: 'en-US', label: 'English (US)' },
                  { value: 'es-ES', label: 'Español' },
                ]}
              />
            </div>
          </div>
        </div>
      </Card>
      
      <Card>
        <h3 className="text-lg font-semibold mb-4">Notificações</h3>
        
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Notificações por Email</label>
              <p className="text-xs text-gray-500">Receber notificações por email</p>
            </div>
            <Switch
              checked={preferences.notifications.email}
              onChange={(checked) => handlePreferencesChange('notifications', 'email', checked)}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Notificações Push</label>
              <p className="text-xs text-gray-500">Receber notificações no navegador</p>
            </div>
            <Switch
              checked={preferences.notifications.push}
              onChange={(checked) => handlePreferencesChange('notifications', 'push', checked)}
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Notificações SMS</label>
              <p className="text-xs text-gray-500">Receber notificações por SMS</p>
            </div>
            <Switch
              checked={preferences.notifications.sms}
              onChange={(checked) => handlePreferencesChange('notifications', 'sms', checked)}
            />
          </div>
        </div>
      </Card>
      
      <Card>
        <h3 className="text-lg font-semibold mb-4">Privacidade</h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Visibilidade do Perfil</label>
            <Select
              value={preferences.privacy.profileVisibility}
              onChange={(value) => handlePreferencesChange('privacy', 'profileVisibility', value)}
              options={[
                { value: 'public', label: 'Público' },
                { value: 'private', label: 'Privado' },
                { value: 'friends', label: 'Apenas Amigos' },
              ]}
            />
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Mostrar Métricas</label>
                <p className="text-xs text-gray-500">Permitir que outros vejam suas estatísticas</p>
              </div>
              <Switch
                checked={preferences.privacy.showMetrics}
                onChange={(checked) => handlePreferencesChange('privacy', 'showMetrics', checked)}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Mostrar Atividades</label>
                <p className="text-xs text-gray-500">Permitir que outros vejam seu histórico</p>
              </div>
              <Switch
                checked={preferences.privacy.showActivity}
                onChange={(checked) => handlePreferencesChange('privacy', 'showActivity', checked)}
              />
            </div>
          </div>
        </div>
      </Card>
      
      <Card>
        <h3 className="text-lg font-semibold mb-4">Configurações de Geração</h3>
        
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Modelo Padrão</label>
              <Select
                value={preferences.generation.defaultModel}
                onChange={(value) => handlePreferencesChange('generation', 'defaultModel', value)}
                options={[
                  { value: 'openai', label: 'OpenAI' },
                  { value: 'deepseek', label: 'DeepSeek' },
                ]}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Idioma Padrão</label>
              <Select
                value={preferences.generation.defaultLanguage}
                onChange={(value) => handlePreferencesChange('generation', 'defaultLanguage', value)}
                options={[
                  { value: 'pt-BR', label: 'Português' },
                  { value: 'en-US', label: 'English' },
                  { value: 'es-ES', label: 'Español' },
                ]}
              />
            </div>
          </div>
          
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Salvamento Automático</label>
              <p className="text-xs text-gray-500">Salvar artigos automaticamente</p>
            </div>
            <Switch
              checked={preferences.generation.autoSave}
              onChange={(checked) => handlePreferencesChange('generation', 'autoSave', checked)}
            />
          </div>
        </div>
      </Card>
    </div>
  );

  const renderHistoryTab = () => (
    <div className="space-y-6">
      <Card>
        <h3 className="text-lg font-semibold mb-4">Histórico de Atividades</h3>
        
        <div className="mb-4">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => filterActivities('all')}
              className={`px-3 py-1 rounded-full text-sm ${
                activityFilter === 'all'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              Todas
            </button>
            <button
              onClick={() => filterActivities('article_generated')}
              className={`px-3 py-1 rounded-full text-sm ${
                activityFilter === 'article_generated'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              Artigos
            </button>
            <button
              onClick={() => filterActivities('blog_created')}
              className={`px-3 py-1 rounded-full text-sm ${
                activityFilter === 'blog_created'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              Blogs
            </button>
            <button
              onClick={() => filterActivities('prompt_uploaded')}
              className={`px-3 py-1 rounded-full text-sm ${
                activityFilter === 'prompt_uploaded'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              Prompts
            </button>
          </div>
        </div>
        
        <div className="space-y-3">
          {activities.map((activity) => (
            <div key={activity.id} className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-gray-50">
              <div className="text-2xl">{getActivityIcon(activity.type)}</div>
              <div className="flex-1">
                <h4 className="font-medium">{activity.title}</h4>
                <p className="text-sm text-gray-600">{activity.description}</p>
                {activity.metadata && (
                  <div className="mt-2 text-xs text-gray-500">
                    {activity.metadata.quality && (
                      <span className="mr-3">Qualidade: {activity.metadata.quality.toFixed(1)}</span>
                    )}
                    {activity.metadata.promptCount && (
                      <span className="mr-3">Prompts: {activity.metadata.promptCount}</span>
                    )}
                  </div>
                )}
              </div>
              <div className="text-xs text-gray-500">
                {formatDate(activity.timestamp)}
              </div>
            </div>
          ))}
          
          {activities.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <div className="text-4xl mb-2">📋</div>
              <p>Nenhuma atividade encontrada</p>
            </div>
          )}
          
          {hasMoreActivities && activities.length > 0 && (
            <div className="text-center pt-4">
              <Button
                variant="secondary"
                onClick={loadMoreActivities}
                disabled={isLoading}
              >
                {isLoading ? 'Carregando...' : 'Carregar Mais'}
              </Button>
            </div>
          )}
        </div>
      </Card>
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'personal':
        return renderPersonalTab();
      case 'preferences':
        return renderPreferencesTab();
      case 'history':
        return renderHistoryTab();
      default:
        return null;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando perfil...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="text-4xl mb-4">🔒</div>
          <h2 className="text-xl font-semibold mb-2">Acesso Restrito</h2>
          <p className="text-gray-600">Faça login para acessar seu perfil</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Perfil do Usuário</h1>
        <p className="text-gray-600 mt-2">
          Gerencie suas informações pessoais, preferências e visualize seu histórico
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
      {activeTab === 'personal' && (
        <div className="flex justify-end">
          <Button
            onClick={saveProfile}
            disabled={isSaving || Object.values(errors).some(error => error !== '')}
          >
            {isSaving ? 'Salvando...' : 'Salvar Perfil'}
          </Button>
        </div>
      )}
      
      {activeTab === 'preferences' && (
        <div className="flex justify-end">
          <Button
            onClick={savePreferences}
            disabled={isSaving}
          >
            {isSaving ? 'Salvando...' : 'Salvar Preferências'}
          </Button>
        </div>
      )}
      
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

export default Profile; 