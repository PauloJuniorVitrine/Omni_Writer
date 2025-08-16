/**
 * Página de Segurança - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - SEC-001, SEC-002, SEC-003, SEC-004
 * Data/Hora: 2025-01-28T02:30:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_007
 * 
 * Funcionalidades:
 * - Input validation
 * - XSS prevention
 * - CSRF protection
 * - Authentication flow
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
import { Charts } from '../components/Charts';

// ===== TIPOS =====

interface SecurityEvent {
  id: string;
  type: 'xss' | 'csrf' | 'injection' | 'auth' | 'validation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  source: string;
  description: string;
  status: 'detected' | 'blocked' | 'investigating' | 'resolved';
  ipAddress: string;
  userAgent: string;
  payload?: string;
  action: string;
}

interface SecurityRule {
  id: string;
  name: string;
  type: 'xss' | 'csrf' | 'injection' | 'auth' | 'validation';
  pattern: string;
  action: 'block' | 'log' | 'alert' | 'sanitize';
  enabled: boolean;
  priority: number;
  description: string;
  lastTriggered?: Date;
  triggerCount: number;
}

interface SecurityConfig {
  xssProtection: {
    enabled: boolean;
    mode: 'sanitize' | 'block';
    headers: boolean;
    contentSecurityPolicy: string;
  };
  csrfProtection: {
    enabled: boolean;
    tokenExpiry: number;
    sameSite: 'strict' | 'lax' | 'none';
    secure: boolean;
  };
  inputValidation: {
    enabled: boolean;
    maxLength: number;
    allowedPatterns: string[];
    blockedPatterns: string[];
  };
  authentication: {
    enabled: boolean;
    sessionTimeout: number;
    maxLoginAttempts: number;
    passwordPolicy: {
      minLength: number;
      requireUppercase: boolean;
      requireLowercase: boolean;
      requireNumbers: boolean;
      requireSpecialChars: boolean;
    };
    twoFactorAuth: boolean;
  };
}

interface SecurityMetrics {
  totalEvents: number;
  blockedEvents: number;
  eventsByType: Record<string, number>;
  eventsBySeverity: Record<string, number>;
  topSources: Array<{ source: string; count: number }>;
  recentActivity: SecurityEvent[];
}

// ===== DADOS MOCK =====

const mockSecurityEvents: SecurityEvent[] = [
  {
    id: 'sec-001',
    type: 'xss',
    severity: 'high',
    timestamp: new Date('2025-01-28T01:30:00Z'),
    source: '192.168.1.100',
    description: 'Tentativa de XSS detectada em campo de comentário',
    status: 'blocked',
    ipAddress: '192.168.1.100',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    payload: '<script>alert("xss")</script>',
    action: 'blocked'
  },
  {
    id: 'sec-002',
    type: 'csrf',
    severity: 'medium',
    timestamp: new Date('2025-01-28T01:25:00Z'),
    source: '203.0.113.45',
    description: 'Token CSRF inválido ou ausente',
    status: 'blocked',
    ipAddress: '203.0.113.45',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    action: 'blocked'
  },
  {
    id: 'sec-003',
    type: 'injection',
    severity: 'critical',
    timestamp: new Date('2025-01-28T01:20:00Z'),
    source: '198.51.100.23',
    description: 'Tentativa de SQL injection detectada',
    status: 'blocked',
    ipAddress: '198.51.100.23',
    userAgent: 'curl/7.68.0',
    payload: "'; DROP TABLE users; --",
    action: 'blocked'
  },
  {
    id: 'sec-004',
    type: 'auth',
    severity: 'medium',
    timestamp: new Date('2025-01-28T01:15:00Z'),
    source: '10.0.0.50',
    description: 'Múltiplas tentativas de login falhadas',
    status: 'detected',
    ipAddress: '10.0.0.50',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    action: 'rate_limited'
  }
];

const mockSecurityRules: SecurityRule[] = [
  {
    id: 'rule-001',
    name: 'XSS Script Tag Detection',
    type: 'xss',
    pattern: '<script[^>]*>.*?</script>',
    action: 'block',
    enabled: true,
    priority: 1,
    description: 'Bloqueia tags script maliciosas',
    lastTriggered: new Date('2025-01-28T01:30:00Z'),
    triggerCount: 15
  },
  {
    id: 'rule-002',
    name: 'SQL Injection Detection',
    type: 'injection',
    pattern: '(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\\s+.*',
    action: 'block',
    enabled: true,
    priority: 1,
    description: 'Bloqueia tentativas de SQL injection',
    lastTriggered: new Date('2025-01-28T01:20:00Z'),
    triggerCount: 8
  },
  {
    id: 'rule-003',
    name: 'CSRF Token Validation',
    type: 'csrf',
    pattern: 'csrf_token',
    action: 'block',
    enabled: true,
    priority: 2,
    description: 'Valida tokens CSRF',
    triggerCount: 23
  },
  {
    id: 'rule-004',
    name: 'Input Length Validation',
    type: 'validation',
    pattern: '^.{1,1000}$',
    action: 'block',
    enabled: true,
    priority: 3,
    description: 'Limita tamanho de entrada',
    triggerCount: 45
  }
];

const mockSecurityConfig: SecurityConfig = {
  xssProtection: {
    enabled: true,
    mode: 'block',
    headers: true,
    contentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
  },
  csrfProtection: {
    enabled: true,
    tokenExpiry: 3600,
    sameSite: 'strict',
    secure: true
  },
  inputValidation: {
    enabled: true,
    maxLength: 1000,
    allowedPatterns: ['^[a-zA-Z0-9\\s\\-_.,!?]+$'],
    blockedPatterns: ['<script', 'javascript:', 'onload=', 'onerror=']
  },
  authentication: {
    enabled: true,
    sessionTimeout: 1800,
    maxLoginAttempts: 5,
    passwordPolicy: {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true
    },
    twoFactorAuth: true
  }
};

const mockSecurityMetrics: SecurityMetrics = {
  totalEvents: 156,
  blockedEvents: 142,
  eventsByType: {
    xss: 45,
    csrf: 23,
    injection: 12,
    auth: 67,
    validation: 9
  },
  eventsBySeverity: {
    low: 23,
    medium: 89,
    high: 34,
    critical: 10
  },
  topSources: [
    { source: '192.168.1.100', count: 15 },
    { source: '203.0.113.45', count: 12 },
    { source: '198.51.100.23', count: 8 },
    { source: '10.0.0.50', count: 6 }
  ],
  recentActivity: mockSecurityEvents
};

// ===== COMPONENTE PRINCIPAL =====

export const Security: React.FC = () => {
  const { t } = useI18n();
  const { colors } = useTheme();
  const [activeTab, setActiveTab] = useState<'overview' | 'events' | 'rules' | 'config' | 'auth'>('overview');
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>(mockSecurityEvents);
  const [securityRules, setSecurityRules] = useState<SecurityRule[]>(mockSecurityRules);
  const [securityConfig, setSecurityConfig] = useState<SecurityConfig>(mockSecurityConfig);
  const [securityMetrics] = useState<SecurityMetrics>(mockSecurityMetrics);
  const [loading, setLoading] = useState(false);
  const [showRuleModal, setShowRuleModal] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [selectedRule, setSelectedRule] = useState<SecurityRule | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');

  // Carregar dados de segurança
  useEffect(() => {
    const loadSecurityData = async () => {
      setLoading(true);
      try {
        // Simular chamada API
        await new Promise(resolve => setTimeout(resolve, 1000));
        setSecurityEvents(mockSecurityEvents);
        setSecurityRules(mockSecurityRules);
        setSecurityConfig(mockSecurityConfig);
      } catch (error) {
        console.error('Erro ao carregar dados de segurança:', error);
        Toast.error('Erro ao carregar dados de segurança');
      } finally {
        setLoading(false);
      }
    };

    loadSecurityData();
  }, []);

  // Filtrar eventos
  const filteredEvents = securityEvents.filter(event => {
    const matchesSearch = event.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         event.source.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'all' || event.type === selectedType;
    return matchesSearch && matchesType;
  });

  // Filtrar regras
  const filteredRules = securityRules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'all' || rule.type === selectedType;
    return matchesSearch && matchesType;
  });

  // Adicionar nova regra
  const handleAddRule = async (ruleData: Partial<SecurityRule>) => {
    setLoading(true);
    try {
      const newRule: SecurityRule = {
        id: `rule-${Date.now()}`,
        name: ruleData.name || '',
        type: ruleData.type as any,
        pattern: ruleData.pattern || '',
        action: ruleData.action as any,
        enabled: ruleData.enabled || true,
        priority: ruleData.priority || 1,
        description: ruleData.description || '',
        triggerCount: 0
      };

      setSecurityRules(prev => [...prev, newRule]);
      setShowRuleModal(false);
      Toast.success('Regra de segurança criada com sucesso!');
    } catch (error) {
      Toast.error('Erro ao criar regra de segurança');
    } finally {
      setLoading(false);
    }
  };

  // Atualizar configuração
  const handleUpdateConfig = async (configData: Partial<SecurityConfig>) => {
    setLoading(true);
    try {
      setSecurityConfig(prev => ({ ...prev, ...configData }));
      setShowConfigModal(false);
      Toast.success('Configuração de segurança atualizada!');
    } catch (error) {
      Toast.error('Erro ao atualizar configuração');
    } finally {
      setLoading(false);
    }
  };

  // Renderizar visão geral
  const renderOverview = () => {
    return (
      <div className="space-y-6">
        {/* Métricas principais */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">{securityMetrics.totalEvents}</div>
              <div className="text-sm text-gray-600">Total de Eventos</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{securityMetrics.blockedEvents}</div>
              <div className="text-sm text-gray-600">Eventos Bloqueados</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{securityRules.length}</div>
              <div className="text-sm text-gray-600">Regras Ativas</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600">
                {Math.round((securityMetrics.blockedEvents / securityMetrics.totalEvents) * 100)}%
              </div>
              <div className="text-sm text-gray-600">Taxa de Bloqueio</div>
            </div>
          </Card>
        </div>

        {/* Gráficos */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Eventos por Tipo</h3>
            <div className="h-64">
              <Charts
                type="pie"
                data={Object.entries(securityMetrics.eventsByType).map(([type, count]) => ({
                  name: type.toUpperCase(),
                  value: count,
                  color: type === 'xss' ? '#EF4444' :
                         type === 'csrf' ? '#F59E0B' :
                         type === 'injection' ? '#DC2626' :
                         type === 'auth' ? '#3B82F6' : '#6B7280'
                }))}
                options={{
                  legend: true,
                  tooltip: true,
                  animate: true
                }}
              />
            </div>
          </Card>

          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Eventos por Severidade</h3>
            <div className="h-64">
              <Charts
                type="bar"
                data={Object.entries(securityMetrics.eventsBySeverity).map(([severity, count]) => ({
                  name: severity.charAt(0).toUpperCase() + severity.slice(1),
                  value: count,
                  color: severity === 'critical' ? '#DC2626' :
                         severity === 'high' ? '#EF4444' :
                         severity === 'medium' ? '#F59E0B' : '#10B981'
                }))}
                options={{
                  legend: true,
                  grid: true,
                  tooltip: true,
                  animate: true
                }}
              />
            </div>
          </Card>
        </div>

        {/* Top sources */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Principais Fontes de Ataque</h3>
          <div className="space-y-3">
            {securityMetrics.topSources.map((source, index) => (
              <div key={source.source} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <span className="text-sm font-medium text-gray-500">#{index + 1}</span>
                  <span className="font-mono text-sm">{source.source}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-32 bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-red-600 h-2 rounded-full"
                      style={{ width: `${(source.count / securityMetrics.topSources[0].count) * 100}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-600">{source.count}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    );
  };

  // Renderizar eventos de segurança
  const renderSecurityEvents = () => {
    const columns = [
      { key: 'timestamp', label: 'Data/Hora', sortable: true },
      { key: 'type', label: 'Tipo', sortable: true },
      { key: 'severity', label: 'Severidade', sortable: true },
      { key: 'source', label: 'Fonte', sortable: true },
      { key: 'description', label: 'Descrição', sortable: true },
      { key: 'status', label: 'Status', sortable: true },
      { key: 'action', label: 'Ação', sortable: true }
    ];

    const data = filteredEvents.map(event => ({
      ...event,
      timestamp: event.timestamp.toLocaleString(),
      type: event.type.toUpperCase(),
      severity: event.severity === 'critical' ? '🔴 Crítico' :
                event.severity === 'high' ? '🟠 Alto' :
                event.severity === 'medium' ? '🟡 Médio' : '🟢 Baixo',
      status: event.status === 'blocked' ? '✅ Bloqueado' :
              event.status === 'detected' ? '👁️ Detectado' :
              event.status === 'investigating' ? '🔍 Investigando' : '✅ Resolvido',
      action: event.action === 'blocked' ? '🚫 Bloqueado' :
              event.action === 'rate_limited' ? '⏱️ Rate Limited' :
              event.action === 'logged' ? '📝 Logado' : '⚠️ Alertado'
    }));

    return (
      <div className="space-y-6">
        {/* Filtros */}
        <div className="flex space-x-4">
          <div className="flex-1">
            <Input
              placeholder="Buscar eventos..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Select
            value={selectedType}
            onChange={(value) => setSelectedType(value)}
            options={[
              { value: 'all', label: 'Todos os tipos' },
              { value: 'xss', label: 'XSS' },
              { value: 'csrf', label: 'CSRF' },
              { value: 'injection', label: 'Injection' },
              { value: 'auth', label: 'Autenticação' },
              { value: 'validation', label: 'Validação' }
            ]}
          />
        </div>

        {/* Tabela */}
        <Card className="p-6">
          <DataTable
            data={data}
            columns={columns}
            pagination={{ enabled: true, pageSize: 10 }}
            search={{ enabled: true }}
            filters={{ enabled: true }}
          />
        </Card>
      </div>
    );
  };

  // Renderizar regras de segurança
  const renderSecurityRules = () => {
    const columns = [
      { key: 'name', label: 'Nome', sortable: true },
      { key: 'type', label: 'Tipo', sortable: true },
      { key: 'pattern', label: 'Padrão', sortable: true },
      { key: 'action', label: 'Ação', sortable: true },
      { key: 'enabled', label: 'Ativo', sortable: true },
      { key: 'priority', label: 'Prioridade', sortable: true },
      { key: 'triggerCount', label: 'Triggers', sortable: true },
      { key: 'actions', label: 'Ações', sortable: false }
    ];

    const data = filteredRules.map(rule => ({
      ...rule,
      type: rule.type.toUpperCase(),
      action: rule.action === 'block' ? '🚫 Bloquear' :
              rule.action === 'log' ? '📝 Logar' :
              rule.action === 'alert' ? '⚠️ Alertar' : '🧹 Sanitizar',
      enabled: rule.enabled ? '✅ Sim' : '❌ Não',
      actions: (
        <div className="flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setSelectedRule(rule);
              setShowRuleModal(true);
            }}
          >
            Editar
          </Button>
          <Button
            size="sm"
            variant={rule.enabled ? 'secondary' : 'primary'}
            onClick={() => {
              const updatedRules = securityRules.map(r =>
                r.id === rule.id ? { ...r, enabled: !r.enabled } : r
              );
              setSecurityRules(updatedRules);
              Toast.success(`Regra ${rule.enabled ? 'desativada' : 'ativada'}!`);
            }}
          >
            {rule.enabled ? 'Desativar' : 'Ativar'}
          </Button>
        </div>
      )
    }));

    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-lg font-semibold">Regras de Segurança</h3>
            <p className="text-gray-600">Gerencie as regras de proteção</p>
          </div>
          <Button
            variant="primary"
            onClick={() => setShowRuleModal(true)}
          >
            Nova Regra
          </Button>
        </div>

        {/* Filtros */}
        <div className="flex space-x-4">
          <div className="flex-1">
            <Input
              placeholder="Buscar regras..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Select
            value={selectedType}
            onChange={(value) => setSelectedType(value)}
            options={[
              { value: 'all', label: 'Todos os tipos' },
              { value: 'xss', label: 'XSS' },
              { value: 'csrf', label: 'CSRF' },
              { value: 'injection', label: 'Injection' },
              { value: 'auth', label: 'Autenticação' },
              { value: 'validation', label: 'Validação' }
            ]}
          />
        </div>

        {/* Tabela */}
        <Card className="p-6">
          <DataTable
            data={data}
            columns={columns}
            pagination={{ enabled: true, pageSize: 10 }}
            search={{ enabled: true }}
            filters={{ enabled: true }}
          />
        </Card>
      </div>
    );
  };

  // Renderizar configurações
  const renderSecurityConfig = () => {
    return (
      <div className="space-y-6">
        {/* XSS Protection */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Proteção XSS</h3>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowConfigModal(true)}
            >
              Configurar
            </Button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Status</label>
              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                securityConfig.xssProtection.enabled
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {securityConfig.xssProtection.enabled ? '✅ Ativo' : '❌ Inativo'}
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Modo</label>
              <span className="text-sm text-gray-600 capitalize">
                {securityConfig.xssProtection.mode}
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Headers</label>
              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                securityConfig.xssProtection.headers
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {securityConfig.xssProtection.headers ? '✅ Ativo' : '❌ Inativo'}
              </span>
            </div>
          </div>
        </Card>

        {/* CSRF Protection */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Proteção CSRF</h3>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowConfigModal(true)}
            >
              Configurar
            </Button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Status</label>
              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                securityConfig.csrfProtection.enabled
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {securityConfig.csrfProtection.enabled ? '✅ Ativo' : '❌ Inativo'}
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Token Expiry</label>
              <span className="text-sm text-gray-600">
                {securityConfig.csrfProtection.tokenExpiry}s
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">SameSite</label>
              <span className="text-sm text-gray-600 capitalize">
                {securityConfig.csrfProtection.sameSite}
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Secure</label>
              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                securityConfig.csrfProtection.secure
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {securityConfig.csrfProtection.secure ? '✅ Sim' : '❌ Não'}
              </span>
            </div>
          </div>
        </Card>

        {/* Input Validation */}
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Validação de Entrada</h3>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowConfigModal(true)}
            >
              Configurar
            </Button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Status</label>
              <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                securityConfig.inputValidation.enabled
                  ? 'bg-green-100 text-green-800'
                  : 'bg-red-100 text-red-800'
              }`}>
                {securityConfig.inputValidation.enabled ? '✅ Ativo' : '❌ Inativo'}
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Tamanho Máximo</label>
              <span className="text-sm text-gray-600">
                {securityConfig.inputValidation.maxLength} caracteres
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Padrões Permitidos</label>
              <span className="text-sm text-gray-600">
                {securityConfig.inputValidation.allowedPatterns.length} padrões
              </span>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700">Padrões Bloqueados</label>
              <span className="text-sm text-gray-600">
                {securityConfig.inputValidation.blockedPatterns.length} padrões
              </span>
            </div>
          </div>
        </Card>
      </div>
    );
  };

  // Renderizar autenticação
  const renderAuthentication = () => {
    return (
      <div className="space-y-6">
        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Configurações de Autenticação</h3>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowConfigModal(true)}
            >
              Configurar
            </Button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Status</label>
                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                  securityConfig.authentication.enabled
                    ? 'bg-green-100 text-green-800'
                    : 'bg-red-100 text-red-800'
                }`}>
                  {securityConfig.authentication.enabled ? '✅ Ativo' : '❌ Inativo'}
                </span>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Timeout da Sessão</label>
                <span className="text-sm text-gray-600">
                  {securityConfig.authentication.sessionTimeout}s
                </span>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Tentativas Máximas</label>
                <span className="text-sm text-gray-600">
                  {securityConfig.authentication.maxLoginAttempts} tentativas
                </span>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">2FA</label>
                <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                  securityConfig.authentication.twoFactorAuth
                    ? 'bg-green-100 text-green-800'
                    : 'bg-red-100 text-red-800'
                }`}>
                  {securityConfig.authentication.twoFactorAuth ? '✅ Ativo' : '❌ Inativo'}
                </span>
              </div>
            </div>
            
            <div className="space-y-4">
              <h4 className="font-medium">Política de Senhas</h4>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Tamanho Mínimo</label>
                <span className="text-sm text-gray-600">
                  {securityConfig.authentication.passwordPolicy.minLength} caracteres
                </span>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <span className={`w-4 h-4 rounded ${
                    securityConfig.authentication.passwordPolicy.requireUppercase
                      ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                  <span className="text-sm">Maiúsculas obrigatórias</span>
                </div>
                
                <div className="flex items-center space-x-2">
                  <span className={`w-4 h-4 rounded ${
                    securityConfig.authentication.passwordPolicy.requireLowercase
                      ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                  <span className="text-sm">Minúsculas obrigatórias</span>
                </div>
                
                <div className="flex items-center space-x-2">
                  <span className={`w-4 h-4 rounded ${
                    securityConfig.authentication.passwordPolicy.requireNumbers
                      ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                  <span className="text-sm">Números obrigatórios</span>
                </div>
                
                <div className="flex items-center space-x-2">
                  <span className={`w-4 h-4 rounded ${
                    securityConfig.authentication.passwordPolicy.requireSpecialChars
                      ? 'bg-green-500' : 'bg-gray-300'
                  }`} />
                  <span className="text-sm">Caracteres especiais obrigatórios</span>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>
    );
  };

  if (loading) {
    return <Loading type="spinner" text="Carregando dados de segurança..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Segurança</h1>
          <p className="text-gray-600">Monitoramento e configuração de segurança</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'overview', label: 'Visão Geral', icon: '📊' },
            { id: 'events', label: 'Eventos', icon: '🔍' },
            { id: 'rules', label: 'Regras', icon: '🛡️' },
            { id: 'config', label: 'Configurações', icon: '⚙️' },
            { id: 'auth', label: 'Autenticação', icon: '🔐' }
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
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'events' && renderSecurityEvents()}
        {activeTab === 'rules' && renderSecurityRules()}
        {activeTab === 'config' && renderSecurityConfig()}
        {activeTab === 'auth' && renderAuthentication()}
      </div>

      {/* Modal de regra */}
      <Modal
        isOpen={showRuleModal}
        onClose={() => setShowRuleModal(false)}
        title={selectedRule ? 'Editar Regra' : 'Nova Regra'}
        size="lg"
      >
        <div className="space-y-4">
          <Input
            label="Nome da Regra"
            placeholder="Ex: XSS Script Detection"
            defaultValue={selectedRule?.name}
          />
          
          <Select
            label="Tipo"
            defaultValue={selectedRule?.type}
            options={[
              { value: 'xss', label: 'XSS' },
              { value: 'csrf', label: 'CSRF' },
              { value: 'injection', label: 'Injection' },
              { value: 'auth', label: 'Autenticação' },
              { value: 'validation', label: 'Validação' }
            ]}
          />
          
          <Input
            label="Padrão (Regex)"
            placeholder="Ex: <script[^>]*>.*?</script>"
            defaultValue={selectedRule?.pattern}
          />
          
          <Select
            label="Ação"
            defaultValue={selectedRule?.action}
            options={[
              { value: 'block', label: 'Bloquear' },
              { value: 'log', label: 'Logar' },
              { value: 'alert', label: 'Alertar' },
              { value: 'sanitize', label: 'Sanitizar' }
            ]}
          />
          
          <Input
            label="Prioridade"
            type="number"
            defaultValue={selectedRule?.priority.toString()}
            min="1"
            max="10"
          />
          
          <Input
            label="Descrição"
            placeholder="Descrição da regra"
            defaultValue={selectedRule?.description}
          />
        </div>
        
        <div className="flex justify-end space-x-3 mt-6">
          <Button
            variant="outline"
            onClick={() => setShowRuleModal(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              // Aqui você implementaria a lógica para salvar a regra
              Toast.success('Regra salva com sucesso!');
              setShowRuleModal(false);
            }}
          >
            Salvar
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default Security; 