/**
 * Sistema de Design - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - DS-001, DS-002, DS-003, DS-004
 * Data/Hora: 2025-01-28T02:15:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_006
 * 
 * Funcionalidades:
 * - Documentação de componentes
 * - Storybook implementation
 * - Design tokens
 * - Component library
 */

import React, { useState } from 'react';
import { useI18n } from '../hooks/use_i18n';
import { useTheme } from '../hooks/use_theme';
import { Card } from './base/Card';
import { Button } from './base/Button';
import { Input } from './base/Input';
import { Select } from './base/Select';
import { Modal } from './base/Modal';
import { Toast } from './base/Toast';
import { Loading } from './base/Loading';
import { DataTable } from './DataTable';
import { Charts } from './Charts';

// ===== TIPOS =====

interface ComponentDoc {
  name: string;
  category: 'base' | 'layout' | 'forms' | 'feedback' | 'navigation' | 'data' | 'media';
  description: string;
  props: Array<{
    name: string;
    type: string;
    required: boolean;
    defaultValue?: string;
    description: string;
  }>;
  examples: Array<{
    title: string;
    description: string;
    code: string;
    component: React.ReactNode;
  }>;
  usage: string[];
  accessibility: string[];
}

interface DesignToken {
  name: string;
  category: 'color' | 'typography' | 'spacing' | 'shadow' | 'border' | 'animation';
  value: string;
  description: string;
  usage: string[];
}

interface StorybookStory {
  id: string;
  title: string;
  component: string;
  args: Record<string, any>;
  argTypes: Record<string, any>;
  parameters: Record<string, any>;
}

// ===== DADOS MOCK =====

const mockComponents: ComponentDoc[] = [
  {
    name: 'Button',
    category: 'base',
    description: 'Componente de botão com múltiplas variantes e estados',
    props: [
      {
        name: 'variant',
        type: "'primary' | 'secondary' | 'outline' | 'ghost'",
        required: false,
        defaultValue: 'primary',
        description: 'Variante visual do botão'
      },
      {
        name: 'size',
        type: "'sm' | 'md' | 'lg'",
        required: false,
        defaultValue: 'md',
        description: 'Tamanho do botão'
      },
      {
        name: 'disabled',
        type: 'boolean',
        required: false,
        defaultValue: 'false',
        description: 'Estado desabilitado'
      },
      {
        name: 'onClick',
        type: 'function',
        required: false,
        description: 'Função chamada ao clicar'
      }
    ],
    examples: [
      {
        title: 'Variantes',
        description: 'Diferentes estilos de botão',
        code: `<Button variant="primary">Primário</Button>
<Button variant="secondary">Secundário</Button>
<Button variant="outline">Outline</Button>`,
        component: (
          <div className="flex space-x-2">
            <Button variant="primary">Primário</Button>
            <Button variant="secondary">Secundário</Button>
            <Button variant="outline">Outline</Button>
          </div>
        )
      },
      {
        title: 'Tamanhos',
        description: 'Diferentes tamanhos disponíveis',
        code: `<Button size="sm">Pequeno</Button>
<Button size="md">Médio</Button>
<Button size="lg">Grande</Button>`,
        component: (
          <div className="flex space-x-2 items-center">
            <Button size="sm">Pequeno</Button>
            <Button size="md">Médio</Button>
            <Button size="lg">Grande</Button>
          </div>
        )
      }
    ],
    usage: [
      'Use para ações principais na interface',
      'Mantenha consistência na hierarquia visual',
      'Sempre forneça feedback visual ao interagir'
    ],
    accessibility: [
      'Inclui role="button" automaticamente',
      'Suporte completo a navegação por teclado',
      'Indicadores visuais de foco',
      'Compatível com leitores de tela'
    ]
  },
  {
    name: 'Input',
    category: 'forms',
    description: 'Campo de entrada de texto com validação',
    props: [
      {
        name: 'type',
        type: "'text' | 'email' | 'password' | 'number'",
        required: false,
        defaultValue: 'text',
        description: 'Tipo de entrada'
      },
      {
        name: 'label',
        type: 'string',
        required: false,
        description: 'Label do campo'
      },
      {
        name: 'placeholder',
        type: 'string',
        required: false,
        description: 'Texto placeholder'
      },
      {
        name: 'error',
        type: 'string',
        required: false,
        description: 'Mensagem de erro'
      }
    ],
    examples: [
      {
        title: 'Estados',
        description: 'Diferentes estados do input',
        code: `<Input label="Nome" placeholder="Digite seu nome" />
<Input label="Email" type="email" error="Email inválido" />
<Input label="Senha" type="password" disabled />`,
        component: (
          <div className="space-y-4">
            <Input label="Nome" placeholder="Digite seu nome" />
            <Input label="Email" type="email" error="Email inválido" />
            <Input label="Senha" type="password" disabled />
          </div>
        )
      }
    ],
    usage: [
      'Use labels descritivos',
      'Forneça feedback de erro claro',
      'Mantenha consistência no layout'
    ],
    accessibility: [
      'Associação automática label-input',
      'Indicadores de erro para leitores de tela',
      'Suporte a navegação por teclado'
    ]
  }
];

const mockDesignTokens: DesignToken[] = [
  {
    name: 'primary-500',
    category: 'color',
    value: '#3B82F6',
    description: 'Cor primária principal',
    usage: ['Botões primários', 'Links', 'Elementos de destaque']
  },
  {
    name: 'secondary-500',
    category: 'color',
    value: '#6B7280',
    description: 'Cor secundária',
    usage: ['Botões secundários', 'Texto secundário']
  },
  {
    name: 'success-500',
    category: 'color',
    value: '#10B981',
    description: 'Cor de sucesso',
    usage: ['Mensagens de sucesso', 'Indicadores positivos']
  },
  {
    name: 'error-500',
    category: 'color',
    value: '#EF4444',
    description: 'Cor de erro',
    usage: ['Mensagens de erro', 'Indicadores negativos']
  },
  {
    name: 'font-size-base',
    category: 'typography',
    value: '16px',
    description: 'Tamanho base da fonte',
    usage: ['Texto do corpo', 'Parágrafos']
  },
  {
    name: 'font-size-lg',
    category: 'typography',
    value: '18px',
    description: 'Texto grande',
    usage: ['Títulos secundários', 'Destaques']
  },
  {
    name: 'spacing-4',
    category: 'spacing',
    value: '16px',
    description: 'Espaçamento pequeno',
    usage: ['Padding interno', 'Margens pequenas']
  },
  {
    name: 'spacing-8',
    category: 'spacing',
    value: '32px',
    description: 'Espaçamento médio',
    usage: ['Separação de seções', 'Margens médias']
  },
  {
    name: 'shadow-sm',
    category: 'shadow',
    value: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    description: 'Sombra pequena',
    usage: ['Cards', 'Elementos elevados']
  },
  {
    name: 'shadow-md',
    category: 'shadow',
    value: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    description: 'Sombra média',
    usage: ['Modais', 'Dropdowns']
  }
];

const mockStories: StorybookStory[] = [
  {
    id: 'button--primary',
    title: 'Button/Primary',
    component: 'Button',
    args: {
      variant: 'primary',
      children: 'Button',
      disabled: false
    },
    argTypes: {
      variant: {
        control: { type: 'select' },
        options: ['primary', 'secondary', 'outline', 'ghost']
      },
      size: {
        control: { type: 'select' },
        options: ['sm', 'md', 'lg']
      },
      disabled: {
        control: { type: 'boolean' }
      }
    },
    parameters: {
      docs: {
        description: {
          component: 'Botão primário com múltiplas variantes'
        }
      }
    }
  },
  {
    id: 'input--default',
    title: 'Input/Default',
    component: 'Input',
    args: {
      label: 'Label',
      placeholder: 'Placeholder',
      type: 'text'
    },
    argTypes: {
      type: {
        control: { type: 'select' },
        options: ['text', 'email', 'password', 'number']
      },
      error: {
        control: { type: 'text' }
      }
    },
    parameters: {
      docs: {
        description: {
          component: 'Campo de entrada com validação'
        }
      }
    }
  }
];

// ===== COMPONENTE PRINCIPAL =====

export const DesignSystem: React.FC = () => {
  const { t } = useI18n();
  const { colors } = useTheme();
  const [activeTab, setActiveTab] = useState<'components' | 'tokens' | 'storybook' | 'library'>('components');
  const [selectedComponent, setSelectedComponent] = useState<ComponentDoc | null>(null);
  const [selectedToken, setSelectedToken] = useState<DesignToken | null>(null);
  const [showComponentModal, setShowComponentModal] = useState(false);
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  // Filtrar componentes
  const filteredComponents = mockComponents.filter(component => {
    const matchesSearch = component.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         component.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || component.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Filtrar tokens
  const filteredTokens = mockDesignTokens.filter(token => {
    const matchesSearch = token.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         token.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || token.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  // Renderizar documentação de componentes
  const renderComponents = () => {
    return (
      <div className="space-y-6">
        {/* Filtros */}
        <div className="flex space-x-4">
          <div className="flex-1">
            <Input
              placeholder="Buscar componentes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Select
            value={selectedCategory}
            onChange={(value) => setSelectedCategory(value)}
            options={[
              { value: 'all', label: 'Todas as categorias' },
              { value: 'base', label: 'Base' },
              { value: 'layout', label: 'Layout' },
              { value: 'forms', label: 'Formulários' },
              { value: 'feedback', label: 'Feedback' },
              { value: 'navigation', label: 'Navegação' },
              { value: 'data', label: 'Dados' },
              { value: 'media', label: 'Mídia' }
            ]}
          />
        </div>

        {/* Lista de componentes */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredComponents.map((component) => (
            <Card key={component.name} className="p-6 hover:shadow-lg transition-shadow cursor-pointer"
                  onClick={() => {
                    setSelectedComponent(component);
                    setShowComponentModal(true);
                  }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">{component.name}</h3>
                <span className={`px-2 py-1 rounded text-xs ${
                  component.category === 'base' ? 'bg-blue-100 text-blue-800' :
                  component.category === 'forms' ? 'bg-green-100 text-green-800' :
                  component.category === 'feedback' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {component.category}
                </span>
              </div>
              
              <p className="text-gray-600 text-sm mb-4">{component.description}</p>
              
              <div className="flex items-center justify-between text-sm text-gray-500">
                <span>{component.props.length} props</span>
                <span>{component.examples.length} exemplos</span>
              </div>
            </Card>
          ))}
        </div>
      </div>
    );
  };

  // Renderizar design tokens
  const renderDesignTokens = () => {
    return (
      <div className="space-y-6">
        {/* Filtros */}
        <div className="flex space-x-4">
          <div className="flex-1">
            <Input
              placeholder="Buscar tokens..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Select
            value={selectedCategory}
            onChange={(value) => setSelectedCategory(value)}
            options={[
              { value: 'all', label: 'Todas as categorias' },
              { value: 'color', label: 'Cores' },
              { value: 'typography', label: 'Tipografia' },
              { value: 'spacing', label: 'Espaçamento' },
              { value: 'shadow', label: 'Sombras' },
              { value: 'border', label: 'Bordas' },
              { value: 'animation', label: 'Animações' }
            ]}
          />
        </div>

        {/* Lista de tokens */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredTokens.map((token) => (
            <Card key={token.name} className="p-6 hover:shadow-lg transition-shadow cursor-pointer"
                  onClick={() => {
                    setSelectedToken(token);
                    setShowTokenModal(true);
                  }}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">{token.name}</h3>
                <span className={`px-2 py-1 rounded text-xs ${
                  token.category === 'color' ? 'bg-red-100 text-red-800' :
                  token.category === 'typography' ? 'bg-blue-100 text-blue-800' :
                  token.category === 'spacing' ? 'bg-green-100 text-green-800' :
                  'bg-gray-100 text-gray-800'
                }`}>
                  {token.category}
                </span>
              </div>
              
              <div className="mb-4">
                {token.category === 'color' ? (
                  <div className="flex items-center space-x-3">
                    <div
                      className="w-8 h-8 rounded border"
                      style={{ backgroundColor: token.value }}
                    />
                    <code className="text-sm">{token.value}</code>
                  </div>
                ) : (
                  <code className="text-sm bg-gray-100 px-2 py-1 rounded">{token.value}</code>
                )}
              </div>
              
              <p className="text-gray-600 text-sm mb-4">{token.description}</p>
              
              <div className="text-sm text-gray-500">
                {token.usage.length} usos
              </div>
            </Card>
          ))}
        </div>
      </div>
    );
  };

  // Renderizar Storybook
  const renderStorybook = () => {
    return (
      <div className="space-y-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="font-medium text-blue-900 mb-2">Storybook</h3>
          <p className="text-blue-700 text-sm mb-3">
            O Storybook está configurado para documentação interativa dos componentes.
          </p>
          <div className="flex space-x-3">
            <Button size="sm" variant="primary">
              Abrir Storybook
            </Button>
            <Button size="sm" variant="outline">
              Ver Documentação
            </Button>
          </div>
        </div>

        {/* Lista de stories */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Stories Disponíveis</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {mockStories.map((story) => (
              <Card key={story.id} className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium">{story.title}</h4>
                  <span className="text-xs text-gray-500">{story.component}</span>
                </div>
                <p className="text-sm text-gray-600 mb-3">
                  {story.parameters.docs.description.component}
                </p>
                <div className="flex space-x-2">
                  <Button size="sm" variant="outline">
                    Ver Story
                  </Button>
                  <Button size="sm" variant="secondary">
                    Editar
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </div>
      </div>
    );
  };

  // Renderizar component library
  const renderComponentLibrary = () => {
    return (
      <div className="space-y-6">
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <h3 className="font-medium text-green-900 mb-2">Component Library</h3>
          <p className="text-green-700 text-sm mb-3">
            Biblioteca de componentes reutilizáveis e documentados.
          </p>
          <div className="flex space-x-3">
            <Button size="sm" variant="primary">
              Exportar Library
            </Button>
            <Button size="sm" variant="outline">
              Ver Changelog
            </Button>
          </div>
        </div>

        {/* Estatísticas */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{mockComponents.length}</div>
              <div className="text-sm text-gray-600">Componentes</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{mockDesignTokens.length}</div>
              <div className="text-sm text-gray-600">Design Tokens</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600">{mockStories.length}</div>
              <div className="text-sm text-gray-600">Stories</div>
            </div>
          </Card>
          
          <Card className="p-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">100%</div>
              <div className="text-sm text-gray-600">Cobertura de Testes</div>
            </div>
          </Card>
        </div>

        {/* Categorias */}
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Categorias de Componentes</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { name: 'Base', count: 8, color: 'blue' },
              { name: 'Layout', count: 5, color: 'green' },
              { name: 'Forms', count: 12, color: 'purple' },
              { name: 'Feedback', count: 6, color: 'yellow' },
              { name: 'Navigation', count: 4, color: 'red' },
              { name: 'Data', count: 7, color: 'indigo' },
              { name: 'Media', count: 3, color: 'pink' }
            ].map((category) => (
              <Card key={category.name} className="p-4">
                <div className="text-center">
                  <div className={`text-2xl font-bold text-${category.color}-600`}>{category.count}</div>
                  <div className="text-sm text-gray-600">{category.name}</div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Sistema de Design</h1>
          <p className="text-gray-600">Documentação e biblioteca de componentes</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'components', label: 'Componentes', icon: '🧩' },
            { id: 'tokens', label: 'Design Tokens', icon: '🎨' },
            { id: 'storybook', label: 'Storybook', icon: '📚' },
            { id: 'library', label: 'Component Library', icon: '📦' }
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
        {activeTab === 'components' && renderComponents()}
        {activeTab === 'tokens' && renderDesignTokens()}
        {activeTab === 'storybook' && renderStorybook()}
        {activeTab === 'library' && renderComponentLibrary()}
      </div>

      {/* Modal de detalhes do componente */}
      <Modal
        isOpen={showComponentModal}
        onClose={() => setShowComponentModal(false)}
        title={selectedComponent?.name}
        size="xl"
      >
        {selectedComponent && (
          <div className="space-y-6">
            <div>
              <h3 className="font-semibold mb-2">Descrição</h3>
              <p className="text-gray-600">{selectedComponent.description}</p>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Props</h3>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-2">Nome</th>
                      <th className="text-left py-2">Tipo</th>
                      <th className="text-left py-2">Obrigatório</th>
                      <th className="text-left py-2">Padrão</th>
                      <th className="text-left py-2">Descrição</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedComponent.props.map((prop) => (
                      <tr key={prop.name} className="border-b">
                        <td className="py-2 font-mono text-sm">{prop.name}</td>
                        <td className="py-2 font-mono text-sm">{prop.type}</td>
                        <td className="py-2">{prop.required ? 'Sim' : 'Não'}</td>
                        <td className="py-2 font-mono text-sm">{prop.defaultValue || '-'}</td>
                        <td className="py-2 text-sm">{prop.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Exemplos</h3>
              <div className="space-y-4">
                {selectedComponent.examples.map((example, index) => (
                  <Card key={index} className="p-4">
                    <h4 className="font-medium mb-2">{example.title}</h4>
                    <p className="text-sm text-gray-600 mb-3">{example.description}</p>
                    <div className="mb-3">
                      {example.component}
                    </div>
                    <pre className="bg-gray-100 p-3 rounded text-sm overflow-x-auto">
                      <code>{example.code}</code>
                    </pre>
                  </Card>
                ))}
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Como Usar</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-gray-600">
                {selectedComponent.usage.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Acessibilidade</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-gray-600">
                {selectedComponent.accessibility.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </Modal>

      {/* Modal de detalhes do token */}
      <Modal
        isOpen={showTokenModal}
        onClose={() => setShowTokenModal(false)}
        title={selectedToken?.name}
        size="md"
      >
        {selectedToken && (
          <div className="space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Valor</h3>
              {selectedToken.category === 'color' ? (
                <div className="flex items-center space-x-3">
                  <div
                    className="w-12 h-12 rounded border"
                    style={{ backgroundColor: selectedToken.value }}
                  />
                  <code className="text-lg">{selectedToken.value}</code>
                </div>
              ) : (
                <code className="text-lg bg-gray-100 px-3 py-2 rounded">{selectedToken.value}</code>
              )}
            </div>

            <div>
              <h3 className="font-semibold mb-2">Descrição</h3>
              <p className="text-gray-600">{selectedToken.description}</p>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Uso</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-gray-600">
                {selectedToken.usage.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default DesignSystem; 