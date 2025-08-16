/**
 * Button Stories - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-026.2
 * Data/Hora: 2025-01-28T02:40:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Todas as variantes do Button
 * - Estados diferentes
 * - Interações
 * - Documentação completa
 */

import type { Meta, StoryObj } from '@storybook/react';
import { Button } from '../components/base/Button';

// ===== METADATA =====

const meta: Meta<typeof Button> = {
  title: 'Components/Base/Button',
  component: Button,
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component: `
          Componente de botão com múltiplas variantes e estados.
          
          **Variantes:**
          - \`primary\`: Botão principal com destaque
          - \`secondary\`: Botão secundário
          - \`outline\`: Botão com borda
          - \`ghost\`: Botão transparente
          
          **Tamanhos:**
          - \`sm\`: Pequeno
          - \`md\`: Médio (padrão)
          - \`lg\`: Grande
          
          **Estados:**
          - Normal
          - Hover
          - Active
          - Disabled
          - Loading
        `
      }
    }
  },
  argTypes: {
    variant: {
      control: { type: 'select' },
      options: ['primary', 'secondary', 'outline', 'ghost'],
      description: 'Variante visual do botão'
    },
    size: {
      control: { type: 'select' },
      options: ['sm', 'md', 'lg'],
      description: 'Tamanho do botão'
    },
    disabled: {
      control: { type: 'boolean' },
      description: 'Estado desabilitado'
    },
    loading: {
      control: { type: 'boolean' },
      description: 'Estado de carregamento'
    },
    onClick: {
      action: 'clicked',
      description: 'Função chamada ao clicar'
    }
  },
  tags: ['autodocs']
};

export default meta;
type Story = StoryObj<typeof Button>;

// ===== STORIES =====

/**
 * Botão Primário - Variante padrão
 */
export const Primary: Story = {
  args: {
    variant: 'primary',
    children: 'Botão Primário',
    onClick: () => console.log('Botão primário clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão primário com destaque visual. Usado para ações principais.'
      }
    }
  }
};

/**
 * Botão Secundário
 */
export const Secondary: Story = {
  args: {
    variant: 'secondary',
    children: 'Botão Secundário',
    onClick: () => console.log('Botão secundário clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão secundário com menos destaque. Usado para ações complementares.'
      }
    }
  }
};

/**
 * Botão Outline
 */
export const Outline: Story = {
  args: {
    variant: 'outline',
    children: 'Botão Outline',
    onClick: () => console.log('Botão outline clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com borda e fundo transparente. Usado para ações menos importantes.'
      }
    }
  }
};

/**
 * Botão Ghost
 */
export const Ghost: Story = {
  args: {
    variant: 'ghost',
    children: 'Botão Ghost',
    onClick: () => console.log('Botão ghost clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão transparente sem borda. Usado para ações sutis.'
      }
    }
  }
};

/**
 * Tamanhos de Botão
 */
export const Sizes: Story = {
  render: () => (
    <div className="flex gap-4 items-center">
      <Button size="sm" variant="primary">
        Pequeno
      </Button>
      <Button size="md" variant="primary">
        Médio
      </Button>
      <Button size="lg" variant="primary">
        Grande
      </Button>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: 'Comparação dos diferentes tamanhos de botão disponíveis.'
      }
    }
  }
};

/**
 * Estados do Botão
 */
export const States: Story = {
  render: () => (
    <div className="flex gap-4 items-center">
      <Button variant="primary">
        Normal
      </Button>
      <Button variant="primary" disabled>
        Desabilitado
      </Button>
      <Button variant="primary" loading>
        Carregando
      </Button>
    </div>
  ),
  parameters: {
    docs: {
      description: {
        story: 'Diferentes estados do botão: normal, desabilitado e carregando.'
      }
    }
  }
};

/**
 * Botão com Ícone
 */
export const WithIcon: Story = {
  args: {
    variant: 'primary',
    children: (
      <>
        <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
        </svg>
        Adicionar Item
      </>
    ),
    onClick: () => console.log('Botão com ícone clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com ícone SVG integrado. Útil para ações específicas.'
      }
    }
  }
};

/**
 * Botão de Ação Perigosa
 */
export const Danger: Story = {
  args: {
    variant: 'primary',
    children: 'Excluir',
    className: 'bg-red-600 hover:bg-red-700 focus:ring-red-500',
    onClick: () => console.log('Ação perigosa executada')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão para ações perigosas com cor vermelha. Use com cautela.'
      }
    }
  }
};

/**
 * Botão de Sucesso
 */
export const Success: Story = {
  args: {
    variant: 'primary',
    children: 'Salvar',
    className: 'bg-green-600 hover:bg-green-700 focus:ring-green-500',
    onClick: () => console.log('Ação de sucesso executada')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão para ações de sucesso com cor verde.'
      }
    }
  }
};

/**
 * Botão Full Width
 */
export const FullWidth: Story = {
  args: {
    variant: 'primary',
    children: 'Botão Largura Total',
    className: 'w-full',
    onClick: () => console.log('Botão full width clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão que ocupa toda a largura disponível do container.'
      }
    }
  }
};

/**
 * Botão com Loading State
 */
export const LoadingState: Story = {
  args: {
    variant: 'primary',
    children: 'Processando...',
    loading: true,
    disabled: true
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão em estado de carregamento com spinner e texto alterado.'
      }
    }
  }
};

/**
 * Botão com Tooltip
 */
export const WithTooltip: Story = {
  args: {
    variant: 'ghost',
    children: '?',
    className: 'w-8 h-8 rounded-full',
    title: 'Clique para obter ajuda',
    onClick: () => console.log('Tooltip button clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão pequeno com tooltip nativo do navegador.'
      }
    }
  }
};

/**
 * Botão com Badge
 */
export const WithBadge: Story = {
  args: {
    variant: 'outline',
    children: (
      <div className="flex items-center">
        Notificações
        <span className="ml-2 bg-red-500 text-white text-xs rounded-full px-2 py-1">
          3
        </span>
      </div>
    ),
    onClick: () => console.log('Botão com badge clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com badge indicando quantidade de notificações.'
      }
    }
  }
};

/**
 * Botão com Dropdown
 */
export const WithDropdown: Story = {
  args: {
    variant: 'outline',
    children: (
      <div className="flex items-center">
        Opções
        <svg className="w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    ),
    onClick: () => console.log('Botão dropdown clicado')
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com ícone de dropdown para menus.'
      }
    }
  }
};

/**
 * Botão com Loading Progressivo
 */
export const ProgressiveLoading: Story = {
  render: () => {
    const [loading, setLoading] = React.useState(false);
    const [progress, setProgress] = React.useState(0);

    const handleClick = () => {
      setLoading(true);
      setProgress(0);
      
      const interval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setLoading(false);
            return 0;
          }
          return prev + 10;
        });
      }, 200);
    };

    return (
      <Button
        variant="primary"
        loading={loading}
        onClick={handleClick}
        className="relative overflow-hidden"
      >
        {loading ? (
          <>
            <span className="relative z-10">Processando... {progress}%</span>
            <div
              className="absolute inset-0 bg-blue-700 transition-all duration-200"
              style={{ width: `${progress}%` }}
            />
          </>
        ) : (
          'Iniciar Processo'
        )}
      </Button>
    );
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com loading progressivo mostrando porcentagem de conclusão.'
      }
    }
  }
};

/**
 * Botão com Confirmação
 */
export const WithConfirmation: Story = {
  render: () => {
    const [confirming, setConfirming] = React.useState(false);

    const handleClick = () => {
      if (!confirming) {
        setConfirming(true);
        setTimeout(() => setConfirming(false), 3000);
      } else {
        console.log('Ação confirmada!');
        setConfirming(false);
      }
    };

    return (
      <Button
        variant={confirming ? 'danger' : 'primary'}
        onClick={handleClick}
        className={confirming ? 'bg-red-600 hover:bg-red-700' : ''}
      >
        {confirming ? 'Clique novamente para confirmar' : 'Ação Perigosa'}
      </Button>
    );
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão que requer confirmação antes de executar ação perigosa.'
      }
    }
  }
};

/**
 * Botão com Feedback Visual
 */
export const WithVisualFeedback: Story = {
  render: () => {
    const [clicked, setClicked] = React.useState(false);

    const handleClick = () => {
      setClicked(true);
      setTimeout(() => setClicked(false), 1000);
    };

    return (
      <Button
        variant="primary"
        onClick={handleClick}
        className={`transition-all duration-200 ${
          clicked ? 'scale-95 bg-green-600' : ''
        }`}
      >
        {clicked ? '✓ Concluído!' : 'Clique Aqui'}
      </Button>
    );
  },
  parameters: {
    docs: {
      description: {
        story: 'Botão com feedback visual imediato ao ser clicado.'
      }
    }
  }
}; 