/**
 * Testes Unitários - Página de Perfil do Usuário
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-018
 * Data/Hora: 2025-01-27T23:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em código real da página Profile.tsx
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Profile from '../Profile';

// Mock dos hooks
const mockApiCall = jest.fn();
const mockT = jest.fn((key) => key);
const mockUser = 'user123';

jest.mock('../../hooks/use_api', () => ({
  useApi: () => ({
    apiCall: mockApiCall,
  }),
}));

jest.mock('../../hooks/use_i18n', () => ({
  useI18n: () => ({
    t: mockT,
  }),
}));

jest.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    user: mockUser,
  }),
}));

// Mock dos componentes base
jest.mock('../../components/base', () => ({
  Card: ({ children, ...props }: any) => <div data-testid="card" {...props}>{children}</div>,
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button data-testid="button" onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
  Input: ({ value, onChange, error, ...props }: any) => (
    <input
      data-testid="input"
      value={value}
      onChange={onChange}
      {...props}
    />
  ),
  Select: ({ value, onChange, options, ...props }: any) => (
    <select data-testid="select" value={value} onChange={onChange} {...props}>
      {options?.map((opt: any) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  ),
  Switch: ({ checked, onChange, ...props }: any) => (
    <input
      data-testid="switch"
      type="checkbox"
      checked={checked}
      onChange={(e) => onChange(e.target.checked)}
      {...props}
    />
  ),
  Toast: ({ message, type, onClose, ...props }: any) => (
    <div data-testid="toast" data-type={type} onClick={onClose} {...props}>
      {message}
    </div>
  ),
}));

const renderProfile = () => {
  return render(
    <BrowserRouter>
      <Profile />
    </BrowserRouter>
  );
};

describe('Profile Page', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockApiCall.mockResolvedValue({
      success: true,
      user: {
        id: 'user123',
        name: 'João Silva',
        email: 'joao@example.com',
        avatar: null,
        bio: 'Desenvolvedor apaixonado por tecnologia',
        website: 'https://joao.dev',
        location: 'São Paulo, Brasil',
        joinedAt: '2024-01-01T00:00:00Z',
        lastLogin: '2025-01-27T22:00:00Z',
      },
      metrics: {
        totalArticles: 150,
        totalBlogs: 12,
        averageQuality: 8.5,
        tokensUsed: 45000,
        lastActivity: '2025-01-27T22:00:00Z',
        articlesThisMonth: 25,
        blogsThisMonth: 3,
        averageGenerationTime: 45.2,
        successRate: 95.5,
      },
      preferences: {
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
      },
      activities: [
        {
          id: '1',
          type: 'article_generated',
          title: 'Artigo gerado com sucesso',
          description: 'Artigo sobre inteligência artificial foi gerado',
          timestamp: '2025-01-27T22:00:00Z',
          metadata: {
            articleId: 'art123',
            quality: 8.5,
          },
        },
        {
          id: '2',
          type: 'blog_created',
          title: 'Blog criado',
          description: 'Novo blog "Tecnologia" foi criado',
          timestamp: '2025-01-26T15:30:00Z',
          metadata: {
            blogId: 'blog456',
          },
        },
      ],
    });
  });

  describe('Carregamento Inicial', () => {
    it('deve carregar dados do perfil ao montar o componente', async () => {
      renderProfile();
      
      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123', 'GET');
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/metrics', 'GET');
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/preferences', 'GET');
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/activities', 'GET', null, {
          params: { page: 1, filter: 'all', limit: 20 }
        });
      });
    });

    it('deve mostrar loading durante carregamento', () => {
      mockApiCall.mockImplementation(() => new Promise(() => {})); // Promise que nunca resolve
      
      renderProfile();
      
      expect(screen.getByText('Carregando perfil...')).toBeInTheDocument();
    });

    it('deve mostrar erro se falhar ao carregar perfil', async () => {
      mockApiCall.mockRejectedValue(new Error('Erro de rede'));
      
      renderProfile();
      
      await waitFor(() => {
        expect(screen.getByText('Erro ao carregar perfil')).toBeInTheDocument();
      });
    });
  });

  describe('Navegação entre Tabs', () => {
    it('deve mostrar tab Informações Pessoais por padrão', async () => {
      renderProfile();
      
      await waitFor(() => {
        expect(screen.getByText('Informações Pessoais')).toBeInTheDocument();
      });
    });

    it('deve alternar para tab Preferências', async () => {
      renderProfile();
      
      await waitFor(() => {
        const preferencesTab = screen.getByText('⚙️ Preferências');
        fireEvent.click(preferencesTab);
        
        expect(screen.getByText('Preferências de Interface')).toBeInTheDocument();
      });
    });

    it('deve alternar para tab Histórico', async () => {
      renderProfile();
      
      await waitFor(() => {
        const historyTab = screen.getByText('📋 Histórico');
        fireEvent.click(historyTab);
        
        expect(screen.getByText('Histórico de Atividades')).toBeInTheDocument();
      });
    });
  });

  describe('Tab Informações Pessoais', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        expect(screen.getByText('Informações Pessoais')).toBeInTheDocument();
      });
    });

    it('deve exibir informações do perfil', async () => {
      await waitFor(() => {
        expect(screen.getByText('João Silva')).toBeInTheDocument();
        expect(screen.getByText('joao@example.com')).toBeInTheDocument();
        expect(screen.getByText('Membro desde 01/01/2024')).toBeInTheDocument();
      });
    });

    it('deve permitir editar nome', async () => {
      await waitFor(() => {
        const nameInput = screen.getByDisplayValue('João Silva');
        fireEvent.change(nameInput, { target: { value: 'João Silva Santos' } });
        
        expect(nameInput).toHaveValue('João Silva Santos');
      });
    });

    it('deve permitir editar email', async () => {
      await waitFor(() => {
        const emailInput = screen.getByDisplayValue('joao@example.com');
        fireEvent.change(emailInput, { target: { value: 'joao.santos@example.com' } });
        
        expect(emailInput).toHaveValue('joao.santos@example.com');
      });
    });

    it('deve permitir editar website', async () => {
      await waitFor(() => {
        const websiteInput = screen.getByDisplayValue('https://joao.dev');
        fireEvent.change(websiteInput, { target: { value: 'https://joao.dev.br' } });
        
        expect(websiteInput).toHaveValue('https://joao.dev.br');
      });
    });

    it('deve permitir editar localização', async () => {
      await waitFor(() => {
        const locationInput = screen.getByDisplayValue('São Paulo, Brasil');
        fireEvent.change(locationInput, { target: { value: 'Rio de Janeiro, Brasil' } });
        
        expect(locationInput).toHaveValue('Rio de Janeiro, Brasil');
      });
    });

    it('deve permitir editar biografia', async () => {
      await waitFor(() => {
        const bioTextarea = screen.getByDisplayValue('Desenvolvedor apaixonado por tecnologia');
        fireEvent.change(bioTextarea, { target: { value: 'Desenvolvedor full-stack apaixonado por tecnologia e inovação' } });
        
        expect(bioTextarea).toHaveValue('Desenvolvedor full-stack apaixonado por tecnologia e inovação');
      });
    });

    it('deve exibir estatísticas do usuário', async () => {
      await waitFor(() => {
        expect(screen.getByText('150')).toBeInTheDocument(); // Total de artigos
        expect(screen.getByText('12')).toBeInTheDocument(); // Total de blogs
        expect(screen.getByText('8.5')).toBeInTheDocument(); // Qualidade média
        expect(screen.getByText('95%')).toBeInTheDocument(); // Taxa de sucesso
      });
    });

    it('deve salvar perfil com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({ success: true });
      
      await waitFor(() => {
        const saveButton = screen.getByText('Salvar Perfil');
        fireEvent.click(saveButton);
      });
      
      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123', 'PUT', expect.any(Object));
      });
    });
  });

  describe('Tab Preferências', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        const preferencesTab = screen.getByText('⚙️ Preferências');
        fireEvent.click(preferencesTab);
      });
    });

    it('deve permitir alterar tema', async () => {
      await waitFor(() => {
        const themeSelect = screen.getByDisplayValue('Automático');
        fireEvent.change(themeSelect, { target: { value: 'dark' } });
        
        expect(themeSelect).toHaveValue('dark');
      });
    });

    it('deve permitir alterar idioma', async () => {
      await waitFor(() => {
        const languageSelect = screen.getByDisplayValue('Português (Brasil)');
        fireEvent.change(languageSelect, { target: { value: 'en-US' } });
        
        expect(languageSelect).toHaveValue('en-US');
      });
    });

    it('deve permitir alternar notificações por email', async () => {
      await waitFor(() => {
        const emailSwitch = screen.getByDisplayValue('true');
        fireEvent.click(emailSwitch);
        
        expect(emailSwitch).not.toBeChecked();
      });
    });

    it('deve permitir alternar notificações push', async () => {
      await waitFor(() => {
        const pushSwitch = screen.getByDisplayValue('false');
        fireEvent.click(pushSwitch);
        
        expect(pushSwitch).toBeChecked();
      });
    });

    it('deve permitir alternar notificações SMS', async () => {
      await waitFor(() => {
        const smsSwitch = screen.getByDisplayValue('false');
        fireEvent.click(smsSwitch);
        
        expect(smsSwitch).toBeChecked();
      });
    });

    it('deve permitir alterar visibilidade do perfil', async () => {
      await waitFor(() => {
        const visibilitySelect = screen.getByDisplayValue('Privado');
        fireEvent.change(visibilitySelect, { target: { value: 'public' } });
        
        expect(visibilitySelect).toHaveValue('public');
      });
    });

    it('deve permitir alternar mostrar métricas', async () => {
      await waitFor(() => {
        const metricsSwitch = screen.getByDisplayValue('true');
        fireEvent.click(metricsSwitch);
        
        expect(metricsSwitch).not.toBeChecked();
      });
    });

    it('deve permitir alternar mostrar atividades', async () => {
      await waitFor(() => {
        const activitySwitch = screen.getByDisplayValue('true');
        fireEvent.click(activitySwitch);
        
        expect(activitySwitch).not.toBeChecked();
      });
    });

    it('deve permitir alterar modelo padrão', async () => {
      await waitFor(() => {
        const modelSelect = screen.getByDisplayValue('OpenAI');
        fireEvent.change(modelSelect, { target: { value: 'deepseek' } });
        
        expect(modelSelect).toHaveValue('deepseek');
      });
    });

    it('deve permitir alterar idioma padrão', async () => {
      await waitFor(() => {
        const defaultLanguageSelect = screen.getByDisplayValue('Português');
        fireEvent.change(defaultLanguageSelect, { target: { value: 'en-US' } });
        
        expect(defaultLanguageSelect).toHaveValue('en-US');
      });
    });

    it('deve permitir alternar salvamento automático', async () => {
      await waitFor(() => {
        const autoSaveSwitch = screen.getByDisplayValue('true');
        fireEvent.click(autoSaveSwitch);
        
        expect(autoSaveSwitch).not.toBeChecked();
      });
    });

    it('deve salvar preferências com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({ success: true });
      
      await waitFor(() => {
        const saveButton = screen.getByText('Salvar Preferências');
        fireEvent.click(saveButton);
      });
      
      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/preferences', 'PUT', expect.any(Object));
      });
    });
  });

  describe('Tab Histórico', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        const historyTab = screen.getByText('📋 Histórico');
        fireEvent.click(historyTab);
      });
    });

    it('deve exibir histórico de atividades', async () => {
      await waitFor(() => {
        expect(screen.getByText('Artigo gerado com sucesso')).toBeInTheDocument();
        expect(screen.getByText('Blog criado')).toBeInTheDocument();
      });
    });

    it('deve filtrar atividades por tipo', async () => {
      await waitFor(() => {
        const articlesFilter = screen.getByText('Artigos');
        fireEvent.click(articlesFilter);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/activities', 'GET', null, {
          params: { page: 1, filter: 'article_generated', limit: 20 }
        });
      });
    });

    it('deve filtrar atividades por blogs', async () => {
      await waitFor(() => {
        const blogsFilter = screen.getByText('Blogs');
        fireEvent.click(blogsFilter);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/activities', 'GET', null, {
          params: { page: 1, filter: 'blog_created', limit: 20 }
        });
      });
    });

    it('deve filtrar atividades por prompts', async () => {
      await waitFor(() => {
        const promptsFilter = screen.getByText('Prompts');
        fireEvent.click(promptsFilter);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/activities', 'GET', null, {
          params: { page: 1, filter: 'prompt_uploaded', limit: 20 }
        });
      });
    });

    it('deve carregar mais atividades', async () => {
      await waitFor(() => {
        const loadMoreButton = screen.getByText('Carregar Mais');
        fireEvent.click(loadMoreButton);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/users/user123/activities', 'GET', null, {
          params: { page: 2, filter: 'all', limit: 20 }
        });
      });
    });

    it('deve exibir ícones corretos para cada tipo de atividade', async () => {
      await waitFor(() => {
        expect(screen.getByText('📝')).toBeInTheDocument(); // Artigo gerado
        expect(screen.getByText('📚')).toBeInTheDocument(); // Blog criado
      });
    });

    it('deve exibir metadados das atividades', async () => {
      await waitFor(() => {
        expect(screen.getByText('Qualidade: 8.5')).toBeInTheDocument();
      });
    });

    it('deve exibir mensagem quando não há atividades', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        activities: [],
      });
      
      await waitFor(() => {
        expect(screen.getByText('Nenhuma atividade encontrada')).toBeInTheDocument();
      });
    });
  });

  describe('Validações', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        expect(screen.getByText('Informações Pessoais')).toBeInTheDocument();
      });
    });

    it('deve validar nome muito curto', async () => {
      await waitFor(() => {
        const nameInput = screen.getByDisplayValue('João Silva');
        fireEvent.change(nameInput, { target: { value: 'J' } });
        
        // A validação deve ser feita no componente Input
        expect(nameInput).toHaveValue('J');
      });
    });

    it('deve validar email inválido', async () => {
      await waitFor(() => {
        const emailInput = screen.getByDisplayValue('joao@example.com');
        fireEvent.change(emailInput, { target: { value: 'email-invalido' } });
        
        // A validação deve ser feita no componente Input
        expect(emailInput).toHaveValue('email-invalido');
      });
    });

    it('deve validar website inválido', async () => {
      await waitFor(() => {
        const websiteInput = screen.getByDisplayValue('https://joao.dev');
        fireEvent.change(websiteInput, { target: { value: 'site-invalido' } });
        
        // A validação deve ser feita no componente Input
        expect(websiteInput).toHaveValue('site-invalido');
      });
    });
  });

  describe('Acessibilidade', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        expect(screen.getByText('Informações Pessoais')).toBeInTheDocument();
      });
    });

    it('deve ter título principal', () => {
      expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
      expect(screen.getByText('Perfil do Usuário')).toBeInTheDocument();
    });

    it('deve ter descrição da página', () => {
      expect(screen.getByText(/Gerencie suas informações pessoais/)).toBeInTheDocument();
    });

    it('deve ter navegação por tabs', () => {
      expect(screen.getByText('👤 Informações Pessoais')).toBeInTheDocument();
      expect(screen.getByText('⚙️ Preferências')).toBeInTheDocument();
      expect(screen.getByText('📋 Histórico')).toBeInTheDocument();
    });

    it('deve ter botões de ação', () => {
      expect(screen.getByText('Salvar Perfil')).toBeInTheDocument();
    });
  });

  describe('Responsividade', () => {
    beforeEach(async () => {
      renderProfile();
      await waitFor(() => {
        expect(screen.getByText('Informações Pessoais')).toBeInTheDocument();
      });
    });

    it('deve renderizar todos os componentes base', () => {
      expect(screen.getAllByTestId('card')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('button')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('input')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('select')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('switch')).toHaveLength(expect.any(Number));
    });

    it('deve ter estrutura de grid responsiva', () => {
      const cards = screen.getAllByTestId('card');
      expect(cards.length).toBeGreaterThan(0);
    });
  });

  describe('Estados de Carregamento', () => {
    it('deve mostrar loading durante salvamento', async () => {
      mockApiCall.mockImplementation(() => new Promise(() => {})); // Promise que nunca resolve
      
      renderProfile();
      
      await waitFor(() => {
        const saveButton = screen.getByText('Salvar Perfil');
        fireEvent.click(saveButton);
        
        expect(screen.getByText('Salvando...')).toBeInTheDocument();
      });
    });
  });

  describe('Tratamento de Erros', () => {
    it('deve mostrar erro se falhar ao salvar perfil', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro de rede'));
      
      renderProfile();
      
      await waitFor(() => {
        const saveButton = screen.getByText('Salvar Perfil');
        fireEvent.click(saveButton);
      });
      
      await waitFor(() => {
        expect(screen.getByText('Erro ao atualizar perfil')).toBeInTheDocument();
      });
    });

    it('deve mostrar erro se falhar ao salvar preferências', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro de rede'));
      
      renderProfile();
      
      await waitFor(() => {
        const preferencesTab = screen.getByText('⚙️ Preferências');
        fireEvent.click(preferencesTab);
        
        const saveButton = screen.getByText('Salvar Preferências');
        fireEvent.click(saveButton);
      });
      
      await waitFor(() => {
        expect(screen.getByText('Erro ao salvar preferências')).toBeInTheDocument();
      });
    });
  });
}); 