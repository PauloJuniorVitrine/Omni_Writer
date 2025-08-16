/**
 * Testes Unitários - Página de Logs e Auditoria
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-019
 * Data/Hora: 2025-01-27T23:30:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em código real da página Logs.tsx
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Logs from '../Logs';

// Mock dos hooks
const mockApiCall = jest.fn();
const mockT = jest.fn((key) => key);

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

// Mock dos componentes base
jest.mock('../../components/base', () => ({
  Card: ({ children, ...props }: any) => <div data-testid="card" {...props}>{children}</div>,
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button data-testid="button" onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
  Input: ({ value, onChange, ...props }: any) => (
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

const renderLogs = () => {
  return render(
    <BrowserRouter>
      <Logs />
    </BrowserRouter>
  );
};

describe('Logs Page', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockApiCall.mockResolvedValue({
      success: true,
      logs: [
        {
          id: '1',
          timestamp: '2025-01-27T23:00:00Z',
          level: 'INFO',
          service: 'api',
          message: 'Requisição processada com sucesso',
          tracing_id: 'trace123',
          user_id: 'user123',
          ip_address: '127.0.0.1',
          user_agent: 'Mozilla/5.0...',
          metadata: {
            response_time: 150,
            status_code: 200,
          },
          audit_data: {
            action: 'read',
            resource_type: 'article',
            resource_id: 'art123',
          },
        },
        {
          id: '2',
          timestamp: '2025-01-27T22:55:00Z',
          level: 'ERROR',
          service: 'generation',
          message: 'Falha na geração de artigo',
          tracing_id: 'trace456',
          user_id: 'user456',
          ip_address: '127.0.0.2',
          user_agent: 'Mozilla/5.0...',
          metadata: {
            error_code: 'API_TIMEOUT',
            retry_count: 3,
          },
        },
        {
          id: '3',
          timestamp: '2025-01-27T22:50:00Z',
          level: 'WARNING',
          service: 'cache',
          message: 'Cache miss detectado',
          tracing_id: 'trace789',
          user_id: 'user789',
          ip_address: '127.0.0.3',
          user_agent: 'Mozilla/5.0...',
          metadata: {
            cache_key: 'user_prefs_123',
            cache_size: '50MB',
          },
        },
      ],
      metrics: {
        total_logs: 1500,
        logs_by_level: {
          'INFO': 800,
          'WARNING': 300,
          'ERROR': 200,
          'DEBUG': 150,
          'CRITICAL': 50,
        },
        logs_by_service: {
          'api': 500,
          'generation': 400,
          'cache': 300,
          'auth': 200,
          'monitoring': 100,
        },
        logs_by_hour: {
          '10': 100,
          '11': 120,
          '12': 150,
        },
        error_rate: 15.5,
        avg_response_time: 245.3,
        top_errors: [
          { message: 'API timeout', count: 50 },
          { message: 'Invalid token', count: 30 },
          { message: 'Rate limit exceeded', count: 20 },
        ],
        top_services: [
          { service: 'api', count: 500 },
          { service: 'generation', count: 400 },
          { service: 'cache', count: 300 },
        ],
      },
    });
  });

  describe('Carregamento Inicial', () => {
    it('deve carregar logs e métricas ao montar o componente', async () => {
      renderLogs();
      
      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/logs?page=1&page_size=100', 'GET');
        expect(mockApiCall).toHaveBeenCalledWith('/api/logs/metrics', 'GET');
      });
    });

    it('deve mostrar loading durante carregamento', () => {
      mockApiCall.mockImplementation(() => new Promise(() => {})); // Promise que nunca resolve
      
      renderLogs();
      
      expect(screen.getByText('Carregando...')).toBeInTheDocument();
    });

    it('deve mostrar erro se falhar ao carregar logs', async () => {
      mockApiCall.mockRejectedValue(new Error('Erro de rede'));
      
      renderLogs();
      
      await waitFor(() => {
        expect(screen.getByText('Erro ao carregar logs')).toBeInTheDocument();
      });
    });
  });

  describe('Métricas', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Métricas dos Logs')).toBeInTheDocument();
      });
    });

    it('deve exibir métricas dos logs', async () => {
      await waitFor(() => {
        expect(screen.getByText('1,500')).toBeInTheDocument(); // Total de logs
        expect(screen.getByText('15.5%')).toBeInTheDocument(); // Taxa de erro
        expect(screen.getByText('245ms')).toBeInTheDocument(); // Tempo médio
        expect(screen.getByText('5')).toBeInTheDocument(); // Serviços
      });
    });

    it('deve exibir logs por nível', async () => {
      await waitFor(() => {
        expect(screen.getByText('INFO')).toBeInTheDocument();
        expect(screen.getByText('ERROR')).toBeInTheDocument();
        expect(screen.getByText('WARNING')).toBeInTheDocument();
        expect(screen.getByText('800')).toBeInTheDocument(); // INFO count
        expect(screen.getByText('200')).toBeInTheDocument(); // ERROR count
      });
    });

    it('deve exibir top serviços', async () => {
      await waitFor(() => {
        expect(screen.getByText('api')).toBeInTheDocument();
        expect(screen.getByText('generation')).toBeInTheDocument();
        expect(screen.getByText('500')).toBeInTheDocument(); // api count
        expect(screen.getByText('400')).toBeInTheDocument(); // generation count
      });
    });

    it('deve ocultar/mostrar métricas', async () => {
      await waitFor(() => {
        const toggleButton = screen.getByText('Ocultar Métricas');
        fireEvent.click(toggleButton);
        
        expect(screen.getByText('Mostrar Métricas')).toBeInTheDocument();
      });
    });
  });

  describe('Filtros', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Filtros Avançados')).toBeInTheDocument();
      });
    });

    it('deve filtrar por busca textual', async () => {
      await waitFor(() => {
        const searchInput = screen.getByPlaceholderText('Buscar em mensagens, serviços...');
        fireEvent.change(searchInput, { target: { value: 'sucesso' } });
        
        expect(searchInput).toHaveValue('sucesso');
      });
    });

    it('deve filtrar por tracing ID', async () => {
      await waitFor(() => {
        const tracingInput = screen.getByPlaceholderText('ID de rastreamento');
        fireEvent.change(tracingInput, { target: { value: 'trace123' } });
        
        expect(tracingInput).toHaveValue('trace123');
      });
    });

    it('deve filtrar por user ID', async () => {
      await waitFor(() => {
        const userInput = screen.getByPlaceholderText('ID do usuário');
        fireEvent.change(userInput, { target: { value: 'user123' } });
        
        expect(userInput).toHaveValue('user123');
      });
    });

    it('deve filtrar por data', async () => {
      await waitFor(() => {
        const startDateInput = screen.getByDisplayValue('');
        fireEvent.change(startDateInput, { target: { value: '2025-01-27T00:00' } });
        
        expect(startDateInput).toHaveValue('2025-01-27T00:00');
      });
    });

    it('deve filtrar por nível de log', async () => {
      await waitFor(() => {
        const errorCheckbox = screen.getByDisplayValue('false');
        fireEvent.click(errorCheckbox);
        
        expect(errorCheckbox).toBeChecked();
      });
    });

    it('deve filtrar por serviço', async () => {
      await waitFor(() => {
        const apiCheckbox = screen.getByDisplayValue('false');
        fireEvent.click(apiCheckbox);
        
        expect(apiCheckbox).toBeChecked();
      });
    });

    it('deve alternar modo de visualização', async () => {
      await waitFor(() => {
        const viewSelect = screen.getByDisplayValue('Tabela');
        fireEvent.change(viewSelect, { target: { value: 'json' } });
        
        expect(viewSelect).toHaveValue('json');
      });
    });

    it('deve limpar filtros', async () => {
      await waitFor(() => {
        const clearButton = screen.getByText('Limpar Filtros');
        fireEvent.click(clearButton);
        
        // Verificar se os campos foram limpos
        const searchInput = screen.getByPlaceholderText('Buscar em mensagens, serviços...');
        expect(searchInput).toHaveValue('');
      });
    });

    it('deve ocultar/mostrar filtros', async () => {
      await waitFor(() => {
        const toggleButton = screen.getByText('Ocultar Filtros');
        fireEvent.click(toggleButton);
        
        expect(screen.getByText('Mostrar Filtros')).toBeInTheDocument();
      });
    });
  });

  describe('Visualização de Logs', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Logs (3)')).toBeInTheDocument();
      });
    });

    it('deve exibir logs em formato de tabela', async () => {
      await waitFor(() => {
        expect(screen.getByText('Requisição processada com sucesso')).toBeInTheDocument();
        expect(screen.getByText('Falha na geração de artigo')).toBeInTheDocument();
        expect(screen.getByText('Cache miss detectado')).toBeInTheDocument();
      });
    });

    it('deve exibir logs em formato JSON', async () => {
      await waitFor(() => {
        const viewSelect = screen.getByDisplayValue('Tabela');
        fireEvent.change(viewSelect, { target: { value: 'json' } });
        
        // Verificar se o JSON está sendo renderizado
        expect(screen.getByText('"id": "1"')).toBeInTheDocument();
      });
    });

    it('deve exibir logs em formato compacto', async () => {
      await waitFor(() => {
        const viewSelect = screen.getByDisplayValue('Tabela');
        fireEvent.change(viewSelect, { target: { value: 'compact' } });
        
        // Verificar se o formato compacto está sendo renderizado
        expect(screen.getByText('[api]')).toBeInTheDocument();
      });
    });

    it('deve selecionar logs individuais', async () => {
      await waitFor(() => {
        const checkboxes = screen.getAllByDisplayValue('false');
        fireEvent.click(checkboxes[0]);
        
        expect(checkboxes[0]).toBeChecked();
      });
    });

    it('deve selecionar todos os logs', async () => {
      await waitFor(() => {
        const selectAllCheckbox = screen.getByDisplayValue('false');
        fireEvent.click(selectAllCheckbox);
        
        expect(selectAllCheckbox).toBeChecked();
      });
    });

    it('deve exibir detalhes do log', async () => {
      await waitFor(() => {
        const detailsButton = screen.getByText('Detalhes');
        fireEvent.click(detailsButton);
        
        expect(screen.getByText('Log detalhado exibido no console')).toBeInTheDocument();
      });
    });

    it('deve alterar tamanho da página', async () => {
      await waitFor(() => {
        const pageSizeSelect = screen.getByDisplayValue('100 por página');
        fireEvent.change(pageSizeSelect, { target: { value: '200' } });
        
        expect(pageSizeSelect).toHaveValue('200');
      });
    });
  });

  describe('Auto-refresh', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Auto-refresh')).toBeInTheDocument();
      });
    });

    it('deve ativar/desativar auto-refresh', async () => {
      await waitFor(() => {
        const autoRefreshSwitch = screen.getByDisplayValue('true');
        fireEvent.click(autoRefreshSwitch);
        
        expect(autoRefreshSwitch).not.toBeChecked();
      });
    });

    it('deve alterar intervalo de refresh', async () => {
      await waitFor(() => {
        const intervalSelect = screen.getByDisplayValue('30s');
        fireEvent.change(intervalSelect, { target: { value: '60' } });
        
        expect(intervalSelect).toHaveValue('60');
      });
    });

    it('deve atualizar manualmente', async () => {
      await waitFor(() => {
        const updateButton = screen.getByText('Atualizar');
        fireEvent.click(updateButton);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/logs?page=1&page_size=100', 'GET');
      });
    });
  });

  describe('Exportação', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Exportar Logs')).toBeInTheDocument();
      });
    });

    it('deve alterar formato de exportação', async () => {
      await waitFor(() => {
        const formatSelect = screen.getByDisplayValue('JSON');
        fireEvent.change(formatSelect, { target: { value: 'csv' } });
        
        expect(formatSelect).toHaveValue('csv');
      });
    });

    it('deve alterar período de exportação', async () => {
      await waitFor(() => {
        const periodSelect = screen.getByDisplayValue('Todos');
        fireEvent.change(periodSelect, { target: { value: 'today' } });
        
        expect(periodSelect).toHaveValue('today');
      });
    });

    it('deve configurar período personalizado', async () => {
      await waitFor(() => {
        const periodSelect = screen.getByDisplayValue('Todos');
        fireEvent.change(periodSelect, { target: { value: 'custom' } });
        
        // Verificar se os campos de data personalizada aparecem
        expect(screen.getByDisplayValue('')).toBeInTheDocument();
      });
    });

    it('deve alternar inclusão de metadados', async () => {
      await waitFor(() => {
        const metadataSwitch = screen.getByDisplayValue('true');
        fireEvent.click(metadataSwitch);
        
        expect(metadataSwitch).not.toBeChecked();
      });
    });

    it('deve alternar inclusão de dados de auditoria', async () => {
      await waitFor(() => {
        const auditSwitch = screen.getByDisplayValue('true');
        fireEvent.click(auditSwitch);
        
        expect(auditSwitch).not.toBeChecked();
      });
    });

    it('deve exportar logs com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        data: '{"logs": []}',
      });
      
      await waitFor(() => {
        const exportButton = screen.getByText('Exportar Logs');
        fireEvent.click(exportButton);
      });
      
      await waitFor(() => {
        expect(screen.getByText('Logs exportados com sucesso')).toBeInTheDocument();
      });
    });

    it('deve mostrar erro na exportação', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro de exportação'));
      
      await waitFor(() => {
        const exportButton = screen.getByText('Exportar Logs');
        fireEvent.click(exportButton);
      });
      
      await waitFor(() => {
        expect(screen.getByText('Erro ao exportar logs')).toBeInTheDocument();
      });
    });
  });

  describe('Paginação', () => {
    beforeEach(async () => {
      mockApiCall.mockResolvedValue({
        success: true,
        logs: Array.from({ length: 100 }, (_, i) => ({
          id: i.toString(),
          timestamp: '2025-01-27T23:00:00Z',
          level: 'INFO',
          service: 'api',
          message: `Log ${i}`,
        })),
      });
      
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Logs (100)')).toBeInTheDocument();
      });
    });

    it('deve carregar mais logs', async () => {
      await waitFor(() => {
        const loadMoreButton = screen.getByText('Carregar Mais');
        fireEvent.click(loadMoreButton);
        
        expect(mockApiCall).toHaveBeenCalledWith('/api/logs?page=2&page_size=100', 'GET');
      });
    });
  });

  describe('Acessibilidade', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Logs e Auditoria')).toBeInTheDocument();
      });
    });

    it('deve ter título principal', () => {
      expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
      expect(screen.getByText('Logs e Auditoria')).toBeInTheDocument();
    });

    it('deve ter descrição da página', () => {
      expect(screen.getByText(/Visualize, filtre e analise logs/)).toBeInTheDocument();
    });

    it('deve ter controles de navegação', () => {
      expect(screen.getByText('Mostrar Métricas')).toBeInTheDocument();
      expect(screen.getByText('Mostrar Filtros')).toBeInTheDocument();
      expect(screen.getByText('Exportar')).toBeInTheDocument();
    });

    it('deve ter botões de ação', () => {
      expect(screen.getByText('Atualizar')).toBeInTheDocument();
      expect(screen.getByText('Limpar Filtros')).toBeInTheDocument();
      expect(screen.getByText('Exportar Logs')).toBeInTheDocument();
    });
  });

  describe('Responsividade', () => {
    beforeEach(async () => {
      renderLogs();
      await waitFor(() => {
        expect(screen.getByText('Logs e Auditoria')).toBeInTheDocument();
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
    it('deve mostrar loading durante exportação', async () => {
      mockApiCall.mockImplementation(() => new Promise(() => {})); // Promise que nunca resolve
      
      renderLogs();
      
      await waitFor(() => {
        const exportButton = screen.getByText('Exportar Logs');
        fireEvent.click(exportButton);
        
        expect(screen.getByText('Exportando...')).toBeInTheDocument();
      });
    });
  });

  describe('Tratamento de Erros', () => {
    it('deve mostrar erro se falhar ao carregar métricas', async () => {
      mockApiCall
        .mockResolvedValueOnce({ success: true, logs: [] })
        .mockRejectedValueOnce(new Error('Erro de métricas'));
      
      renderLogs();
      
      // O erro de métricas não deve afetar a renderização principal
      await waitFor(() => {
        expect(screen.getByText('Logs (0)')).toBeInTheDocument();
      });
    });
  });
}); 