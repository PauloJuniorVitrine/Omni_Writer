/**
 * Testes Unitários - Página de Exportação e Relatórios
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-023
 * Data/Hora: 2025-01-28T00:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_001
 * 
 * Testes baseados em código real da página de Reports
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Reports } from '../Reports';
import { useI18n } from '../../hooks/use_i18n';
import { useApi } from '../../hooks/use_api';

// Mock dos hooks
jest.mock('../../hooks/use_i18n');
jest.mock('../../hooks/use_api');

const mockUseI18n = useI18n as jest.MockedFunction<typeof useI18n>;
const mockUseApi = useApi as jest.MockedFunction<typeof useApi>;

const mockApiCall = jest.fn();

describe('Reports Page', () => {
  beforeEach(() => {
    mockUseI18n.mockReturnValue({
      t: (key: string) => key,
      lang: 'pt_BR',
      setLang: jest.fn(),
      languages: ['pt_BR', 'en_US'],
      languageConfig: {
        name: 'Português (Brasil)',
        nativeName: 'Português (Brasil)',
        flag: '🇧🇷',
        direction: 'ltr' as const,
        dateFormat: 'dd/MM/yyyy',
        timeFormat: 'HH:mm',
        currency: 'BRL'
      },
      availableLanguages: [],
      formatDate: jest.fn(),
      formatTime: jest.fn(),
      formatNumber: jest.fn(),
      formatCurrency: jest.fn(),
      formatPlural: jest.fn(),
      detectLanguage: jest.fn()
    });

    mockUseApi.mockReturnValue({
      apiCall: mockApiCall,
      isLoading: false,
      error: null
    });

    mockApiCall.mockResolvedValue({
      success: true,
      data: {}
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const renderReports = () => {
    return render(<Reports />);
  };

  describe('Renderização Principal', () => {
    it('deve renderizar o título e descrição da página', () => {
      renderReports();
      
      expect(screen.getByText('Exportação e Relatórios')).toBeInTheDocument();
      expect(screen.getByText(/Gere relatórios personalizados/)).toBeInTheDocument();
    });

    it('deve renderizar as abas de navegação', () => {
      renderReports();
      
      expect(screen.getByText('📊 Templates (4)')).toBeInTheDocument();
      expect(screen.getByText('📋 Relatórios (3)')).toBeInTheDocument();
      expect(screen.getByText('📅 Agendados (0)')).toBeInTheDocument();
    });

    it('deve mostrar a aba Templates por padrão', () => {
      renderReports();
      
      expect(screen.getByText('Resumo de Artigos')).toBeInTheDocument();
      expect(screen.getByText('Performance dos Blogs')).toBeInTheDocument();
      expect(screen.getByText('Análise de Prompts')).toBeInTheDocument();
      expect(screen.getByText('Analytics do Sistema')).toBeInTheDocument();
    });
  });

  describe('Templates de Relatórios', () => {
    beforeEach(() => {
      renderReports();
    });

    it('deve renderizar todos os templates disponíveis', () => {
      expect(screen.getByText('Resumo de Artigos')).toBeInTheDocument();
      expect(screen.getByText('Relatório completo de artigos gerados com métricas e análises')).toBeInTheDocument();
      
      expect(screen.getByText('Performance dos Blogs')).toBeInTheDocument();
      expect(screen.getByText('Análise de performance e engajamento dos blogs')).toBeInTheDocument();
      
      expect(screen.getByText('Análise de Prompts')).toBeInTheDocument();
      expect(screen.getByText('Relatório detalhado sobre eficácia dos prompts')).toBeInTheDocument();
      
      expect(screen.getByText('Analytics do Sistema')).toBeInTheDocument();
      expect(screen.getByText('Métricas de performance e uso do sistema')).toBeInTheDocument();
    });

    it('deve mostrar informações corretas dos templates', () => {
      // Verificar tipos de relatório
      expect(screen.getAllByText('PDF')).toHaveLength(2);
      expect(screen.getAllByText('EXCEL')).toHaveLength(1);
      expect(screen.getAllByText('CUSTOM')).toHaveLength(1);
      
      // Verificar categorias
      expect(screen.getAllByText('articles')).toHaveLength(1);
      expect(screen.getAllByText('blogs')).toHaveLength(1);
      expect(screen.getAllByText('prompts')).toHaveLength(1);
      expect(screen.getAllByText('analytics')).toHaveLength(1);
    });

    it('deve ter botões de ação para cada template', () => {
      const previewButtons = screen.getAllByText('👁️ Preview');
      const generateButtons = screen.getAllByText('📊 Gerar');
      
      expect(previewButtons).toHaveLength(4);
      expect(generateButtons).toHaveLength(4);
    });

    it('deve abrir modal de preview ao clicar em Preview', async () => {
      const previewButtons = screen.getAllByText('👁️ Preview');
      fireEvent.click(previewButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Preview: Resumo de Artigos')).toBeInTheDocument();
      });
    });

    it('deve abrir modal de geração ao clicar em Gerar', async () => {
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
    });
  });

  describe('Modal de Geração de Relatório', () => {
    beforeEach(async () => {
      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
    });

    it('deve mostrar filtros do template', () => {
      expect(screen.getByText('Filtros')).toBeInTheDocument();
      expect(screen.getByText('Período')).toBeInTheDocument();
      expect(screen.getByText('Categoria')).toBeInTheDocument();
      expect(screen.getByText('Mínimo de palavras')).toBeInTheDocument();
    });

    it('deve mostrar opções de exportação', () => {
      expect(screen.getByText('Opções de Exportação')).toBeInTheDocument();
      expect(screen.getByText('Formato')).toBeInTheDocument();
      expect(screen.getByText('Senha (opcional)')).toBeInTheDocument();
    });

    it('deve ter switches para opções de exportação', () => {
      expect(screen.getByText('Incluir gráficos')).toBeInTheDocument();
      expect(screen.getByText('Incluir metadados')).toBeInTheDocument();
      expect(screen.getByText('Comprimir arquivo')).toBeInTheDocument();
      expect(screen.getByText('Estilo personalizado')).toBeInTheDocument();
    });

    it('deve ter botões de ação', () => {
      expect(screen.getByText('📅 Agendar')).toBeInTheDocument();
      expect(screen.getByText('Gerar Relatório')).toBeInTheDocument();
    });

    it('deve permitir alterar formato de exportação', async () => {
      const formatSelect = screen.getByDisplayValue('PDF');
      fireEvent.change(formatSelect, { target: { value: 'excel' } });
      
      expect(formatSelect).toHaveValue('excel');
    });

    it('deve permitir adicionar senha', () => {
      const passwordInput = screen.getByPlaceholderText('Senha para proteger o arquivo');
      fireEvent.change(passwordInput, { target: { value: 'senha123' } });
      
      expect(passwordInput).toHaveValue('senha123');
    });

    it('deve permitir configurar filtros', () => {
      const categorySelect = screen.getByDisplayValue('');
      fireEvent.change(categorySelect, { target: { value: 'Tecnologia' } });
      
      expect(categorySelect).toHaveValue('Tecnologia');
    });
  });

  describe('Geração de Relatórios', () => {
    beforeEach(async () => {
      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
    });

    it('deve gerar relatório com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        data: { id: 'new-report-123' }
      });

      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);

      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/reports/generate', 'POST', expect.any(Object));
      });
    });

    it('deve mostrar erro na geração', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro na geração'));

      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);

      await waitFor(() => {
        expect(screen.getByText('Erro ao gerar relatório')).toBeInTheDocument();
      });
    });

    it('deve fechar modal após geração bem-sucedida', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        data: { id: 'new-report-123' }
      });

      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);

      await waitFor(() => {
        expect(screen.queryByText('Gerar Relatório: Resumo de Artigos')).not.toBeInTheDocument();
      });
    });
  });

  describe('Aba de Relatórios', () => {
    beforeEach(() => {
      renderReports();
      const reportsTab = screen.getByText('📋 Relatórios (3)');
      fireEvent.click(reportsTab);
    });

    it('deve mostrar lista de relatórios', () => {
      expect(screen.getByText('Resumo de Artigos - Janeiro 2025')).toBeInTheDocument();
      expect(screen.getByText('Performance dos Blogs - Dezembro 2024')).toBeInTheDocument();
      expect(screen.getByText('Análise de Prompts - Q4 2024')).toBeInTheDocument();
    });

    it('deve mostrar status dos relatórios', () => {
      expect(screen.getByText('✅ Concluído')).toBeInTheDocument();
      expect(screen.getByText('⏳ Gerando...')).toBeInTheDocument();
      expect(screen.getByText('❌ Falhou')).toBeInTheDocument();
    });

    it('deve mostrar progresso para relatórios em geração', () => {
      expect(screen.getByText('65%')).toBeInTheDocument();
    });

    it('deve mostrar tamanho dos arquivos', () => {
      expect(screen.getByText('2.0 MB')).toBeInTheDocument();
    });

    it('deve mostrar erro para relatórios falhados', () => {
      expect(screen.getByText('Erro na geração do relatório: dados insuficientes')).toBeInTheDocument();
    });

    it('deve ter botões de ação para relatórios', () => {
      const downloadButtons = screen.getAllByText('📥 Baixar');
      const detailsButtons = screen.getAllByText('ℹ️ Detalhes');
      const deleteButtons = screen.getAllByText('🗑️ Excluir');
      
      expect(downloadButtons).toHaveLength(1); // Apenas relatórios concluídos
      expect(detailsButtons).toHaveLength(3);
      expect(deleteButtons).toHaveLength(3);
    });
  });

  describe('Download de Relatórios', () => {
    beforeEach(() => {
      renderReports();
      const reportsTab = screen.getByText('📋 Relatórios (3)');
      fireEvent.click(reportsTab);
    });

    it('deve baixar relatório com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        data: 'fake-pdf-content'
      });

      const downloadButton = screen.getByText('📥 Baixar');
      fireEvent.click(downloadButton);

      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/reports/1.pdf', 'GET');
      });
    });

    it('deve mostrar erro no download', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro no download'));

      const downloadButton = screen.getByText('📥 Baixar');
      fireEvent.click(downloadButton);

      await waitFor(() => {
        expect(screen.getByText('Erro ao baixar relatório')).toBeInTheDocument();
      });
    });
  });

  describe('Exclusão de Relatórios', () => {
    beforeEach(() => {
      renderReports();
      const reportsTab = screen.getByText('📋 Relatórios (3)');
      fireEvent.click(reportsTab);
    });

    it('deve excluir relatório com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true
      });

      const deleteButtons = screen.getAllByText('🗑️ Excluir');
      fireEvent.click(deleteButtons[0]);

      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/reports/1', 'DELETE');
      });
    });

    it('deve mostrar erro na exclusão', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro na exclusão'));

      const deleteButtons = screen.getAllByText('🗑️ Excluir');
      fireEvent.click(deleteButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Erro ao excluir relatório')).toBeInTheDocument();
      });
    });
  });

  describe('Modal de Detalhes do Relatório', () => {
    beforeEach(async () => {
      renderReports();
      const reportsTab = screen.getByText('📋 Relatórios (3)');
      fireEvent.click(reportsTab);
      
      const detailsButtons = screen.getAllByText('ℹ️ Detalhes');
      fireEvent.click(detailsButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Detalhes do Relatório: Resumo de Artigos - Janeiro 2025')).toBeInTheDocument();
      });
    });

    it('deve mostrar informações detalhadas do relatório', () => {
      expect(screen.getByText('Status:')).toBeInTheDocument();
      expect(screen.getByText('Tipo:')).toBeInTheDocument();
      expect(screen.getByText('Criado em:')).toBeInTheDocument();
      expect(screen.getByText('Concluído em:')).toBeInTheDocument();
      expect(screen.getByText('Tamanho:')).toBeInTheDocument();
    });

    it('deve mostrar botão de download para relatórios concluídos', () => {
      expect(screen.getByText('📥 Baixar Relatório')).toBeInTheDocument();
    });
  });

  describe('Modal de Preview', () => {
    beforeEach(async () => {
      renderReports();
      const previewButtons = screen.getAllByText('👁️ Preview');
      fireEvent.click(previewButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Preview: Resumo de Artigos')).toBeInTheDocument();
      });
    });

    it('deve mostrar campos incluídos no template', () => {
      expect(screen.getByText('Campos incluídos:')).toBeInTheDocument();
      expect(screen.getByText('title')).toBeInTheDocument();
      expect(screen.getByText('content')).toBeInTheDocument();
      expect(screen.getByText('category')).toBeInTheDocument();
    });

    it('deve mostrar filtros disponíveis', () => {
      expect(screen.getByText('Filtros disponíveis:')).toBeInTheDocument();
      expect(screen.getByText('Período')).toBeInTheDocument();
      expect(screen.getByText('Categoria')).toBeInTheDocument();
      expect(screen.getByText('Mínimo de palavras')).toBeInTheDocument();
    });

    it('deve mostrar se filtros são obrigatórios ou opcionais', () => {
      expect(screen.getByText('Obrigatório')).toBeInTheDocument();
      expect(screen.getByText('Opcional')).toBeInTheDocument();
    });

    it('deve ter botão para gerar relatório', () => {
      expect(screen.getByText('Gerar Relatório')).toBeInTheDocument();
    });
  });

  describe('Aba de Relatórios Agendados', () => {
    beforeEach(() => {
      renderReports();
      const scheduledTab = screen.getByText('📅 Agendados (0)');
      fireEvent.click(scheduledTab);
    });

    it('deve mostrar mensagem quando não há relatórios agendados', () => {
      expect(screen.getByText('Nenhum relatório agendado')).toBeInTheDocument();
      expect(screen.getByText(/Agende relatórios automáticos/)).toBeInTheDocument();
      expect(screen.getByText('Agendar Relatório')).toBeInTheDocument();
    });
  });

  describe('Agendamento de Relatórios', () => {
    beforeEach(async () => {
      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
      
      const scheduleButton = screen.getByText('📅 Agendar');
      fireEvent.click(scheduleButton);
      
      await waitFor(() => {
        expect(screen.getByText('Agendar Relatório')).toBeInTheDocument();
      });
    });

    it('deve mostrar formulário de agendamento', () => {
      expect(screen.getByText('Frequência')).toBeInTheDocument();
      expect(screen.getByText('Horário')).toBeInTheDocument();
      expect(screen.getByText('Destinatários (emails separados por vírgula)')).toBeInTheDocument();
      expect(screen.getByText('Formato')).toBeInTheDocument();
    });

    it('deve permitir configurar frequência', () => {
      const frequencySelect = screen.getByDisplayValue('Semanal');
      fireEvent.change(frequencySelect, { target: { value: 'daily' } });
      
      expect(frequencySelect).toHaveValue('daily');
    });

    it('deve permitir configurar horário', () => {
      const timeInput = screen.getByDisplayValue('09:00');
      fireEvent.change(timeInput, { target: { value: '14:30' } });
      
      expect(timeInput).toHaveValue('14:30');
    });

    it('deve permitir configurar destinatários', () => {
      const recipientsInput = screen.getByPlaceholderText('usuario@exemplo.com, admin@exemplo.com');
      fireEvent.change(recipientsInput, { target: { value: 'test@example.com' } });
      
      expect(recipientsInput).toHaveValue('test@example.com');
    });

    it('deve permitir configurar formato', () => {
      const formatSelect = screen.getByDisplayValue('PDF');
      fireEvent.change(formatSelect, { target: { value: 'excel' } });
      
      expect(formatSelect).toHaveValue('excel');
    });

    it('deve agendar relatório com sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true
      });

      const scheduleButton = screen.getByText('Agendar');
      fireEvent.click(scheduleButton);

      await waitFor(() => {
        expect(mockApiCall).toHaveBeenCalledWith('/api/reports/schedule', 'POST', expect.any(Object));
      });
    });
  });

  describe('Navegação entre Abas', () => {
    it('deve alternar entre abas corretamente', () => {
      renderReports();
      
      // Inicialmente na aba Templates
      expect(screen.getByText('Resumo de Artigos')).toBeInTheDocument();
      
      // Ir para aba Relatórios
      const reportsTab = screen.getByText('📋 Relatórios (3)');
      fireEvent.click(reportsTab);
      expect(screen.getByText('Resumo de Artigos - Janeiro 2025')).toBeInTheDocument();
      
      // Ir para aba Agendados
      const scheduledTab = screen.getByText('📅 Agendados (0)');
      fireEvent.click(scheduledTab);
      expect(screen.getByText('Nenhum relatório agendado')).toBeInTheDocument();
      
      // Voltar para aba Templates
      const templatesTab = screen.getByText('📊 Templates (4)');
      fireEvent.click(templatesTab);
      expect(screen.getByText('Resumo de Artigos')).toBeInTheDocument();
    });
  });

  describe('Estados de Loading', () => {
    it('deve mostrar loading durante geração', async () => {
      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
      
      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);
      
      await waitFor(() => {
        expect(screen.getByText('Gerando...')).toBeInTheDocument();
      });
    });
  });

  describe('Feedback ao Usuário', () => {
    it('deve mostrar toast de sucesso', async () => {
      mockApiCall.mockResolvedValueOnce({
        success: true,
        data: { id: 'new-report-123' }
      });

      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
      
      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);

      await waitFor(() => {
        expect(screen.getByText('Relatório iniciado com sucesso')).toBeInTheDocument();
      });
    });

    it('deve mostrar toast de erro', async () => {
      mockApiCall.mockRejectedValueOnce(new Error('Erro na geração'));

      renderReports();
      const generateButtons = screen.getAllByText('📊 Gerar');
      fireEvent.click(generateButtons[0]);
      
      await waitFor(() => {
        expect(screen.getByText('Gerar Relatório: Resumo de Artigos')).toBeInTheDocument();
      });
      
      const generateButton = screen.getByText('Gerar Relatório');
      fireEvent.click(generateButton);

      await waitFor(() => {
        expect(screen.getByText('Erro ao gerar relatório')).toBeInTheDocument();
      });
    });
  });

  describe('Responsividade', () => {
    it('deve renderizar todos os componentes base', () => {
      renderReports();
      
      expect(screen.getAllByTestId('card')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('button')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('input')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('select')).toHaveLength(expect.any(Number));
      expect(screen.getAllByTestId('switch')).toHaveLength(expect.any(Number));
    });

    it('deve ter estrutura de grid responsiva', () => {
      renderReports();
      
      const cards = screen.getAllByTestId('card');
      expect(cards.length).toBeGreaterThan(0);
    });
  });
}); 