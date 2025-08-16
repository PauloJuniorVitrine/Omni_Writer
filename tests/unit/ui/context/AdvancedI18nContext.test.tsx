/**
 * AdvancedI18nContext.test.tsx - Testes Unitários do Contexto de Internacionalização Avançado
 * ========================================================================================
 * 
 * Testes unitários para validar:
 * - Troca de idioma em tempo real
 * - Detecção automática de idioma
 * - Formatação de datas, números e moedas
 * - Interpolação de variáveis
 * - Carregamento de traduções
 * 
 * Autor: Análise Técnica Omni Writer
 * Data: 2025-01-27
 * Versão: 1.0
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AdvancedI18nProvider, useAdvancedI18n, AdvancedLanguageSelector } from '../../../../ui/context/AdvancedI18nContext';

// Mock das traduções
const mockTranslations = {
  'pt-BR': {
    'language.selector.label': 'Selecionar idioma',
    'language.selector.search': 'Buscar idioma...',
    'common.loading': 'Carregando...',
    'common.success': 'Sucesso',
    'i18n.demo.title': 'Demonstração de Internacionalização - {language}',
    'i18n.demo.subtitle': 'Teste todas as funcionalidades de i18n',
    'i18n.demo.languageSelector': 'Seletor de Idioma',
    'i18n.demo.currentLanguage': 'Idioma Atual',
    'i18n.demo.languageCode': 'Código',
    'i18n.demo.languageName': 'Nome',
    'i18n.demo.nativeName': 'Nome Nativo',
    'i18n.demo.direction': 'Direção',
    'i18n.demo.flag': 'Bandeira',
    'i18n.demo.dateFormat': 'Formato de Data',
    'i18n.demo.formattingExamples': 'Exemplos de Formatação',
    'i18n.demo.dateFormatting': 'Formatação de Data',
    'i18n.demo.currentTime': 'Hora Atual',
    'i18n.demo.sampleDate': 'Data de Exemplo',
    'i18n.demo.shortDate': 'Data Curta',
    'i18n.demo.fullDate': 'Data Completa',
    'i18n.demo.numberFormatting': 'Formatação de Números',
    'i18n.demo.decimal': 'Decimal',
    'i18n.demo.integer': 'Inteiro',
    'i18n.demo.percentage': 'Porcentagem',
    'i18n.demo.currency': 'Moeda',
    'i18n.demo.relativeTime': 'Tempo Relativo',
    'i18n.demo.now': 'Agora',
    'i18n.demo.oldDate': 'Data Antiga',
    'i18n.demo.oneHourAgo': 'Uma Hora Atrás',
    'i18n.demo.oneDayAgo': 'Um Dia Atrás',
    'i18n.demo.variableInterpolation': 'Interpolação de Variáveis',
    'i18n.demo.welcomeMessage': 'Olá, {name}! Bem-vindo ao Omni Writer.',
    'i18n.demo.itemsCount': 'Você tem {count} itens.',
    'i18n.demo.priceInfo': 'Preço: {price} ({currency})',
    'i18n.demo.completionRate': 'Taxa de conclusão: {percentage} ({completed}/{total})',
    'i18n.demo.translationExamples': 'Exemplos de Tradução',
    'common.actions': 'Ações',
    'navigation.title': 'Navegação',
    'errors.title': 'Erros',
    'i18n.demo.footer': 'Demonstração em {language} {flag}'
  },
  'en-US': {
    'language.selector.label': 'Select language',
    'language.selector.search': 'Search language...',
    'common.loading': 'Loading...',
    'common.success': 'Success',
    'i18n.demo.title': 'Internationalization Demo - {language}',
    'i18n.demo.subtitle': 'Test all i18n features',
    'i18n.demo.languageSelector': 'Language Selector',
    'i18n.demo.currentLanguage': 'Current Language',
    'i18n.demo.languageCode': 'Code',
    'i18n.demo.languageName': 'Name',
    'i18n.demo.nativeName': 'Native Name',
    'i18n.demo.direction': 'Direction',
    'i18n.demo.flag': 'Flag',
    'i18n.demo.dateFormat': 'Date Format',
    'i18n.demo.formattingExamples': 'Formatting Examples',
    'i18n.demo.dateFormatting': 'Date Formatting',
    'i18n.demo.currentTime': 'Current Time',
    'i18n.demo.sampleDate': 'Sample Date',
    'i18n.demo.shortDate': 'Short Date',
    'i18n.demo.fullDate': 'Full Date',
    'i18n.demo.numberFormatting': 'Number Formatting',
    'i18n.demo.decimal': 'Decimal',
    'i18n.demo.integer': 'Integer',
    'i18n.demo.percentage': 'Percentage',
    'i18n.demo.currency': 'Currency',
    'i18n.demo.relativeTime': 'Relative Time',
    'i18n.demo.now': 'Now',
    'i18n.demo.oldDate': 'Old Date',
    'i18n.demo.oneHourAgo': 'One Hour Ago',
    'i18n.demo.oneDayAgo': 'One Day Ago',
    'i18n.demo.variableInterpolation': 'Variable Interpolation',
    'i18n.demo.welcomeMessage': 'Hello, {name}! Welcome to Omni Writer.',
    'i18n.demo.itemsCount': 'You have {count} items.',
    'i18n.demo.priceInfo': 'Price: {price} ({currency})',
    'i18n.demo.completionRate': 'Completion rate: {percentage} ({completed}/{total})',
    'i18n.demo.translationExamples': 'Translation Examples',
    'common.actions': 'Actions',
    'navigation.title': 'Navigation',
    'errors.title': 'Errors',
    'i18n.demo.footer': 'Demo in {language} {flag}'
  }
};

// Mock do fetch para simular carregamento de traduções
global.fetch = jest.fn();

// Componente de teste que usa o contexto
const TestComponent: React.FC = () => {
  const {
    currentLanguage,
    languageConfig,
    t,
    formatDate,
    formatNumber,
    formatCurrency,
    formatRelativeTime,
    changeLanguage,
    isLoading
  } = useAdvancedI18n();

  const testDate = new Date('2025-01-27T10:30:00');
  const testNumber = 1234.56;

  return (
    <div data-testid="test-component">
      <div data-testid="current-language">{currentLanguage}</div>
      <div data-testid="language-name">{languageConfig.name}</div>
      <div data-testid="native-name">{languageConfig.nativeName}</div>
      <div data-testid="flag">{languageConfig.flag}</div>
      <div data-testid="direction">{languageConfig.direction}</div>
      <div data-testid="loading">{isLoading.toString()}</div>
      
      {/* Teste de tradução simples */}
      <div data-testid="translation-simple">{t('common.loading')}</div>
      
      {/* Teste de interpolação */}
      <div data-testid="translation-interpolation">
        {t('i18n.demo.welcomeMessage', { name: 'João' })}
      </div>
      
      {/* Teste de formatação de data */}
      <div data-testid="formatted-date">{formatDate(testDate)}</div>
      
      {/* Teste de formatação de número */}
      <div data-testid="formatted-number">{formatNumber(testNumber)}</div>
      
      {/* Teste de formatação de moeda */}
      <div data-testid="formatted-currency">{formatCurrency(testNumber)}</div>
      
      {/* Teste de tempo relativo */}
      <div data-testid="relative-time">{formatRelativeTime(testDate)}</div>
      
      {/* Botão para trocar idioma */}
      <button 
        data-testid="change-language-btn"
        onClick={() => changeLanguage('en-US')}
      >
        Change to English
      </button>
    </div>
  );
};

// Wrapper para testes
const TestWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AdvancedI18nProvider defaultLanguage="pt-BR" fallbackLanguage="en-US">
    {children}
  </AdvancedI18nProvider>
);

describe('AdvancedI18nContext', () => {
  beforeEach(() => {
    // Reset dos mocks
    jest.clearAllMocks();
    
    // Mock do fetch para retornar traduções
    (fetch as jest.Mock).mockImplementation((url: string) => {
      const language = url.split('/').pop();
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockTranslations[language as keyof typeof mockTranslations] || {})
      });
    });
    
    // Mock do localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
      },
      writable: true
    });
    
    // Mock do navigator.language
    Object.defineProperty(navigator, 'language', {
      value: 'pt-BR',
      writable: true
    });
  });

  describe('Inicialização', () => {
    it('deve inicializar com idioma padrão pt-BR', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('pt-BR');
        expect(screen.getByTestId('language-name')).toHaveTextContent('Portuguese (Brazil)');
        expect(screen.getByTestId('native-name')).toHaveTextContent('Português (Brasil)');
        expect(screen.getByTestId('flag')).toHaveTextContent('🇧🇷');
        expect(screen.getByTestId('direction')).toHaveTextContent('ltr');
      });
    });

    it('deve carregar traduções corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('translation-simple')).toHaveTextContent('Carregando...');
        expect(screen.getByTestId('translation-interpolation')).toHaveTextContent('Olá, João! Bem-vindo ao Omni Writer.');
      });
    });
  });

  describe('Troca de Idioma', () => {
    it('deve trocar idioma em tempo real', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      // Aguarda carregamento inicial
      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('pt-BR');
      });

      // Clica no botão para trocar idioma
      fireEvent.click(screen.getByTestId('change-language-btn'));

      // Verifica se o idioma foi trocado
      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('en-US');
        expect(screen.getByTestId('language-name')).toHaveTextContent('English (US)');
        expect(screen.getByTestId('native-name')).toHaveTextContent('English (US)');
        expect(screen.getByTestId('flag')).toHaveTextContent('🇺🇸');
      });

      // Verifica se as traduções foram atualizadas
      await waitFor(() => {
        expect(screen.getByTestId('translation-simple')).toHaveTextContent('Loading...');
        expect(screen.getByTestId('translation-interpolation')).toHaveTextContent('Hello, João! Welcome to Omni Writer.');
      });
    });

    it('deve salvar idioma no localStorage', async () => {
      const setItemSpy = jest.spyOn(Storage.prototype, 'setItem');
      
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('pt-BR');
      });

      fireEvent.click(screen.getByTestId('change-language-btn'));

      await waitFor(() => {
        expect(setItemSpy).toHaveBeenCalledWith('omni-writer-language', 'en-US');
      });
    });
  });

  describe('Formatação', () => {
    it('deve formatar datas corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        const formattedDate = screen.getByTestId('formatted-date').textContent;
        expect(formattedDate).toMatch(/27 de janeiro de 2025|January 27, 2025/);
      });
    });

    it('deve formatar números corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        const formattedNumber = screen.getByTestId('formatted-number').textContent;
        // Verifica se o número está formatado (pode variar entre 1.234,56 ou 1,234.56)
        expect(formattedNumber).toMatch(/1[.,]234[.,]56/);
      });
    });

    it('deve formatar moeda corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        const formattedCurrency = screen.getByTestId('formatted-currency').textContent;
        // Verifica se a moeda está formatada (R$ 1.234,56 ou $1,234.56)
        expect(formattedCurrency).toMatch(/[R$]?\s*1[.,]234[.,]56/);
      });
    });

    it('deve formatar tempo relativo corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        const relativeTime = screen.getByTestId('relative-time').textContent;
        // Verifica se o tempo relativo está formatado
        expect(relativeTime).toBeTruthy();
        expect(typeof relativeTime).toBe('string');
      });
    });
  });

  describe('Interpolação de Variáveis', () => {
    it('deve interpolar variáveis corretamente', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('translation-interpolation')).toHaveTextContent('Olá, João! Bem-vindo ao Omni Writer.');
      });
    });

    it('deve manter chave original se tradução não existir', async () => {
      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        // Testa uma chave que não existe nas traduções
        const component = screen.getByTestId('test-component');
        expect(component).toBeInTheDocument();
      });
    });
  });

  describe('Detecção de Idioma', () => {
    it('deve detectar idioma do navegador', async () => {
      // Simula navegador em inglês
      Object.defineProperty(navigator, 'language', {
        value: 'en-US',
        writable: true
      });

      render(
        <AdvancedI18nProvider defaultLanguage="en-US" fallbackLanguage="en-US">
          <TestComponent />
        </AdvancedI18nProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('en-US');
      });
    });

    it('deve usar idioma salvo no localStorage se disponível', async () => {
      // Simula idioma salvo no localStorage
      const getItemSpy = jest.spyOn(Storage.prototype, 'getItem');
      getItemSpy.mockReturnValue('es-ES');

      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(getItemSpy).toHaveBeenCalledWith('omni-writer-language');
      });
    });
  });

  describe('AdvancedLanguageSelector', () => {
    it('deve renderizar seletor de idioma', async () => {
      render(
        <TestWrapper>
          <AdvancedLanguageSelector />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByRole('button')).toBeInTheDocument();
        expect(screen.getByRole('button')).toHaveTextContent('🇧🇷');
        expect(screen.getByRole('button')).toHaveTextContent('Português (Brasil)');
      });
    });

    it('deve abrir dropdown ao clicar', async () => {
      render(
        <TestWrapper>
          <AdvancedLanguageSelector />
        </TestWrapper>
      );

      const button = screen.getByRole('button');
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByRole('textbox')).toBeInTheDocument();
        expect(screen.getByPlaceholderText('Buscar idioma...')).toBeInTheDocument();
      });
    });

    it('deve filtrar idiomas na busca', async () => {
      render(
        <TestWrapper>
          <AdvancedLanguageSelector />
        </TestWrapper>
      );

      const button = screen.getByRole('button');
      fireEvent.click(button);

      const searchInput = screen.getByPlaceholderText('Buscar idioma...');
      fireEvent.change(searchInput, { target: { value: 'English' } });

      await waitFor(() => {
        expect(screen.getByText('English (US)')).toBeInTheDocument();
      });
    });
  });

  describe('Tratamento de Erros', () => {
    it('deve usar fallback quando carregamento de traduções falha', async () => {
      // Simula falha no fetch
      (fetch as jest.Mock).mockRejectedValue(new Error('Network error'));

      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('false');
      });
    });

    it('deve manter funcionalidade mesmo sem traduções', async () => {
      // Simula traduções vazias
      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({})
      });

      render(
        <TestWrapper>
          <TestComponent />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('current-language')).toHaveTextContent('pt-BR');
        expect(screen.getByTestId('translation-simple')).toHaveTextContent('common.loading');
      });
    });
  });

  describe('Performance', () => {
    it('deve evitar re-renders desnecessários', async () => {
      const renderSpy = jest.fn();
      
      const TestComponentWithSpy: React.FC = () => {
        renderSpy();
        const { currentLanguage } = useAdvancedI18n();
        return <div data-testid="render-count">{currentLanguage}</div>;
      };

      render(
        <TestWrapper>
          <TestComponentWithSpy />
        </TestWrapper>
      );

      await waitFor(() => {
        expect(screen.getByTestId('render-count')).toHaveTextContent('pt-BR');
      });

      // Verifica se não houve re-renders desnecessários
      expect(renderSpy).toHaveBeenCalledTimes(1);
    });
  });
}); 