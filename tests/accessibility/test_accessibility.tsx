/**
 * Testes de Acessibilidade - Omni Writer
 * ======================================
 * 
 * Implementa testes de acessibilidade automatizados:
 * - Validação WCAG 2.1 AAA
 * - Testes de contraste
 * - Navegação por teclado
 * - Leitores de tela
 * - Foco visível
 * 
 * Autor: Análise Técnica Omni Writer
 * Data: 2025-01-27
 * Versão: 1.0
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import { InteractiveTour, getDefaultTourSteps } from '../../ui/components/InteractiveTour';
import { EnhancedDarkMode } from '../../ui/components/EnhancedDarkMode';

// Configuração do jest-axe
expect.extend(toHaveNoViolations);

// Mock das traduções
const mockTranslations = {
  'tour.welcome.title': 'Bem-vindo ao Omni Writer',
  'tour.welcome.content': 'Vamos explorar as funcionalidades principais',
  'tour.generation.title': 'Geração de Artigos',
  'tour.generation.content': 'Aqui você pode gerar artigos automaticamente',
  'tour.categoria.title': 'Seleção de Categoria',
  'tour.categoria.content': 'Escolha a categoria do seu artigo',
  'tour.generate.title': 'Botão de Geração',
  'tour.generate.content': 'Clique para gerar o artigo',
  'tour.blogs.title': 'Lista de Blogs',
  'tour.blogs.content': 'Visualize todos os seus artigos gerados',
  'tour.language.title': 'Seletor de Idioma',
  'tour.language.content': 'Altere o idioma da interface',
  'tour.darkmode.title': 'Modo Escuro',
  'tour.darkmode.content': 'Alternar entre modo claro e escuro',
  'tour.completion.title': 'Concluído!',
  'tour.completion.content': 'Você está pronto para usar o Omni Writer',
  'tour.step': 'Passo',
  'tour.of': 'de',
  'tour.previous': 'Anterior',
  'tour.next': 'Próximo',
  'tour.finish': 'Concluir',
  'tour.skip': 'Pular',
  'tour.completed': 'Tour concluído com sucesso!',
  'tour.completed.announcement': 'Tour concluído com sucesso',
  'tour.skipped': 'Tour pulado',
  'tour.skipped.announcement': 'Tour foi pulado',
  'tour.accessibility.focus': 'Elemento em foco',
  'darkmode.enable': 'Ativar modo escuro',
  'darkmode.disable': 'Desativar modo escuro',
  'darkmode.dark': 'Modo Escuro',
  'darkmode.light': 'Modo Claro',
  'darkmode.transitioning': 'Alterando tema...',
  'accessibility.info': 'Informações de Acessibilidade',
  'accessibility.score': 'Score de Acessibilidade',
  'accessibility.contrast': 'Contraste',
  'accessibility.test': 'Testar Acessibilidade'
};

// Mock do hook useI18n
jest.mock('../../ui/hooks/use_i18n', () => ({
  useI18n: () => ({
    t: (key: string) => mockTranslations[key] || key
  })
}));

// Mock do hook useTheme
jest.mock('../../ui/context/ThemeContext', () => ({
  useTheme: () => ({
    theme: 'light',
    toggleTheme: jest.fn()
  })
}));

describe('Testes de Acessibilidade - InteractiveTour', () => {
  const defaultProps = {
    isVisible: true,
    onComplete: jest.fn(),
    onSkip: jest.fn(),
    steps: getDefaultTourSteps((key: string) => mockTranslations[key] || key),
    autoStart: true
  };

  beforeEach(() => {
    // Configura elementos DOM necessários
    document.body.innerHTML = `
      <div class="main-header">Header</div>
      <div class="generation-form">Form</div>
      <select id="categoria">Categoria</select>
      <button id="generate-btn">Gerar</button>
      <div class="blog-list">Blogs</div>
      <div class="language-selector">Idioma</div>
      <button id="dark-mode-toggle">Tema</button>
      <div class="main-content">Conteúdo</div>
    `;
  });

  afterEach(() => {
    document.body.innerHTML = '';
    jest.clearAllMocks();
  });

  test('deve passar nos testes de acessibilidade do axe', async () => {
    const { container } = render(<InteractiveTour {...defaultProps} />);
    
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  test('deve ter navegação por teclado funcional', async () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Foca no overlay do tour
    const overlay = screen.getByRole('dialog');
    overlay.focus();
    
    // Testa navegação com setas
    fireEvent.keyDown(overlay, { key: 'ArrowRight' });
    await waitFor(() => {
      expect(screen.getByText('Passo 2 de 8')).toBeInTheDocument();
    });
    
    fireEvent.keyDown(overlay, { key: 'ArrowLeft' });
    await waitFor(() => {
      expect(screen.getByText('Passo 1 de 8')).toBeInTheDocument();
    });
    
    // Testa tecla Escape para pular
    fireEvent.keyDown(overlay, { key: 'Escape' });
    expect(defaultProps.onSkip).toHaveBeenCalled();
  });

  test('deve anunciar mudanças para leitores de tela', async () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica se há região live para anúncios
    const liveRegion = document.querySelector('[aria-live="polite"]');
    expect(liveRegion).toBeInTheDocument();
    
    // Verifica se o anúncio inicial está presente
    expect(liveRegion).toHaveTextContent('Passo 1 de 8: Bem-vindo ao Omni Writer');
  });

  test('deve ter foco visível em todos os elementos interativos', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    const buttons = screen.getAllByRole('button');
    
    buttons.forEach(button => {
      fireEvent.focus(button);
      expect(button).toHaveStyle('outline: 2px solid var(--color-focus)');
      
      fireEvent.blur(button);
      expect(button).not.toHaveStyle('outline: 2px solid var(--color-focus)');
    });
  });

  test('deve ter labels ARIA apropriados', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica labels dos botões
    expect(screen.getByLabelText('Pular')).toBeInTheDocument();
    expect(screen.getByLabelText('Próximo')).toBeInTheDocument();
    
    // Verifica roles apropriados
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByRole('tooltip')).toBeInTheDocument();
  });

  test('deve ter ordem de tab apropriada', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    const focusableElements = screen.getAllByRole('button');
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    // Foca no primeiro elemento
    firstElement.focus();
    expect(document.activeElement).toBe(firstElement);
    
    // Testa navegação por Tab
    fireEvent.keyDown(firstElement, { key: 'Tab' });
    expect(document.activeElement).toBe(focusableElements[1]);
  });

  test('deve ter contraste adequado WCAG 2.1 AAA', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica se as cores CSS custom properties estão definidas
    const root = document.documentElement;
    const computedStyle = getComputedStyle(root);
    
    // Verifica contraste de texto principal
    const primaryColor = computedStyle.getPropertyValue('--color-primary');
    const backgroundColor = computedStyle.getPropertyValue('--color-background');
    
    // Calcula contraste (simplificado)
    const contrast = calculateContrastRatio(primaryColor, backgroundColor);
    expect(contrast).toBeGreaterThanOrEqual(7); // WCAG 2.1 AAA
  });

  test('deve ter feedback de acessibilidade em tempo real', async () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica se o feedback de acessibilidade aparece
    await waitFor(() => {
      expect(screen.getByText('Elemento em foco')).toBeInTheDocument();
    });
  });

  test('deve ser totalmente navegável por teclado', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    const overlay = screen.getByRole('dialog');
    
    // Testa todas as teclas de navegação
    const navigationKeys = ['ArrowRight', 'ArrowLeft', 'Enter', 'Escape'];
    
    navigationKeys.forEach(key => {
      fireEvent.keyDown(overlay, { key });
      // Não deve quebrar a aplicação
      expect(overlay).toBeInTheDocument();
    });
  });

  test('deve ter estrutura semântica correta', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica hierarquia de cabeçalhos
    const headings = screen.getAllByRole('heading');
    expect(headings).toHaveLength(1); // Apenas o título do tour
    
    // Verifica se não há cabeçalhos pulados
    const headingLevels = headings.map(h => parseInt(h.tagName.charAt(1)));
    expect(Math.max(...headingLevels) - Math.min(...headingLevels)).toBeLessThanOrEqual(1);
  });

  test('deve ter texto alternativo para elementos visuais', () => {
    render(<InteractiveTour {...defaultProps} />);
    
    // Verifica se há texto alternativo para ícones
    const icons = screen.getAllByText(/[🌙☀️]/);
    icons.forEach(icon => {
      expect(icon).toHaveAttribute('aria-label');
    });
  });
});

describe('Testes de Acessibilidade - EnhancedDarkMode', () => {
  const defaultProps = {
    onThemeChange: jest.fn(),
    showAccessibilityInfo: true
  };

  beforeEach(() => {
    // Mock do localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: jest.fn(() => 'light'),
        setItem: jest.fn(),
        removeItem: jest.fn()
      },
      writable: true
    });
    
    // Mock do matchMedia
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    });
  });

  test('deve passar nos testes de acessibilidade do axe', async () => {
    const { container } = render(<EnhancedDarkMode {...defaultProps} />);
    
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  test('deve ter toggle de tema acessível', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    const toggleButton = screen.getByLabelText('Ativar modo escuro');
    expect(toggleButton).toBeInTheDocument();
    expect(toggleButton).toHaveAttribute('aria-label');
    
    // Testa funcionalidade
    fireEvent.click(toggleButton);
    expect(defaultProps.onThemeChange).toHaveBeenCalledWith('dark');
  });

  test('deve ter informações de acessibilidade visíveis', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    expect(screen.getByText('Informações de Acessibilidade')).toBeInTheDocument();
    expect(screen.getByText('Score de Acessibilidade:')).toBeInTheDocument();
    expect(screen.getByText('Contraste:')).toBeInTheDocument();
    expect(screen.getByText('Testar Acessibilidade')).toBeInTheDocument();
  });

  test('deve calcular contraste WCAG 2.1 AAA corretamente', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    // Verifica se o score de acessibilidade está presente
    const scoreElement = screen.getByText(/Score de Acessibilidade: \d+\/100/);
    expect(scoreElement).toBeInTheDocument();
    
    // Extrai o score
    const scoreText = scoreElement.textContent;
    const score = parseInt(scoreText?.match(/\d+/)?.[0] || '0');
    
    // Score deve ser alto para WCAG 2.1 AAA
    expect(score).toBeGreaterThanOrEqual(90);
  });

  test('deve ter foco visível no toggle', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    const toggleButton = screen.getByLabelText('Ativar modo escuro');
    
    fireEvent.focus(toggleButton);
    expect(toggleButton).toHaveStyle('box-shadow: 0 0 0 2px var(--color-focus)');
    
    fireEvent.blur(toggleButton);
    expect(toggleButton).toHaveStyle('box-shadow: none');
  });

  test('deve persistir preferência de tema', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    const toggleButton = screen.getByLabelText('Ativar modo escuro');
    fireEvent.click(toggleButton);
    
    expect(window.localStorage.setItem).toHaveBeenCalledWith('omni-writer-theme', 'dark');
  });

  test('deve respeitar preferência do sistema', () => {
    // Mock para preferência escura do sistema
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    });
    
    render(<EnhancedDarkMode {...defaultProps} />);
    
    // Deve mostrar toggle para modo claro quando sistema prefere escuro
    expect(screen.getByLabelText('Desativar modo escuro')).toBeInTheDocument();
  });

  test('deve ter transições suaves', async () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    const toggleButton = screen.getByLabelText('Ativar modo escuro');
    
    // Simula transição
    fireEvent.click(toggleButton);
    
    // Deve mostrar indicador de transição
    await waitFor(() => {
      expect(screen.getByText('Alterando tema...')).toBeInTheDocument();
    });
    
    // Indicador deve desaparecer após transição
    await waitFor(() => {
      expect(screen.queryByText('Alterando tema...')).not.toBeInTheDocument();
    }, { timeout: 1000 });
  });

  test('deve ter CSS custom properties para cores', () => {
    render(<EnhancedDarkMode {...defaultProps} />);
    
    const root = document.documentElement;
    const computedStyle = getComputedStyle(root);
    
    // Verifica se as variáveis CSS estão definidas
    const cssVars = [
      '--color-primary',
      '--color-secondary',
      '--color-background',
      '--color-surface',
      '--color-border',
      '--color-accent',
      '--color-focus'
    ];
    
    cssVars.forEach(cssVar => {
      const value = computedStyle.getPropertyValue(cssVar);
      expect(value).not.toBe('');
    });
  });
});

// Função auxiliar para calcular contraste (simplificada)
function calculateContrastRatio(color1: string, color2: string): number {
  // Implementação simplificada - em produção usar biblioteca especializada
  const hexToRgb = (hex: string) => {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  };
  
  const rgb1 = hexToRgb(color1);
  const rgb2 = hexToRgb(color2);
  
  if (!rgb1 || !rgb2) return 1;
  
  const luminance1 = (0.299 * rgb1.r + 0.587 * rgb1.g + 0.114 * rgb1.b) / 255;
  const luminance2 = (0.299 * rgb2.r + 0.587 * rgb2.g + 0.114 * rgb2.b) / 255;
  
  const lighter = Math.max(luminance1, luminance2);
  const darker = Math.min(luminance1, luminance2);
  
  return (lighter + 0.05) / (darker + 0.05);
}

// Testes de integração de acessibilidade
describe('Testes de Integração de Acessibilidade', () => {
  test('deve ter navegação completa por teclado', () => {
    render(
      <div>
        <InteractiveTour
          isVisible={true}
          onComplete={jest.fn()}
          onSkip={jest.fn()}
          steps={getDefaultTourSteps((key: string) => mockTranslations[key] || key)}
          autoStart={true}
        />
        <EnhancedDarkMode showAccessibilityInfo={true} />
      </div>
    );
    
    // Testa navegação entre componentes
    const tourOverlay = screen.getByRole('dialog');
    const darkModeToggle = screen.getByLabelText('Ativar modo escuro');
    
    tourOverlay.focus();
    expect(document.activeElement).toBe(tourOverlay);
    
    // Navega para o toggle de tema
    fireEvent.keyDown(tourOverlay, { key: 'Tab' });
    expect(document.activeElement).toBe(darkModeToggle);
  });

  test('deve manter acessibilidade durante transições', async () => {
    render(
      <div>
        <InteractiveTour
          isVisible={true}
          onComplete={jest.fn()}
          onSkip={jest.fn()}
          steps={getDefaultTourSteps((key: string) => mockTranslations[key] || key)}
          autoStart={true}
        />
        <EnhancedDarkMode showAccessibilityInfo={true} />
      </div>
    );
    
    const darkModeToggle = screen.getByLabelText('Ativar modo escuro');
    
    // Testa acessibilidade durante transição de tema
    fireEvent.click(darkModeToggle);
    
    // Deve manter foco e navegação durante transição
    await waitFor(() => {
      expect(darkModeToggle).toHaveAttribute('disabled');
    });
    
    // Após transição, deve restaurar funcionalidade
    await waitFor(() => {
      expect(darkModeToggle).not.toHaveAttribute('disabled');
    }, { timeout: 1000 });
  });
});

export default {}; 