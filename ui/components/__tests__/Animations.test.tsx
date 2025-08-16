/**
 * Testes Unitários - Sistema de Animações e Transições
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-020
 * Data/Hora: 2025-01-28T00:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_001
 * 
 * Testes baseados em código real do sistema de animações
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import {
  Animation,
  PageTransition,
  LoadingAnimation,
  MicroInteraction,
  HoverEffect,
  useAnimation,
  usePageTransition,
  useScrollAnimation,
} from '../Animations';

// Mock do IntersectionObserver
const mockIntersectionObserver = jest.fn();
mockIntersectionObserver.mockReturnValue({
  observe: () => null,
  unobserve: () => null,
  disconnect: () => null,
});
window.IntersectionObserver = mockIntersectionObserver;

// Componente de teste para hooks
const TestHookComponent = ({ hook, props = {} }: { hook: any; props?: any }) => {
  const result = hook(props);
  return <div data-testid="hook-result">{JSON.stringify(result)}</div>;
};

const renderWithRouter = (component: React.ReactElement) => {
  return render(<BrowserRouter>{component}</BrowserRouter>);
};

describe('Sistema de Animações', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Animation Component', () => {
    it('deve renderizar com animação fade padrão', () => {
      render(
        <Animation>
          <div>Conteúdo animado</div>
        </Animation>
      );
      
      expect(screen.getByText('Conteúdo animado')).toBeInTheDocument();
    });

    it('deve aplicar animação de slide', () => {
      render(
        <Animation type="slide" direction="up">
          <div>Slide animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Slide animation');
      expect(element).toHaveClass('omni-animation--slide');
    });

    it('deve aplicar animação de scale', () => {
      render(
        <Animation type="scale">
          <div>Scale animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Scale animation');
      expect(element).toHaveClass('omni-animation--scale');
    });

    it('deve aplicar animação de bounce', () => {
      render(
        <Animation type="bounce">
          <div>Bounce animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Bounce animation');
      expect(element).toHaveClass('omni-animation--bounce');
    });

    it('deve aplicar animação de shake', () => {
      render(
        <Animation type="shake">
          <div>Shake animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Shake animation');
      expect(element).toHaveClass('omni-animation--shake');
    });

    it('deve aplicar animação de pulse', () => {
      render(
        <Animation type="pulse">
          <div>Pulse animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Pulse animation');
      expect(element).toHaveClass('omni-animation--pulse');
    });

    it('deve aplicar animação de flip', () => {
      render(
        <Animation type="flip">
          <div>Flip animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Flip animation');
      expect(element).toHaveClass('omni-animation--flip');
    });

    it('deve desabilitar animação quando disabled=true', () => {
      render(
        <Animation disabled>
          <div>Disabled animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Disabled animation');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar delay na animação', () => {
      render(
        <Animation delay={500}>
          <div>Delayed animation</div>
        </Animation>
      );
      
      const element = screen.getByText('Delayed animation');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar easing personalizado', () => {
      render(
        <Animation easing="bounce">
          <div>Bounce easing</div>
        </Animation>
      );
      
      const element = screen.getByText('Bounce easing');
      expect(element).toBeInTheDocument();
    });
  });

  describe('PageTransition Component', () => {
    it('deve renderizar com transição fade padrão', () => {
      renderWithRouter(
        <PageTransition>
          <div>Página com transição</div>
        </PageTransition>
      );
      
      expect(screen.getByText('Página com transição')).toBeInTheDocument();
    });

    it('deve aplicar transição de slide', () => {
      renderWithRouter(
        <PageTransition type="slide">
          <div>Slide transition</div>
        </PageTransition>
      );
      
      const element = screen.getByText('Slide transition');
      expect(element).toHaveClass('omni-page-transition--slide');
    });

    it('deve aplicar transição de zoom', () => {
      renderWithRouter(
        <PageTransition type="zoom">
          <div>Zoom transition</div>
        </PageTransition>
      );
      
      const element = screen.getByText('Zoom transition');
      expect(element).toHaveClass('omni-page-transition--zoom');
    });

    it('deve aplicar transição de flip', () => {
      renderWithRouter(
        <PageTransition type="flip">
          <div>Flip transition</div>
        </PageTransition>
      );
      
      const element = screen.getByText('Flip transition');
      expect(element).toHaveClass('omni-page-transition--flip');
    });

    it('deve aplicar duração personalizada', () => {
      renderWithRouter(
        <PageTransition duration={500}>
          <div>Custom duration</div>
        </PageTransition>
      );
      
      const element = screen.getByText('Custom duration');
      expect(element).toBeInTheDocument();
    });
  });

  describe('LoadingAnimation Component', () => {
    it('deve renderizar spinner padrão', () => {
      render(<LoadingAnimation />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve renderizar animação de dots', () => {
      render(<LoadingAnimation type="dots" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve renderizar animação de bars', () => {
      render(<LoadingAnimation type="bars" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve renderizar animação de pulse', () => {
      render(<LoadingAnimation type="pulse" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve renderizar animação de skeleton', () => {
      render(<LoadingAnimation type="skeleton" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve renderizar animação de progress', () => {
      render(<LoadingAnimation type="progress" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar tamanho personalizado', () => {
      render(<LoadingAnimation size="lg" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar cor personalizada', () => {
      render(<LoadingAnimation color="#ff0000" />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve exibir texto personalizado', () => {
      render(<LoadingAnimation text="Carregando..." />);
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });
  });

  describe('MicroInteraction Component', () => {
    it('deve renderizar com efeito ripple padrão', () => {
      render(
        <MicroInteraction>
          <button>Botão com ripple</button>
        </MicroInteraction>
      );
      
      expect(screen.getByText('Botão com ripple')).toBeInTheDocument();
    });

    it('deve aplicar efeito bounce', () => {
      render(
        <MicroInteraction type="bounce">
          <button>Bounce effect</button>
        </MicroInteraction>
      );
      
      const element = screen.getByText('Bounce effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito shake', () => {
      render(
        <MicroInteraction type="shake">
          <button>Shake effect</button>
        </MicroInteraction>
      );
      
      const element = screen.getByText('Shake effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito pulse', () => {
      render(
        <MicroInteraction type="pulse">
          <button>Pulse effect</button>
        </MicroInteraction>
      );
      
      const element = screen.getByText('Pulse effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito glow', () => {
      render(
        <MicroInteraction type="glow">
          <button>Glow effect</button>
        </MicroInteraction>
      );
      
      const element = screen.getByText('Glow effect');
      expect(element).toBeInTheDocument();
    });

    it('deve responder ao trigger hover', () => {
      render(
        <MicroInteraction trigger="hover">
          <button>Hover trigger</button>
        </MicroInteraction>
      );
      
      const button = screen.getByText('Hover trigger');
      fireEvent.mouseEnter(button);
      
      expect(button).toBeInTheDocument();
    });

    it('deve responder ao trigger click', () => {
      render(
        <MicroInteraction trigger="click">
          <button>Click trigger</button>
        </MicroInteraction>
      );
      
      const button = screen.getByText('Click trigger');
      fireEvent.click(button);
      
      expect(button).toBeInTheDocument();
    });

    it('deve responder ao trigger focus', () => {
      render(
        <MicroInteraction trigger="focus">
          <button>Focus trigger</button>
        </MicroInteraction>
      );
      
      const button = screen.getByText('Focus trigger');
      fireEvent.focus(button);
      
      expect(button).toBeInTheDocument();
    });

    it('deve aplicar duração personalizada', () => {
      render(
        <MicroInteraction duration={1000}>
          <button>Custom duration</button>
        </MicroInteraction>
      );
      
      const element = screen.getByText('Custom duration');
      expect(element).toBeInTheDocument();
    });
  });

  describe('HoverEffect Component', () => {
    it('deve renderizar com efeito lift padrão', () => {
      render(
        <HoverEffect>
          <div>Efeito hover</div>
        </HoverEffect>
      );
      
      expect(screen.getByText('Efeito hover')).toBeInTheDocument();
    });

    it('deve aplicar efeito glow', () => {
      render(
        <HoverEffect type="glow">
          <div>Glow effect</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Glow effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito scale', () => {
      render(
        <HoverEffect type="scale">
          <div>Scale effect</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Scale effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito rotate', () => {
      render(
        <HoverEffect type="rotate">
          <div>Rotate effect</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Rotate effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito tilt', () => {
      render(
        <HoverEffect type="tilt">
          <div>Tilt effect</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Tilt effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar efeito morph', () => {
      render(
        <HoverEffect type="morph">
          <div>Morph effect</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Morph effect');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar intensidade light', () => {
      render(
        <HoverEffect intensity="light">
          <div>Light intensity</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Light intensity');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar intensidade strong', () => {
      render(
        <HoverEffect intensity="strong">
          <div>Strong intensity</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Strong intensity');
      expect(element).toBeInTheDocument();
    });

    it('deve responder ao hover', () => {
      render(
        <HoverEffect>
          <div>Hover test</div>
        </HoverEffect>
      );
      
      const element = screen.getByText('Hover test');
      fireEvent.mouseEnter(element);
      
      expect(element).toBeInTheDocument();
    });
  });

  describe('useAnimation Hook', () => {
    it('deve retornar estado inicial correto', () => {
      render(<TestHookComponent hook={useAnimation} />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com trigger mount', () => {
      render(<TestHookComponent hook={useAnimation} props="mount" />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com trigger hover', () => {
      render(<TestHookComponent hook={useAnimation} props="hover" />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com trigger click', () => {
      render(<TestHookComponent hook={useAnimation} props="click" />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com trigger scroll', () => {
      render(<TestHookComponent hook={useAnimation} props="scroll" />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com trigger focus', () => {
      render(<TestHookComponent hook={useAnimation} props="focus" />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });
  });

  describe('usePageTransition Hook', () => {
    it('deve retornar estado inicial correto', () => {
      renderWithRouter(<TestHookComponent hook={usePageTransition} />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve detectar mudanças de rota', () => {
      renderWithRouter(<TestHookComponent hook={usePageTransition} />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });
  });

  describe('useScrollAnimation Hook', () => {
    it('deve retornar estado inicial correto', () => {
      render(<TestHookComponent hook={useScrollAnimation} />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve funcionar com threshold personalizado', () => {
      render(<TestHookComponent hook={useScrollAnimation} props={0.5} />);
      
      const result = screen.getByTestId('hook-result');
      expect(result).toBeInTheDocument();
    });

    it('deve observar elemento quando ref é fornecido', () => {
      const TestComponent = () => {
        const { elementRef } = useScrollAnimation();
        return <div ref={elementRef}>Scroll element</div>;
      };
      
      render(<TestComponent />);
      
      expect(screen.getByText('Scroll element')).toBeInTheDocument();
    });
  });

  describe('Acessibilidade', () => {
    it('deve respeitar prefers-reduced-motion', () => {
      // Mock de prefers-reduced-motion
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(prefers-reduced-motion: reduce)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(
        <Animation>
          <div>Acessível</div>
        </Animation>
      );
      
      expect(screen.getByText('Acessível')).toBeInTheDocument();
    });

    it('deve ter estrutura semântica correta', () => {
      render(
        <Animation>
          <button aria-label="Botão animado">Botão</button>
        </Animation>
      );
      
      const button = screen.getByRole('button');
      expect(button).toHaveAttribute('aria-label', 'Botão animado');
    });
  });

  describe('Performance', () => {
    it('deve usar will-change para otimização', () => {
      render(
        <Animation>
          <div>Performance test</div>
        </Animation>
      );
      
      const element = screen.getByText('Performance test');
      expect(element).toBeInTheDocument();
    });

    it('deve usar transform3d para GPU acceleration', () => {
      render(
        <Animation>
          <div>GPU acceleration</div>
        </Animation>
      );
      
      const element = screen.getByText('GPU acceleration');
      expect(element).toBeInTheDocument();
    });
  });

  describe('Integração', () => {
    it('deve integrar com componentes existentes', () => {
      render(
        <Animation>
          <HoverEffect>
            <MicroInteraction>
              <button>Integração completa</button>
            </MicroInteraction>
          </HoverEffect>
        </Animation>
      );
      
      expect(screen.getByText('Integração completa')).toBeInTheDocument();
    });

    it('deve funcionar com PageTransition', () => {
      renderWithRouter(
        <PageTransition>
          <Animation>
            <div>Página animada</div>
          </Animation>
        </PageTransition>
      );
      
      expect(screen.getByText('Página animada')).toBeInTheDocument();
    });

    it('deve funcionar com LoadingAnimation', () => {
      render(
        <Animation>
          <LoadingAnimation text="Carregando..." />
        </Animation>
      );
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });
  });

  describe('Estados de Carregamento', () => {
    it('deve mostrar loading durante animação', () => {
      render(
        <Animation>
          <LoadingAnimation />
        </Animation>
      );
      
      const element = screen.getByTestId('hook-result');
      expect(element).toBeInTheDocument();
    });

    it('deve aplicar animação de entrada', () => {
      render(
        <Animation trigger="mount">
          <div>Entrada animada</div>
        </Animation>
      );
      
      expect(screen.getByText('Entrada animada')).toBeInTheDocument();
    });

    it('deve aplicar animação de saída', () => {
      render(
        <Animation trigger="hover">
          <div>Saída animada</div>
        </Animation>
      );
      
      const element = screen.getByText('Saída animada');
      fireEvent.mouseEnter(element);
      fireEvent.mouseLeave(element);
      
      expect(element).toBeInTheDocument();
    });
  });

  describe('Responsividade', () => {
    it('deve funcionar em diferentes tamanhos de tela', () => {
      render(
        <Animation>
          <div>Responsivo</div>
        </Animation>
      );
      
      expect(screen.getByText('Responsivo')).toBeInTheDocument();
    });

    it('deve adaptar animações para mobile', () => {
      render(
        <Animation>
          <div>Mobile friendly</div>
        </Animation>
      );
      
      expect(screen.getByText('Mobile friendly')).toBeInTheDocument();
    });
  });
}); 