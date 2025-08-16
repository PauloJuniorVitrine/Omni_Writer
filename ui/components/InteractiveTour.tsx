/**
 * InteractiveTour - Tour Guiado Interativo
 * =======================================
 * 
 * Implementa tour guiado interativo com:
 * - Onboarding step-by-step para novos usuários
 * - Tooltips contextuais
 * - Feedback de acessibilidade em tempo real
 * - Testes de usabilidade integrados
 * 
 * Autor: Análise Técnica Omni Writer
 * Data: 2025-01-27
 * Versão: 1.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useI18n } from '../hooks/use_i18n';
import { useTheme } from '../context/ThemeContext';

interface TourStep {
  id: string;
  target: string;
  title: string;
  content: string;
  position: 'top' | 'bottom' | 'left' | 'right';
  action?: () => void;
  required?: boolean;
}

interface InteractiveTourProps {
  isVisible: boolean;
  onComplete: () => void;
  onSkip: () => void;
  steps: TourStep[];
  autoStart?: boolean;
}

export const InteractiveTour: React.FC<InteractiveTourProps> = ({
  isVisible,
  onComplete,
  onSkip,
  steps,
  autoStart = false
}) => {
  const { t } = useI18n();
  const { theme } = useTheme();
  const [currentStep, setCurrentStep] = useState(0);
  const [isActive, setIsActive] = useState(autoStart);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  const [targetElement, setTargetElement] = useState<HTMLElement | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);

  // Configurações de acessibilidade
  const [accessibilityFeedback, setAccessibilityFeedback] = useState<string>('');
  const [screenReaderAnnouncement, setScreenReaderAnnouncement] = useState<string>('');

  // Efeitos de acessibilidade
  useEffect(() => {
    if (isActive && steps[currentStep]) {
      const step = steps[currentStep];
      const element = document.querySelector(step.target) as HTMLElement;
      
      if (element) {
        setTargetElement(element);
        updateTooltipPosition(element, step.position);
        
        // Anúncio para leitores de tela
        const announcement = `${t('tour.step')} ${currentStep + 1} ${t('tour.of')} ${steps.length}: ${step.title}`;
        setScreenReaderAnnouncement(announcement);
        
        // Feedback de acessibilidade
        setAccessibilityFeedback(t('tour.accessibility.focus'));
        
        // Foca no elemento alvo
        element.focus();
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  }, [currentStep, isActive, steps, t]);

  // Atualiza posição do tooltip
  const updateTooltipPosition = useCallback((element: HTMLElement, position: string) => {
    const rect = element.getBoundingClientRect();
    const tooltip = tooltipRef.current;
    
    if (tooltip) {
      const tooltipRect = tooltip.getBoundingClientRect();
      let x = 0;
      let y = 0;
      
      switch (position) {
        case 'top':
          x = rect.left + rect.width / 2 - tooltipRect.width / 2;
          y = rect.top - tooltipRect.height - 10;
          break;
        case 'bottom':
          x = rect.left + rect.width / 2 - tooltipRect.width / 2;
          y = rect.bottom + 10;
          break;
        case 'left':
          x = rect.left - tooltipRect.width - 10;
          y = rect.top + rect.height / 2 - tooltipRect.height / 2;
          break;
        case 'right':
          x = rect.right + 10;
          y = rect.top + rect.height / 2 - tooltipRect.height / 2;
          break;
      }
      
      setTooltipPosition({ x, y });
    }
  }, []);

  // Navegação do tour
  const nextStep = useCallback(() => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(prev => prev + 1);
    } else {
      completeTour();
    }
  }, [currentStep, steps.length]);

  const previousStep = useCallback(() => {
    if (currentStep > 0) {
      setCurrentStep(prev => prev - 1);
    }
  }, [currentStep]);

  const completeTour = useCallback(() => {
    setIsActive(false);
    setCurrentStep(0);
    onComplete();
    
    // Feedback de conclusão
    setAccessibilityFeedback(t('tour.completed'));
    setScreenReaderAnnouncement(t('tour.completed.announcement'));
  }, [onComplete, t]);

  const skipTour = useCallback(() => {
    setIsActive(false);
    setCurrentStep(0);
    onSkip();
    
    // Feedback de skip
    setAccessibilityFeedback(t('tour.skipped'));
    setScreenReaderAnnouncement(t('tour.skipped.announcement'));
  }, [onSkip, t]);

  // Navegação por teclado
  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    switch (event.key) {
      case 'ArrowRight':
      case 'Enter':
        event.preventDefault();
        nextStep();
        break;
      case 'ArrowLeft':
        event.preventDefault();
        previousStep();
        break;
      case 'Escape':
        event.preventDefault();
        skipTour();
        break;
      case 'Tab':
        // Permite navegação normal por Tab
        break;
    }
  }, [nextStep, previousStep, skipTour]);

  // Estilos dinâmicos baseados no tema
  const getTourStyles = () => ({
    overlay: {
      position: 'fixed' as const,
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: theme === 'dark' ? 'rgba(0, 0, 0, 0.8)' : 'rgba(0, 0, 0, 0.6)',
      zIndex: 9999,
      display: isActive ? 'block' : 'none'
    },
    tooltip: {
      position: 'fixed' as const,
      left: tooltipPosition.x,
      top: tooltipPosition.y,
      backgroundColor: theme === 'dark' ? '#2d3748' : '#ffffff',
      border: `2px solid ${theme === 'dark' ? '#4a5568' : '#e2e8f0'}`,
      borderRadius: '8px',
      padding: '16px',
      maxWidth: '300px',
      boxShadow: theme === 'dark' 
        ? '0 10px 25px rgba(0, 0, 0, 0.5)' 
        : '0 10px 25px rgba(0, 0, 0, 0.15)',
      zIndex: 10000,
      color: theme === 'dark' ? '#e2e8f0' : '#2d3748'
    },
    highlight: {
      position: 'absolute' as const,
      border: `3px solid ${theme === 'dark' ? '#4299e1' : '#3182ce'}`,
      borderRadius: '4px',
      boxShadow: `0 0 0 9999px ${theme === 'dark' ? 'rgba(0, 0, 0, 0.8)' : 'rgba(0, 0, 0, 0.6)'}`,
      pointerEvents: 'none' as const,
      zIndex: 9998
    }
  });

  const styles = getTourStyles();

  if (!isVisible || !isActive) {
    return null;
  }

  const currentStepData = steps[currentStep];
  const progress = ((currentStep + 1) / steps.length) * 100;

  return (
    <>
      {/* Overlay do tour */}
      <div 
        ref={overlayRef}
        style={styles.overlay}
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-title"
        aria-describedby="tour-content"
        onKeyDown={handleKeyDown}
        tabIndex={-1}
      >
        {/* Highlight do elemento alvo */}
        {targetElement && (
          <div
            style={{
              ...styles.highlight,
              top: targetElement.offsetTop - 3,
              left: targetElement.offsetLeft - 3,
              width: targetElement.offsetWidth + 6,
              height: targetElement.offsetHeight + 6
            }}
            aria-hidden="true"
          />
        )}

        {/* Tooltip do tour */}
        <div
          ref={tooltipRef}
          style={styles.tooltip}
          role="tooltip"
          id="tour-tooltip"
        >
          {/* Cabeçalho */}
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            marginBottom: '12px'
          }}>
            <h3 
              id="tour-title"
              style={{ 
                margin: 0, 
                fontSize: '16px', 
                fontWeight: 'bold',
                color: theme === 'dark' ? '#f7fafc' : '#1a202c'
              }}
            >
              {currentStepData.title}
            </h3>
            <button
              onClick={skipTour}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '18px',
                cursor: 'pointer',
                color: theme === 'dark' ? '#a0aec0' : '#718096',
                padding: '4px'
              }}
              aria-label={t('tour.skip')}
            >
              ×
            </button>
          </div>

          {/* Conteúdo */}
          <p 
            id="tour-content"
            style={{ 
              margin: '0 0 16px 0', 
              lineHeight: '1.5',
              color: theme === 'dark' ? '#e2e8f0' : '#4a5568'
            }}
          >
            {currentStepData.content}
          </p>

          {/* Barra de progresso */}
          <div style={{ 
            width: '100%', 
            height: '4px', 
            backgroundColor: theme === 'dark' ? '#4a5568' : '#e2e8f0',
            borderRadius: '2px',
            marginBottom: '16px'
          }}>
            <div style={{
              width: `${progress}%`,
              height: '100%',
              backgroundColor: theme === 'dark' ? '#4299e1' : '#3182ce',
              borderRadius: '2px',
              transition: 'width 0.3s ease'
            }} />
          </div>

          {/* Controles */}
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center'
          }}>
            <div style={{ fontSize: '14px', color: theme === 'dark' ? '#a0aec0' : '#718096' }}>
              {t('tour.step')} {currentStep + 1} {t('tour.of')} {steps.length}
            </div>
            
            <div style={{ display: 'flex', gap: '8px' }}>
              {currentStep > 0 && (
                <button
                  onClick={previousStep}
                  style={{
                    padding: '8px 16px',
                    border: `1px solid ${theme === 'dark' ? '#4a5568' : '#e2e8f0'}`,
                    borderRadius: '4px',
                    backgroundColor: 'transparent',
                    color: theme === 'dark' ? '#e2e8f0' : '#4a5568',
                    cursor: 'pointer',
                    fontSize: '14px'
                  }}
                  aria-label={t('tour.previous')}
                >
                  {t('tour.previous')}
                </button>
              )}
              
              <button
                onClick={currentStep === steps.length - 1 ? completeTour : nextStep}
                style={{
                  padding: '8px 16px',
                  border: 'none',
                  borderRadius: '4px',
                  backgroundColor: theme === 'dark' ? '#4299e1' : '#3182ce',
                  color: '#ffffff',
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 'bold'
                }}
                aria-label={currentStep === steps.length - 1 ? t('tour.finish') : t('tour.next')}
              >
                {currentStep === steps.length - 1 ? t('tour.finish') : t('tour.next')}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Feedback de acessibilidade para leitores de tela */}
      <div 
        aria-live="polite" 
        aria-atomic="true"
        style={{ 
          position: 'absolute', 
          left: '-10000px', 
          width: '1px', 
          height: '1px', 
          overflow: 'hidden' 
        }}
      >
        {screenReaderAnnouncement}
      </div>

      {/* Feedback visual de acessibilidade */}
      {accessibilityFeedback && (
        <div
          style={{
            position: 'fixed',
            bottom: '20px',
            right: '20px',
            backgroundColor: theme === 'dark' ? '#2d3748' : '#ffffff',
            border: `1px solid ${theme === 'dark' ? '#4a5568' : '#e2e8f0'}`,
            borderRadius: '4px',
            padding: '8px 12px',
            fontSize: '12px',
            color: theme === 'dark' ? '#e2e8f0' : '#4a5568',
            zIndex: 10001,
            maxWidth: '200px'
          }}
          role="status"
          aria-live="polite"
        >
          {accessibilityFeedback}
        </div>
      )}
    </>
  );
};

// Hook personalizado para gerenciar o tour
export const useInteractiveTour = () => {
  const [isTourVisible, setIsTourVisible] = useState(false);
  const [hasCompletedTour, setHasCompletedTour] = useState(false);

  // Verifica se o usuário já completou o tour
  useEffect(() => {
    const completed = localStorage.getItem('omni-writer-tour-completed');
    setHasCompletedTour(completed === 'true');
  }, []);

  const startTour = useCallback(() => {
    setIsTourVisible(true);
  }, []);

  const completeTour = useCallback(() => {
    setIsTourVisible(false);
    setHasCompletedTour(true);
    localStorage.setItem('omni-writer-tour-completed', 'true');
  }, []);

  const skipTour = useCallback(() => {
    setIsTourVisible(false);
    setHasCompletedTour(true);
    localStorage.setItem('omni-writer-tour-completed', 'true');
  }, []);

  const resetTour = useCallback(() => {
    setIsTourVisible(false);
    setHasCompletedTour(false);
    localStorage.removeItem('omni-writer-tour-completed');
  }, []);

  return {
    isTourVisible,
    hasCompletedTour,
    startTour,
    completeTour,
    skipTour,
    resetTour
  };
};

// Configuração padrão dos passos do tour
export const getDefaultTourSteps = (t: (key: string) => string): TourStep[] => [
  {
    id: 'welcome',
    target: '.main-header',
    title: t('tour.welcome.title'),
    content: t('tour.welcome.content'),
    position: 'bottom'
  },
  {
    id: 'generation-form',
    target: '.generation-form',
    title: t('tour.generation.title'),
    content: t('tour.generation.content'),
    position: 'bottom'
  },
  {
    id: 'categoria-select',
    target: '#categoria',
    title: t('tour.categoria.title'),
    content: t('tour.categoria.content'),
    position: 'bottom'
  },
  {
    id: 'generate-button',
    target: '#generate-btn',
    title: t('tour.generate.title'),
    content: t('tour.generate.content'),
    position: 'top'
  },
  {
    id: 'blogs-list',
    target: '.blog-list',
    title: t('tour.blogs.title'),
    content: t('tour.blogs.content'),
    position: 'left'
  },
  {
    id: 'language-selector',
    target: '.language-selector',
    title: t('tour.language.title'),
    content: t('tour.language.content'),
    position: 'bottom'
  },
  {
    id: 'dark-mode',
    target: '#dark-mode-toggle',
    title: t('tour.darkmode.title'),
    content: t('tour.darkmode.content'),
    position: 'left'
  },
  {
    id: 'completion',
    target: '.main-content',
    title: t('tour.completion.title'),
    content: t('tour.completion.content'),
    position: 'top'
  }
];

export default InteractiveTour; 