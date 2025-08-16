/**
 * Tour Guiado Interativo - Omni Writer
 * 
 * Prompt: checklist_primeira_revisao.md - Item 9: Tour Guiado Interativo
 * Ruleset: enterprise_control_layer.yaml
 * Data: 2025-01-27T15:30:00Z
 * 
 * Componente de tour overlay que destaca elementos específicos da interface
 * com tooltips contextuais e navegação step-by-step.
 */

import React, { useState, useEffect, useRef } from 'react';
import { Card } from './Card';
import { Button } from './Button';
import { useI18n } from '../hooks/use_i18n';

interface TourStep {
  id: string;
  target: string; // CSS selector do elemento a destacar
  titulo: string;
  descricao: string;
  posicao: 'top' | 'bottom' | 'left' | 'right';
  acao?: () => void; // Ação opcional a executar no passo
}

interface TourOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  onComplete: () => void;
}

/**
 * Componente de Tour Overlay Interativo.
 * Destaca elementos específicos da interface com overlay e tooltips.
 */
export const TourOverlay: React.FC<TourOverlayProps> = ({ isOpen, onClose, onComplete }) => {
  const { t } = useI18n();
  const [passo, setPasso] = useState(0);
  const [targetElement, setTargetElement] = useState<HTMLElement | null>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  const tourSteps: TourStep[] = [
    {
      id: 'welcome',
      target: '.dashboard-header',
      titulo: 'onboarding_welcome_title',
      descricao: 'onboarding_welcome_desc',
      posicao: 'bottom'
    },
    {
      id: 'blogs',
      target: '.blogs-section',
      titulo: 'onboarding_blogs_title',
      descricao: 'onboarding_blogs_desc',
      posicao: 'right'
    },
    {
      id: 'generation',
      target: '.generation-form',
      titulo: 'onboarding_generation_title',
      descricao: 'onboarding_generation_desc',
      posicao: 'top'
    },
    {
      id: 'feedback',
      target: '.feedback-section',
      titulo: 'onboarding_feedback_title',
      descricao: 'onboarding_feedback_desc',
      posicao: 'left'
    },
    {
      id: 'security',
      target: '.security-section',
      titulo: 'onboarding_security_title',
      descricao: 'onboarding_security_desc',
      posicao: 'bottom'
    },
    {
      id: 'ready',
      target: '.main-content',
      titulo: 'onboarding_ready_title',
      descricao: 'onboarding_ready_desc',
      posicao: 'top'
    }
  ];

  useEffect(() => {
    if (!isOpen) return;

    const currentStep = tourSteps[passo];
    const element = document.querySelector(currentStep.target) as HTMLElement;
    
    if (element) {
      setTargetElement(element);
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      
      // Adiciona highlight temporário
      element.style.outline = '3px solid #6366f1';
      element.style.outlineOffset = '2px';
      element.style.transition = 'outline 0.3s ease';
      
      return () => {
        element.style.outline = '';
        element.style.outlineOffset = '';
      };
    }
  }, [passo, isOpen]);

  const handleAvancar = () => {
    if (passo < tourSteps.length - 1) {
      setPasso(passo + 1);
    } else {
      onComplete();
    }
  };

  const handleVoltar = () => {
    if (passo > 0) {
      setPasso(passo - 1);
    }
  };

  const handlePular = () => {
    onComplete();
  };

  if (!isOpen) return null;

  const currentStep = tourSteps[passo];
  const isFirst = passo === 0;
  const isLast = passo === tourSteps.length - 1;

  return (
    <>
      {/* Overlay de fundo */}
      <div
        ref={overlayRef}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          zIndex: 9999,
          backdropFilter: 'blur(2px)'
        }}
        onClick={handlePular}
      />

      {/* Tooltip do tour */}
      {targetElement && (
        <div
          style={{
            position: 'absolute',
            zIndex: 10000,
            maxWidth: 400,
            backgroundColor: '#fff',
            borderRadius: 12,
            boxShadow: '0 20px 40px rgba(0, 0, 0, 0.3)',
            border: '1px solid #e2e8f0',
            ...getTooltipPosition(targetElement, currentStep.posicao)
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <Card 
            title={t(currentStep.titulo)} 
            description={t(currentStep.descricao)}
            style={{ border: 'none', boxShadow: 'none', margin: 0 }}
          >
            <div style={{ display: 'flex', gap: 12, marginTop: 16, justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <Button 
                  variant="secondary" 
                  onClick={handleVoltar} 
                  disabled={isFirst}
                  size="small"
                >
                  {t('back')}
                </Button>
                <Button 
                  variant="primary" 
                  onClick={handleAvancar}
                  size="small"
                >
                  {isLast ? t('finish') : t('next')}
                </Button>
              </div>
              <Button 
                variant="text" 
                onClick={handlePular}
                size="small"
                style={{ color: '#666' }}
              >
                {t('skip')}
              </Button>
            </div>
            
            {/* Indicador de progresso */}
            <div style={{ marginTop: 16, display: 'flex', justifyContent: 'center', gap: 4 }}>
              {tourSteps.map((_, index) => (
                <div
                  key={index}
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    backgroundColor: index === passo ? '#6366f1' : '#e2e8f0',
                    transition: 'background-color 0.3s ease'
                  }}
                />
              ))}
            </div>
            
            <div style={{ marginTop: 8, fontSize: 12, color: '#888', textAlign: 'center' }}>
              {t('step')} {passo + 1} {t('of')} {tourSteps.length}
            </div>
          </Card>
        </div>
      )}
    </>
  );
};

/**
 * Calcula a posição do tooltip baseado no elemento alvo e posição desejada.
 */
function getTooltipPosition(element: HTMLElement, posicao: string) {
  const rect = element.getBoundingClientRect();
  const tooltipWidth = 400;
  const tooltipHeight = 200;
  const margin = 16;

  switch (posicao) {
    case 'top':
      return {
        left: rect.left + rect.width / 2 - tooltipWidth / 2,
        top: rect.top - tooltipHeight - margin,
        transform: 'translateY(-8px)'
      };
    case 'bottom':
      return {
        left: rect.left + rect.width / 2 - tooltipWidth / 2,
        top: rect.bottom + margin,
        transform: 'translateY(8px)'
      };
    case 'left':
      return {
        left: rect.left - tooltipWidth - margin,
        top: rect.top + rect.height / 2 - tooltipHeight / 2,
        transform: 'translateX(-8px)'
      };
    case 'right':
      return {
        left: rect.right + margin,
        top: rect.top + rect.height / 2 - tooltipHeight / 2,
        transform: 'translateX(8px)'
      };
    default:
      return {
        left: rect.left + rect.width / 2 - tooltipWidth / 2,
        top: rect.bottom + margin
      };
  }
} 