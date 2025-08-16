import { useState, useEffect } from 'react';

interface TourState {
  isOpen: boolean;
  hasCompleted: boolean;
  currentStep: number;
}

/**
 * Hook para gerenciar o estado do tour interativo.
 * Persiste o progresso no localStorage e controla a exibição do tour.
 */
export const useTour = () => {
  const [tourState, setTourState] = useState<TourState>({
    isOpen: false,
    hasCompleted: false,
    currentStep: 0
  });

  // Carrega estado inicial do localStorage
  useEffect(() => {
    const savedState = localStorage.getItem('omni_writer_tour');
    if (savedState) {
      try {
        const parsed = JSON.parse(savedState);
        setTourState(prev => ({
          ...prev,
          hasCompleted: parsed.hasCompleted || false,
          currentStep: parsed.currentStep || 0
        }));
      } catch (error) {
        console.warn('Erro ao carregar estado do tour:', error);
      }
    }
  }, []);

  // Salva estado no localStorage
  const saveTourState = (newState: Partial<TourState>) => {
    const updatedState = { ...tourState, ...newState };
    setTourState(updatedState);
    
    try {
      localStorage.setItem('omni_writer_tour', JSON.stringify(updatedState));
    } catch (error) {
      console.warn('Erro ao salvar estado do tour:', error);
    }
  };

  // Abre o tour
  const openTour = () => {
    saveTourState({ isOpen: true, currentStep: 0 });
  };

  // Fecha o tour
  const closeTour = () => {
    saveTourState({ isOpen: false });
  };

  // Completa o tour
  const completeTour = () => {
    saveTourState({ 
      isOpen: false, 
      hasCompleted: true, 
      currentStep: 0 
    });
  };

  // Avança para o próximo passo
  const nextStep = () => {
    const nextStepNumber = tourState.currentStep + 1;
    saveTourState({ currentStep: nextStepNumber });
  };

  // Volta para o passo anterior
  const previousStep = () => {
    const prevStepNumber = Math.max(0, tourState.currentStep - 1);
    saveTourState({ currentStep: prevStepNumber });
  };

  // Pula o tour
  const skipTour = () => {
    saveTourState({ 
      isOpen: false, 
      hasCompleted: true, 
      currentStep: 0 
    });
  };

  // Reseta o tour (para testes ou re-exibição)
  const resetTour = () => {
    saveTourState({ 
      isOpen: false, 
      hasCompleted: false, 
      currentStep: 0 
    });
  };

  // Verifica se deve mostrar o tour automaticamente
  const shouldShowTour = () => {
    return !tourState.hasCompleted && !tourState.isOpen;
  };

  return {
    // Estado
    isOpen: tourState.isOpen,
    hasCompleted: tourState.hasCompleted,
    currentStep: tourState.currentStep,
    
    // Ações
    openTour,
    closeTour,
    completeTour,
    nextStep,
    previousStep,
    skipTour,
    resetTour,
    
    // Utilitários
    shouldShowTour
  };
}; 