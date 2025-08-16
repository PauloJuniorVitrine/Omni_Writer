/**
 * Componente GenerationWizard - Geração de Artigos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Steps progressivos
 * - Indicadores visuais
 * - Navegação entre steps
 * - Validação visual
 */

import React from 'react';

interface Step {
  id: number;
  title: string;
  description: string;
}

interface GenerationWizardProps {
  steps: Step[];
  currentStep: number;
  onStepClick: (step: number) => void;
}

/**
 * Componente wizard para geração de artigos
 */
const GenerationWizard: React.FC<GenerationWizardProps> = ({
  steps,
  currentStep,
  onStepClick
}) => {
  const getStepStatus = (stepId: number) => {
    if (stepId < currentStep) return 'completed';
    if (stepId === currentStep) return 'current';
    return 'pending';
  };

  const getStepIcon = (stepId: number, status: string) => {
    if (status === 'completed') return '✓';
    if (status === 'current') return stepId.toString();
    return stepId.toString();
  };

  const getStepClasses = (status: string) => {
    const baseClasses = 'flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium transition-all duration-200';
    
    switch (status) {
      case 'completed':
        return `${baseClasses} bg-green-500 text-white`;
      case 'current':
        return `${baseClasses} bg-blue-500 text-white ring-4 ring-blue-100`;
      case 'pending':
        return `${baseClasses} bg-gray-200 text-gray-500`;
      default:
        return baseClasses;
    }
  };

  const getLineClasses = (stepId: number) => {
    if (stepId < currentStep) return 'bg-green-500';
    return 'bg-gray-200';
  };

  return (
    <div className="w-full">
      <div className="flex items-center justify-between">
        {steps.map((step, index) => {
          const status = getStepStatus(step.id);
          const isLast = index === steps.length - 1;
          
          return (
            <React.Fragment key={step.id}>
              {/* Step */}
              <div className="flex flex-col items-center">
                <button
                  onClick={() => onStepClick(step.id)}
                  className={`${getStepClasses(status)} ${
                    status === 'completed' || status === 'current' 
                      ? 'cursor-pointer hover:scale-110' 
                      : 'cursor-not-allowed'
                  }`}
                  disabled={status === 'pending'}
                >
                  {getStepIcon(step.id, status)}
                </button>
                
                <div className="mt-2 text-center">
                  <h3 className={`text-sm font-medium ${
                    status === 'completed' || status === 'current'
                      ? 'text-gray-900'
                      : 'text-gray-500'
                  }`}>
                    {step.title}
                  </h3>
                  <p className={`text-xs mt-1 ${
                    status === 'completed' || status === 'current'
                      ? 'text-gray-600'
                      : 'text-gray-400'
                  }`}>
                    {step.description}
                  </p>
                </div>
              </div>

              {/* Linha conectora */}
              {!isLast && (
                <div className="flex-1 mx-4">
                  <div className={`h-1 rounded-full transition-all duration-300 ${getLineClasses(step.id)}`} />
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>

      {/* Progress bar */}
      <div className="mt-6">
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className="bg-blue-500 h-2 rounded-full transition-all duration-500"
            style={{ width: `${(currentStep / steps.length) * 100}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-gray-500 mt-2">
          <span>Step {currentStep} de {steps.length}</span>
          <span>{Math.round((currentStep / steps.length) * 100)}% completo</span>
        </div>
      </div>
    </div>
  );
};

export default GenerationWizard; 