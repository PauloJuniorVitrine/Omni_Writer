import React, { useState, useEffect, useRef } from 'react';
import { useI18n } from '../hooks/use_i18n';
import { useTheme } from '../hooks/use_theme';

interface AccessibilityIssue {
  id: string;
  type: 'error' | 'warning' | 'info';
  message: string;
  element?: HTMLElement;
  severity: 'low' | 'medium' | 'high';
  wcagCriteria?: string;
}

interface AccessibilityFeedbackProps {
  enabled?: boolean;
  showNotifications?: boolean;
  autoScan?: boolean;
}

/**
 * Componente de feedback de acessibilidade em tempo real.
 * Monitora e reporta problemas de acessibilidade WCAG 2.1.
 */
export const AccessibilityFeedback: React.FC<AccessibilityFeedbackProps> = ({
  enabled = true,
  showNotifications = true,
  autoScan = true
}) => {
  const { t } = useI18n();
  const { colors } = useTheme();
  const [issues, setIssues] = useState<AccessibilityIssue[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScan, setLastScan] = useState<Date | null>(null);
  const scanIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Scanner de acessibilidade
  const scanAccessibility = (): AccessibilityIssue[] => {
    const newIssues: AccessibilityIssue[] = [];
    
    // Verificar elementos sem alt text
    const images = document.querySelectorAll('img');
    images.forEach((img, index) => {
      if (!img.alt && !img.getAttribute('aria-label')) {
        newIssues.push({
          id: `missing-alt-${index}`,
          type: 'error',
          message: 'Imagem sem texto alternativo',
          element: img,
          severity: 'high',
          wcagCriteria: '1.1.1'
        });
      }
    });

    // Verificar botões sem texto
    const buttons = document.querySelectorAll('button');
    buttons.forEach((button, index) => {
      const hasText = button.textContent?.trim();
      const hasAriaLabel = button.getAttribute('aria-label');
      const hasTitle = button.getAttribute('title');
      
      if (!hasText && !hasAriaLabel && !hasTitle) {
        newIssues.push({
          id: `missing-button-text-${index}`,
          type: 'error',
          message: 'Botão sem texto ou label acessível',
          element: button,
          severity: 'high',
          wcagCriteria: '4.1.2'
        });
      }
    });

    // Verificar contraste de cores
    const textElements = document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, span, div');
    textElements.forEach((element, index) => {
      const style = window.getComputedStyle(element);
      const color = style.color;
      const backgroundColor = style.backgroundColor;
      
      // Verificação simplificada de contraste
      if (color && backgroundColor) {
        const contrastRatio = calculateContrastRatio(color, backgroundColor);
        if (contrastRatio < 4.5) {
          newIssues.push({
            id: `low-contrast-${index}`,
            type: 'warning',
            message: `Contraste baixo (${contrastRatio.toFixed(1)}:1)`,
            element: element as HTMLElement,
            severity: 'medium',
            wcagCriteria: '1.4.3'
          });
        }
      }
    });

    // Verificar elementos sem foco visível
    const focusableElements = document.querySelectorAll('button, a, input, select, textarea, [tabindex]');
    focusableElements.forEach((element, index) => {
      const style = window.getComputedStyle(element);
      const outline = style.outline;
      const boxShadow = style.boxShadow;
      
      if (outline === 'none' && !boxShadow.includes('inset')) {
        newIssues.push({
          id: `no-focus-${index}`,
          type: 'warning',
          message: 'Elemento sem indicador de foco visível',
          element: element as HTMLElement,
          severity: 'medium',
          wcagCriteria: '2.4.7'
        });
      }
    });

    return newIssues;
  };

  // Calcular contraste de cores (simplificado)
  const calculateContrastRatio = (color1: string, color2: string): number => {
    // Implementação simplificada - em produção usar biblioteca real
    return 7.0; // Placeholder
  };

  // Iniciar scan automático
  useEffect(() => {
    if (!enabled || !autoScan) return;

    const startAutoScan = () => {
      scanIntervalRef.current = setInterval(() => {
        if (!isScanning) {
          setIsScanning(true);
          const newIssues = scanAccessibility();
          setIssues(newIssues);
          setLastScan(new Date());
          setIsScanning(false);
        }
      }, 5000); // Scan a cada 5 segundos
    };

    startAutoScan();

    return () => {
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
      }
    };
  }, [enabled, autoScan, isScanning]);

  // Scan manual
  const handleManualScan = () => {
    setIsScanning(true);
    const newIssues = scanAccessibility();
    setIssues(newIssues);
    setLastScan(new Date());
    setIsScanning(false);
  };

  // Limpar issues
  const clearIssues = () => {
    setIssues([]);
  };

  // Navegar para elemento com problema
  const navigateToIssue = (issue: AccessibilityIssue) => {
    if (issue.element) {
      issue.element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      issue.element.style.outline = '3px solid #ef4444';
      issue.element.style.outlineOffset = '2px';
      
      setTimeout(() => {
        issue.element!.style.outline = '';
        issue.element!.style.outlineOffset = '';
      }, 3000);
    }
  };

  // Estatísticas
  const errorCount = issues.filter(i => i.type === 'error').length;
  const warningCount = issues.filter(i => i.type === 'warning').length;
  const infoCount = issues.filter(i => i.type === 'info').length;

  if (!enabled) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 20,
        right: 20,
        zIndex: 1000,
        maxWidth: 400,
        background: colors.surface,
        border: `1px solid ${colors.border}`,
        borderRadius: 12,
        boxShadow: '0 10px 25px rgba(0, 0, 0, 0.15)',
        padding: 16
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <h3 style={{ 
          margin: 0, 
          fontSize: 16, 
          fontWeight: 600, 
          color: colors.text 
        }}>
          Acessibilidade
        </h3>
        
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={handleManualScan}
            disabled={isScanning}
            style={{
              padding: '4px 8px',
              fontSize: 12,
              border: `1px solid ${colors.border}`,
              borderRadius: 6,
              background: colors.surface,
              color: colors.text,
              cursor: 'pointer',
              opacity: isScanning ? 0.5 : 1
            }}
          >
            {isScanning ? 'Escaneando...' : 'Scan'}
          </button>
          
          <button
            onClick={clearIssues}
            style={{
              padding: '4px 8px',
              fontSize: 12,
              border: `1px solid ${colors.border}`,
              borderRadius: 6,
              background: colors.surface,
              color: colors.text,
              cursor: 'pointer'
            }}
          >
            Limpar
          </button>
        </div>
      </div>

      {/* Estatísticas */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 4,
          color: colors.error,
          fontSize: 12
        }}>
          <span>●</span>
          <span>{errorCount} erros</span>
        </div>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 4,
          color: colors.warning,
          fontSize: 12
        }}>
          <span>●</span>
          <span>{warningCount} avisos</span>
        </div>
        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 4,
          color: colors.info,
          fontSize: 12
        }}>
          <span>●</span>
          <span>{infoCount} info</span>
        </div>
      </div>

      {/* Lista de issues */}
      {issues.length > 0 ? (
        <div style={{ maxHeight: 300, overflowY: 'auto' }}>
          {issues.map((issue) => (
            <div
              key={issue.id}
              style={{
                padding: 8,
                marginBottom: 8,
                border: `1px solid ${issue.type === 'error' ? colors.error : issue.type === 'warning' ? colors.warning : colors.info}`,
                borderRadius: 6,
                background: issue.type === 'error' ? `${colors.error}10` : issue.type === 'warning' ? `${colors.warning}10` : `${colors.info}10`,
                cursor: 'pointer',
                transition: 'all 0.2s ease'
              }}
              onClick={() => navigateToIssue(issue)}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateX(-4px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateX(0)';
              }}
            >
              <div style={{ 
                fontSize: 12, 
                fontWeight: 500,
                color: issue.type === 'error' ? colors.error : issue.type === 'warning' ? colors.warning : colors.info,
                marginBottom: 4
              }}>
                {issue.message}
              </div>
              {issue.wcagCriteria && (
                <div style={{ 
                  fontSize: 10, 
                  color: colors.textSecondary 
                }}>
                  WCAG {issue.wcagCriteria}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div style={{ 
          textAlign: 'center', 
          color: colors.textSecondary, 
          fontSize: 12,
          padding: 20
        }}>
          Nenhum problema de acessibilidade encontrado
        </div>
      )}

      {/* Status do scan */}
      {lastScan && (
        <div style={{ 
          fontSize: 10, 
          color: colors.textSecondary, 
          textAlign: 'center',
          marginTop: 8
        }}>
          Último scan: {lastScan.toLocaleTimeString()}
        </div>
      )}
    </div>
  );
}; 