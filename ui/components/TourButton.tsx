import React from 'react';
import { Button } from './Button';
import { useI18n } from '../hooks/use_i18n';

interface TourButtonProps {
  onStartTour: () => void;
  variant?: 'primary' | 'secondary' | 'text';
  size?: 'small' | 'medium' | 'large';
  style?: React.CSSProperties;
}

/**
 * Componente de botão para iniciar o tour interativo.
 * Exibe ícone de ajuda e texto contextual.
 */
export const TourButton: React.FC<TourButtonProps> = ({ 
  onStartTour, 
  variant = 'secondary',
  size = 'medium',
  style 
}) => {
  const { t } = useI18n();

  return (
    <Button
      variant={variant}
      size={size}
      onClick={onStartTour}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        ...style
      }}
      aria-label={t('skip_tour')}
      title={t('skip_tour')}
    >
      <span role="img" aria-label="help" style={{ fontSize: 16 }}>
        💡
      </span>
      {t('skip_tour')}
    </Button>
  );
}; 