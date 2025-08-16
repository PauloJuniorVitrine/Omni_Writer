import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Componente/Página de Onboarding/Tour Guiado.
 * Exibe instruções passo a passo, uso de Card/Button, placeholders para integração futura.
 */
const passosKeys = [
  { titulo: 'onboarding_welcome_title', descricao: 'onboarding_welcome_desc' },
  { titulo: 'onboarding_dashboard_title', descricao: 'onboarding_dashboard_desc' },
  { titulo: 'onboarding_blogs_title', descricao: 'onboarding_blogs_desc' },
  { titulo: 'onboarding_feedback_title', descricao: 'onboarding_feedback_desc' },
  { titulo: 'onboarding_security_title', descricao: 'onboarding_security_desc' },
  { titulo: 'onboarding_ready_title', descricao: 'onboarding_ready_desc' },
];

export const Onboarding: React.FC = () => {
  const { t } = useI18n();
  const [passo, setPasso] = useState(0);

  // Placeholder para integração futura (ex: salvar progresso)
  const handleAvancar = () => {
    if (passo < passosKeys.length - 1) setPasso(passo + 1);
  };
  const handleVoltar = () => {
    if (passo > 0) setPasso(passo - 1);
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 600, margin: '0 auto' }}>
      <Card title={t(passosKeys[passo].titulo)} description={t(passosKeys[passo].descricao)}>
        <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
          <Button variant="secondary" onClick={handleVoltar} disabled={passo === 0}>{t('back')}</Button>
          <Button variant="primary" onClick={handleAvancar} disabled={passo === passosKeys.length - 1}>{t('next')}</Button>
        </div>
        <div style={{ marginTop: 16, fontSize: 12, color: '#888' }}>{t('step')} {passo + 1} {t('of')} {passosKeys.length}</div>
      </Card>
    </main>
  );
}; 