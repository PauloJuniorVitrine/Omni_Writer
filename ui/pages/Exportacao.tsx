import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de Exportação de Dados.
 * Painel de exportação de artigos e prompts, status mock, placeholders para integração backend.
 */
export const Exportacao: React.FC = () => {
  const { t } = useI18n();
  const [status, setStatus] = useState<string | null>(null);

  // Placeholder para exportação de artigos
  const handleExportarArtigos = () => {
    setStatus(t('exporting_articles'));
    setTimeout(() => {
      setStatus(t('articles_exported_success'));
    }, 1200);
  };

  // Placeholder para exportação de prompts
  const handleExportarPrompts = () => {
    setStatus(t('exporting_prompts'));
    setTimeout(() => {
      setStatus(t('prompts_exported_success'));
    }, 1200);
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 600 }}>
      <h1>{t('export_data')}</h1>
      <Card title={t('export_articles')}>
        <Button variant="secondary" onClick={handleExportarArtigos}>
          {t('export_articles_csv')}
        </Button>
      </Card>
      <Card title={t('export_prompts')} style={{ marginTop: 24 }}>
        <Button variant="secondary" onClick={handleExportarPrompts}>
          {t('export_prompts_csv')}
        </Button>
      </Card>
      {status && (
        <div style={{ marginTop: 24 }}>
          <Card title={t('export_status')}>
            <p>{status}</p>
          </Card>
        </div>
      )}
    </main>
  );
}; 