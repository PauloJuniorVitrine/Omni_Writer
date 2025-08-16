import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de Geração de Artigos.
 * Formulário mock para geração, status/resultados mock, placeholders para integração backend.
 */
export const GeracaoArtigos: React.FC = () => {
  const { t } = useI18n();
  const [titulo, setTitulo] = useState('');
  const [status, setStatus] = useState<'idle' | 'gerando' | 'concluido'>('idle');
  const [resultado, setResultado] = useState<string | null>(null);

  // Placeholder para geração
  const handleGerar = () => {
    setStatus('gerando');
    setTimeout(() => {
      setStatus('concluido');
      setResultado(t('article_generated_success'));
    }, 1500);
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 600 }}>
      <h1>{t('generate')}</h1>
      <Card title={t('new_article')}>
        <form onSubmit={e => { e.preventDefault(); handleGerar(); }} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <label>
            {t('article_title')}:
            <input type="text" value={titulo} onChange={e => setTitulo(e.target.value)} style={{ width: '100%', padding: 8, borderRadius: 4, border: '1px solid #ccc' }} />
          </label>
          <Button variant="success" type="submit" disabled={status === 'gerando' || !titulo}>
            {status === 'gerando' ? t('generating') : t('generate_article')}
          </Button>
        </form>
      </Card>
      {status === 'concluido' && resultado && (
        <Card title={t('result')}>
          <p>{resultado}</p>
        </Card>
      )}
    </main>
  );
}; 