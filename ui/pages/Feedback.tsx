import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de Feedback.
 * Formulário mock para envio, listagem mock de feedbacks, placeholders para integração backend.
 */
export const Feedback: React.FC = () => {
  const { t } = useI18n();
  const [mensagem, setMensagem] = useState('');
  const [feedbacks, setFeedbacks] = useState([
    { id: 1, usuario: 'Alice', texto: 'Ótimo sistema!' },
    { id: 2, usuario: 'Bob', texto: 'Sugestão: exportar em PDF.' },
  ]);
  const [enviando, setEnviando] = useState(false);
  const [sucesso, setSucesso] = useState(false);

  // Placeholder para envio de feedback
  const handleEnviar = (e: React.FormEvent) => {
    e.preventDefault();
    setEnviando(true);
    setTimeout(() => {
      setEnviando(false);
      setSucesso(true);
      setMensagem('');
      // TODO: Integrar com backend e atualizar lista
    }, 1000);
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 600 }}>
      <h1>{t('feedback')}</h1>
      <Card title={t('send_feedback')}>
        <form onSubmit={handleEnviar} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <textarea
            value={mensagem}
            onChange={e => setMensagem(e.target.value)}
            placeholder={t('feedback_placeholder')}
            rows={4}
            style={{ width: '100%', padding: 8, borderRadius: 4, border: '1px solid #ccc' }}
          />
          <Button variant="primary" type="submit" disabled={enviando || !mensagem}>
            {enviando ? t('sending') : t('send')}
          </Button>
          {sucesso && <span style={{ color: 'green' }}>{t('feedback_sent')}</span>}
        </form>
      </Card>
      <h2 style={{ marginTop: 32 }}>{t('recent_feedbacks')}</h2>
      <section style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        {feedbacks.length === 0 ? (
          <p>{t('no_feedbacks')}</p>
        ) : (
          feedbacks.map(fb => (
            <Card key={fb.id} title={fb.usuario} description={fb.texto} />
          ))
        )}
      </section>
    </main>
  );
}; 