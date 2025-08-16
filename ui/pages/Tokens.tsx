import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de Gestão de Tokens.
 * Listagem mock de tokens, botões de rotação/revogação (placeholders), Card/Button.
 */
export const Tokens: React.FC = () => {
  const { t } = useI18n();
  const [tokens, setTokens] = useState([
    { id: 1, valor: 'sk-1234...abcd', criado: '2024-06-01', status: 'ativo' },
    { id: 2, valor: 'sk-5678...efgh', criado: '2024-05-20', status: 'revogado' },
  ]);

  // Placeholder para rotação de token
  const handleRotacionar = (id: number) => {
    alert(t('token_rotate_placeholder', { id }));
  };

  // Placeholder para revogação de token
  const handleRevogar = (id: number) => {
    alert(t('token_revoke_placeholder', { id }));
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 800 }}>
      <h1>{t('token_management')}</h1>
      <section style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        {tokens.length === 0 ? (
          <p>{t('no_tokens')}</p>
        ) : (
          tokens.map(token => (
            <Card key={token.id} title={`${t('token')} #${token.id}`} description={`${t('created_at')}: ${token.criado} | ${t('status')}: ${token.status}`}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ fontFamily: 'monospace', fontSize: 14 }}>{token.valor}</span>
                <Button variant="secondary" onClick={() => handleRotacionar(token.id)} disabled={token.status !== 'ativo'}>
                  {t('rotate')}
                </Button>
                <Button variant="danger" onClick={() => handleRevogar(token.id)} disabled={token.status !== 'ativo'}>
                  {t('revoke')}
                </Button>
              </div>
            </Card>
          ))
        )}
      </section>
    </main>
  );
}; 