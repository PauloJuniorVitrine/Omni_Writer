import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de Status e Logs do Sistema.
 * Painel de status, listagem mock de logs, filtros, placeholders para SSE/integr. backend.
 */
export const StatusLogs: React.FC = () => {
  const { t } = useI18n();
  const [filtro, setFiltro] = useState('todos');
  const [logs] = useState([
    { id: 1, tipo: 'INFO', mensagem: 'Sistema iniciado', data: '2024-06-01 10:00' },
    { id: 2, tipo: 'WARN', mensagem: 'Token expirado', data: '2024-06-01 10:05' },
    { id: 3, tipo: 'ERROR', mensagem: 'Falha ao exportar', data: '2024-06-01 10:10' },
  ]);

  // Filtro de logs
  const logsFiltrados = filtro === 'todos' ? logs : logs.filter(l => l.tipo === filtro);

  // Placeholder para atualização via SSE
  const handleAtualizar = () => {
    alert(t('logs_update_placeholder'));
  };

  return (
    <main style={{ padding: '2rem', maxWidth: 800 }}>
      <h1>{t('status_logs')}</h1>
      <Card title={t('general_status')}>
        <p>{t('system_operational')} 2024-06-01 10:15</p>
        <Button variant="primary" onClick={handleAtualizar}>{t('update_status_logs')}</Button>
      </Card>
      <Card title={t('recent_logs')} style={{ marginTop: 24 }}>
        <div style={{ marginBottom: 16 }}>
          <label>{t('filter_by_type')}: </label>
          <select value={filtro} onChange={e => setFiltro(e.target.value)}>
            <option value="todos">{t('all')}</option>
            <option value="INFO">INFO</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {logsFiltrados.length === 0 ? (
            <li>{t('no_logs_found')}</li>
          ) : (
            logsFiltrados.map(log => (
              <li key={log.id} style={{ marginBottom: 8 }}>
                <b>[{log.tipo}]</b> {log.mensagem} <span style={{ color: '#888' }}>({log.data})</span>
              </li>
            ))
          )}
        </ul>
      </Card>
    </main>
  );
}; 