import React, { useState } from 'react';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { useI18n } from '../hooks/use_i18n';

/**
 * Página de gerenciamento de Clusters.
 * Exibe lista mock de clusters, permite criar, editar e excluir (placeholders).
 */
export const Clusters: React.FC = () => {
  const { t } = useI18n();
  // Lista mock de clusters
  const [clusters, setClusters] = useState([
    { id: 1, nome: 'Cluster A', descricao: 'Agrupamento de temas A' },
    { id: 2, nome: 'Cluster B', descricao: 'Agrupamento de temas B' },
  ]);

  // Placeholder para criar novo cluster
  const handleNovoCluster = () => {
    alert(t('cluster_create_placeholder'));
  };

  // Placeholder para editar cluster
  const handleEditar = (id: number) => {
    alert(t('cluster_edit_placeholder', { id }));
  };

  // Placeholder para excluir cluster
  const handleExcluir = (id: number) => {
    alert(t('cluster_delete_placeholder', { id }));
  };

  return (
    <main style={{ padding: '2rem' }}>
      <h1>{t('clusters')}</h1>
      <Button variant="primary" onClick={handleNovoCluster} style={{ marginBottom: 24 }}>
        {t('new_cluster')}
      </Button>
      <section style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        {clusters.length === 0 ? (
          <p>{t('no_clusters')}</p>
        ) : (
          clusters.map((cluster) => (
            <Card key={cluster.id} title={cluster.nome} description={cluster.descricao}>
              <div style={{ display: 'flex', gap: 8 }}>
                <Button variant="secondary" onClick={() => handleEditar(cluster.id)}>
                  {t('edit')}
                </Button>
                <Button variant="danger" onClick={() => handleExcluir(cluster.id)}>
                  {t('delete')}
                </Button>
              </div>
            </Card>
          ))
        )}
      </section>
    </main>
  );
}; 