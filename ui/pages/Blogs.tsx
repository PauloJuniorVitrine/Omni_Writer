/**
 * Página de Gestão de Blogs - UI-008
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Ruleset: enterprise_control_layer.yaml
 * 
 * Funcionalidades implementadas:
 * - Lista com paginação
 * - CRUD completo
 * - Filtros avançados
 * - Bulk actions
 * - Integração com API real
 * - Validações de limite (15 blogs)
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/base/Card';
import { Button } from '../components/base/Button';
import { Input } from '../components/base/Input';
import { Select } from '../components/base/Select';
import { Modal } from '../components/base/Modal';
import { Toast } from '../components/base/Toast';
import { Loading } from '../components/base/Loading';
import { EmptyState } from '../components/base/EmptyState';
import { useI18n } from '../hooks/use_i18n';
import { useApi } from '../hooks/use_api';

interface Blog {
  id: number;
  nome: string;
  desc?: string;
  created_at?: string;
  updated_at?: string;
  stats?: {
    categorias_count: number;
    prompts_count: number;
    max_categorias: number;
    max_prompts_per_categoria: number;
  };
}

interface BlogFormData {
  nome: string;
  desc: string;
}

export const Blogs: React.FC = () => {
  const { t } = useI18n();
  const { data: blogs, loading, error, request } = useApi<Blog[]>();
  
  // Estados de controle
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [selectedBlog, setSelectedBlog] = useState<Blog | null>(null);
  const [selectedBlogs, setSelectedBlogs] = useState<number[]>([]);
  const [formData, setFormData] = useState<BlogFormData>({ nome: '', desc: '' });
  const [formErrors, setFormErrors] = useState<Partial<BlogFormData>>({});
  
  // Estados de paginação e filtros
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'nome' | 'created_at'>('nome');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  
  // Estados de feedback
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  // Carregar blogs na inicialização
  useEffect(() => {
    loadBlogs();
  }, []);

  // Carregar blogs da API
  const loadBlogs = useCallback(async () => {
    await request('/api/blogs');
  }, [request]);

  // Filtrar e ordenar blogs
  const filteredAndSortedBlogs = React.useMemo(() => {
    if (!blogs) return [];
    
    let filtered = blogs.filter(blog => 
      blog.nome.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (blog.desc && blog.desc.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    filtered.sort((a, b) => {
      const aValue = a[sortBy] || '';
      const bValue = b[sortBy] || '';
      
      if (sortOrder === 'asc') {
        return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      } else {
        return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
      }
    });

    return filtered;
  }, [blogs, searchTerm, sortBy, sortOrder]);

  // Paginação
  const totalPages = Math.ceil(filteredAndSortedBlogs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentBlogs = filteredAndSortedBlogs.slice(startIndex, endIndex);

  // Validação do formulário
  const validateForm = (data: BlogFormData): Partial<BlogFormData> => {
    const errors: Partial<BlogFormData> = {};
    
    if (!data.nome.trim()) {
      errors.nome = 'Nome é obrigatório';
    } else if (data.nome.length > 100) {
      errors.nome = 'Nome deve ter no máximo 100 caracteres';
    }
    
    if (data.desc && data.desc.length > 500) {
      errors.desc = 'Descrição deve ter no máximo 500 caracteres';
    }
    
    return errors;
  };

  // Criar novo blog
  const handleCreateBlog = async () => {
    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    try {
      const response = await request('/api/blogs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (response) {
        setToast({ message: 'Blog criado com sucesso!', type: 'success' });
        setShowCreateModal(false);
        setFormData({ nome: '', desc: '' });
        setFormErrors({});
        loadBlogs();
      }
    } catch (err) {
      setToast({ message: 'Erro ao criar blog', type: 'error' });
    }
  };

  // Editar blog
  const handleEditBlog = async () => {
    if (!selectedBlog) return;

    const errors = validateForm(formData);
    if (Object.keys(errors).length > 0) {
      setFormErrors(errors);
      return;
    }

    try {
      const response = await request(`/api/blogs/${selectedBlog.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (response) {
        setToast({ message: 'Blog atualizado com sucesso!', type: 'success' });
        setShowEditModal(false);
        setSelectedBlog(null);
        setFormData({ nome: '', desc: '' });
        setFormErrors({});
        loadBlogs();
      }
    } catch (err) {
      setToast({ message: 'Erro ao atualizar blog', type: 'error' });
    }
  };

  // Excluir blog
  const handleDeleteBlog = async () => {
    if (!selectedBlog) return;

    try {
      const response = await request(`/api/blogs/${selectedBlog.id}`, {
        method: 'DELETE'
      });

      if (response !== null) {
        setToast({ message: 'Blog excluído com sucesso!', type: 'success' });
        setShowDeleteModal(false);
        setSelectedBlog(null);
        loadBlogs();
      }
    } catch (err) {
      setToast({ message: 'Erro ao excluir blog', type: 'error' });
    }
  };

  // Bulk delete
  const handleBulkDelete = async () => {
    if (selectedBlogs.length === 0) return;

    try {
      const deletePromises = selectedBlogs.map(id => 
        request(`/api/blogs/${id}`, { method: 'DELETE' })
      );
      
      await Promise.all(deletePromises);
      setToast({ message: `${selectedBlogs.length} blogs excluídos com sucesso!`, type: 'success' });
      setSelectedBlogs([]);
      loadBlogs();
    } catch (err) {
      setToast({ message: 'Erro ao excluir blogs', type: 'error' });
    }
  };

  // Seleção de blogs
  const handleSelectBlog = (blogId: number) => {
    setSelectedBlogs(prev => 
      prev.includes(blogId) 
        ? prev.filter(id => id !== blogId)
        : [...prev, blogId]
    );
  };

  const handleSelectAll = () => {
    if (selectedBlogs.length === currentBlogs.length) {
      setSelectedBlogs([]);
    } else {
      setSelectedBlogs(currentBlogs.map(blog => blog.id));
    }
  };

  // Abrir modal de edição
  const openEditModal = (blog: Blog) => {
    setSelectedBlog(blog);
    setFormData({ nome: blog.nome, desc: blog.desc || '' });
    setFormErrors({});
    setShowEditModal(true);
  };

  // Abrir modal de exclusão
  const openDeleteModal = (blog: Blog) => {
    setSelectedBlog(blog);
    setShowDeleteModal(true);
  };

  // Resetar formulário
  const resetForm = () => {
    setFormData({ nome: '', desc: '' });
    setFormErrors({});
  };

  if (loading && !blogs) {
    return <Loading message="Carregando blogs..." />;
  }

  if (error) {
    return (
      <EmptyState
        title="Erro ao carregar blogs"
        description={error}
        action={
          <Button variant="primary" onClick={loadBlogs}>
            Tentar novamente
          </Button>
        }
      />
    );
  }

  return (
    <main style={{ padding: '2rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <div>
          <h1>{t('blogs')}</h1>
          <p style={{ color: '#666', margin: 0 }}>
            {blogs?.length || 0} blogs • Limite: 15 blogs
          </p>
        </div>
        <Button 
          variant="primary" 
          onClick={() => setShowCreateModal(true)}
          disabled={blogs && blogs.length >= 15}
        >
          {t('new_blog')}
        </Button>
      </div>

      {/* Filtros e Controles */}
      <Card style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <Input
            placeholder="Buscar blogs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ flex: 1, minWidth: '200px' }}
          />
          
          <Select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'nome' | 'created_at')}
            style={{ minWidth: '150px' }}
          >
            <option value="nome">Ordenar por Nome</option>
            <option value="created_at">Ordenar por Data</option>
          </Select>
          
          <Button
            variant="secondary"
            onClick={() => setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
          >
            {sortOrder === 'asc' ? '↑' : '↓'}
          </Button>

          {selectedBlogs.length > 0 && (
            <Button variant="danger" onClick={handleBulkDelete}>
              Excluir ({selectedBlogs.length})
            </Button>
          )}
        </div>
      </Card>

      {/* Lista de Blogs */}
      {currentBlogs.length === 0 ? (
        <EmptyState
          title={searchTerm ? "Nenhum blog encontrado" : "Nenhum blog criado"}
          description={searchTerm ? "Tente ajustar os filtros de busca" : "Crie seu primeiro blog para começar"}
          action={
            !searchTerm && (
              <Button variant="primary" onClick={() => setShowCreateModal(true)}>
                {t('new_blog')}
              </Button>
            )
          }
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Header da tabela */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: '40px 1fr 200px 150px 120px', 
            gap: '1rem',
            padding: '1rem',
            backgroundColor: '#f8f9fa',
            borderRadius: '8px',
            fontWeight: 'bold'
          }}>
            <input
              type="checkbox"
              checked={selectedBlogs.length === currentBlogs.length && currentBlogs.length > 0}
              onChange={handleSelectAll}
            />
            <span>Nome</span>
            <span>Descrição</span>
            <span>Estatísticas</span>
            <span>Ações</span>
          </div>

          {/* Itens da lista */}
          {currentBlogs.map((blog) => (
            <Card key={blog.id} style={{ padding: '1rem' }}>
              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: '40px 1fr 200px 150px 120px', 
                gap: '1rem',
                alignItems: 'center'
              }}>
                <input
                  type="checkbox"
                  checked={selectedBlogs.includes(blog.id)}
                  onChange={() => handleSelectBlog(blog.id)}
                />
                
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.1rem' }}>{blog.nome}</h3>
                  <small style={{ color: '#666' }}>
                    Criado em {blog.created_at ? new Date(blog.created_at).toLocaleDateString() : 'N/A'}
                  </small>
                </div>
                
                <div style={{ color: '#666', fontSize: '0.9rem' }}>
                  {blog.desc || 'Sem descrição'}
                </div>
                
                <div style={{ fontSize: '0.8rem', color: '#666' }}>
                  {blog.stats && (
                    <>
                      <div>{blog.stats.categorias_count}/{blog.stats.max_categorias} categorias</div>
                      <div>{blog.stats.prompts_count} prompts</div>
                    </>
                  )}
                </div>
                
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <Button 
                    variant="secondary" 
                    size="small"
                    onClick={() => openEditModal(blog)}
                  >
                    {t('edit')}
                  </Button>
                  <Button 
                    variant="danger" 
                    size="small"
                    onClick={() => openDeleteModal(blog)}
                  >
                    {t('delete')}
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Paginação */}
      {totalPages > 1 && (
        <Card style={{ marginTop: '1.5rem', padding: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem', alignItems: 'center' }}>
            <Button
              variant="secondary"
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
            >
              Anterior
            </Button>
            
            <span>
              Página {currentPage} de {totalPages}
            </span>
            
            <Button
              variant="secondary"
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
            >
              Próxima
            </Button>
          </div>
        </Card>
      )}

      {/* Modal de Criação */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => {
          setShowCreateModal(false);
          resetForm();
        }}
        title="Criar Novo Blog"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Input
            label="Nome do Blog *"
            value={formData.nome}
            onChange={(e) => setFormData(prev => ({ ...prev, nome: e.target.value }))}
            error={formErrors.nome}
            placeholder="Digite o nome do blog"
            maxLength={100}
          />
          
          <Input
            label="Descrição"
            value={formData.desc}
            onChange={(e) => setFormData(prev => ({ ...prev, desc: e.target.value }))}
            error={formErrors.desc}
            placeholder="Digite uma descrição (opcional)"
            maxLength={500}
            multiline
            rows={3}
          />
          
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setShowCreateModal(false);
                resetForm();
              }}
            >
              Cancelar
            </Button>
            <Button variant="primary" onClick={handleCreateBlog}>
              Criar Blog
            </Button>
          </div>
        </div>
      </Modal>

      {/* Modal de Edição */}
      <Modal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false);
          setSelectedBlog(null);
          resetForm();
        }}
        title="Editar Blog"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <Input
            label="Nome do Blog *"
            value={formData.nome}
            onChange={(e) => setFormData(prev => ({ ...prev, nome: e.target.value }))}
            error={formErrors.nome}
            placeholder="Digite o nome do blog"
            maxLength={100}
          />
          
          <Input
            label="Descrição"
            value={formData.desc}
            onChange={(e) => setFormData(prev => ({ ...prev, desc: e.target.value }))}
            error={formErrors.desc}
            placeholder="Digite uma descrição (opcional)"
            maxLength={500}
            multiline
            rows={3}
          />
          
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setShowEditModal(false);
                setSelectedBlog(null);
                resetForm();
              }}
            >
              Cancelar
            </Button>
            <Button variant="primary" onClick={handleEditBlog}>
              Salvar Alterações
            </Button>
          </div>
        </div>
      </Modal>

      {/* Modal de Confirmação de Exclusão */}
      <Modal
        isOpen={showDeleteModal}
        onClose={() => {
          setShowDeleteModal(false);
          setSelectedBlog(null);
        }}
        title="Confirmar Exclusão"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <p>
            Tem certeza que deseja excluir o blog <strong>"{selectedBlog?.nome}"</strong>?
          </p>
          <p style={{ color: '#666', fontSize: '0.9rem' }}>
            Esta ação não pode ser desfeita. Todas as categorias e prompts associados também serão removidos.
          </p>
          
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setShowDeleteModal(false);
                setSelectedBlog(null);
              }}
            >
              Cancelar
            </Button>
            <Button variant="danger" onClick={handleDeleteBlog}>
              Excluir Blog
            </Button>
          </div>
        </div>
      </Modal>

      {/* Toast de Feedback */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
    </main>
  );
}; 