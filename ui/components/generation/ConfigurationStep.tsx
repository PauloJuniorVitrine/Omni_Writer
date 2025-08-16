/**
 * Componente ConfigurationStep - Geração de Artigos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Formulário de configuração
 * - Validação em tempo real
 * - Seleção de blog e categoria
 * - Configurações avançadas
 */

import React, { useState } from 'react';
import Input from '../base/Input';
import Select from '../base/Select';

interface ArticleConfig {
  title: string;
  blogId: string;
  categoryId: string;
  keywords: string[];
  wordCount: number;
  tone: 'professional' | 'casual' | 'academic' | 'conversational';
  language: 'pt-BR' | 'en-US' | 'es-ES';
  seoOptimized: boolean;
}

interface ConfigurationStepProps {
  config: ArticleConfig;
  blogs: Array<{ id: string; name: string; description: string }>;
  categories: Array<{ id: string; name: string; blogId: string }>;
  onUpdate: (updates: Partial<ArticleConfig>) => void;
}

/**
 * Componente de configuração do artigo
 */
const ConfigurationStep: React.FC<ConfigurationStepProps> = ({
  config,
  blogs,
  categories,
  onUpdate
}) => {
  const [keywordInput, setKeywordInput] = useState('');

  const filteredCategories = categories.filter(cat => 
    !config.blogId || cat.blogId === config.blogId
  );

  const addKeyword = () => {
    if (keywordInput.trim() && !config.keywords.includes(keywordInput.trim())) {
      onUpdate({
        keywords: [...config.keywords, keywordInput.trim()]
      });
      setKeywordInput('');
    }
  };

  const removeKeyword = (keyword: string) => {
    onUpdate({
      keywords: config.keywords.filter(k => k !== keyword)
    });
  };

  const handleBlogChange = (blogId: string) => {
    onUpdate({
      blogId,
      categoryId: '' // Reset categoria quando blog muda
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">
          Configuração do Artigo
        </h2>
        <p className="text-gray-600">
          Configure os parâmetros básicos do artigo que será gerado.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Título */}
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Título do Artigo *
          </label>
          <Input
            type="text"
            value={config.title}
            onChange={(e) => onUpdate({ title: e.target.value })}
            placeholder="Digite o título do artigo..."
            className="w-full"
            required
          />
        </div>

        {/* Blog */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Blog *
          </label>
          <Select
            value={config.blogId}
            onChange={(e) => handleBlogChange(e.target.value)}
            className="w-full"
            required
          >
            <option value="">Selecione um blog</option>
            {blogs.map(blog => (
              <option key={blog.id} value={blog.id}>
                {blog.name}
              </option>
            ))}
          </Select>
        </div>

        {/* Categoria */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Categoria *
          </label>
          <Select
            value={config.categoryId}
            onChange={(e) => onUpdate({ categoryId: e.target.value })}
            className="w-full"
            required
            disabled={!config.blogId}
          >
            <option value="">Selecione uma categoria</option>
            {filteredCategories.map(category => (
              <option key={category.id} value={category.id}>
                {category.name}
              </option>
            ))}
          </Select>
        </div>

        {/* Palavras-chave */}
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Palavras-chave
          </label>
          <div className="flex space-x-2 mb-2">
            <Input
              type="text"
              value={keywordInput}
              onChange={(e) => setKeywordInput(e.target.value)}
              placeholder="Digite uma palavra-chave..."
              className="flex-1"
              onKeyPress={(e) => e.key === 'Enter' && addKeyword()}
            />
            <button
              onClick={addKeyword}
              className="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors"
            >
              Adicionar
            </button>
          </div>
          {config.keywords.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {config.keywords.map(keyword => (
                <span
                  key={keyword}
                  className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-blue-100 text-blue-800"
                >
                  {keyword}
                  <button
                    onClick={() => removeKeyword(keyword)}
                    className="ml-2 text-blue-600 hover:text-blue-800"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Número de palavras */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Número de Palavras
          </label>
          <Select
            value={config.wordCount}
            onChange={(e) => onUpdate({ wordCount: parseInt(e.target.value) })}
            className="w-full"
          >
            <option value={300}>300 palavras</option>
            <option value={500}>500 palavras</option>
            <option value={800}>800 palavras</option>
            <option value={1000}>1000 palavras</option>
            <option value={1500}>1500 palavras</option>
            <option value={2000}>2000 palavras</option>
          </Select>
        </div>

        {/* Tom */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Tom do Artigo
          </label>
          <Select
            value={config.tone}
            onChange={(e) => onUpdate({ tone: e.target.value as any })}
            className="w-full"
          >
            <option value="professional">Profissional</option>
            <option value="casual">Casual</option>
            <option value="academic">Acadêmico</option>
            <option value="conversational">Conversacional</option>
          </Select>
        </div>

        {/* Idioma */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Idioma
          </label>
          <Select
            value={config.language}
            onChange={(e) => onUpdate({ language: e.target.value as any })}
            className="w-full"
          >
            <option value="pt-BR">Português (Brasil)</option>
            <option value="en-US">English (US)</option>
            <option value="es-ES">Español</option>
          </Select>
        </div>

        {/* SEO Otimizado */}
        <div className="md:col-span-2">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={config.seoOptimized}
              onChange={(e) => onUpdate({ seoOptimized: e.target.checked })}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="ml-2 text-sm text-gray-700">
              Otimizar para SEO
            </span>
          </label>
          <p className="text-xs text-gray-500 mt-1">
            Inclui meta tags, estrutura de headings e otimização de palavras-chave
          </p>
        </div>
      </div>

      {/* Resumo da configuração */}
      <div className="bg-gray-50 p-4 rounded-lg">
        <h3 className="text-sm font-medium text-gray-900 mb-2">
          Resumo da Configuração
        </h3>
        <div className="text-sm text-gray-600 space-y-1">
          <p><strong>Título:</strong> {config.title || 'Não definido'}</p>
          <p><strong>Blog:</strong> {blogs.find(b => b.id === config.blogId)?.name || 'Não selecionado'}</p>
          <p><strong>Categoria:</strong> {categories.find(c => c.id === config.categoryId)?.name || 'Não selecionada'}</p>
          <p><strong>Palavras:</strong> {config.wordCount}</p>
          <p><strong>Tom:</strong> {config.tone}</p>
          <p><strong>Idioma:</strong> {config.language}</p>
          <p><strong>SEO:</strong> {config.seoOptimized ? 'Sim' : 'Não'}</p>
        </div>
      </div>
    </div>
  );
};

export default ConfigurationStep; 