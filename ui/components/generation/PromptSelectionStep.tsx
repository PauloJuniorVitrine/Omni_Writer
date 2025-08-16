/**
 * Componente PromptSelectionStep - Geração de Artigos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Seleção de prompts com cards
 * - Filtros por categoria
 * - Preview do prompt
 * - Busca e tags
 */

import React, { useState } from 'react';
import Card from '../base/Card';

interface PromptTemplate {
  id: string;
  name: string;
  description: string;
  content: string;
  category: string;
  tags: string[];
}

interface PromptSelectionStepProps {
  prompts: PromptTemplate[];
  selectedPrompt: PromptTemplate | null;
  onSelect: (prompt: PromptTemplate) => void;
}

/**
 * Componente de seleção de prompts
 */
const PromptSelectionStep: React.FC<PromptSelectionStepProps> = ({
  prompts,
  selectedPrompt,
  onSelect
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');

  // Categorias únicas
  const categories = ['all', ...Array.from(new Set(prompts.map(p => p.category)))];

  // Filtra prompts
  const filteredPrompts = prompts.filter(prompt => {
    const matchesSearch = prompt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         prompt.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         prompt.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesCategory = selectedCategory === 'all' || prompt.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'informativo':
        return 'bg-blue-100 text-blue-800';
      case 'lista':
        return 'bg-green-100 text-green-800';
      case 'review':
        return 'bg-purple-100 text-purple-800';
      case 'tutorial':
        return 'bg-orange-100 text-orange-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">
          Seleção de Prompt
        </h2>
        <p className="text-gray-600">
          Escolha o template de prompt que será usado para gerar o artigo.
        </p>
      </div>

      {/* Filtros */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1">
          <input
            type="text"
            placeholder="Buscar prompts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        <div className="sm:w-48">
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {categories.map(category => (
              <option key={category} value={category}>
                {category === 'all' ? 'Todas as categorias' : category.charAt(0).toUpperCase() + category.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Grid de prompts */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredPrompts.map(prompt => (
          <Card
            key={prompt.id}
            className={`cursor-pointer transition-all duration-200 hover:shadow-lg ${
              selectedPrompt?.id === prompt.id
                ? 'ring-2 ring-blue-500 bg-blue-50'
                : 'hover:bg-gray-50'
            }`}
            onClick={() => onSelect(prompt)}
          >
            <div className="p-4">
              <div className="flex items-start justify-between mb-3">
                <h3 className="font-semibold text-gray-900">{prompt.name}</h3>
                {selectedPrompt?.id === prompt.id && (
                  <span className="text-blue-500">✓</span>
                )}
              </div>
              
              <p className="text-sm text-gray-600 mb-3">
                {prompt.description}
              </p>
              
              <div className="flex items-center justify-between">
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(prompt.category)}`}>
                  {prompt.category}
                </span>
                
                <div className="flex flex-wrap gap-1">
                  {prompt.tags.slice(0, 2).map(tag => (
                    <span
                      key={tag}
                      className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-600"
                    >
                      {tag}
                    </span>
                  ))}
                  {prompt.tags.length > 2 && (
                    <span className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-600">
                      +{prompt.tags.length - 2}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Prompt selecionado */}
      {selectedPrompt && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="font-semibold text-blue-900 mb-2">
            Prompt Selecionado: {selectedPrompt.name}
          </h3>
          <div className="bg-white rounded border p-3">
            <pre className="text-sm text-gray-700 whitespace-pre-wrap font-mono">
              {selectedPrompt.content}
            </pre>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {selectedPrompt.tags.map(tag => (
              <span
                key={tag}
                className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-100 text-blue-800"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Estatísticas */}
      <div className="text-sm text-gray-500 text-center">
        {filteredPrompts.length} de {prompts.length} prompts encontrados
      </div>
    </div>
  );
};

export default PromptSelectionStep; 