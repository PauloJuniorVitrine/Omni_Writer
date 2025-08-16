/**
 * Componente PreviewStep - Geração de Artigos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Preview do artigo
 * - Configurações resumidas
 * - Botão de geração de preview
 * - Visualização em tempo real
 */

import React from 'react';
import Loading from '../base/Loading';

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

interface PromptTemplate {
  id: string;
  name: string;
  description: string;
  content: string;
  category: string;
  tags: string[];
}

interface PreviewStepProps {
  config: ArticleConfig;
  selectedPrompt: PromptTemplate | null;
  preview: string;
  onGeneratePreview: () => void;
  isGenerating: boolean;
  progress: number;
}

/**
 * Componente de preview do artigo
 */
const PreviewStep: React.FC<PreviewStepProps> = ({
  config,
  selectedPrompt,
  preview,
  onGeneratePreview,
  isGenerating,
  progress
}) => {
  const getToneLabel = (tone: string) => {
    switch (tone) {
      case 'professional': return 'Profissional';
      case 'casual': return 'Casual';
      case 'academic': return 'Acadêmico';
      case 'conversational': return 'Conversacional';
      default: return tone;
    }
  };

  const getLanguageLabel = (language: string) => {
    switch (language) {
      case 'pt-BR': return 'Português (Brasil)';
      case 'en-US': return 'English (US)';
      case 'es-ES': return 'Español';
      default: return language;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">
          Preview do Artigo
        </h2>
        <p className="text-gray-600">
          Visualize como o artigo será gerado com base nas configurações selecionadas.
        </p>
      </div>

      {/* Configurações resumidas */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-3">Configurações Selecionadas</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <p><strong>Título:</strong> {config.title || 'Não definido'}</p>
            <p><strong>Palavras:</strong> {config.wordCount}</p>
            <p><strong>Tom:</strong> {getToneLabel(config.tone)}</p>
            <p><strong>Idioma:</strong> {getLanguageLabel(config.language)}</p>
          </div>
          <div>
            <p><strong>SEO Otimizado:</strong> {config.seoOptimized ? 'Sim' : 'Não'}</p>
            <p><strong>Palavras-chave:</strong> {config.keywords.length}</p>
            <p><strong>Prompt:</strong> {selectedPrompt?.name || 'Não selecionado'}</p>
            <p><strong>Categoria:</strong> {selectedPrompt?.category || 'N/A'}</p>
          </div>
        </div>
      </div>

      {/* Botão de geração de preview */}
      <div className="text-center">
        <button
          onClick={onGeneratePreview}
          disabled={!selectedPrompt || isGenerating}
          className="px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
        >
          {isGenerating ? (
            <div className="flex items-center space-x-2">
              <Loading size="small" />
              <span>Gerando Preview... {progress}%</span>
            </div>
          ) : (
            'Gerar Preview'
          )}
        </button>
      </div>

      {/* Preview do artigo */}
      {preview && (
        <div className="border rounded-lg overflow-hidden">
          <div className="bg-gray-100 px-4 py-2 border-b">
            <h3 className="font-medium text-gray-900">Preview do Artigo</h3>
          </div>
          <div className="p-6">
            <div className="prose max-w-none">
              <div 
                className="text-gray-700 leading-relaxed"
                dangerouslySetInnerHTML={{
                  __html: preview
                    .replace(/\n/g, '<br>')
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/\*(.*?)\*/g, '<em>$1</em>')
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Informações adicionais */}
      {selectedPrompt && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="font-medium text-blue-900 mb-2">
            Prompt que será usado
          </h3>
          <div className="bg-white rounded border p-3 mb-3">
            <pre className="text-sm text-gray-700 whitespace-pre-wrap font-mono">
              {selectedPrompt.content}
            </pre>
          </div>
          <div className="flex flex-wrap gap-2">
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

      {/* Dicas */}
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
        <h3 className="font-medium text-yellow-900 mb-2">
          💡 Dicas
        </h3>
        <ul className="text-sm text-yellow-800 space-y-1">
          <li>• O preview mostra uma versão simplificada do artigo final</li>
          <li>• O artigo gerado terá mais detalhes e estrutura completa</li>
          <li>• Você pode voltar e ajustar as configurações se necessário</li>
          <li>• O processo de geração pode levar alguns minutos</li>
        </ul>
      </div>
    </div>
  );
};

export default PreviewStep; 