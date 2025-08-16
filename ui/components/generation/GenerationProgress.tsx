/**
 * Componente GenerationProgress - Geração de Artigos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Progresso visual da geração
 * - Animações e feedback
 * - Tratamento de erros
 * - Botão de início
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

interface GenerationProgressProps {
  config: ArticleConfig;
  selectedPrompt: PromptTemplate | null;
  isGenerating: boolean;
  progress: number;
  error: string | null;
  onStart: () => void;
}

/**
 * Componente de progresso de geração
 */
const GenerationProgress: React.FC<GenerationProgressProps> = ({
  config,
  selectedPrompt,
  isGenerating,
  progress,
  error,
  onStart
}) => {
  const getProgressMessage = (progress: number) => {
    if (progress < 20) return 'Inicializando geração...';
    if (progress < 40) return 'Processando configurações...';
    if (progress < 60) return 'Gerando conteúdo...';
    if (progress < 80) return 'Otimizando SEO...';
    if (progress < 100) return 'Finalizando artigo...';
    return 'Artigo gerado com sucesso!';
  };

  const getProgressColor = (progress: number) => {
    if (progress < 30) return 'bg-blue-500';
    if (progress < 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">
          Geração do Artigo
        </h2>
        <p className="text-gray-600">
          {isGenerating 
            ? 'Aguarde enquanto o artigo está sendo gerado...'
            : 'Clique no botão abaixo para iniciar a geração do artigo.'
          }
        </p>
      </div>

      {/* Resumo final */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="font-medium text-gray-900 mb-3">Configuração Final</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div>
            <p><strong>Título:</strong> {config.title}</p>
            <p><strong>Palavras:</strong> {config.wordCount}</p>
            <p><strong>Tom:</strong> {config.tone}</p>
            <p><strong>Idioma:</strong> {config.language}</p>
          </div>
          <div>
            <p><strong>SEO:</strong> {config.seoOptimized ? 'Sim' : 'Não'}</p>
            <p><strong>Palavras-chave:</strong> {config.keywords.join(', ') || 'Nenhuma'}</p>
            <p><strong>Prompt:</strong> {selectedPrompt?.name}</p>
            <p><strong>Categoria:</strong> {selectedPrompt?.category}</p>
          </div>
        </div>
      </div>

      {/* Progresso */}
      {isGenerating && (
        <div className="space-y-4">
          <div className="bg-white border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-medium text-gray-900">Progresso da Geração</h3>
              <span className="text-sm font-medium text-gray-500">{progress}%</span>
            </div>
            
            {/* Barra de progresso */}
            <div className="w-full bg-gray-200 rounded-full h-3 mb-4">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${getProgressColor(progress)}`}
                style={{ width: `${progress}%` }}
              />
            </div>
            
            {/* Mensagem de progresso */}
            <div className="flex items-center space-x-3">
              <Loading size="small" />
              <span className="text-sm text-gray-600">
                {getProgressMessage(progress)}
              </span>
            </div>
          </div>

          {/* Etapas do processo */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`text-center p-4 rounded-lg ${
              progress >= 20 ? 'bg-green-50 border border-green-200' : 'bg-gray-50 border border-gray-200'
            }`}>
              <div className={`w-8 h-8 rounded-full mx-auto mb-2 flex items-center justify-center ${
                progress >= 20 ? 'bg-green-500 text-white' : 'bg-gray-300 text-gray-500'
              }`}>
                {progress >= 20 ? '✓' : '1'}
              </div>
              <p className="text-sm font-medium">Inicialização</p>
            </div>
            
            <div className={`text-center p-4 rounded-lg ${
              progress >= 60 ? 'bg-green-50 border border-green-200' : 'bg-gray-50 border border-gray-200'
            }`}>
              <div className={`w-8 h-8 rounded-full mx-auto mb-2 flex items-center justify-center ${
                progress >= 60 ? 'bg-green-500 text-white' : 'bg-gray-300 text-gray-500'
              }`}>
                {progress >= 60 ? '✓' : '2'}
              </div>
              <p className="text-sm font-medium">Geração</p>
            </div>
            
            <div className={`text-center p-4 rounded-lg ${
              progress >= 100 ? 'bg-green-50 border border-green-200' : 'bg-gray-50 border border-gray-200'
            }`}>
              <div className={`w-8 h-8 rounded-full mx-auto mb-2 flex items-center justify-center ${
                progress >= 100 ? 'bg-green-500 text-white' : 'bg-gray-300 text-gray-500'
              }`}>
                {progress >= 100 ? '✓' : '3'}
              </div>
              <p className="text-sm font-medium">Finalização</p>
            </div>
          </div>
        </div>
      )}

      {/* Erro */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <span className="text-red-500">❌</span>
            <h3 className="font-medium text-red-900">Erro na Geração</h3>
          </div>
          <p className="text-sm text-red-700">{error}</p>
          <button
            onClick={onStart}
            className="mt-3 px-4 py-2 bg-red-500 text-white rounded-md hover:bg-red-600 transition-colors"
          >
            Tentar Novamente
          </button>
        </div>
      )}

      {/* Sucesso */}
      {progress === 100 && !error && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center space-x-2 mb-2">
            <span className="text-green-500">✅</span>
            <h3 className="font-medium text-green-900">Artigo Gerado com Sucesso!</h3>
          </div>
          <p className="text-sm text-green-700">
            O artigo foi gerado e salvo. Você será redirecionado em alguns segundos...
          </p>
        </div>
      )}

      {/* Botão de início */}
      {!isGenerating && !error && progress < 100 && (
        <div className="text-center">
          <button
            onClick={onStart}
            className="px-8 py-4 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-colors text-lg font-medium"
          >
            🚀 Gerar Artigo
          </button>
          <p className="text-sm text-gray-500 mt-2">
            Este processo pode levar alguns minutos
          </p>
        </div>
      )}

      {/* Informações adicionais */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h3 className="font-medium text-blue-900 mb-2">
          ℹ️ Informações
        </h3>
        <ul className="text-sm text-blue-800 space-y-1">
          <li>• O artigo será salvo automaticamente no blog selecionado</li>
          <li>• Você receberá uma notificação quando a geração for concluída</li>
          <li>• O artigo pode ser editado posteriormente na seção de blogs</li>
          <li>• Em caso de erro, você pode tentar novamente</li>
        </ul>
      </div>
    </div>
  );
};

export default GenerationProgress; 