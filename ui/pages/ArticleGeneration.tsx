/**
 * Página de Geração de Artigos - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Wizard com steps progressivos
 * - Formulário de configuração
 * - Seleção de prompts
 * - Preview em tempo real
 * - Progresso de geração
 * - Validação em cada step
 */

import React, { useState, useEffect } from 'react';
import Card from '../components/base/Card';
import Button from '../components/base/Button';
import Input from '../components/base/Input';
import Select from '../components/base/Select';
import Loading from '../components/base/Loading';
import { useNavigation } from '../hooks/useNavigation';

// Componentes específicos da geração
import GenerationWizard from '../components/generation/GenerationWizard';
import ConfigurationStep from '../components/generation/ConfigurationStep';
import PromptSelectionStep from '../components/generation/PromptSelectionStep';
import PreviewStep from '../components/generation/PreviewStep';
import GenerationProgress from '../components/generation/GenerationProgress';

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

interface GenerationState {
  step: number;
  config: ArticleConfig;
  selectedPrompt: PromptTemplate | null;
  preview: string;
  isGenerating: boolean;
  progress: number;
  error: string | null;
}

/**
 * Página principal de geração de artigos
 */
const ArticleGeneration: React.FC = () => {
  const navigation = useNavigation();
  const [state, setState] = useState<GenerationState>({
    step: 1,
    config: {
      title: '',
      blogId: '',
      categoryId: '',
      keywords: [],
      wordCount: 800,
      tone: 'professional',
      language: 'pt-BR',
      seoOptimized: true
    },
    selectedPrompt: null,
    preview: '',
    isGenerating: false,
    progress: 0,
    error: null
  });

  // Dados simulados
  const [blogs, setBlogs] = useState([]);
  const [categories, setCategories] = useState([]);
  const [prompts, setPrompts] = useState<PromptTemplate[]>([]);

  useEffect(() => {
    // Simula carregamento de dados
    setBlogs([
      { id: '1', name: 'Tech Tips', description: 'Dicas de tecnologia' },
      { id: '2', name: 'Saúde e Bem-estar', description: 'Artigos sobre saúde' },
      { id: '3', name: 'Finanças Pessoais', description: 'Dicas financeiras' }
    ]);

    setCategories([
      { id: '1', name: 'Programação', blogId: '1' },
      { id: '2', name: 'Produtividade', blogId: '1' },
      { id: '3', name: 'Fitness', blogId: '2' },
      { id: '4', name: 'Nutrição', blogId: '2' },
      { id: '5', name: 'Investimentos', blogId: '3' }
    ]);

    setPrompts([
      {
        id: '1',
        name: 'Artigo Informativo',
        description: 'Template para artigos informativos com introdução, desenvolvimento e conclusão',
        content: 'Escreva um artigo informativo sobre {tema} com {wordCount} palavras...',
        category: 'informativo',
        tags: ['informativo', 'educativo']
      },
      {
        id: '2',
        name: 'Lista de Dicas',
        description: 'Template para listas de dicas e conselhos práticos',
        content: 'Crie uma lista de {number} dicas sobre {tema}...',
        category: 'lista',
        tags: ['dicas', 'prático']
      },
      {
        id: '3',
        name: 'Review de Produto',
        description: 'Template para reviews detalhados de produtos',
        content: 'Faça uma análise completa do produto {produto}...',
        category: 'review',
        tags: ['review', 'análise']
      }
    ]);
  }, []);

  const updateConfig = (updates: Partial<ArticleConfig>) => {
    setState(prev => ({
      ...prev,
      config: { ...prev.config, ...updates }
    }));
  };

  const nextStep = () => {
    if (state.step < 4) {
      setState(prev => ({ ...prev, step: prev.step + 1 }));
    }
  };

  const prevStep = () => {
    if (state.step > 1) {
      setState(prev => ({ ...prev, step: prev.step - 1 }));
    }
  };

  const selectPrompt = (prompt: PromptTemplate) => {
    setState(prev => ({ ...prev, selectedPrompt: prompt }));
  };

  const generatePreview = async () => {
    if (!state.selectedPrompt) return;

    setState(prev => ({ ...prev, isGenerating: true, progress: 0 }));

    // Simula geração de preview
    for (let i = 0; i <= 100; i += 10) {
      await new Promise(resolve => setTimeout(resolve, 200));
      setState(prev => ({ ...prev, progress: i }));
    }

    // Preview simulado
    const preview = `# ${state.config.title}

Este é um preview do artigo que será gerado com base nas configurações selecionadas.

**Configurações:**
- Blog: ${blogs.find(b => b.id === state.config.blogId)?.name || 'N/A'}
- Categoria: ${categories.find(c => c.id === state.config.categoryId)?.name || 'N/A'}
- Palavras: ${state.config.wordCount}
- Tom: ${state.config.tone}
- Idioma: ${state.config.language}
- SEO: ${state.config.seoOptimized ? 'Sim' : 'Não'}

**Prompt selecionado:** ${state.selectedPrompt.name}

O artigo final será gerado com base nestas configurações e no template de prompt escolhido.`;

    setState(prev => ({
      ...prev,
      preview,
      isGenerating: false,
      progress: 100
    }));
  };

  const startGeneration = async () => {
    setState(prev => ({ ...prev, isGenerating: true, progress: 0, error: null }));

    try {
      // Simula processo de geração
      for (let i = 0; i <= 100; i += 5) {
        await new Promise(resolve => setTimeout(resolve, 300));
        setState(prev => ({ ...prev, progress: i }));
      }

      // Simula sucesso
      setState(prev => ({ ...prev, isGenerating: false, progress: 100 }));
      
      // Redireciona para o artigo gerado
      setTimeout(() => {
        navigation.navigateTo('/blogs');
      }, 2000);

    } catch (error) {
      setState(prev => ({
        ...prev,
        isGenerating: false,
        error: 'Erro na geração do artigo. Tente novamente.'
      }));
    }
  };

  const steps = [
    { id: 1, title: 'Configuração', description: 'Configure o artigo' },
    { id: 2, title: 'Seleção de Prompt', description: 'Escolha o template' },
    { id: 3, title: 'Preview', description: 'Visualize o resultado' },
    { id: 4, title: 'Geração', description: 'Gere o artigo' }
  ];

  const renderStep = () => {
    switch (state.step) {
      case 1:
        return (
          <ConfigurationStep
            config={state.config}
            blogs={blogs}
            categories={categories}
            onUpdate={updateConfig}
          />
        );
      case 2:
        return (
          <PromptSelectionStep
            prompts={prompts}
            selectedPrompt={state.selectedPrompt}
            onSelect={selectPrompt}
          />
        );
      case 3:
        return (
          <PreviewStep
            config={state.config}
            selectedPrompt={state.selectedPrompt}
            preview={state.preview}
            onGeneratePreview={generatePreview}
            isGenerating={state.isGenerating}
            progress={state.progress}
          />
        );
      case 4:
        return (
          <GenerationProgress
            config={state.config}
            selectedPrompt={state.selectedPrompt}
            isGenerating={state.isGenerating}
            progress={state.progress}
            error={state.error}
            onStart={startGeneration}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">
            Geração de Artigos
          </h1>
          <p className="text-gray-600 mt-1">
            Configure e gere artigos automaticamente
          </p>
        </div>
        <div className="mt-4 sm:mt-0">
          <Button 
            variant="secondary"
            onClick={() => navigation.goBack()}
          >
            Voltar
          </Button>
        </div>
      </div>

      {/* Wizard */}
      <GenerationWizard
        steps={steps}
        currentStep={state.step}
        onStepClick={(step) => setState(prev => ({ ...prev, step }))}
      />

      {/* Conteúdo do Step */}
      <Card>
        <div className="p-6">
          {renderStep()}
        </div>
      </Card>

      {/* Navegação */}
      <div className="flex justify-between">
        <Button
          variant="secondary"
          onClick={prevStep}
          disabled={state.step === 1}
        >
          Anterior
        </Button>

        <div className="space-x-3">
          {state.step === 3 && (
            <Button
              variant="secondary"
              onClick={generatePreview}
              disabled={!state.selectedPrompt || state.isGenerating}
            >
              {state.isGenerating ? (
                <>
                  <Loading size="small" />
                  Gerando Preview...
                </>
              ) : (
                'Gerar Preview'
              )}
            </Button>
          )}

          {state.step < 4 ? (
            <Button
              variant="primary"
              onClick={nextStep}
              disabled={
                (state.step === 1 && !state.config.title) ||
                (state.step === 2 && !state.selectedPrompt)
              }
            >
              Próximo
            </Button>
          ) : (
            <Button
              variant="primary"
              onClick={startGeneration}
              disabled={state.isGenerating}
            >
              {state.isGenerating ? (
                <>
                  <Loading size="small" />
                  Gerando...
                </>
              ) : (
                'Gerar Artigo'
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ArticleGeneration; 