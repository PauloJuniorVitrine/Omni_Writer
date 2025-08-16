/**
 * Editor de Texto Rico - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Syntax highlighting para Markdown
 * - Auto-complete básico
 * - Preview side-by-side
 * - Formatação Markdown
 * - Auto-resize
 * - Modo de visualização
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Button } from './base/Button';
import { Card } from './base/Card';

interface EditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  showPreview?: boolean;
  showToolbar?: boolean;
  height?: string;
  className?: string;
}

interface MarkdownSuggestion {
  trigger: string;
  replacement: string;
  description: string;
}

const MARKDOWN_SUGGESTIONS: MarkdownSuggestion[] = [
  { trigger: '#', replacement: '# ', description: 'Título H1' },
  { trigger: '##', replacement: '## ', description: 'Título H2' },
  { trigger: '###', replacement: '### ', description: 'Título H3' },
  { trigger: '**', replacement: '**texto**', description: 'Negrito' },
  { trigger: '*', replacement: '*texto*', description: 'Itálico' },
  { trigger: '`', replacement: '`código`', description: 'Código inline' },
  { trigger: '```', replacement: '```\n\n```', description: 'Bloco de código' },
  { trigger: '-', replacement: '- ', description: 'Lista não ordenada' },
  { trigger: '1.', replacement: '1. ', description: 'Lista ordenada' },
  { trigger: '>', replacement: '> ', description: 'Citação' },
  { trigger: '[', replacement: '[texto](url)', description: 'Link' },
  { trigger: '![', replacement: '![alt](url)', description: 'Imagem' },
];

export const Editor: React.FC<EditorProps> = ({
  value,
  onChange,
  placeholder = 'Digite seu texto aqui...',
  readOnly = false,
  showPreview = true,
  showToolbar = true,
  height = '400px',
  className = '',
}) => {
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggestions, setSuggestions] = useState<MarkdownSuggestion[]>([]);
  const [suggestionIndex, setSuggestionIndex] = useState(0);
  const [cursorPosition, setCursorPosition] = useState(0);
  const [isPreviewMode, setIsPreviewMode] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  // Auto-resize do textarea
  const adjustTextareaHeight = useCallback(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, []);

  useEffect(() => {
    adjustTextareaHeight();
  }, [value, adjustTextareaHeight]);

  // Syntax highlighting básico para markdown
  const highlightMarkdown = (text: string): string => {
    return text
      // Headers
      .replace(/^(#{1,6})\s+(.+)$/gm, '<span class="text-blue-600 font-bold">$1</span> <span class="text-gray-900">$2</span>')
      // Bold
      .replace(/\*\*(.+?)\*\*/g, '<span class="font-bold text-gray-900">$1</span>')
      // Italic
      .replace(/\*(.+?)\*/g, '<span class="italic text-gray-900">$1</span>')
      // Code inline
      .replace(/`(.+?)`/g, '<span class="bg-gray-100 text-gray-800 px-1 rounded font-mono text-sm">$1</span>')
      // Links
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<span class="text-blue-600 underline">$1</span>')
      // Lists
      .replace(/^(\s*[-*+]\s+)/gm, '<span class="text-gray-500">$1</span>')
      .replace(/^(\s*\d+\.\s+)/gm, '<span class="text-gray-500">$1</span>')
      // Blockquotes
      .replace(/^>\s+(.+)$/gm, '<span class="text-gray-500">></span> <span class="text-gray-700 italic">$1</span>');
  };

  // Auto-complete
  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newValue = e.target.value;
    const cursorPos = e.target.selectionStart;
    const lineStart = newValue.lastIndexOf('\n', cursorPos - 1) + 1;
    const currentLine = newValue.substring(lineStart, cursorPos);
    
    // Verificar sugestões
    const matchingSuggestions = MARKDOWN_SUGGESTIONS.filter(suggestion =>
      currentLine.trim().startsWith(suggestion.trigger)
    );

    if (matchingSuggestions.length > 0) {
      setSuggestions(matchingSuggestions);
      setSuggestionIndex(0);
      setShowSuggestions(true);
    } else {
      setShowSuggestions(false);
    }

    onChange(newValue);
    setCursorPosition(cursorPos);
  };

  // Aplicar sugestão
  const applySuggestion = (suggestion: MarkdownSuggestion) => {
    if (textareaRef.current) {
      const newValue = value;
      const lineStart = newValue.lastIndexOf('\n', cursorPosition - 1) + 1;
      const beforeLine = newValue.substring(0, lineStart);
      const afterLine = newValue.substring(cursorPosition);
      
      const newText = beforeLine + suggestion.replacement + afterLine;
      onChange(newText);
      
      // Posicionar cursor após a aplicação
      setTimeout(() => {
        if (textareaRef.current) {
          const newCursorPos = lineStart + suggestion.replacement.length;
          textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
          textareaRef.current.focus();
        }
      }, 0);
    }
    
    setShowSuggestions(false);
  };

  // Navegação por teclado nas sugestões
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (showSuggestions) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSuggestionIndex(prev => (prev + 1) % suggestions.length);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSuggestionIndex(prev => (prev - 1 + suggestions.length) % suggestions.length);
      } else if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        if (suggestions[suggestionIndex]) {
          applySuggestion(suggestions[suggestionIndex]);
        }
      } else if (e.key === 'Escape') {
        setShowSuggestions(false);
      }
    }
  };

  // Renderizar preview markdown
  const renderPreview = () => {
    if (!value.trim()) {
      return (
        <div className="text-gray-400 italic p-4">
          Nenhum conteúdo para visualizar
        </div>
      );
    }

    const highlightedText = highlightMarkdown(value);
    
    return (
      <div 
        className="prose max-w-none p-4"
        dangerouslySetInnerHTML={{ __html: highlightedText }}
      />
    );
  };

  // Toolbar de formatação
  const formatText = (format: string) => {
    if (textareaRef.current) {
      const start = textareaRef.current.selectionStart;
      const end = textareaRef.current.selectionEnd;
      const selectedText = value.substring(start, end);
      
      let replacement = '';
      switch (format) {
        case 'bold':
          replacement = `**${selectedText}**`;
          break;
        case 'italic':
          replacement = `*${selectedText}*`;
          break;
        case 'code':
          replacement = `\`${selectedText}\``;
          break;
        case 'link':
          replacement = `[${selectedText}](url)`;
          break;
        case 'h1':
          replacement = `# ${selectedText}`;
          break;
        case 'h2':
          replacement = `## ${selectedText}`;
          break;
        case 'h3':
          replacement = `### ${selectedText}`;
          break;
        case 'list':
          replacement = `- ${selectedText}`;
          break;
        case 'quote':
          replacement = `> ${selectedText}`;
          break;
        default:
          return;
      }
      
      const newValue = value.substring(0, start) + replacement + value.substring(end);
      onChange(newValue);
      
      // Posicionar cursor após a formatação
      setTimeout(() => {
        if (textareaRef.current) {
          const newCursorPos = start + replacement.length;
          textareaRef.current.setSelectionRange(newCursorPos, newCursorPos);
          textareaRef.current.focus();
        }
      }, 0);
    }
  };

  return (
    <div className={`editor-container ${className}`}>
      {/* Toolbar */}
      {showToolbar && !readOnly && (
        <div className="bg-gray-50 border-b border-gray-200 p-2 flex flex-wrap gap-1">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('bold')}
            title="Negrito (Ctrl+B)"
          >
            <strong>B</strong>
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('italic')}
            title="Itálico (Ctrl+I)"
          >
            <em>I</em>
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('code')}
            title="Código (Ctrl+`)"
          >
            <code>{'<>'}</code>
          </Button>
          <div className="w-px h-6 bg-gray-300 mx-1" />
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('h1')}
            title="Título H1"
          >
            H1
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('h2')}
            title="Título H2"
          >
            H2
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('h3')}
            title="Título H3"
          >
            H3
          </Button>
          <div className="w-px h-6 bg-gray-300 mx-1" />
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('list')}
            title="Lista"
          >
            •
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('quote')}
            title="Citação"
          >
            "
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => formatText('link')}
            title="Link"
          >
            🔗
          </Button>
          <div className="flex-1" />
          {showPreview && (
            <Button
              variant={isPreviewMode ? "primary" : "secondary"}
              size="sm"
              onClick={() => setIsPreviewMode(!isPreviewMode)}
              title="Alternar preview"
            >
              👁️
            </Button>
          )}
        </div>
      )}

      {/* Editor e Preview */}
      <div className="flex" style={{ height }}>
        {/* Editor */}
        <div className={`relative ${isPreviewMode ? 'w-1/2' : 'w-full'}`}>
          <textarea
            ref={textareaRef}
            value={value}
            onChange={handleInput}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            readOnly={readOnly}
            className="w-full h-full p-4 border-0 resize-none focus:outline-none font-mono text-sm leading-relaxed"
            style={{ 
              fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace',
              lineHeight: '1.6'
            }}
          />
          
          {/* Sugestões de auto-complete */}
          {showSuggestions && suggestions.length > 0 && (
            <div
              ref={suggestionsRef}
              className="absolute bg-white border border-gray-200 rounded-lg shadow-lg max-h-48 overflow-y-auto z-10"
              style={{
                top: `${Math.floor(cursorPosition / 50) * 20 + 60}px`,
                left: '16px',
                minWidth: '200px'
              }}
            >
              {suggestions.map((suggestion, index) => (
                <div
                  key={suggestion.trigger}
                  className={`px-3 py-2 cursor-pointer hover:bg-gray-100 ${
                    index === suggestionIndex ? 'bg-blue-50 text-blue-900' : ''
                  }`}
                  onClick={() => applySuggestion(suggestion)}
                >
                  <div className="font-medium">{suggestion.trigger}</div>
                  <div className="text-sm text-gray-600">{suggestion.description}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Preview */}
        {showPreview && isPreviewMode && (
          <div className="w-1/2 border-l border-gray-200 overflow-y-auto">
            <div className="bg-gray-50 px-3 py-1 text-xs text-gray-500 border-b">
              Preview
            </div>
            {renderPreview()}
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="bg-gray-50 border-t border-gray-200 px-3 py-1 text-xs text-gray-500 flex justify-between">
        <span>
          {value.length} caracteres
          {value.split('\n').length > 1 && ` • ${value.split('\n').length} linhas`}
        </span>
        <span>
          {showPreview && isPreviewMode ? 'Editor + Preview' : 'Editor'}
        </span>
      </div>
    </div>
  );
};

export default Editor; 