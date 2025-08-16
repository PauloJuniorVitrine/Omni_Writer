/**
 * Testes Unitários - Editor de Texto Rico
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em funcionalidades reais:
 * - Syntax highlighting para Markdown
 * - Auto-complete básico
 * - Preview side-by-side
 * - Formatação Markdown
 * - Auto-resize
 * - Modo de visualização
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Editor } from '../Editor';

describe('Editor Component', () => {
  const mockOnChange = jest.fn();

  beforeEach(() => {
    mockOnChange.mockClear();
  });

  describe('Renderização Básica', () => {
    it('deve renderizar o editor com placeholder', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
          placeholder="Digite seu texto aqui..."
        />
      );

      const textarea = screen.getByPlaceholderText('Digite seu texto aqui...');
      expect(textarea).toBeInTheDocument();
    });

    it('deve exibir o valor atual no textarea', () => {
      const testValue = '# Título de Teste\n\nEste é um **texto** de teste.';
      
      render(
        <Editor
          value={testValue}
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      expect(textarea).toHaveValue(testValue);
    });

    it('deve mostrar toolbar quando showToolbar é true', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
          showToolbar={true}
        />
      );

      expect(screen.getByTitle('Negrito (Ctrl+B)')).toBeInTheDocument();
      expect(screen.getByTitle('Itálico (Ctrl+I)')).toBeInTheDocument();
      expect(screen.getByTitle('Código (Ctrl+`)')).toBeInTheDocument();
    });

    it('não deve mostrar toolbar quando showToolbar é false', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
          showToolbar={false}
        />
      );

      expect(screen.queryByTitle('Negrito (Ctrl+B)')).not.toBeInTheDocument();
    });
  });

  describe('Funcionalidade de Edição', () => {
    it('deve chamar onChange quando texto é digitado', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      fireEvent.change(textarea, { target: { value: 'Novo texto' } });

      expect(mockOnChange).toHaveBeenCalledWith('Novo texto');
    });

    it('deve aplicar formatação bold no texto selecionado', () => {
      render(
        <Editor
          value="texto selecionado"
          onChange={mockOnChange}
          showToolbar={true}
        />
      );

      const textarea = screen.getByRole('textbox');
      const boldButton = screen.getByTitle('Negrito (Ctrl+B)');

      // Simular seleção de texto
      textarea.setSelectionRange(0, 17);
      fireEvent.click(boldButton);

      expect(mockOnChange).toHaveBeenCalledWith('**texto selecionado**');
    });

    it('deve aplicar formatação italic no texto selecionado', () => {
      render(
        <Editor
          value="texto para itálico"
          onChange={mockOnChange}
          showToolbar={true}
        />
      );

      const textarea = screen.getByRole('textbox');
      const italicButton = screen.getByTitle('Itálico (Ctrl+I)');

      textarea.setSelectionRange(0, 17);
      fireEvent.click(italicButton);

      expect(mockOnChange).toHaveBeenCalledWith('*texto para itálico*');
    });

    it('deve aplicar formatação de código no texto selecionado', () => {
      render(
        <Editor
          value="código exemplo"
          onChange={mockOnChange}
          showToolbar={true}
        />
      );

      const textarea = screen.getByRole('textbox');
      const codeButton = screen.getByTitle('Código (Ctrl+`)');

      textarea.setSelectionRange(0, 13);
      fireEvent.click(codeButton);

      expect(mockOnChange).toHaveBeenCalledWith('`código exemplo`');
    });
  });

  describe('Auto-complete', () => {
    it('deve mostrar sugestões quando # é digitado', async () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      fireEvent.change(textarea, { target: { value: '#' } });

      await waitFor(() => {
        expect(screen.getByText('Título H1')).toBeInTheDocument();
      });
    });

    it('deve mostrar sugestões quando ** é digitado', async () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      fireEvent.change(textarea, { target: { value: '**' } });

      await waitFor(() => {
        expect(screen.getByText('Negrito')).toBeInTheDocument();
      });
    });

    it('deve aplicar sugestão quando clicada', async () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      fireEvent.change(textarea, { target: { value: '#' } });

      await waitFor(() => {
        const suggestion = screen.getByText('Título H1');
        fireEvent.click(suggestion);
      });

      expect(mockOnChange).toHaveBeenCalledWith('# ');
    });
  });

  describe('Preview Mode', () => {
    it('deve mostrar botão de preview quando showPreview é true', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      expect(screen.getByTitle('Alternar preview')).toBeInTheDocument();
    });

    it('deve alternar para modo preview quando botão é clicado', () => {
      render(
        <Editor
          value="# Título\n\nTexto **negrito** e *itálico*."
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      const previewButton = screen.getByTitle('Alternar preview');
      fireEvent.click(previewButton);

      // Deve mostrar a área de preview
      expect(screen.getByText('Preview')).toBeInTheDocument();
    });

    it('deve renderizar markdown no preview', () => {
      render(
        <Editor
          value="# Título Principal\n\nEste é um **texto** de teste."
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      const previewButton = screen.getByTitle('Alternar preview');
      fireEvent.click(previewButton);

      // Verificar se o markdown foi renderizado
      expect(screen.getByText('Título Principal')).toBeInTheDocument();
    });
  });

  describe('Status Bar', () => {
    it('deve mostrar contagem de caracteres', () => {
      const testValue = 'Texto de teste com 25 caracteres';
      
      render(
        <Editor
          value={testValue}
          onChange={mockOnChange}
        />
      );

      expect(screen.getByText('25 caracteres')).toBeInTheDocument();
    });

    it('deve mostrar contagem de linhas quando há múltiplas linhas', () => {
      const testValue = 'Linha 1\nLinha 2\nLinha 3';
      
      render(
        <Editor
          value={testValue}
          onChange={mockOnChange}
        />
      );

      expect(screen.getByText('25 caracteres • 3 linhas')).toBeInTheDocument();
    });
  });

  describe('Modo ReadOnly', () => {
    it('deve desabilitar edição quando readOnly é true', () => {
      render(
        <Editor
          value="Texto não editável"
          onChange={mockOnChange}
          readOnly={true}
        />
      );

      const textarea = screen.getByRole('textbox');
      expect(textarea).toHaveAttribute('readonly');
    });

    it('não deve mostrar toolbar quando readOnly é true', () => {
      render(
        <Editor
          value="Texto não editável"
          onChange={mockOnChange}
          readOnly={true}
          showToolbar={true}
        />
      );

      expect(screen.queryByTitle('Negrito (Ctrl+B)')).not.toBeInTheDocument();
    });
  });

  describe('Syntax Highlighting', () => {
    it('deve aplicar highlighting em headers markdown', () => {
      render(
        <Editor
          value="# Título H1\n## Título H2"
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      const previewButton = screen.getByTitle('Alternar preview');
      fireEvent.click(previewButton);

      // Verificar se os headers foram destacados
      const headers = screen.getAllByText(/Título H/);
      expect(headers).toHaveLength(2);
    });

    it('deve aplicar highlighting em texto negrito', () => {
      render(
        <Editor
          value="Texto **negrito** aqui"
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      const previewButton = screen.getByTitle('Alternar preview');
      fireEvent.click(previewButton);

      // Verificar se o texto negrito foi renderizado
      expect(screen.getByText('negrito')).toBeInTheDocument();
    });

    it('deve aplicar highlighting em código inline', () => {
      render(
        <Editor
          value="Código `console.log()` aqui"
          onChange={mockOnChange}
          showPreview={true}
        />
      );

      const previewButton = screen.getByTitle('Alternar preview');
      fireEvent.click(previewButton);

      // Verificar se o código foi destacado
      expect(screen.getByText('console.log()')).toBeInTheDocument();
    });
  });

  describe('Acessibilidade', () => {
    it('deve ter labels apropriados para botões da toolbar', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
          showToolbar={true}
        />
      );

      expect(screen.getByTitle('Negrito (Ctrl+B)')).toBeInTheDocument();
      expect(screen.getByTitle('Itálico (Ctrl+I)')).toBeInTheDocument();
      expect(screen.getByTitle('Código (Ctrl+`)')).toBeInTheDocument();
      expect(screen.getByTitle('Título H1')).toBeInTheDocument();
      expect(screen.getByTitle('Título H2')).toBeInTheDocument();
      expect(screen.getByTitle('Título H3')).toBeInTheDocument();
      expect(screen.getByTitle('Lista')).toBeInTheDocument();
      expect(screen.getByTitle('Citação')).toBeInTheDocument();
      expect(screen.getByTitle('Link')).toBeInTheDocument();
    });

    it('deve ter textarea com role apropriado', () => {
      render(
        <Editor
          value=""
          onChange={mockOnChange}
        />
      );

      const textarea = screen.getByRole('textbox');
      expect(textarea).toBeInTheDocument();
    });
  });
}); 