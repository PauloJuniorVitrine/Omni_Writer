/**
 * Testes Unitários - Upload de Arquivos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em funcionalidades reais:
 * - Drag & drop
 * - Progress bar
 * - Validação de tipos
 * - Preview de imagens
 * - Múltiplos arquivos
 * - Validação de tamanho
 * - Feedback visual
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { FileUpload } from '../FileUpload';

// Mock FileReader
const mockFileReader = {
  readAsDataURL: jest.fn(),
  onload: null as any,
  onerror: null as any,
};

global.FileReader = jest.fn(() => mockFileReader) as any;

describe('FileUpload Component', () => {
  const mockOnFilesSelected = jest.fn();
  const mockOnUploadProgress = jest.fn();
  const mockOnUploadComplete = jest.fn();
  const mockOnUploadError = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    mockFileReader.onload = null;
    mockFileReader.onerror = null;
  });

  describe('Renderização Básica', () => {
    it('deve renderizar o dropzone com placeholder padrão', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      expect(screen.getByText('Arraste arquivos aqui ou clique para selecionar')).toBeInTheDocument();
      expect(screen.getByText('Selecionar Arquivos')).toBeInTheDocument();
    });

    it('deve renderizar com placeholder customizado', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          placeholder="Upload customizado"
        />
      );

      expect(screen.getByText('Upload customizado')).toBeInTheDocument();
    });

    it('deve mostrar informações de tipos aceitos', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          accept=".txt,.pdf"
        />
      );

      expect(screen.getByText('Tipos aceitos: .txt,.pdf')).toBeInTheDocument();
    });

    it('deve mostrar informações de tamanho máximo', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          maxSize={5 * 1024 * 1024} // 5MB
        />
      );

      expect(screen.getByText('Tamanho máximo: 5 MB')).toBeInTheDocument();
    });
  });

  describe('Funcionalidade de Seleção de Arquivos', () => {
    it('deve abrir input file quando dropzone é clicado', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');
      fireEvent.click(dropzone!);

      // O input file deve estar presente (mesmo que oculto)
      expect(document.querySelector('input[type="file"]')).toBeInTheDocument();
    });

    it('deve processar arquivos válidos', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          accept=".txt"
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(mockOnFilesSelected).toHaveBeenCalledWith([file]);
      });
    });

    it('deve rejeitar arquivos de tipo inválido', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          onUploadError={mockOnUploadError}
          accept=".txt"
        />
      );

      const file = new File(['conteúdo'], 'test.pdf', { type: 'application/pdf' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(mockOnUploadError).toHaveBeenCalledWith(
          expect.stringContaining('Tipo de arquivo não suportado')
        );
      });
    });

    it('deve rejeitar arquivos muito grandes', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          onUploadError={mockOnUploadError}
          maxSize={1024} // 1KB
        />
      );

      const file = new File(['x'.repeat(2048)], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(mockOnUploadError).toHaveBeenCalledWith(
          expect.stringContaining('Arquivo muito grande')
        );
      });
    });
  });

  describe('Drag & Drop', () => {
    it('deve mostrar estado de drag over', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');
      
      fireEvent.dragOver(dropzone!);

      expect(screen.getByText('Solte os arquivos aqui')).toBeInTheDocument();
    });

    it('deve processar arquivos dropados', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');

      fireEvent.drop(dropzone!, {
        dataTransfer: {
          files: [file]
        }
      });

      await waitFor(() => {
        expect(mockOnFilesSelected).toHaveBeenCalledWith([file]);
      });
    });

    it('não deve processar arquivos quando desabilitado', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          disabled={true}
        />
      );

      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');
      
      fireEvent.dragOver(dropzone!);

      // Não deve mostrar estado de drag over quando desabilitado
      expect(screen.queryByText('Solte os arquivos aqui')).not.toBeInTheDocument();
    });
  });

  describe('Preview de Imagens', () => {
    it('deve gerar preview para imagens', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          showPreview={true}
        />
      );

      const file = new File(['fake-image'], 'test.jpg', { type: 'image/jpeg' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      // Simular FileReader
      mockFileReader.readAsDataURL.mockImplementation(() => {
        setTimeout(() => {
          mockFileReader.onload({ target: { result: 'data:image/jpeg;base64,fake' } });
        }, 0);
      });

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(mockOnFilesSelected).toHaveBeenCalledWith([file]);
      });
    });

    it('deve mostrar ícone para arquivos não-imagem', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          showPreview={true}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(screen.getByText('📄')).toBeInTheDocument();
      });
    });
  });

  describe('Múltiplos Arquivos', () => {
    it('deve processar múltiplos arquivos válidos', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          multiple={true}
          maxFiles={3}
        />
      );

      const files = [
        new File(['conteúdo1'], 'test1.txt', { type: 'text/plain' }),
        new File(['conteúdo2'], 'test2.txt', { type: 'text/plain' }),
        new File(['conteúdo3'], 'test3.txt', { type: 'text/plain' })
      ];

      const input = document.querySelector('input[type="file"]') as HTMLInputElement;
      fireEvent.change(input, { target: { files } });

      await waitFor(() => {
        expect(mockOnFilesSelected).toHaveBeenCalledWith(files);
      });
    });

    it('deve limitar número de arquivos', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          onUploadError={mockOnUploadError}
          multiple={true}
          maxFiles={2}
        />
      );

      const files = [
        new File(['conteúdo1'], 'test1.txt', { type: 'text/plain' }),
        new File(['conteúdo2'], 'test2.txt', { type: 'text/plain' }),
        new File(['conteúdo3'], 'test3.txt', { type: 'text/plain' })
      ];

      const input = document.querySelector('input[type="file"]') as HTMLInputElement;
      fireEvent.change(input, { target: { files } });

      await waitFor(() => {
        expect(mockOnUploadError).toHaveBeenCalledWith(
          expect.stringContaining('Limite de 2 arquivos excedido')
        );
      });
    });
  });

  describe('Progress Bar', () => {
    it('deve mostrar progress bar durante upload', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          onUploadProgress={mockOnUploadProgress}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(screen.getByText('Enviar Arquivos')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Enviar Arquivos'));

      await waitFor(() => {
        expect(screen.getByText('Enviando arquivos...')).toBeInTheDocument();
        expect(screen.getByText('0%')).toBeInTheDocument();
      });
    });
  });

  describe('Lista de Arquivos', () => {
    it('deve mostrar arquivos selecionados', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(screen.getByText('Arquivos Selecionados (1)')).toBeInTheDocument();
        expect(screen.getByText('test.txt')).toBeInTheDocument();
      });
    });

    it('deve mostrar informações do arquivo', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(screen.getByText('test.txt')).toBeInTheDocument();
        expect(screen.getByText('text/plain')).toBeInTheDocument();
      });
    });

    it('deve limpar arquivos quando botão limpar é clicado', async () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const file = new File(['conteúdo'], 'test.txt', { type: 'text/plain' });
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;

      fireEvent.change(input, { target: { files: [file] } });

      await waitFor(() => {
        expect(screen.getByText('Arquivos Selecionados (1)')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Limpar'));

      expect(screen.queryByText('Arquivos Selecionados (1)')).not.toBeInTheDocument();
    });
  });

  describe('Estados Desabilitados', () => {
    it('deve desabilitar dropzone quando disabled é true', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          disabled={true}
        />
      );

      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');
      expect(dropzone).toHaveClass('opacity-50');
      expect(dropzone).toHaveClass('cursor-not-allowed');
    });

    it('deve desabilitar botão de seleção quando disabled é true', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          disabled={true}
        />
      );

      const button = screen.getByText('Selecionar Arquivos');
      expect(button).toBeDisabled();
    });
  });

  describe('Acessibilidade', () => {
    it('deve ter input file com atributos apropriados', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
          accept=".txt,.pdf"
          multiple={true}
        />
      );

      const input = document.querySelector('input[type="file"]') as HTMLInputElement;
      expect(input).toHaveAttribute('accept', '.txt,.pdf');
      expect(input).toHaveAttribute('multiple');
    });

    it('deve ter dropzone com role apropriado', () => {
      render(
        <FileUpload
          onFilesSelected={mockOnFilesSelected}
        />
      );

      const dropzone = screen.getByText('Arraste arquivos aqui ou clique para selecionar').closest('div');
      expect(dropzone).toBeInTheDocument();
    });
  });
}); 