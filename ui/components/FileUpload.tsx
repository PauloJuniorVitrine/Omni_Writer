/**
 * Upload de Arquivos - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Drag & drop
 * - Progress bar
 * - Validação de tipos
 * - Preview de imagens
 * - Múltiplos arquivos
 * - Validação de tamanho
 * - Feedback visual
 */

import React, { useState, useRef, useCallback, useMemo } from 'react';
import { Button } from './base/Button';
import { Card } from './base/Card';

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void;
  onUploadProgress?: (progress: number) => void;
  onUploadComplete?: (results: UploadResult[]) => void;
  onUploadError?: (error: string) => void;
  accept?: string;
  multiple?: boolean;
  maxSize?: number; // em bytes
  maxFiles?: number;
  showPreview?: boolean;
  className?: string;
  disabled?: boolean;
  placeholder?: string;
}

interface UploadResult {
  file: File;
  success: boolean;
  error?: string;
  url?: string;
}

interface FileValidation {
  isValid: boolean;
  error?: string;
}

const DEFAULT_MAX_SIZE = 10 * 1024 * 1024; // 10MB
const DEFAULT_MAX_FILES = 10;

const IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
const TEXT_TYPES = ['text/plain', 'text/csv', 'text/markdown', 'text/md'];

export const FileUpload: React.FC<FileUploadProps> = ({
  onFilesSelected,
  onUploadProgress,
  onUploadComplete,
  onUploadError,
  accept = '*',
  multiple = false,
  maxSize = DEFAULT_MAX_SIZE,
  maxFiles = DEFAULT_MAX_FILES,
  showPreview = true,
  className = '',
  disabled = false,
  placeholder = 'Arraste arquivos aqui ou clique para selecionar',
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [previews, setPreviews] = useState<Map<string, string>>(new Map());
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Validar arquivo individual
  const validateFile = useCallback((file: File): FileValidation => {
    // Validar tamanho
    if (file.size > maxSize) {
      return {
        isValid: false,
        error: `Arquivo muito grande. Máximo: ${formatFileSize(maxSize)}`
      };
    }

    // Validar tipo se accept não for '*'
    if (accept !== '*') {
      const acceptedTypes = accept.split(',').map(type => type.trim());
      const fileType = file.type;
      const fileExtension = `.${file.name.split('.').pop()?.toLowerCase()}`;
      
      const isTypeAccepted = acceptedTypes.some(type => {
        if (type.startsWith('.')) {
          return fileExtension === type;
        }
        return fileType === type || type === '*/*';
      });

      if (!isTypeAccepted) {
        return {
          isValid: false,
          error: `Tipo de arquivo não suportado. Aceitos: ${accept}`
        };
      }
    }

    return { isValid: true };
  }, [accept, maxSize]);

  // Validar múltiplos arquivos
  const validateFiles = useCallback((files: File[]): { valid: File[], invalid: { file: File, error: string }[] } => {
    const valid: File[] = [];
    const invalid: { file: File, error: string }[] = [];

    // Verificar limite de arquivos
    if (files.length > maxFiles) {
      const excessFiles = files.slice(maxFiles);
      excessFiles.forEach(file => {
        invalid.push({
          file,
          error: `Limite de ${maxFiles} arquivos excedido`
        });
      });
      files = files.slice(0, maxFiles);
    }

    // Validar cada arquivo
    files.forEach(file => {
      const validation = validateFile(file);
      if (validation.isValid) {
        valid.push(file);
      } else {
        invalid.push({
          file,
          error: validation.error!
        });
      }
    });

    return { valid, invalid };
  }, [validateFile, maxFiles]);

  // Gerar preview para imagens
  const generatePreview = useCallback((file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      if (!IMAGE_TYPES.includes(file.type)) {
        reject(new Error('Não é uma imagem'));
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        resolve(e.target?.result as string);
      };
      reader.onerror = () => {
        reject(new Error('Erro ao ler arquivo'));
      };
      reader.readAsDataURL(file);
    });
  }, []);

  // Processar arquivos selecionados
  const processFiles = useCallback(async (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    const { valid, invalid } = validateFiles(fileArray);

    // Mostrar erros de validação
    if (invalid.length > 0) {
      const errorMessage = invalid.map(item => 
        `${item.file.name}: ${item.error}`
      ).join('\n');
      onUploadError?.(errorMessage);
    }

    if (valid.length === 0) return;

    // Gerar previews para imagens
    if (showPreview) {
      const newPreviews = new Map(previews);
      for (const file of valid) {
        try {
          const preview = await generatePreview(file);
          newPreviews.set(file.name, preview);
        } catch (error) {
          // Não é uma imagem, não precisa de preview
        }
      }
      setPreviews(newPreviews);
    }

    setSelectedFiles(valid);
    onFilesSelected(valid);
  }, [validateFiles, showPreview, generatePreview, previews, onFilesSelected, onUploadError]);

  // Handlers de drag & drop
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setIsDragOver(true);
    }
  }, [disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (disabled) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      processFiles(files);
    }
  }, [disabled, processFiles]);

  // Handler de input file
  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      processFiles(files);
    }
    // Reset input para permitir selecionar o mesmo arquivo novamente
    e.target.value = '';
  }, [processFiles]);

  // Simular upload com progress
  const simulateUpload = useCallback(async (files: File[]) => {
    setIsUploading(true);
    setUploadProgress(0);

    const results: UploadResult[] = [];
    const totalFiles = files.length;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      
      // Simular progresso
      const fileProgress = (i / totalFiles) * 100;
      setUploadProgress(fileProgress);
      onUploadProgress?.(fileProgress);

      // Simular upload (substitua por upload real)
      await new Promise(resolve => setTimeout(resolve, 500));

      // Simular resultado
      results.push({
        file,
        success: Math.random() > 0.1, // 90% de sucesso
        url: Math.random() > 0.1 ? `https://example.com/uploads/${file.name}` : undefined,
        error: Math.random() > 0.1 ? undefined : 'Erro simulado'
      });
    }

    setUploadProgress(100);
    onUploadProgress?.(100);
    setIsUploading(false);

    onUploadComplete?.(results);
  }, [onUploadProgress, onUploadComplete]);

  // Limpar arquivos selecionados
  const clearFiles = useCallback(() => {
    setSelectedFiles([]);
    setPreviews(new Map());
    setUploadProgress(0);
  }, []);

  // Formatar tamanho de arquivo
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Verificar se arquivo é imagem
  const isImage = useCallback((file: File): boolean => {
    return IMAGE_TYPES.includes(file.type);
  }, []);

  // Verificar se arquivo é texto
  const isText = useCallback((file: File): boolean => {
    return TEXT_TYPES.includes(file.type);
  }, []);

  // Classes CSS dinâmicas
  const dropzoneClasses = useMemo(() => {
    const baseClasses = [
      'file-upload-dropzone',
      'border-2 border-dashed rounded-lg p-8 text-center transition-all duration-200',
      'hover:border-blue-400 hover:bg-blue-50',
      disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
    ];

    if (isDragOver) {
      baseClasses.push('border-blue-500 bg-blue-100');
    } else {
      baseClasses.push('border-gray-300 bg-gray-50');
    }

    return baseClasses.join(' ');
  }, [isDragOver, disabled]);

  return (
    <div className={`file-upload-container ${className}`}>
      {/* Dropzone */}
      <div
        className={dropzoneClasses}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <div className="flex flex-col items-center space-y-4">
          {/* Ícone */}
          <div className="text-4xl text-gray-400">
            {isDragOver ? '📁' : '📤'}
          </div>

          {/* Texto */}
          <div className="text-center">
            <p className="text-lg font-medium text-gray-700">
              {isDragOver ? 'Solte os arquivos aqui' : placeholder}
            </p>
            <p className="text-sm text-gray-500 mt-2">
              {accept !== '*' ? `Tipos aceitos: ${accept}` : 'Todos os tipos de arquivo'}
              {multiple && ` • Máximo: ${maxFiles} arquivos`}
              {` • Tamanho máximo: ${formatFileSize(maxSize)}`}
            </p>
          </div>

          {/* Botão de seleção */}
          <Button
            variant="secondary"
            size="sm"
            onClick={(e) => {
              e.stopPropagation();
              fileInputRef.current?.click();
            }}
            disabled={disabled}
          >
            Selecionar Arquivos
          </Button>

          {/* Input file oculto */}
          <input
            ref={fileInputRef}
            type="file"
            accept={accept}
            multiple={multiple}
            onChange={handleFileInput}
            className="hidden"
            disabled={disabled}
          />
        </div>
      </div>

      {/* Progress bar */}
      {isUploading && (
        <div className="mt-4">
          <div className="flex justify-between text-sm text-gray-600 mb-2">
            <span>Enviando arquivos...</span>
            <span>{Math.round(uploadProgress)}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
              style={{ width: `${uploadProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Lista de arquivos selecionados */}
      {selectedFiles.length > 0 && (
        <div className="mt-4 space-y-3">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-medium text-gray-900">
              Arquivos Selecionados ({selectedFiles.length})
            </h3>
            <div className="flex space-x-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={simulateUpload}
                disabled={isUploading}
              >
                {isUploading ? 'Enviando...' : 'Enviar Arquivos'}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={clearFiles}
                disabled={isUploading}
              >
                Limpar
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {selectedFiles.map((file) => (
              <Card key={file.name} className="p-4">
                <div className="flex items-start space-x-3">
                  {/* Preview ou ícone */}
                  <div className="flex-shrink-0">
                    {showPreview && isImage(file) && previews.has(file.name) ? (
                      <img
                        src={previews.get(file.name)}
                        alt={file.name}
                        className="w-16 h-16 object-cover rounded-lg"
                      />
                    ) : (
                      <div className="w-16 h-16 bg-gray-100 rounded-lg flex items-center justify-center">
                        <span className="text-2xl">
                          {isImage(file) ? '🖼️' : isText(file) ? '📄' : '📁'}
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Informações do arquivo */}
                  <div className="flex-1 min-w-0">
                    <h4 className="text-sm font-medium text-gray-900 truncate">
                      {file.name}
                    </h4>
                    <p className="text-xs text-gray-500">
                      {formatFileSize(file.size)}
                    </p>
                    <p className="text-xs text-gray-400">
                      {file.type || 'Tipo desconhecido'}
                    </p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default FileUpload; 