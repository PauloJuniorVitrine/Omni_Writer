/**
 * Hook para validação de runtime no frontend
 * Tracing ID: FRONTEND_VALIDATION_20250127_001
 * 
 * Implementa validação similar ao runtime_validator.py do backend
 * usando Zod para garantir consistência entre frontend e backend.
 */

import { useState, useCallback, useMemo } from 'react';
import { z } from 'zod';
import { 
  Blog, 
  BlogCreate, 
  BlogUpdate, 
  GenerationRequest, 
  AuthRequest,
  ValidationError,
  ValidationResponse 
} from '../../shared/types/api_types';

// ============================================================================
// SCHEMAS ZOD
// ============================================================================

// Schema para Blog
const BlogSchema = z.object({
  id: z.string().optional(),
  title: z.string().min(1, "Título é obrigatório").max(200, "Título muito longo"),
  content: z.string().min(1, "Conteúdo é obrigatório"),
  author_id: z.string().optional(),
  status: z.enum(['draft', 'published', 'archived']).optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.object({
    seo_title: z.string().optional(),
    seo_description: z.string().optional(),
    featured_image: z.string().optional(),
    reading_time: z.number().optional(),
    word_count: z.number().optional()
  }).optional(),
  created_at: z.string().optional(),
  updated_at: z.string().optional()
});

// Schema para BlogCreate
const BlogCreateSchema = z.object({
  title: z.string().min(1, "Título é obrigatório").max(200, "Título muito longo"),
  content: z.string().min(1, "Conteúdo é obrigatório"),
  author_id: z.string().optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.object({
    seo_title: z.string().optional(),
    seo_description: z.string().optional(),
    featured_image: z.string().optional(),
    reading_time: z.number().optional(),
    word_count: z.number().optional()
  }).optional()
});

// Schema para BlogUpdate
const BlogUpdateSchema = z.object({
  title: z.string().min(1, "Título é obrigatório").max(200, "Título muito longo").optional(),
  content: z.string().min(1, "Conteúdo é obrigatório").optional(),
  status: z.enum(['draft', 'published', 'archived']).optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.object({
    seo_title: z.string().optional(),
    seo_description: z.string().optional(),
    featured_image: z.string().optional(),
    reading_time: z.number().optional(),
    word_count: z.number().optional()
  }).optional()
});

// Schema para GenerationRequest
const GenerationRequestSchema = z.object({
  prompt: z.string().min(1, "Prompt é obrigatório"),
  max_tokens: z.number().min(1).max(4000).optional(),
  temperature: z.number().min(0.0).max(2.0).optional(),
  top_p: z.number().min(0.0).max(1.0).optional(),
  frequency_penalty: z.number().min(-2.0).max(2.0).optional(),
  presence_penalty: z.number().min(-2.0).max(2.0).optional(),
  stop_sequences: z.array(z.string()).optional(),
  model: z.string().optional(),
  stream: z.boolean().optional()
});

// Schema para AuthRequest
const AuthRequestSchema = z.object({
  email: z.string().email("Email inválido"),
  password: z.string().min(6, "Senha deve ter pelo menos 6 caracteres")
});

// ============================================================================
// TIPOS DE VALIDAÇÃO
// ============================================================================

export type ValidationSchema = 
  | typeof BlogSchema
  | typeof BlogCreateSchema
  | typeof BlogUpdateSchema
  | typeof GenerationRequestSchema
  | typeof AuthRequestSchema;

export type ValidationType = 
  | 'blog'
  | 'blog_create'
  | 'blog_update'
  | 'generation_request'
  | 'auth_request';

// ============================================================================
// HOOK PRINCIPAL
// ============================================================================

interface UseValidationReturn<T> {
  validate: (data: T) => ValidationResponse;
  validateField: (field: string, value: any) => ValidationError | null;
  errors: ValidationError[];
  isValid: boolean;
  clearErrors: () => void;
}

export function useValidation<T = any>(type: ValidationType): UseValidationReturn<T> {
  const [errors, setErrors] = useState<ValidationError[]>([]);

  // Mapear tipo para schema
  const schema = useMemo(() => {
    switch (type) {
      case 'blog':
        return BlogSchema;
      case 'blog_create':
        return BlogCreateSchema;
      case 'blog_update':
        return BlogUpdateSchema;
      case 'generation_request':
        return GenerationRequestSchema;
      case 'auth_request':
        return AuthRequestSchema;
      default:
        throw new Error(`Tipo de validação não suportado: ${type}`);
    }
  }, [type]);

  // Validar dados completos
  const validate = useCallback((data: T): ValidationResponse => {
    try {
      const validatedData = schema.parse(data);
      setErrors([]);
      return {
        valid: true,
        errors: [],
        data: validatedData
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        const validationErrors: ValidationError[] = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code,
          value: err.received
        }));
        
        setErrors(validationErrors);
        return {
          valid: false,
          errors: validationErrors
        };
      }
      
      const genericError: ValidationError = {
        field: 'root',
        message: 'Erro de validação desconhecido',
        code: 'unknown_error',
        value: data
      };
      
      setErrors([genericError]);
      return {
        valid: false,
        errors: [genericError]
      };
    }
  }, [schema]);

  // Validar campo específico
  const validateField = useCallback((field: string, value: any): ValidationError | null => {
    try {
      // Criar objeto com apenas o campo específico
      const fieldData = { [field]: value };
      const fieldSchema = z.object({ [field]: schema.shape[field as keyof typeof schema.shape] });
      
      fieldSchema.parse(fieldData);
      return null;
    } catch (error) {
      if (error instanceof z.ZodError) {
        const fieldError = error.errors.find(err => err.path[0] === field);
        if (fieldError) {
          return {
            field: fieldError.path.join('.'),
            message: fieldError.message,
            code: fieldError.code,
            value: fieldError.received
          };
        }
      }
      return null;
    }
  }, [schema]);

  // Limpar erros
  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  return {
    validate,
    validateField,
    errors,
    isValid: errors.length === 0,
    clearErrors
  };
}

// ============================================================================
// HOOKS ESPECIALIZADOS
// ============================================================================

export function useBlogValidation() {
  return useValidation<Blog>('blog');
}

export function useBlogCreateValidation() {
  return useValidation<BlogCreate>('blog_create');
}

export function useBlogUpdateValidation() {
  return useValidation<BlogUpdate>('blog_update');
}

export function useGenerationRequestValidation() {
  return useValidation<GenerationRequest>('generation_request');
}

export function useAuthValidation() {
  return useValidation<AuthRequest>('auth_request');
}

// ============================================================================
// HOOK PARA VALIDAÇÃO EM TEMPO REAL
// ============================================================================

interface UseRealTimeValidationReturn<T> {
  data: T;
  errors: ValidationError[];
  isValid: boolean;
  updateField: (field: keyof T, value: any) => void;
  validateAll: () => ValidationResponse;
  clearErrors: () => void;
}

export function useRealTimeValidation<T extends Record<string, any>>(
  type: ValidationType,
  initialData: T
): UseRealTimeValidationReturn<T> {
  const [data, setData] = useState<T>(initialData);
  const { validate, validateField, errors, clearErrors } = useValidation<T>(type);

  // Atualizar campo específico
  const updateField = useCallback((field: keyof T, value: any) => {
    setData(prev => ({ ...prev, [field]: value }));
    
    // Validar campo em tempo real
    const fieldError = validateField(field as string, value);
    // Note: A validação em tempo real seria implementada aqui
    // Por simplicidade, apenas atualizamos o campo
  }, [validateField]);

  // Validar todos os dados
  const validateAll = useCallback(() => {
    return validate(data);
  }, [validate, data]);

  return {
    data,
    errors,
    isValid: errors.length === 0,
    updateField,
    validateAll,
    clearErrors
  };
}

// ============================================================================
// UTILITÁRIOS
// ============================================================================

export function formatValidationErrors(errors: ValidationError[]): string {
  if (errors.length === 0) return '';
  
  return errors
    .map(error => `${error.field}: ${error.message}`)
    .join('; ');
}

export function hasFieldError(errors: ValidationError[], field: string): boolean {
  return errors.some(error => error.field === field);
}

export function getFieldError(errors: ValidationError[], field: string): ValidationError | undefined {
  return errors.find(error => error.field === field);
}

export function isFormValid(errors: ValidationError[]): boolean {
  return errors.length === 0;
}

// ============================================================================
// DECORATOR PARA COMPONENTES
// ============================================================================

export function withValidation<P extends object>(
  Component: React.ComponentType<P>,
  validationType: ValidationType
) {
  return function ValidatedComponent(props: P) {
    const validation = useValidation(validationType);
    
    return (
      <Component
        {...props}
        validation={validation}
      />
    );
  };
} 