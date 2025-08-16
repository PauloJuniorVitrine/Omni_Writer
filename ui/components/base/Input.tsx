/**
 * Componente Input - Omni Writer
 * 
 * Campos de entrada com validação e estados
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useState, forwardRef } from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface InputProps {
  /** Tipo do input */
  type?: 'text' | 'email' | 'password' | 'number' | 'tel' | 'url' | 'search';
  /** Valor do input */
  value?: string;
  /** Valor padrão */
  defaultValue?: string;
  /** Placeholder */
  placeholder?: string;
  /** Label do campo */
  label?: string;
  /** Descrição/ajuda */
  description?: string;
  /** Estado de erro */
  error?: string;
  /** Estado de sucesso */
  success?: boolean;
  /** Estado desabilitado */
  disabled?: boolean;
  /** Estado somente leitura */
  readOnly?: boolean;
  /** Tamanho do input */
  size?: 'sm' | 'md' | 'lg';
  /** Ícone à esquerda */
  leftIcon?: React.ReactNode;
  /** Ícone à direita */
  rightIcon?: React.ReactNode;
  /** Função de mudança */
  onChange?: (value: string) => void;
  /** Função de foco */
  onFocus?: () => void;
  /** Função de blur */
  onBlur?: () => void;
  /** Função de tecla pressionada */
  onKeyDown?: (e: React.KeyboardEvent) => void;
  /** Nome do campo */
  name?: string;
  /** ID do campo */
  id?: string;
  /** Classe CSS adicional */
  className?: string;
  /** Máximo de caracteres */
  maxLength?: number;
  /** Mínimo de caracteres */
  minLength?: number;
  /** Padrão de validação */
  pattern?: string;
  /** Título para acessibilidade */
  title?: string;
  /** Auto-complete */
  autoComplete?: string;
  /** Auto-focus */
  autoFocus?: boolean;
}

// ===== ESTILOS =====
const getInputStyles = (size: string, hasError: boolean, hasSuccess: boolean, disabled: boolean) => {
  const baseStyles = {
    width: '100%',
    border: `1px solid ${hasError ? theme.colors.semantic.border.error : theme.colors.semantic.border.primary}`,
    borderRadius: theme.spacing.spacing[6],
    fontFamily: theme.typography.fonts.family.primary,
    fontSize: theme.typography.fontSizes.base,
    lineHeight: theme.typography.fonts.lineHeight.normal,
    color: theme.colors.semantic.text.primary,
    backgroundColor: disabled ? theme.colors.semantic.state.disabled : theme.colors.semantic.background.primary,
    outline: 'none',
    transition: 'all 0.2s ease-in-out',
    cursor: disabled ? 'not-allowed' : 'text',
  };

  const sizeStyles = {
    sm: {
      padding: `${theme.spacing.spacing[6]} ${theme.spacing.spacing[8]}`,
      fontSize: theme.typography.fontSizes.sm,
      minHeight: '32px',
    },
    md: {
      padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
      fontSize: theme.typography.fontSizes.base,
      minHeight: '40px',
    },
    lg: {
      padding: `${theme.spacing.spacing[10]} ${theme.spacing.spacing[16]}`,
      fontSize: theme.typography.fontSizes.lg,
      minHeight: '48px',
    },
  };

  const stateStyles = {
    focus: {
      borderColor: theme.colors.semantic.border.focus,
      boxShadow: `0 0 0 3px ${theme.colors.semantic.border.focus}20`,
    },
    error: {
      borderColor: theme.colors.semantic.border.error,
      backgroundColor: theme.colors.component.input.error.background,
    },
    success: {
      borderColor: theme.colors.base.success[500],
    },
    disabled: {
      opacity: 0.6,
      cursor: 'not-allowed',
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
    ...(hasError && stateStyles.error),
    ...(hasSuccess && stateStyles.success),
    ...(disabled && stateStyles.disabled),
  };
};

const getLabelStyles = (size: string) => {
  const sizeStyles = {
    sm: {
      fontSize: theme.typography.fontSizes.sm,
      marginBottom: theme.spacing.spacing[2],
    },
    md: {
      fontSize: theme.typography.fontSizes.base,
      marginBottom: theme.spacing.spacing[4],
    },
    lg: {
      fontSize: theme.typography.fontSizes.lg,
      marginBottom: theme.spacing.spacing[6],
    },
  };

  return {
    display: 'block',
    fontWeight: theme.typography.fonts.weight.medium,
    color: theme.colors.semantic.text.primary,
    marginBottom: theme.spacing.spacing[4],
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getDescriptionStyles = (size: string, isError: boolean) => {
  const sizeStyles = {
    sm: {
      fontSize: theme.typography.fontSizes.xs,
      marginTop: theme.spacing.spacing[2],
    },
    md: {
      fontSize: theme.typography.fontSizes.sm,
      marginTop: theme.spacing.spacing[4],
    },
    lg: {
      fontSize: theme.typography.fontSizes.base,
      marginTop: theme.spacing.spacing[6],
    },
  };

  return {
    display: 'block',
    color: isError ? theme.colors.semantic.border.error : theme.colors.semantic.text.secondary,
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

// ===== COMPONENTE =====
export const Input = forwardRef<HTMLInputElement, InputProps>(({
  type = 'text',
  value,
  defaultValue,
  placeholder,
  label,
  description,
  error,
  success = false,
  disabled = false,
  readOnly = false,
  size = 'md',
  leftIcon,
  rightIcon,
  onChange,
  onFocus,
  onBlur,
  onKeyDown,
  name,
  id,
  className = '',
  maxLength,
  minLength,
  pattern,
  title,
  autoComplete,
  autoFocus,
}, ref) => {
  const [isFocused, setIsFocused] = useState(false);
  const [internalValue, setInternalValue] = useState(defaultValue || '');

  const currentValue = value !== undefined ? value : internalValue;
  const hasError = !!error;
  const hasSuccess = success && !hasError;

  const inputStyles = getInputStyles(size, hasError, hasSuccess, disabled);
  const labelStyles = getLabelStyles(size);
  const descriptionStyles = getDescriptionStyles(size, hasError);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    if (value === undefined) {
      setInternalValue(newValue);
    }
    if (onChange) {
      onChange(newValue);
    }
  };

  const handleFocus = () => {
    setIsFocused(true);
    if (onFocus) {
      onFocus();
    }
  };

  const handleBlur = () => {
    setIsFocused(false);
    if (onBlur) {
      onBlur();
    }
  };

  const inputId = id || name || `input-${Math.random().toString(36).substr(2, 9)}`;
  const descriptionId = `${inputId}-description`;
  const errorId = `${inputId}-error`;

  return (
    <div className={`omni-writer-input ${className}`}>
      {/* Label */}
      {label && (
        <label
          htmlFor={inputId}
          style={labelStyles}
          className="omni-writer-input__label"
        >
          {label}
        </label>
      )}

      {/* Container do input */}
      <div
        style={{
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
        }}
        className="omni-writer-input__container"
      >
        {/* Ícone à esquerda */}
        {leftIcon && (
          <div
            style={{
              position: 'absolute',
              left: theme.spacing.spacing[8],
              zIndex: 1,
              color: theme.colors.semantic.text.secondary,
              display: 'flex',
              alignItems: 'center',
            }}
            className="omni-writer-input__left-icon"
          >
            {leftIcon}
          </div>
        )}

        {/* Input */}
        <input
          ref={ref}
          type={type}
          value={currentValue}
          placeholder={placeholder}
          disabled={disabled}
          readOnly={readOnly}
          name={name}
          id={inputId}
          maxLength={maxLength}
          minLength={minLength}
          pattern={pattern}
          title={title}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          style={{
            ...inputStyles,
            paddingLeft: leftIcon ? `${theme.spacing.spacing[32]}` : undefined,
            paddingRight: rightIcon ? `${theme.spacing.spacing[32]}` : undefined,
            ...(isFocused && {
              borderColor: theme.colors.semantic.border.focus,
              boxShadow: `0 0 0 3px ${theme.colors.semantic.border.focus}20`,
            }),
          }}
          className="omni-writer-input__field"
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          onKeyDown={onKeyDown}
          aria-describedby={error ? errorId : description ? descriptionId : undefined}
          aria-invalid={hasError}
          aria-required={minLength ? minLength > 0 : undefined}
        />

        {/* Ícone à direita */}
        {rightIcon && (
          <div
            style={{
              position: 'absolute',
              right: theme.spacing.spacing[8],
              zIndex: 1,
              color: theme.colors.semantic.text.secondary,
              display: 'flex',
              alignItems: 'center',
            }}
            className="omni-writer-input__right-icon"
          >
            {rightIcon}
          </div>
        )}
      </div>

      {/* Descrição ou erro */}
      {(description || error) && (
        <div
          id={error ? errorId : descriptionId}
          style={descriptionStyles}
          className={`omni-writer-input__${error ? 'error' : 'description'}`}
        >
          {error || description}
        </div>
      )}
    </div>
  );
});

Input.displayName = 'Input';

// ===== VARIAÇÕES =====
export const TextInput: React.FC<Omit<InputProps, 'type'>> = (props) => (
  <Input {...props} type="text" />
);

export const EmailInput: React.FC<Omit<InputProps, 'type'>> = (props) => (
  <Input {...props} type="email" />
);

export const PasswordInput: React.FC<Omit<InputProps, 'type'>> = (props) => (
  <Input {...props} type="password" />
);

export const NumberInput: React.FC<Omit<InputProps, 'type'>> = (props) => (
  <Input {...props} type="number" />
);

export const SearchInput: React.FC<Omit<InputProps, 'type'>> = (props) => (
  <Input {...props} type="search" />
);

// ===== EXPORTAÇÃO PADRÃO =====
export default Input; 