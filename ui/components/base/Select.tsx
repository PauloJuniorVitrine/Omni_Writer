/**
 * Componente Select - Omni Writer
 * 
 * Dropdowns customizados com validação e estados
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useState, useRef, useEffect, forwardRef } from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface SelectOption {
  /** Valor da opção */
  value: string;
  /** Label da opção */
  label: string;
  /** Opção desabilitada */
  disabled?: boolean;
  /** Ícone da opção */
  icon?: React.ReactNode;
  /** Dados adicionais */
  data?: any;
}

interface SelectProps {
  /** Opções do select */
  options: SelectOption[];
  /** Valor selecionado */
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
  /** Tamanho do select */
  size?: 'sm' | 'md' | 'lg';
  /** Múltipla seleção */
  multiple?: boolean;
  /** Busca habilitada */
  searchable?: boolean;
  /** Máximo de itens visíveis */
  maxVisibleItems?: number;
  /** Função de mudança */
  onChange?: (value: string | string[]) => void;
  /** Função de foco */
  onFocus?: () => void;
  /** Função de blur */
  onBlur?: () => void;
  /** Nome do campo */
  name?: string;
  /** ID do campo */
  id?: string;
  /** Classe CSS adicional */
  className?: string;
  /** Título para acessibilidade */
  title?: string;
  /** Auto-focus */
  autoFocus?: boolean;
  /** Posição do dropdown */
  position?: 'top' | 'bottom' | 'auto';
}

// ===== ESTILOS =====
const getSelectStyles = (size: string, hasError: boolean, hasSuccess: boolean, disabled: boolean, isOpen: boolean) => {
  const baseStyles = {
    position: 'relative' as const,
    width: '100%',
    fontFamily: theme.typography.fonts.family.primary,
    fontSize: theme.typography.fontSizes.base,
    lineHeight: theme.typography.fonts.lineHeight.normal,
    color: theme.colors.semantic.text.primary,
    cursor: disabled ? 'not-allowed' : 'pointer',
    userSelect: 'none' as const,
  };

  const sizeStyles = {
    sm: {
      minHeight: '32px',
    },
    md: {
      minHeight: '40px',
    },
    lg: {
      minHeight: '48px',
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
    opacity: disabled ? 0.6 : 1,
  };
};

const getTriggerStyles = (size: string, hasError: boolean, hasSuccess: boolean, disabled: boolean, isOpen: boolean) => {
  const baseStyles = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
    border: `1px solid ${hasError ? theme.colors.semantic.border.error : theme.colors.semantic.border.primary}`,
    borderRadius: theme.spacing.spacing[6],
    backgroundColor: disabled ? theme.colors.semantic.state.disabled : theme.colors.semantic.background.primary,
    color: theme.colors.semantic.text.primary,
    outline: 'none',
    transition: 'all 0.2s ease-in-out',
    cursor: disabled ? 'not-allowed' : 'pointer',
  };

  const sizeStyles = {
    sm: {
      padding: `${theme.spacing.spacing[6]} ${theme.spacing.spacing[8]}`,
      fontSize: theme.typography.fontSizes.sm,
    },
    md: {
      padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
      fontSize: theme.typography.fontSizes.base,
    },
    lg: {
      padding: `${theme.spacing.spacing[10]} ${theme.spacing.spacing[16]}`,
      fontSize: theme.typography.fontSizes.lg,
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
    open: {
      borderColor: theme.colors.semantic.border.focus,
      boxShadow: `0 0 0 3px ${theme.colors.semantic.border.focus}20`,
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
    ...(hasError && stateStyles.error),
    ...(hasSuccess && stateStyles.success),
    ...(isOpen && stateStyles.open),
  };
};

const getDropdownStyles = (size: string, position: string) => {
  const baseStyles = {
    position: 'absolute' as const,
    left: 0,
    right: 0,
    backgroundColor: theme.colors.semantic.background.primary,
    border: `1px solid ${theme.colors.semantic.border.primary}`,
    borderRadius: theme.spacing.spacing[6],
    boxShadow: theme.shadows.shadows.lg,
    zIndex: 1000,
    maxHeight: '300px',
    overflowY: 'auto' as const,
    overflowX: 'hidden' as const,
  };

  const positionStyles = {
    top: {
      bottom: '100%',
      marginBottom: theme.spacing.spacing[4],
    },
    bottom: {
      top: '100%',
      marginTop: theme.spacing.spacing[4],
    },
  };

  return {
    ...baseStyles,
    ...positionStyles[position as keyof typeof positionStyles],
  };
};

const getOptionStyles = (size: string, isSelected: boolean, isDisabled: boolean, isHovered: boolean) => {
  const baseStyles = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[8],
    width: '100%',
    border: 'none',
    backgroundColor: 'transparent',
    color: theme.colors.semantic.text.primary,
    cursor: isDisabled ? 'not-allowed' : 'pointer',
    transition: 'all 0.15s ease-in-out',
    textAlign: 'left' as const,
  };

  const sizeStyles = {
    sm: {
      padding: `${theme.spacing.spacing[6]} ${theme.spacing.spacing[8]}`,
      fontSize: theme.typography.fontSizes.sm,
    },
    md: {
      padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
      fontSize: theme.typography.fontSizes.base,
    },
    lg: {
      padding: `${theme.spacing.spacing[10]} ${theme.spacing.spacing[16]}`,
      fontSize: theme.typography.fontSizes.lg,
    },
  };

  const stateStyles = {
    selected: {
      backgroundColor: theme.colors.base.primary[100],
      color: theme.colors.base.primary[700],
      fontWeight: theme.typography.fonts.weight.medium,
    },
    hovered: {
      backgroundColor: theme.colors.semantic.state.hover,
    },
    disabled: {
      opacity: 0.5,
      cursor: 'not-allowed',
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
    ...(isSelected && stateStyles.selected),
    ...(isHovered && !isSelected && !isDisabled && stateStyles.hovered),
    ...(isDisabled && stateStyles.disabled),
  };
};

// ===== COMPONENTE =====
export const Select = forwardRef<HTMLDivElement, SelectProps>(({
  options,
  value,
  defaultValue,
  placeholder = 'Selecione uma opção',
  label,
  description,
  error,
  success = false,
  disabled = false,
  readOnly = false,
  size = 'md',
  multiple = false,
  searchable = false,
  maxVisibleItems = 8,
  onChange,
  onFocus,
  onBlur,
  name,
  id,
  className = '',
  title,
  autoFocus = false,
  position = 'bottom',
}, ref) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedValue, setSelectedValue] = useState<string | string[]>(value || defaultValue || (multiple ? [] : ''));
  const [searchTerm, setSearchTerm] = useState('');
  const [hoveredIndex, setHoveredIndex] = useState(-1);
  
  const selectRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Filtrar opções baseado na busca
  const filteredOptions = searchable 
    ? options.filter(option => 
        option.label.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !option.disabled
      )
    : options.filter(option => !option.disabled);

  // Encontrar opção selecionada
  const selectedOption = options.find(option => 
    multiple 
      ? Array.isArray(selectedValue) && selectedValue.includes(option.value)
      : option.value === selectedValue
  );

  // Encontrar múltiplas opções selecionadas
  const selectedOptions = multiple && Array.isArray(selectedValue)
    ? options.filter(option => selectedValue.includes(option.value))
    : [];

  // Handlers
  const handleToggle = () => {
    if (disabled || readOnly) return;
    
    setIsOpen(!isOpen);
    if (!isOpen && searchable) {
      setTimeout(() => searchInputRef.current?.focus(), 0);
    }
  };

  const handleOptionClick = (option: SelectOption) => {
    if (option.disabled) return;

    let newValue: string | string[];
    
    if (multiple) {
      const currentValues = Array.isArray(selectedValue) ? selectedValue : [];
      if (currentValues.includes(option.value)) {
        newValue = currentValues.filter(v => v !== option.value);
      } else {
        newValue = [...currentValues, option.value];
      }
    } else {
      newValue = option.value;
      setIsOpen(false);
    }

    setSelectedValue(newValue);
    onChange?.(newValue);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (disabled || readOnly) return;

    switch (e.key) {
      case 'Enter':
      case ' ':
        e.preventDefault();
        if (isOpen && hoveredIndex >= 0 && filteredOptions[hoveredIndex]) {
          handleOptionClick(filteredOptions[hoveredIndex]);
        } else {
          handleToggle();
        }
        break;
      case 'Escape':
        setIsOpen(false);
        break;
      case 'ArrowDown':
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
        } else {
          setHoveredIndex(prev => 
            prev < filteredOptions.length - 1 ? prev + 1 : 0
          );
        }
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (!isOpen) {
          setIsOpen(true);
        } else {
          setHoveredIndex(prev => 
            prev > 0 ? prev - 1 : filteredOptions.length - 1
          );
        }
        break;
    }
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value);
    setHoveredIndex(-1);
  };

  // Fechar dropdown ao clicar fora
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (selectRef.current && !selectRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Atualizar valor quando prop value mudar
  useEffect(() => {
    if (value !== undefined) {
      setSelectedValue(value);
    }
  }, [value]);

  // Estilos
  const selectStyles = getSelectStyles(size, !!error, success, disabled, isOpen);
  const triggerStyles = getTriggerStyles(size, !!error, success, disabled, isOpen);
  const dropdownStyles = getDropdownStyles(size, position);

  // Renderizar valor selecionado
  const renderSelectedValue = () => {
    if (multiple && Array.isArray(selectedValue) && selectedValue.length > 0) {
      if (selectedOptions.length === 1) {
        return selectedOptions[0].label;
      } else if (selectedOptions.length > 1) {
        return `${selectedOptions.length} itens selecionados`;
      }
    } else if (!multiple && selectedOption) {
      return selectedOption.label;
    }
    return placeholder;
  };

  return (
    <div
      ref={selectRef}
      style={selectStyles}
      className={`omni-writer-select omni-writer-select--${size} ${className}`}
      onKeyDown={handleKeyDown}
      tabIndex={disabled ? -1 : 0}
      role="combobox"
      aria-expanded={isOpen}
      aria-haspopup="listbox"
      aria-labelledby={label ? `${id}-label` : undefined}
      aria-describedby={description ? `${id}-description` : undefined}
      aria-invalid={!!error}
      aria-disabled={disabled}
    >
      {label && (
        <label
          id={`${id}-label`}
          style={{
            display: 'block',
            fontWeight: theme.typography.fonts.weight.medium,
            color: theme.colors.semantic.text.primary,
            marginBottom: theme.spacing.spacing[4],
            fontSize: size === 'sm' ? theme.typography.fontSizes.sm : theme.typography.fontSizes.base,
          }}
        >
          {label}
        </label>
      )}

      <div
        style={triggerStyles}
        onClick={handleToggle}
        onFocus={onFocus}
        onBlur={onBlur}
        role="button"
        tabIndex={-1}
        aria-label={title || placeholder}
      >
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {renderSelectedValue()}
        </span>
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          style={{
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
            transition: 'transform 0.2s ease-in-out',
            flexShrink: 0,
          }}
        >
          <path d="m6 9 6 6 6-6"/>
        </svg>
      </div>

      {isOpen && (
        <div
          ref={dropdownRef}
          style={dropdownStyles}
          role="listbox"
          aria-label={title || 'Opções disponíveis'}
        >
          {searchable && (
            <div style={{ padding: theme.spacing.spacing[8], borderBottom: `1px solid ${theme.colors.semantic.border.primary}` }}>
              <input
                ref={searchInputRef}
                type="text"
                value={searchTerm}
                onChange={handleSearchChange}
                placeholder="Buscar..."
                style={{
                  width: '100%',
                  border: 'none',
                  outline: 'none',
                  fontSize: theme.typography.fontSizes.sm,
                  backgroundColor: 'transparent',
                  color: theme.colors.semantic.text.primary,
                }}
              />
            </div>
          )}

          {filteredOptions.length === 0 ? (
            <div style={{
              padding: theme.spacing.spacing[12],
              textAlign: 'center',
              color: theme.colors.semantic.text.secondary,
              fontSize: theme.typography.fontSizes.sm,
            }}>
              Nenhuma opção encontrada
            </div>
          ) : (
            filteredOptions.slice(0, maxVisibleItems).map((option, index) => {
              const isSelected = multiple
                ? Array.isArray(selectedValue) && selectedValue.includes(option.value)
                : option.value === selectedValue;
              const isHovered = index === hoveredIndex;

              return (
                <button
                  key={option.value}
                  style={getOptionStyles(size, isSelected, !!option.disabled, isHovered)}
                  onClick={() => handleOptionClick(option)}
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(-1)}
                  role="option"
                  aria-selected={isSelected}
                  disabled={option.disabled}
                >
                  {option.icon && <span>{option.icon}</span>}
                  <span style={{ flex: 1 }}>{option.label}</span>
                  {isSelected && (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 6 9 17l-5-5"/>
                    </svg>
                  )}
                </button>
              );
            })
          )}
        </div>
      )}

      {description && (
        <div
          id={`${id}-description`}
          style={{
            display: 'block',
            color: theme.colors.semantic.text.secondary,
            fontSize: size === 'sm' ? theme.typography.fontSizes.xs : theme.typography.fontSizes.sm,
            marginTop: theme.spacing.spacing[4],
          }}
        >
          {description}
        </div>
      )}

      {error && (
        <div style={{
          display: 'block',
          color: theme.colors.semantic.border.error,
          fontSize: size === 'sm' ? theme.typography.fontSizes.xs : theme.typography.fontSizes.sm,
          marginTop: theme.spacing.spacing[4],
        }}>
          {error}
        </div>
      )}
    </div>
  );
});

// ===== COMPONENTES ESPECIALIZADOS =====
export const SmallSelect: React.FC<Omit<SelectProps, 'size'>> = (props) => (
  <Select {...props} size="sm" />
);

export const LargeSelect: React.FC<Omit<SelectProps, 'size'>> = (props) => (
  <Select {...props} size="lg" />
);

export const MultiSelect: React.FC<Omit<SelectProps, 'multiple'>> = (props) => (
  <Select {...props} multiple={true} />
);

export const SearchableSelect: React.FC<Omit<SelectProps, 'searchable'>> = (props) => (
  <Select {...props} searchable={true} />
);

export const DisabledSelect: React.FC<Omit<SelectProps, 'disabled'>> = (props) => (
  <Select {...props} disabled={true} />
);

// ===== EXPORTAÇÃO =====
Select.displayName = 'Select';
export default Select; 