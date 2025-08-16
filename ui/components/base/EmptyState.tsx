/**
 * Componente EmptyState - Omni Writer
 * 
 * Estados vazios com diferentes variantes
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../../theme';

// ===== TIPOS =====
interface EmptyStateProps {
  /** Título do estado vazio */
  title: string;
  /** Descrição do estado vazio */
  description?: string;
  /** Ícone do estado vazio */
  icon?: React.ReactNode;
  /** Ações disponíveis */
  actions?: React.ReactNode;
  /** Variante do estado vazio */
  variant?: 'default' | 'search' | 'error' | 'no-data' | 'no-results' | 'no-permission';
  /** Tamanho do estado vazio */
  size?: 'sm' | 'md' | 'lg';
  /** Imagem customizada */
  image?: string;
  /** Altura da imagem */
  imageHeight?: string;
  /** Largura da imagem */
  imageWidth?: string;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
  /** Centralizar conteúdo */
  centered?: boolean;
  /** Padding customizado */
  padding?: string;
}

// ===== ESTILOS =====
const getContainerStyles = (size: string, centered: boolean, padding?: string) => {
  const baseStyles = {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: centered ? 'center' : 'flex-start',
    justifyContent: 'center',
    textAlign: centered ? 'center' as const : 'left' as const,
    width: '100%',
  };

  const sizeStyles = {
    sm: {
      padding: padding || theme.spacing.spacing[16],
      gap: theme.spacing.spacing[8],
    },
    md: {
      padding: padding || theme.spacing.spacing[24],
      gap: theme.spacing.spacing[12],
    },
    lg: {
      padding: padding || theme.spacing.spacing[32],
      gap: theme.spacing.spacing[16],
    },
  };

  return {
    ...baseStyles,
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getIconStyles = (size: string, variant: string) => {
  const sizeStyles = {
    sm: { width: '48px', height: '48px' },
    md: { width: '64px', height: '64px' },
    lg: { width: '96px', height: '96px' },
  };

  const variantColors = {
    default: theme.colors.semantic.text.secondary,
    search: theme.colors.base.info[500],
    error: theme.colors.base.error[500],
    'no-data': theme.colors.base.warning[500],
    'no-results': theme.colors.base.info[500],
    'no-permission': theme.colors.base.error[500],
  };

  return {
    ...sizeStyles[size as keyof typeof sizeStyles],
    color: variantColors[variant as keyof typeof variantColors],
    marginBottom: theme.spacing.spacing[8],
  };
};

const getImageStyles = (imageHeight?: string, imageWidth?: string) => {
  return {
    width: imageWidth || 'auto',
    height: imageHeight || '200px',
    objectFit: 'contain' as const,
    marginBottom: theme.spacing.spacing[16],
  };
};

const getTitleStyles = (size: string) => {
  const sizeStyles = {
    sm: { fontSize: theme.typography.fontSizes.lg },
    md: { fontSize: theme.typography.fontSizes.xl },
    lg: { fontSize: theme.typography.fontSizes['2xl'] },
  };

  return {
    fontWeight: theme.typography.fonts.weight.semibold,
    color: theme.colors.semantic.text.primary,
    margin: 0,
    marginBottom: theme.spacing.spacing[8],
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getDescriptionStyles = (size: string) => {
  const sizeStyles = {
    sm: { fontSize: theme.typography.fontSizes.sm },
    md: { fontSize: theme.typography.fontSizes.base },
    lg: { fontSize: theme.typography.fontSizes.lg },
  };

  return {
    color: theme.colors.semantic.text.secondary,
    margin: 0,
    marginBottom: theme.spacing.spacing[16],
    lineHeight: theme.typography.fonts.lineHeight.relaxed,
    maxWidth: '500px',
    ...sizeStyles[size as keyof typeof sizeStyles],
  };
};

const getActionsStyles = (centered: boolean) => {
  return {
    display: 'flex',
    flexDirection: 'row' as const,
    gap: theme.spacing.spacing[8],
    alignItems: 'center',
    justifyContent: centered ? 'center' : 'flex-start',
    flexWrap: 'wrap' as const,
  };
};

// ===== ÍCONES PADRÃO =====
const getDefaultIcon = (variant: string) => {
  const icons = {
    default: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5.586a1 1 0 0 1 .707.293l5.414 5.414a1 1 0 0 1 .293.707V19a2 2 0 0 1-2 2z"/>
      </svg>
    ),
    search: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="11" cy="11" r="8"/>
        <path d="m21 21-4.35-4.35"/>
      </svg>
    ),
    error: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="12" cy="12" r="10"/>
        <line x1="15" y1="9" x2="9" y2="15"/>
        <line x1="9" y1="9" x2="15" y2="15"/>
      </svg>
    ),
    'no-data': (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14,2 14,8 20,8"/>
        <line x1="16" y1="13" x2="8" y2="13"/>
        <line x1="16" y1="17" x2="8" y2="17"/>
        <polyline points="10,9 9,9 8,9"/>
      </svg>
    ),
    'no-results': (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <circle cx="11" cy="11" r="8"/>
        <path d="m21 21-4.35-4.35"/>
        <line x1="8" y1="8" x2="16" y2="16"/>
      </svg>
    ),
    'no-permission': (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
        <circle cx="12" cy="16" r="1"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    ),
  };

  return icons[variant as keyof typeof icons] || icons.default;
};

// ===== TÍTULOS E DESCRIÇÕES PADRÃO =====
const getDefaultContent = (variant: string) => {
  const content = {
    default: {
      title: 'Nenhum conteúdo disponível',
      description: 'Não há conteúdo para exibir no momento.',
    },
    search: {
      title: 'Nenhum resultado encontrado',
      description: 'Tente ajustar seus filtros ou termos de busca.',
    },
    error: {
      title: 'Algo deu errado',
      description: 'Ocorreu um erro inesperado. Tente novamente.',
    },
    'no-data': {
      title: 'Nenhum dado disponível',
      description: 'Não há dados para exibir. Adicione alguns itens para começar.',
    },
    'no-results': {
      title: 'Nenhum resultado',
      description: 'Sua busca não retornou resultados. Tente outros termos.',
    },
    'no-permission': {
      title: 'Acesso negado',
      description: 'Você não tem permissão para acessar este conteúdo.',
    },
  };

  return content[variant as keyof typeof content] || content.default;
};

// ===== COMPONENTE PRINCIPAL =====
export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actions,
  variant = 'default',
  size = 'md',
  image,
  imageHeight,
  imageWidth,
  className = '',
  id,
  centered = true,
  padding,
}) => {
  const containerStyles = getContainerStyles(size, centered, padding);
  const iconStyles = getIconStyles(size, variant);
  const imageStyles = getImageStyles(imageHeight, imageWidth);
  const titleStyles = getTitleStyles(size);
  const descriptionStyles = getDescriptionStyles(size);
  const actionsStyles = getActionsStyles(centered);

  const defaultIcon = getDefaultIcon(variant);
  const defaultContent = getDefaultContent(variant);
  
  const finalTitle = title || defaultContent.title;
  const finalDescription = description || defaultContent.description;
  const finalIcon = icon || defaultIcon;

  return (
    <div
      style={containerStyles}
      className={`omni-writer-empty-state omni-writer-empty-state--${variant} omni-writer-empty-state--${size} ${className}`}
      id={id}
      role="status"
      aria-live="polite"
    >
      {image ? (
        <img
          src={image}
          alt={finalTitle}
          style={imageStyles}
          className="omni-writer-empty-state-image"
        />
      ) : (
        <div style={iconStyles} className="omni-writer-empty-state-icon">
          {finalIcon}
        </div>
      )}

      <h3 style={titleStyles} className="omni-writer-empty-state-title">
        {finalTitle}
      </h3>

      {finalDescription && (
        <p style={descriptionStyles} className="omni-writer-empty-state-description">
          {finalDescription}
        </p>
      )}

      {actions && (
        <div style={actionsStyles} className="omni-writer-empty-state-actions">
          {actions}
        </div>
      )}
    </div>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const SearchEmptyState: React.FC<Omit<EmptyStateProps, 'variant'>> = (props) => (
  <EmptyState {...props} variant="search" />
);

export const ErrorEmptyState: React.FC<Omit<EmptyStateProps, 'variant'>> = (props) => (
  <EmptyState {...props} variant="error" />
);

export const NoDataEmptyState: React.FC<Omit<EmptyStateProps, 'variant'>> = (props) => (
  <EmptyState {...props} variant="no-data" />
);

export const NoResultsEmptyState: React.FC<Omit<EmptyStateProps, 'variant'>> = (props) => (
  <EmptyState {...props} variant="no-results" />
);

export const NoPermissionEmptyState: React.FC<Omit<EmptyStateProps, 'variant'>> = (props) => (
  <EmptyState {...props} variant="no-permission" />
);

export const SmallEmptyState: React.FC<Omit<EmptyStateProps, 'size'>> = (props) => (
  <EmptyState {...props} size="sm" />
);

export const LargeEmptyState: React.FC<Omit<EmptyStateProps, 'size'>> = (props) => (
  <EmptyState {...props} size="lg" />
);

export const CenteredEmptyState: React.FC<Omit<EmptyStateProps, 'centered'>> = (props) => (
  <EmptyState {...props} centered={true} />
);

export const LeftAlignedEmptyState: React.FC<Omit<EmptyStateProps, 'centered'>> = (props) => (
  <EmptyState {...props} centered={false} />
);

// ===== COMPONENTES DE CONVENIÊNCIA =====
interface EmptyStateWithActionProps extends Omit<EmptyStateProps, 'actions'> {
  /** Texto do botão principal */
  primaryActionText?: string;
  /** Função do botão principal */
  primaryAction?: () => void;
  /** Texto do botão secundário */
  secondaryActionText?: string;
  /** Função do botão secundário */
  secondaryAction?: () => void;
}

export const EmptyStateWithAction: React.FC<EmptyStateWithActionProps> = ({
  primaryActionText,
  primaryAction,
  secondaryActionText,
  secondaryAction,
  ...props
}) => {
  const actions = (
    <>
      {primaryAction && primaryActionText && (
        <button
          onClick={primaryAction}
          style={{
            padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[16]}`,
            backgroundColor: theme.colors.base.primary[500],
            color: 'white',
            border: 'none',
            borderRadius: theme.spacing.spacing[6],
            fontSize: theme.typography.fontSizes.sm,
            fontWeight: theme.typography.fonts.weight.medium,
            cursor: 'pointer',
            transition: 'all 0.2s ease-in-out',
          }}
        >
          {primaryActionText}
        </button>
      )}
      {secondaryAction && secondaryActionText && (
        <button
          onClick={secondaryAction}
          style={{
            padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[16]}`,
            backgroundColor: 'transparent',
            color: theme.colors.semantic.text.primary,
            border: `1px solid ${theme.colors.semantic.border.primary}`,
            borderRadius: theme.spacing.spacing[6],
            fontSize: theme.typography.fontSizes.sm,
            fontWeight: theme.typography.fonts.weight.medium,
            cursor: 'pointer',
            transition: 'all 0.2s ease-in-out',
          }}
        >
          {secondaryActionText}
        </button>
      )}
    </>
  );

  return <EmptyState {...props} actions={actions} />;
};

// ===== COMPONENTE PARA LISTAS VAZIAS =====
interface EmptyListProps extends Omit<EmptyStateProps, 'variant' | 'title' | 'description'> {
  /** Tipo de lista */
  listType?: 'posts' | 'users' | 'files' | 'comments' | 'notifications' | 'custom';
  /** Nome customizado da lista */
  customName?: string;
}

export const EmptyList: React.FC<EmptyListProps> = ({
  listType = 'custom',
  customName,
  ...props
}) => {
  const listContent = {
    posts: {
      title: 'Nenhum post encontrado',
      description: 'Não há posts para exibir. Crie seu primeiro post para começar.',
      variant: 'no-data' as const,
    },
    users: {
      title: 'Nenhum usuário encontrado',
      description: 'Não há usuários para exibir.',
      variant: 'no-data' as const,
    },
    files: {
      title: 'Nenhum arquivo encontrado',
      description: 'Não há arquivos para exibir. Faça upload de alguns arquivos.',
      variant: 'no-data' as const,
    },
    comments: {
      title: 'Nenhum comentário',
      description: 'Não há comentários para exibir.',
      variant: 'no-data' as const,
    },
    notifications: {
      title: 'Nenhuma notificação',
      description: 'Você está em dia! Não há notificações pendentes.',
      variant: 'default' as const,
    },
    custom: {
      title: customName ? `Nenhum ${customName} encontrado` : 'Lista vazia',
      description: customName ? `Não há ${customName} para exibir.` : 'Não há itens para exibir.',
      variant: 'no-data' as const,
    },
  };

  const content = listContent[listType];

  return (
    <EmptyState
      {...props}
      variant={content.variant}
      title={content.title}
      description={content.description}
    />
  );
};

// ===== EXPORTAÇÃO =====
EmptyState.displayName = 'EmptyState';
export default EmptyState; 