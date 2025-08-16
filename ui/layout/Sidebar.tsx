/**
 * Componente Sidebar - Omni Writer
 * 
 * Menu lateral responsivo com navegação
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useState } from 'react';
import { theme } from '../theme';

// ===== TIPOS =====
interface SidebarProps {
  /** Itens de navegação */
  navigationItems?: SidebarItem[];
  /** Estado de abertura */
  isOpen?: boolean;
  /** Função de toggle */
  onToggle?: () => void;
  /** Largura da sidebar */
  width?: string;
  /** Posição da sidebar */
  position?: 'left' | 'right';
  /** Variante da sidebar */
  variant?: 'default' | 'collapsed' | 'overlay';
  /** Conteúdo do header da sidebar */
  header?: React.ReactNode;
  /** Conteúdo do footer da sidebar */
  footer?: React.ReactNode;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
}

interface SidebarItem {
  /** ID do item */
  id: string;
  /** Label do item */
  label: string;
  /** URL do item */
  href: string;
  /** Ícone do item */
  icon?: React.ReactNode;
  /** Item ativo */
  active?: boolean;
  /** Item desabilitado */
  disabled?: boolean;
  /** Subitens */
  children?: SidebarItem[];
  /** Item expandido */
  expanded?: boolean;
}

// ===== ESTILOS =====
const getSidebarStyles = (isOpen: boolean, width: string, position: string, variant: string) => {
  const baseStyles = {
    backgroundColor: theme.colors.semantic.background.primary,
    borderRight: position === 'left' ? `1px solid ${theme.colors.semantic.border.primary}` : 'none',
    borderLeft: position === 'right' ? `1px solid ${theme.colors.semantic.border.primary}` : 'none',
    height: '100vh',
    display: 'flex',
    flexDirection: 'column' as const,
    transition: 'all 0.3s ease-in-out',
    zIndex: 200,
  };

  const variantStyles = {
    default: {
      width: isOpen ? width : '0px',
      overflow: 'hidden',
    },
    collapsed: {
      width: isOpen ? width : '64px',
      overflow: 'hidden',
    },
    overlay: {
      position: 'fixed' as const,
      top: 0,
      [position]: isOpen ? 0 : '-100%',
      width,
      boxShadow: theme.shadows.shadows.lg,
    },
  };

  return {
    ...baseStyles,
    ...variantStyles[variant as keyof typeof variantStyles],
  };
};

const getHeaderStyles = () => {
  return {
    padding: theme.spacing.spacing[16],
    borderBottom: `1px solid ${theme.colors.semantic.border.primary}`,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    minHeight: '64px',
  };
};

const getNavigationStyles = () => {
  return {
    flex: 1,
    padding: theme.spacing.spacing[8],
    overflowY: 'auto' as const,
    overflowX: 'hidden' as const,
  };
};

const getItemStyles = (active: boolean, disabled: boolean, hasChildren: boolean) => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[12],
    padding: `${theme.spacing.spacing[12]} ${theme.spacing.spacing[16]}`,
    borderRadius: theme.spacing.spacing[6],
    textDecoration: 'none',
    color: disabled ? theme.colors.semantic.text.disabled : (active ? theme.colors.base.primary[600] : theme.colors.semantic.text.primary),
    backgroundColor: active ? theme.colors.base.primary[50] : 'transparent',
    fontWeight: active ? theme.typography.fonts.weight.medium : theme.typography.fonts.weight.normal,
    fontSize: theme.typography.fontSizes.sm,
    transition: 'all 0.2s ease-in-out',
    cursor: disabled ? 'not-allowed' : 'pointer',
    width: '100%',
    border: 'none',
    textAlign: 'left' as const,
    position: 'relative' as const,
  };
};

const getIconStyles = () => {
  return {
    width: '20px',
    height: '20px',
    flexShrink: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  };
};

const getLabelStyles = (collapsed: boolean) => {
  return {
    flex: 1,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    opacity: collapsed ? 0 : 1,
    transition: 'opacity 0.2s ease-in-out',
  };
};

const getExpandIconStyles = (expanded: boolean) => {
  return {
    width: '16px',
    height: '16px',
    transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
    transition: 'transform 0.2s ease-in-out',
    flexShrink: 0,
  };
};

const getChildrenStyles = (expanded: boolean) => {
  return {
    marginLeft: theme.spacing.spacing[24],
    overflow: 'hidden',
    maxHeight: expanded ? '1000px' : '0px',
    transition: 'max-height 0.3s ease-in-out',
  };
};

const getFooterStyles = () => {
  return {
    padding: theme.spacing.spacing[16],
    borderTop: `1px solid ${theme.colors.semantic.border.primary}`,
  };
};

const getToggleButtonStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    border: 'none',
    backgroundColor: 'transparent',
    borderRadius: theme.spacing.spacing[4],
    cursor: 'pointer',
    color: theme.colors.semantic.text.secondary,
    transition: 'all 0.2s ease-in-out',
  };
};

// ===== COMPONENTE =====
export const Sidebar: React.FC<SidebarProps> = ({
  navigationItems = [],
  isOpen = true,
  onToggle,
  width = '280px',
  position = 'left',
  variant = 'default',
  header,
  footer,
  className = '',
  id,
}) => {
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());

  const sidebarStyles = getSidebarStyles(isOpen, width, position, variant);
  const headerStyles = getHeaderStyles();
  const navigationStyles = getNavigationStyles();
  const footerStyles = getFooterStyles();
  const toggleButtonStyles = getToggleButtonStyles();

  const isCollapsed = variant === 'collapsed' && !isOpen;

  const handleItemClick = (item: SidebarItem) => {
    if (item.disabled) return;

    if (item.children && item.children.length > 0) {
      const newExpandedItems = new Set(expandedItems);
      if (newExpandedItems.has(item.id)) {
        newExpandedItems.delete(item.id);
      } else {
        newExpandedItems.add(item.id);
      }
      setExpandedItems(newExpandedItems);
    }
  };

  const renderItem = (item: SidebarItem, level: number = 0) => {
    const hasChildren = item.children && item.children.length > 0;
    const isExpanded = expandedItems.has(item.id);
    const itemStyles = getItemStyles(item.active || false, item.disabled || false, hasChildren);
    const iconStyles = getIconStyles();
    const labelStyles = getLabelStyles(isCollapsed);
    const expandIconStyles = getExpandIconStyles(isExpanded);

    return (
      <div key={item.id} style={{ marginBottom: theme.spacing.spacing[4] }}>
        <button
          onClick={() => handleItemClick(item)}
          style={itemStyles}
          className={`omni-writer-sidebar-item ${item.active ? 'omni-writer-sidebar-item--active' : ''} ${item.disabled ? 'omni-writer-sidebar-item--disabled' : ''}`}
          aria-current={item.active ? 'page' : undefined}
          aria-expanded={hasChildren ? isExpanded : undefined}
          aria-disabled={item.disabled}
        >
          {item.icon && (
            <div style={iconStyles}>
              {item.icon}
            </div>
          )}
          <span style={labelStyles}>
            {item.label}
          </span>
          {hasChildren && (
            <svg
              style={expandIconStyles}
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
            >
              <path d="m9 18 6-6-6-6"/>
            </svg>
          )}
        </button>

        {hasChildren && (
          <div style={getChildrenStyles(isExpanded)}>
            {item.children!.map(child => renderItem(child, level + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <aside
      style={sidebarStyles}
      className={`omni-writer-sidebar omni-writer-sidebar--${variant} omni-writer-sidebar--${position} ${className}`}
      id={id}
      role="navigation"
      aria-label="Navegação lateral"
    >
      {/* Header da Sidebar */}
      {header && (
        <div style={headerStyles} className="omni-writer-sidebar-header">
          {header}
          {onToggle && (
            <button
              onClick={onToggle}
              style={toggleButtonStyles}
              className="omni-writer-sidebar-toggle"
              aria-label={isOpen ? 'Recolher sidebar' : 'Expandir sidebar'}
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                {position === 'left' ? (
                  isOpen ? <path d="m15 18-6-6 6-6"/> : <path d="m9 18 6-6-6-6"/>
                ) : (
                  isOpen ? <path d="m9 18 6-6-6-6"/> : <path d="m15 18-6-6 6-6"/>
                )}
              </svg>
            </button>
          )}
        </div>
      )}

      {/* Navegação */}
      <nav style={navigationStyles} className="omni-writer-sidebar-navigation">
        {navigationItems.map(item => renderItem(item))}
      </nav>

      {/* Footer da Sidebar */}
      {footer && (
        <div style={footerStyles} className="omni-writer-sidebar-footer">
          {footer}
        </div>
      )}
    </aside>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const CollapsedSidebar: React.FC<Omit<SidebarProps, 'variant'>> = (props) => (
  <Sidebar {...props} variant="collapsed" />
);

export const OverlaySidebar: React.FC<Omit<SidebarProps, 'variant'>> = (props) => (
  <Sidebar {...props} variant="overlay" />
);

export const LeftSidebar: React.FC<Omit<SidebarProps, 'position'>> = (props) => (
  <Sidebar {...props} position="left" />
);

export const RightSidebar: React.FC<Omit<SidebarProps, 'position'>> = (props) => (
  <Sidebar {...props} position="right" />
);

export const NarrowSidebar: React.FC<Omit<SidebarProps, 'width'>> = (props) => (
  <Sidebar {...props} width="200px" />
);

export const WideSidebar: React.FC<Omit<SidebarProps, 'width'>> = (props) => (
  <Sidebar {...props} width="320px" />
);

// ===== EXPORTAÇÃO =====
Sidebar.displayName = 'Sidebar';
export default Sidebar; 