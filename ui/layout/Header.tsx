/**
 * Componente Header - Omni Writer
 * 
 * Cabeçalho principal com navegação e branding
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useState } from 'react';
import { theme } from '../theme';
import { Branding } from './Branding';
import { Button } from '../components/base/Button';

// ===== TIPOS =====
interface HeaderProps {
  /** Itens de navegação */
  navigationItems?: NavigationItem[];
  /** Função de toggle do menu mobile */
  onMobileMenuToggle?: () => void;
  /** Estado do menu mobile */
  isMobileMenuOpen?: boolean;
  /** Função de toggle do tema */
  onThemeToggle?: () => void;
  /** Tema atual */
  currentTheme?: 'light' | 'dark';
  /** Informações do usuário */
  user?: {
    name: string;
    email: string;
    avatar?: string;
  };
  /** Função de logout */
  onLogout?: () => void;
  /** Classe CSS adicional */
  className?: string;
}

interface NavigationItem {
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
}

// ===== ESTILOS =====
const getHeaderStyles = () => {
  return {
    width: '100%',
    height: '64px',
    backgroundColor: theme.colors.semantic.background.primary,
    borderBottom: `1px solid ${theme.colors.semantic.border.primary}`,
    boxShadow: theme.shadows.shadows.sm,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: `0 ${theme.spacing.spacing[24]}`,
    position: 'sticky' as const,
    top: 0,
    zIndex: 100,
  };
};

const getNavigationStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[8],
  };
};

const getNavigationItemStyles = (active: boolean) => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[4],
    padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
    borderRadius: theme.spacing.spacing[6],
    textDecoration: 'none',
    color: active ? theme.colors.base.primary[600] : theme.colors.semantic.text.primary,
    backgroundColor: active ? theme.colors.base.primary[50] : 'transparent',
    fontWeight: active ? theme.typography.fonts.weight.medium : theme.typography.fonts.weight.normal,
    fontSize: theme.typography.fontSizes.sm,
    transition: 'all 0.2s ease-in-out',
    cursor: 'pointer',
  };
};

const getActionsStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[16],
  };
};

const getUserStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[8],
    padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
    borderRadius: theme.spacing.spacing[6],
    cursor: 'pointer',
    transition: 'all 0.2s ease-in-out',
  };
};

const getAvatarStyles = () => {
  return {
    width: '32px',
    height: '32px',
    borderRadius: '50%',
    backgroundColor: theme.colors.base.primary[500],
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'white',
    fontSize: theme.typography.fontSizes.sm,
    fontWeight: theme.typography.fonts.weight.medium,
  };
};

const getMobileMenuButtonStyles = () => {
  return {
    display: 'none',
    alignItems: 'center',
    justifyContent: 'center',
    width: '40px',
    height: '40px',
    border: 'none',
    backgroundColor: 'transparent',
    borderRadius: theme.spacing.spacing[6],
    cursor: 'pointer',
    color: theme.colors.semantic.text.primary,
  };
};

// ===== COMPONENTE =====
export const Header: React.FC<HeaderProps> = ({
  navigationItems = [],
  onMobileMenuToggle,
  isMobileMenuOpen = false,
  onThemeToggle,
  currentTheme = 'light',
  user,
  onLogout,
  className = '',
}) => {
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);

  const headerStyles = getHeaderStyles();
  const navigationStyles = getNavigationStyles();
  const actionsStyles = getActionsStyles();

  const handleUserMenuToggle = () => {
    setIsUserMenuOpen(!isUserMenuOpen);
  };

  const handleLogout = () => {
    setIsUserMenuOpen(false);
    onLogout?.();
  };

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(word => word[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <header
      style={headerStyles}
      className={`omni-writer-header ${className}`}
      role="banner"
    >
      {/* Logo e Branding */}
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing.spacing[24] }}>
        <Branding />
        
        {/* Navegação Desktop */}
        <nav
          style={navigationStyles}
          className="omni-writer-header-navigation"
          role="navigation"
          aria-label="Navegação principal"
        >
          {navigationItems.map((item) => (
            <a
              key={item.id}
              href={item.href}
              style={getNavigationItemStyles(item.active || false)}
              className={`omni-writer-nav-item ${item.active ? 'omni-writer-nav-item--active' : ''}`}
              aria-current={item.active ? 'page' : undefined}
              aria-disabled={item.disabled}
            >
              {item.icon && <span>{item.icon}</span>}
              {item.label}
            </a>
          ))}
        </nav>
      </div>

      {/* Ações do Header */}
      <div style={actionsStyles} className="omni-writer-header-actions">
        {/* Toggle de Tema */}
        {onThemeToggle && (
          <button
            onClick={onThemeToggle}
            aria-label={`Alternar para tema ${currentTheme === 'light' ? 'escuro' : 'claro'}`}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '40px',
              height: '40px',
              border: 'none',
              backgroundColor: 'transparent',
              borderRadius: theme.spacing.spacing[6],
              cursor: 'pointer',
              color: theme.colors.semantic.text.primary,
              transition: 'all 0.2s ease-in-out',
            }}
            className="omni-writer-theme-toggle"
          >
            {currentTheme === 'light' ? '🌙' : '☀️'}
          </button>
        )}

        {/* Menu do Usuário */}
        {user && (
          <div style={{ position: 'relative' as const }}>
            <button
              onClick={handleUserMenuToggle}
              style={getUserStyles()}
              className="omni-writer-user-menu"
              aria-expanded={isUserMenuOpen}
              aria-haspopup="true"
            >
              <div style={getAvatarStyles()}>
                {user.avatar ? (
                  <img
                    src={user.avatar}
                    alt={user.name}
                    style={{ width: '100%', height: '100%', borderRadius: '50%' }}
                  />
                ) : (
                  getInitials(user.name)
                )}
              </div>
              <span style={{
                fontSize: theme.typography.fontSizes.sm,
                fontWeight: theme.typography.fonts.weight.medium,
                color: theme.colors.semantic.text.primary,
              }}>
                {user.name}
              </span>
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                style={{
                  transform: isUserMenuOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.2s ease-in-out',
                }}
              >
                <path d="m6 9 6 6 6-6"/>
              </svg>
            </button>

            {/* Dropdown do Usuário */}
            {isUserMenuOpen && (
              <div style={{
                position: 'absolute',
                top: '100%',
                right: 0,
                marginTop: theme.spacing.spacing[4],
                backgroundColor: theme.colors.semantic.background.primary,
                border: `1px solid ${theme.colors.semantic.border.primary}`,
                borderRadius: theme.spacing.spacing[8],
                boxShadow: theme.shadows.shadows.lg,
                minWidth: '200px',
                zIndex: 1000,
              }}>
                <div style={{
                  padding: theme.spacing.spacing[12],
                  borderBottom: `1px solid ${theme.colors.semantic.border.primary}`,
                }}>
                  <div style={{
                    fontSize: theme.typography.fontSizes.sm,
                    fontWeight: theme.typography.fonts.weight.medium,
                    color: theme.colors.semantic.text.primary,
                  }}>
                    {user.name}
                  </div>
                  <div style={{
                    fontSize: theme.typography.fontSizes.xs,
                    color: theme.colors.semantic.text.secondary,
                  }}>
                    {user.email}
                  </div>
                </div>
                <div style={{ padding: theme.spacing.spacing[4] }}>
                  <button
                    onClick={handleLogout}
                    style={{
                      width: '100%',
                      padding: `${theme.spacing.spacing[8]} ${theme.spacing.spacing[12]}`,
                      border: 'none',
                      backgroundColor: 'transparent',
                      borderRadius: theme.spacing.spacing[4],
                      cursor: 'pointer',
                      fontSize: theme.typography.fontSizes.sm,
                      color: theme.colors.semantic.text.primary,
                      textAlign: 'left' as const,
                      transition: 'all 0.2s ease-in-out',
                    }}
                    className="omni-writer-logout-button"
                  >
                    Sair
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Menu Mobile */}
        <button
          onClick={onMobileMenuToggle}
          style={getMobileMenuButtonStyles()}
          className="omni-writer-mobile-menu-button"
          aria-label="Abrir menu de navegação"
          aria-expanded={isMobileMenuOpen}
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            {isMobileMenuOpen ? (
              <path d="M18 6 6 18M6 6l12 12"/>
            ) : (
              <path d="M3 12h18M3 6h18M3 18h18"/>
            )}
          </svg>
        </button>
      </div>
    </header>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const SimpleHeader: React.FC<Omit<HeaderProps, 'navigationItems'>> = (props) => (
  <Header {...props} navigationItems={[]} />
);

export const HeaderWithNavigation: React.FC<HeaderProps> = (props) => (
  <Header {...props} />
);

export const HeaderWithUser: React.FC<Omit<HeaderProps, 'user'>> & { user: NonNullable<HeaderProps['user']> } = (props) => (
  <Header {...props} />
);

// ===== EXPORTAÇÃO =====
Header.displayName = 'Header';
export default Header; 