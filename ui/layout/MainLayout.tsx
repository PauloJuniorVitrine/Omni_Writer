/**
 * Componente MainLayout - Omni Writer
 * 
 * Layout wrapper principal com header, sidebar e footer
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React, { useState } from 'react';
import { theme } from '../theme';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';
import Breadcrumbs from '../components/Breadcrumbs';

// ===== TIPOS =====
interface MainLayoutProps {
  /** Conteúdo principal */
  children: React.ReactNode;
  /** Itens de navegação do header */
  headerNavigation?: HeaderNavigationItem[];
  /** Itens de navegação da sidebar */
  sidebarNavigation?: SidebarNavigationItem[];
  /** Informações do usuário */
  user?: {
    name: string;
    email: string;
    avatar?: string;
  };
  /** Função de logout */
  onLogout?: () => void;
  /** Função de toggle do tema */
  onThemeToggle?: () => void;
  /** Tema atual */
  currentTheme?: 'light' | 'dark';
  /** Configuração da sidebar */
  sidebarConfig?: {
    /** Estado inicial da sidebar */
    isOpen?: boolean;
    /** Largura da sidebar */
    width?: string;
    /** Posição da sidebar */
    position?: 'left' | 'right';
    /** Variante da sidebar */
    variant?: 'default' | 'collapsed' | 'overlay';
  };
  /** Configuração do footer */
  footerConfig?: {
    /** Links do footer */
    links?: FooterLink[];
    /** Versão da aplicação */
    version?: string;
    /** Links sociais */
    socialLinks?: SocialLink[];
    /** Variante do footer */
    variant?: 'default' | 'minimal' | 'extended';
  };
  /** Mostrar header */
  showHeader?: boolean;
  /** Mostrar sidebar */
  showSidebar?: boolean;
  /** Mostrar footer */
  showFooter?: boolean;
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
}

interface HeaderNavigationItem {
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

interface SidebarNavigationItem {
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
  children?: SidebarNavigationItem[];
}

interface FooterLink {
  /** ID do link */
  id: string;
  /** Label do link */
  label: string;
  /** URL do link */
  href: string;
  /** Link externo */
  external?: boolean;
}

interface SocialLink {
  /** ID do link */
  id: string;
  /** Label do link */
  label: string;
  /** URL do link */
  href: string;
  /** Ícone do link */
  icon: React.ReactNode;
  /** Link externo */
  external?: boolean;
}

// ===== ESTILOS =====
const getLayoutStyles = () => {
  return {
    display: 'flex',
    flexDirection: 'column' as const,
    minHeight: '100vh',
    backgroundColor: theme.colors.semantic.background.primary,
  };
};

const getMainStyles = (showSidebar: boolean, sidebarPosition: string) => {
  return {
    display: 'flex',
    flex: 1,
    flexDirection: showSidebar && sidebarPosition === 'right' ? 'row-reverse' as const : 'row' as const,
  };
};

const getContentStyles = () => {
  return {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    minHeight: 0,
  };
};

const getMainContentStyles = () => {
  return {
    flex: 1,
    padding: theme.spacing.spacing[24],
    overflowY: 'auto' as const,
    overflowX: 'hidden' as const,
  };
};

// ===== COMPONENTE =====
export const MainLayout: React.FC<MainLayoutProps> = ({
  children,
  headerNavigation = [],
  sidebarNavigation = [],
  user,
  onLogout,
  onThemeToggle,
  currentTheme = 'light',
  sidebarConfig = {},
  footerConfig = {},
  showHeader = true,
  showSidebar = false,
  showFooter = true,
  className = '',
  id,
}) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(sidebarConfig.isOpen ?? true);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const layoutStyles = getLayoutStyles();
  const mainStyles = getMainStyles(showSidebar, sidebarConfig.position || 'left');
  const contentStyles = getContentStyles();
  const mainContentStyles = getMainContentStyles();

  const handleSidebarToggle = () => {
    setIsSidebarOpen(!isSidebarOpen);
  };

  const handleMobileMenuToggle = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const handleLogout = () => {
    setIsMobileMenuOpen(false);
    onLogout?.();
  };

  return (
    <div
      style={layoutStyles}
      className={`omni-writer-main-layout ${className}`}
      id={id}
    >
      {/* Header */}
      {showHeader && (
        <Header
          navigationItems={headerNavigation}
          onMobileMenuToggle={handleMobileMenuToggle}
          isMobileMenuOpen={isMobileMenuOpen}
          onThemeToggle={onThemeToggle}
          currentTheme={currentTheme}
          user={user}
          onLogout={handleLogout}
        />
      )}

      {/* Layout Principal */}
      <main style={mainStyles} className="omni-writer-main">
        {/* Sidebar */}
        {showSidebar && (
          <Sidebar
            navigationItems={sidebarNavigation}
            isOpen={isSidebarOpen}
            onToggle={handleSidebarToggle}
            width={sidebarConfig.width || '280px'}
            position={sidebarConfig.position || 'left'}
            variant={sidebarConfig.variant || 'default'}
            header={
              <div style={{
                fontSize: theme.typography.fontSizes.lg,
                fontWeight: theme.typography.fonts.weight.semibold,
                color: theme.colors.semantic.text.primary,
              }}>
                Menu
              </div>
            }
          />
        )}

        {/* Conteúdo Principal */}
        <div style={contentStyles} className="omni-writer-content">
          <div style={mainContentStyles} className="omni-writer-main-content">
            <Breadcrumbs />
            {children}
          </div>

          {/* Footer */}
          {showFooter && (
            <Footer
              links={footerConfig.links}
              version={footerConfig.version}
              socialLinks={footerConfig.socialLinks}
              variant={footerConfig.variant || 'default'}
            />
          )}
        </div>
      </main>
    </div>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const LayoutWithSidebar: React.FC<Omit<MainLayoutProps, 'showSidebar'>> = (props) => (
  <MainLayout {...props} showSidebar={true} />
);

export const LayoutWithoutSidebar: React.FC<Omit<MainLayoutProps, 'showSidebar'>> = (props) => (
  <MainLayout {...props} showSidebar={false} />
);

export const LayoutWithHeader: React.FC<Omit<MainLayoutProps, 'showHeader'>> = (props) => (
  <MainLayout {...props} showHeader={true} />
);

export const LayoutWithoutHeader: React.FC<Omit<MainLayoutProps, 'showHeader'>> = (props) => (
  <MainLayout {...props} showHeader={false} />
);

export const LayoutWithFooter: React.FC<Omit<MainLayoutProps, 'showFooter'>> = (props) => (
  <MainLayout {...props} showFooter={true} />
);

export const LayoutWithoutFooter: React.FC<Omit<MainLayoutProps, 'showFooter'>> = (props) => (
  <MainLayout {...props} showFooter={false} />
);

export const FullLayout: React.FC<Omit<MainLayoutProps, 'showHeader' | 'showSidebar' | 'showFooter'>> = (props) => (
  <MainLayout {...props} showHeader={true} showSidebar={true} showFooter={true} />
);

export const ContentOnlyLayout: React.FC<Omit<MainLayoutProps, 'showHeader' | 'showSidebar' | 'showFooter'>> = (props) => (
  <MainLayout {...props} showHeader={false} showSidebar={false} showFooter={false} />
);

// ===== LAYOUT PADRÃO OMNI WRITER =====
export const OmniWriterLayout: React.FC<Omit<MainLayoutProps, 'headerNavigation' | 'sidebarNavigation' | 'footerConfig'>> = (props) => {
  const defaultHeaderNavigation: HeaderNavigationItem[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      href: '/dashboard',
      active: true,
    },
    {
      id: 'articles',
      label: 'Artigos',
      href: '/articles',
    },
    {
      id: 'blogs',
      label: 'Blogs',
      href: '/blogs',
    },
    {
      id: 'categories',
      label: 'Categorias',
      href: '/categories',
    },
    {
      id: 'prompts',
      label: 'Prompts',
      href: '/prompts',
    },
  ];

  const defaultSidebarNavigation: SidebarNavigationItem[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      href: '/dashboard',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7"/>
          <rect x="14" y="3" width="7" height="7"/>
          <rect x="14" y="14" width="7" height="7"/>
          <rect x="3" y="14" width="7" height="7"/>
        </svg>
      ),
      active: true,
    },
    {
      id: 'content',
      label: 'Conteúdo',
      href: '/content',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14,2 14,8 20,8"/>
          <line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/>
          <polyline points="10,9 9,9 8,9"/>
        </svg>
      ),
      children: [
        {
          id: 'articles',
          label: 'Artigos',
          href: '/articles',
        },
        {
          id: 'blogs',
          label: 'Blogs',
          href: '/blogs',
        },
        {
          id: 'categories',
          label: 'Categorias',
          href: '/categories',
        },
      ],
    },
    {
      id: 'ai',
      label: 'Inteligência Artificial',
      href: '/ai',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 12l2 2 4-4"/>
          <path d="M21 12c-1 0-2-1-2-2s1-2 2-2 2 1 2 2-1 2-2 2z"/>
          <path d="M3 12c1 0 2-1 2-2s-1-2-2-2-2 1-2 2 1 2 2 2z"/>
          <path d="M12 3c0 1-1 2-2 2s-2-1-2-2 1-2 2-2 2 1 2 2z"/>
          <path d="M12 21c0-1 1-2 2-2s2 1 2 2-1 2-2 2-2-1-2-2z"/>
        </svg>
      ),
      children: [
        {
          id: 'prompts',
          label: 'Prompts',
          href: '/prompts',
        },
        {
          id: 'pipeline',
          label: 'Pipeline',
          href: '/pipeline',
        },
        {
          id: 'monitoring',
          label: 'Monitoramento',
          href: '/monitoring',
        },
      ],
    },
    {
      id: 'settings',
      label: 'Configurações',
      href: '/settings',
      icon: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3"/>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1 1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
      ),
    },
  ];

  const defaultFooterConfig = {
    links: [
      { id: 'docs', label: 'Documentação', href: '/docs', external: false },
      { id: 'support', label: 'Suporte', href: '/support', external: false },
      { id: 'privacy', label: 'Privacidade', href: '/privacy', external: false },
      { id: 'terms', label: 'Termos', href: '/terms', external: false },
    ],
    version: '3.5.0',
    variant: 'default' as const,
  };

  return (
    <MainLayout
      {...props}
      headerNavigation={defaultHeaderNavigation}
      sidebarNavigation={defaultSidebarNavigation}
      footerConfig={defaultFooterConfig}
    />
  );
};

// ===== EXPORTAÇÃO =====
MainLayout.displayName = 'MainLayout';
export default MainLayout; 