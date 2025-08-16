/**
 * Componente Footer - Omni Writer
 * 
 * Rodapé com informações e links
 * Acessível e responsivo
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

import React from 'react';
import { theme } from '../theme';

// ===== TIPOS =====
interface FooterProps {
  /** Links do footer */
  links?: FooterLink[];
  /** Informações de copyright */
  copyright?: string;
  /** Versão da aplicação */
  version?: string;
  /** Links sociais */
  socialLinks?: SocialLink[];
  /** Conteúdo customizado */
  children?: React.ReactNode;
  /** Variante do footer */
  variant?: 'default' | 'minimal' | 'extended';
  /** Classe CSS adicional */
  className?: string;
  /** ID do elemento */
  id?: string;
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
const getFooterStyles = (variant: string) => {
  const baseStyles = {
    backgroundColor: theme.colors.semantic.background.secondary,
    borderTop: `1px solid ${theme.colors.semantic.border.primary}`,
    padding: `${theme.spacing.spacing[24]} ${theme.spacing.spacing[24]}`,
    display: 'flex',
    flexDirection: 'column' as const,
    gap: theme.spacing.spacing[16],
  };

  const variantStyles = {
    default: {
      padding: `${theme.spacing.spacing[24]} ${theme.spacing.spacing[24]}`,
    },
    minimal: {
      padding: `${theme.spacing.spacing[16]} ${theme.spacing.spacing[24]}`,
    },
    extended: {
      padding: `${theme.spacing.spacing[32]} ${theme.spacing.spacing[24]}`,
    },
  };

  return {
    ...baseStyles,
    ...variantStyles[variant as keyof typeof variantStyles],
  };
};

const getContentStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap' as const,
    gap: theme.spacing.spacing[16],
  };
};

const getLinksStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[24],
    flexWrap: 'wrap' as const,
  };
};

const getLinkStyles = () => {
  return {
    color: theme.colors.semantic.text.secondary,
    textDecoration: 'none',
    fontSize: theme.typography.fontSizes.sm,
    transition: 'color 0.2s ease-in-out',
    cursor: 'pointer',
  };
};

const getSocialLinksStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing.spacing[12],
  };
};

const getSocialLinkStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    borderRadius: theme.spacing.spacing[4],
    backgroundColor: 'transparent',
    color: theme.colors.semantic.text.secondary,
    textDecoration: 'none',
    transition: 'all 0.2s ease-in-out',
    cursor: 'pointer',
  };
};

const getCopyrightStyles = () => {
  return {
    color: theme.colors.semantic.text.secondary,
    fontSize: theme.typography.fontSizes.sm,
    margin: 0,
  };
};

const getVersionStyles = () => {
  return {
    color: theme.colors.semantic.text.disabled,
    fontSize: theme.typography.fontSizes.xs,
    margin: 0,
  };
};

const getBottomStyles = () => {
  return {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap' as const,
    gap: theme.spacing.spacing[16],
    paddingTop: theme.spacing.spacing[16],
    borderTop: `1px solid ${theme.colors.semantic.border.primary}`,
  };
};

// ===== COMPONENTE =====
export const Footer: React.FC<FooterProps> = ({
  links = [],
  copyright = '© 2025 Omni Writer. Todos os direitos reservados.',
  version,
  socialLinks = [],
  children,
  variant = 'default',
  className = '',
  id,
}) => {
  const footerStyles = getFooterStyles(variant);
  const contentStyles = getContentStyles();
  const linksStyles = getLinksStyles();
  const linkStyles = getLinkStyles();
  const socialLinksStyles = getSocialLinksStyles();
  const socialLinkStyles = getSocialLinkStyles();
  const copyrightStyles = getCopyrightStyles();
  const versionStyles = getVersionStyles();
  const bottomStyles = getBottomStyles();

  const handleLinkClick = (link: FooterLink | SocialLink) => {
    if (link.external) {
      window.open(link.href, '_blank', 'noopener,noreferrer');
    } else {
      window.location.href = link.href;
    }
  };

  return (
    <footer
      style={footerStyles}
      className={`omni-writer-footer omni-writer-footer--${variant} ${className}`}
      id={id}
      role="contentinfo"
    >
      {/* Conteúdo Principal */}
      <div style={contentStyles} className="omni-writer-footer-content">
        {/* Links */}
        {links.length > 0 && (
          <nav style={linksStyles} className="omni-writer-footer-links" role="navigation" aria-label="Links do rodapé">
            {links.map((link) => (
              <a
                key={link.id}
                href={link.href}
                onClick={(e) => {
                  e.preventDefault();
                  handleLinkClick(link);
                }}
                style={linkStyles}
                className="omni-writer-footer-link"
                target={link.external ? '_blank' : undefined}
                rel={link.external ? 'noopener noreferrer' : undefined}
              >
                {link.label}
              </a>
            ))}
          </nav>
        )}

        {/* Links Sociais */}
        {socialLinks.length > 0 && (
          <div style={socialLinksStyles} className="omni-writer-footer-social">
            {socialLinks.map((link) => (
              <a
                key={link.id}
                href={link.href}
                onClick={(e) => {
                  e.preventDefault();
                  handleLinkClick(link);
                }}
                style={socialLinkStyles}
                className="omni-writer-footer-social-link"
                aria-label={link.label}
                target={link.external ? '_blank' : undefined}
                rel={link.external ? 'noopener noreferrer' : undefined}
              >
                {link.icon}
              </a>
            ))}
          </div>
        )}
      </div>

      {/* Conteúdo Customizado */}
      {children && (
        <div className="omni-writer-footer-custom">
          {children}
        </div>
      )}

      {/* Rodapé Inferior */}
      <div style={bottomStyles} className="omni-writer-footer-bottom">
        <p style={copyrightStyles} className="omni-writer-footer-copyright">
          {copyright}
        </p>
        {version && (
          <p style={versionStyles} className="omni-writer-footer-version">
            v{version}
          </p>
        )}
      </div>
    </footer>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====
export const MinimalFooter: React.FC<Omit<FooterProps, 'variant'>> = (props) => (
  <Footer {...props} variant="minimal" />
);

export const ExtendedFooter: React.FC<Omit<FooterProps, 'variant'>> = (props) => (
  <Footer {...props} variant="extended" />
);

// ===== FOOTER PADRÃO OMNI WRITER =====
export const OmniWriterFooter: React.FC<Omit<FooterProps, 'links' | 'copyright' | 'socialLinks'>> = (props) => {
  const defaultLinks: FooterLink[] = [
    { id: 'docs', label: 'Documentação', href: '/docs', external: false },
    { id: 'support', label: 'Suporte', href: '/support', external: false },
    { id: 'privacy', label: 'Privacidade', href: '/privacy', external: false },
    { id: 'terms', label: 'Termos', href: '/terms', external: false },
  ];

  const defaultSocialLinks: SocialLink[] = [
    {
      id: 'github',
      label: 'GitHub',
      href: 'https://github.com/omni-writer',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
        </svg>
      ),
      external: true,
    },
    {
      id: 'twitter',
      label: 'Twitter',
      href: 'https://twitter.com/omni_writer',
      icon: (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
        </svg>
      ),
      external: true,
    },
  ];

  return (
    <Footer
      {...props}
      links={defaultLinks}
      copyright="© 2025 Omni Writer. Todos os direitos reservados."
      socialLinks={defaultSocialLinks}
    />
  );
};

// ===== EXPORTAÇÃO =====
Footer.displayName = 'Footer';
export default Footer; 