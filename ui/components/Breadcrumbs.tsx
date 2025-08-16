/**
 * Componente de Breadcrumbs
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Breadcrumbs dinâmicos baseados na rota atual
 * - Navegação clicável
 * - Design responsivo
 * - Integração com BreadcrumbContext
 */

import React from 'react';
import { Link } from 'react-router-dom';
import { useBreadcrumbs } from '../context/BreadcrumbContext';

/**
 * Componente de breadcrumbs
 */
const Breadcrumbs: React.FC = () => {
  const { breadcrumbs } = useBreadcrumbs();

  if (breadcrumbs.length <= 1) {
    return null;
  }

  return (
    <nav className="flex items-center space-x-2 text-sm text-gray-600 mb-4">
      {breadcrumbs.map((breadcrumb, index) => {
        const isLast = index === breadcrumbs.length - 1;
        
        return (
          <React.Fragment key={breadcrumb.path}>
            {isLast ? (
              <span className="font-medium text-gray-900">
                {breadcrumb.label}
              </span>
            ) : (
              <>
                <Link
                  to={breadcrumb.path}
                  className="hover:text-gray-900 hover:underline transition-colors"
                >
                  {breadcrumb.label}
                </Link>
                <span className="text-gray-400">/</span>
              </>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
};

export default Breadcrumbs; 