/**
 * Contexto de Breadcrumbs Dinâmicos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Breadcrumbs dinâmicos baseados na rota
 * - Mapeamento automático de rotas para labels
 * - Suporte a breadcrumbs customizados
 * - Integração com React Router
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useLocation } from 'react-router-dom';

export interface BreadcrumbItem {
  label: string;
  path: string;
  icon?: string;
}

interface BreadcrumbContextType {
  breadcrumbs: BreadcrumbItem[];
  setCustomBreadcrumbs: (breadcrumbs: BreadcrumbItem[]) => void;
  clearCustomBreadcrumbs: () => void;
}

const BreadcrumbContext = createContext<BreadcrumbContextType | undefined>(undefined);

// Mapeamento de rotas para labels
const routeLabels: Record<string, string> = {
  dashboard: 'Dashboard',
  'article-generation': 'Geração de Artigos',
  blogs: 'Blogs',
  categories: 'Categorias',
  prompts: 'Prompts',
  pipeline: 'Pipeline',
  monitoring: 'Monitoramento',
  settings: 'Configurações',
  profile: 'Perfil',
  logs: 'Logs'
};

interface BreadcrumbProviderProps {
  children: ReactNode;
}

/**
 * Provider do contexto de breadcrumbs
 */
export const BreadcrumbProvider: React.FC<BreadcrumbProviderProps> = ({ children }) => {
  const [breadcrumbs, setBreadcrumbs] = useState<BreadcrumbItem[]>([]);
  const [customBreadcrumbs, setCustomBreadcrumbsState] = useState<BreadcrumbItem[]>([]);
  const location = useLocation();

  // Gera breadcrumbs automáticos baseados na rota
  const generateBreadcrumbsFromPath = (pathname: string): BreadcrumbItem[] => {
    const segments = pathname.split('/').filter(Boolean);
    const generatedBreadcrumbs: BreadcrumbItem[] = [];

    // Sempre inclui Dashboard como primeiro item
    generatedBreadcrumbs.push({
      label: 'Dashboard',
      path: '/dashboard'
    });

    // Constrói breadcrumbs baseado nos segmentos da URL
    let currentPath = '';
    segments.forEach((segment, index) => {
      currentPath += `/${segment}`;
      
      // Pula o primeiro segmento se for 'dashboard' (já incluído)
      if (index === 0 && segment === 'dashboard') {
        return;
      }

      const label = routeLabels[segment] || segment.charAt(0).toUpperCase() + segment.slice(1);
      generatedBreadcrumbs.push({
        label,
        path: currentPath
      });
    });

    return generatedBreadcrumbs;
  };

  // Atualiza breadcrumbs quando a rota muda
  useEffect(() => {
    if (customBreadcrumbs.length > 0) {
      setBreadcrumbs(customBreadcrumbs);
    } else {
      const autoBreadcrumbs = generateBreadcrumbsFromPath(location.pathname);
      setBreadcrumbs(autoBreadcrumbs);
    }
  }, [location.pathname, customBreadcrumbs]);

  const setCustomBreadcrumbs = (newBreadcrumbs: BreadcrumbItem[]) => {
    setCustomBreadcrumbsState(newBreadcrumbs);
  };

  const clearCustomBreadcrumbs = () => {
    setCustomBreadcrumbsState([]);
  };

  const value: BreadcrumbContextType = {
    breadcrumbs,
    setCustomBreadcrumbs,
    clearCustomBreadcrumbs
  };

  return (
    <BreadcrumbContext.Provider value={value}>
      {children}
    </BreadcrumbContext.Provider>
  );
};

/**
 * Hook para usar o contexto de breadcrumbs
 */
export const useBreadcrumbs = (): BreadcrumbContextType => {
  const context = useContext(BreadcrumbContext);
  if (context === undefined) {
    throw new Error('useBreadcrumbs deve ser usado dentro de um BreadcrumbProvider');
  }
  return context;
}; 