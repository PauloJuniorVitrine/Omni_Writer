/**
 * Hook de Navegação - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Navegação programática
 * - Histórico de navegação
 * - Verificação de permissões
 * - Breadcrumbs automáticos
 */

import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useBreadcrumbs } from '../context/BreadcrumbContext';
import { getRouteConfig, hasRoutePermission, RouteConfig } from '../router/routes';

export interface NavigationOptions {
  replace?: boolean;
  state?: any;
  permissions?: string[];
}

export interface NavigationHistory {
  path: string;
  timestamp: number;
  title: string;
}

/**
 * Hook personalizado para navegação
 */
export const useNavigation = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const { setCustomBreadcrumbs, clearCustomBreadcrumbs } = useBreadcrumbs();

  /**
   * Navega para uma rota com verificação de permissões
   */
  const navigateTo = (path: string, options: NavigationOptions = {}) => {
    const { replace = false, state, permissions = [] } = options;
    
    // Verifica permissões se especificadas
    if (permissions.length > 0) {
      const userPermissions = user?.permissions || [];
      const hasPermission = permissions.every(permission =>
        userPermissions.includes(permission)
      );
      
      if (!hasPermission) {
        navigate('/unauthorized', { replace: true });
        return;
      }
    }

    // Verifica permissões da rota
    if (!hasRoutePermission(path, user?.permissions || [])) {
      navigate('/unauthorized', { replace: true });
      return;
    }

    // Navega para a rota
    navigate(path, { replace, state });
  };

  /**
   * Navega para uma rota com breadcrumbs customizados
   */
  const navigateWithBreadcrumbs = (
    path: string, 
    customBreadcrumbs: Array<{ label: string; path: string }>,
    options: NavigationOptions = {}
  ) => {
    setCustomBreadcrumbs(customBreadcrumbs);
    navigateTo(path, options);
  };

  /**
   * Limpa breadcrumbs customizados e navega
   */
  const navigateWithAutoBreadcrumbs = (path: string, options: NavigationOptions = {}) => {
    clearCustomBreadcrumbs();
    navigateTo(path, options);
  };

  /**
   * Volta para a página anterior
   */
  const goBack = () => {
    navigate(-1);
  };

  /**
   * Vai para a próxima página no histórico
   */
  const goForward = () => {
    navigate(1);
  };

  /**
   * Navega para o dashboard
   */
  const goToDashboard = () => {
    navigateTo('/dashboard');
  };

  /**
   * Obtém informações da rota atual
   */
  const getCurrentRoute = (): RouteConfig | undefined => {
    return getRouteConfig(location.pathname);
  };

  /**
   * Verifica se está em uma rota específica
   */
  const isCurrentRoute = (path: string): boolean => {
    return location.pathname === path;
  };

  /**
   * Verifica se está em uma rota que começa com o path especificado
   */
  const isInRoute = (path: string): boolean => {
    return location.pathname.startsWith(path);
  };

  return {
    // Navegação
    navigateTo,
    navigateWithBreadcrumbs,
    navigateWithAutoBreadcrumbs,
    goBack,
    goForward,
    goToDashboard,
    
    // Informações da rota
    getCurrentRoute,
    isCurrentRoute,
    isInRoute,
    
    // Estado atual
    currentPath: location.pathname,
    currentState: location.state
  };
}; 