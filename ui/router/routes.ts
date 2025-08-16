/**
 * Configuração de Rotas - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Definição centralizada de rotas
 * - Metadados das rotas (título, ícone, permissões)
 * - Configuração de breadcrumbs
 * - Lazy loading configurado
 */

export interface RouteConfig {
  path: string;
  title: string;
  icon?: string;
  permissions?: string[];
  breadcrumb?: string;
  children?: RouteConfig[];
}

/**
 * Configuração das rotas da aplicação
 */
export const routes: RouteConfig[] = [
  {
    path: '/dashboard',
    title: 'Dashboard',
    icon: 'dashboard',
    breadcrumb: 'Dashboard'
  },
  {
    path: '/article-generation',
    title: 'Geração de Artigos',
    icon: 'article',
    breadcrumb: 'Geração de Artigos'
  },
  {
    path: '/blogs',
    title: 'Blogs',
    icon: 'blog',
    breadcrumb: 'Blogs'
  },
  {
    path: '/categories',
    title: 'Categorias',
    icon: 'category',
    breadcrumb: 'Categorias'
  },
  {
    path: '/prompts',
    title: 'Prompts',
    icon: 'prompt',
    breadcrumb: 'Prompts'
  },
  {
    path: '/pipeline',
    title: 'Pipeline',
    icon: 'pipeline',
    breadcrumb: 'Pipeline'
  },
  {
    path: '/monitoring',
    title: 'Monitoramento',
    icon: 'monitoring',
    breadcrumb: 'Monitoramento'
  },
  {
    path: '/settings',
    title: 'Configurações',
    icon: 'settings',
    breadcrumb: 'Configurações'
  },
  {
    path: '/profile',
    title: 'Perfil',
    icon: 'profile',
    breadcrumb: 'Perfil'
  },
  {
    path: '/logs',
    title: 'Logs',
    icon: 'logs',
    breadcrumb: 'Logs'
  }
];

/**
 * Função para obter configuração de rota por path
 */
export const getRouteConfig = (path: string): RouteConfig | undefined => {
  return routes.find(route => route.path === path);
};

/**
 * Função para obter breadcrumb de uma rota
 */
export const getRouteBreadcrumb = (path: string): string => {
  const route = getRouteConfig(path);
  return route?.breadcrumb || route?.title || 'Página';
};

/**
 * Função para verificar se usuário tem permissão para a rota
 */
export const hasRoutePermission = (path: string, userPermissions: string[] = []): boolean => {
  const route = getRouteConfig(path);
  if (!route?.permissions) return true;
  
  return route.permissions.every(permission => 
    userPermissions.includes(permission)
  );
}; 