/**
 * Componente de Rota Protegida
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Verificação de autenticação
 * - Redirecionamento para login se não autenticado
 * - Verificação de permissões (futuro)
 * - Loading state durante verificação
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Loading from '../components/base/Loading';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermissions?: string[];
}

/**
 * Componente que protege rotas baseado em autenticação
 */
const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requiredPermissions = [] 
}) => {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  // Loading state durante verificação de autenticação
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loading size="large" />
      </div>
    );
  }

  // Redireciona para login se não autenticado
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Verificação de permissões (implementação futura)
  if (requiredPermissions.length > 0 && user) {
    const hasPermission = requiredPermissions.every(permission =>
      user.permissions?.includes(permission)
    );

    if (!hasPermission) {
      return <Navigate to="/unauthorized" replace />;
    }
  }

  // Renderiza o conteúdo se autenticado e autorizado
  return <>{children}</>;
};

export default ProtectedRoute; 