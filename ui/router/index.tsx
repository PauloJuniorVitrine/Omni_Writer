/**
 * Sistema de Roteamento - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Lazy loading para performance
 * - Proteção de rotas com autenticação
 * - Breadcrumbs dinâmicos
 * - 404 handling
 * - Nested routes
 */

import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from '../context/AuthContext';
import { BreadcrumbProvider } from '../context/BreadcrumbContext';
import MainLayout from '../layout/MainLayout';
import Loading from '../components/base/Loading';
import ProtectedRoute from './ProtectedRoute';
import NotFound from '../pages/NotFound';

// Lazy loading das páginas para melhor performance
const Dashboard = lazy(() => import('../pages/Dashboard'));
const ArticleGeneration = lazy(() => import('../pages/ArticleGeneration'));
const Blogs = lazy(() => import('../pages/Blogs'));
const Categories = lazy(() => import('../pages/Categories'));
const Prompts = lazy(() => import('../pages/Prompts'));
const Pipeline = lazy(() => import('../pages/Pipeline'));
const Monitoring = lazy(() => import('../pages/Monitoring'));
const Settings = lazy(() => import('../pages/Settings'));
const Profile = lazy(() => import('../pages/Profile'));
const Logs = lazy(() => import('../pages/Logs'));

/**
 * Componente de loading para lazy loading
 */
const PageLoading: React.FC = () => (
  <div className="flex items-center justify-center min-h-screen">
    <Loading size="large" />
  </div>
);

/**
 * Componente principal do roteamento
 */
const AppRouter: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <BreadcrumbProvider>
          <Suspense fallback={<PageLoading />}>
            <Routes>
              {/* Rota raiz - redireciona para dashboard */}
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              
              {/* Rotas protegidas com layout principal */}
              <Route path="/" element={<MainLayout />}>
                <Route path="dashboard" element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } />
                
                <Route path="article-generation" element={
                  <ProtectedRoute>
                    <ArticleGeneration />
                  </ProtectedRoute>
                } />
                
                <Route path="blogs" element={
                  <ProtectedRoute>
                    <Blogs />
                  </ProtectedRoute>
                } />
                
                <Route path="categories" element={
                  <ProtectedRoute>
                    <Categories />
                  </ProtectedRoute>
                } />
                
                <Route path="prompts" element={
                  <ProtectedRoute>
                    <Prompts />
                  </ProtectedRoute>
                } />
                
                <Route path="pipeline" element={
                  <ProtectedRoute>
                    <Pipeline />
                  </ProtectedRoute>
                } />
                
                <Route path="monitoring" element={
                  <ProtectedRoute>
                    <Monitoring />
                  </ProtectedRoute>
                } />
                
                <Route path="settings" element={
                  <ProtectedRoute>
                    <Settings />
                  </ProtectedRoute>
                } />
                
                <Route path="profile" element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                } />
                
                <Route path="logs" element={
                  <ProtectedRoute>
                    <Logs />
                  </ProtectedRoute>
                } />
              </Route>
              
              {/* Rota 404 - deve ser a última */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </BreadcrumbProvider>
      </AuthProvider>
    </BrowserRouter>
  );
};

export default AppRouter; 