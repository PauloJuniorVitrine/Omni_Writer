/**
 * Página 404 - Página não encontrada
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Design consistente com o sistema
 * - Navegação de volta para páginas principais
 * - Mensagem amigável e útil
 */

import React from 'react';
import { Link } from 'react-router-dom';
import Button from '../components/base/Button';
import Card from '../components/base/Card';

/**
 * Página 404 personalizada
 */
const NotFound: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <Card className="max-w-md w-full mx-4 text-center">
        <div className="mb-8">
          <div className="text-6xl font-bold text-gray-300 mb-4">404</div>
          <h1 className="text-2xl font-semibold text-gray-800 mb-2">
            Página não encontrada
          </h1>
          <p className="text-gray-600 mb-6">
            A página que você está procurando não existe ou foi movida.
          </p>
        </div>

        <div className="space-y-4">
          <Link to="/dashboard">
            <Button variant="primary" className="w-full">
              Voltar ao Dashboard
            </Button>
          </Link>
          
          <div className="text-sm text-gray-500">
            Ou navegue para:
          </div>
          
          <div className="flex flex-wrap gap-2 justify-center">
            <Link to="/blogs">
              <Button variant="secondary" size="small">
                Blogs
              </Button>
            </Link>
            <Link to="/categories">
              <Button variant="secondary" size="small">
                Categorias
              </Button>
            </Link>
            <Link to="/article-generation">
              <Button variant="secondary" size="small">
                Gerar Artigo
              </Button>
            </Link>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-xs text-gray-400">
            Se você acredita que isso é um erro, entre em contato com o suporte.
          </p>
        </div>
      </Card>
    </div>
  );
};

export default NotFound; 