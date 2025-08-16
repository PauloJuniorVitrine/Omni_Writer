import { useState, useEffect, useCallback } from 'react';
import { useTypedApi } from './useTypedApi';

// Tipos baseados no código real
interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  user: any | null;
  loading: boolean;
  error: string | null;
}

interface LoginCredentials {
  api_key: string;
}

interface AuthContextType extends AuthState {
  login: (credentials: LoginCredentials) => Promise<boolean>;
  logout: () => void;
  validateToken: () => Promise<boolean>;
  refreshToken: () => Promise<boolean>;
}

// Configuração baseada no código real
const AUTH_CONFIG = {
  tokenKey: 'omni_writer_auth_token',
  refreshInterval: 5 * 60 * 1000, // 5 minutos
  tokenExpiryThreshold: 10 * 60 * 1000, // 10 minutos
};

export const useAuth = (): AuthContextType => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    token: null,
    user: null,
    loading: true,
    error: null,
  });

  const { generation } = useTypedApi();

  // Carregar token do localStorage na inicialização
  useEffect(() => {
    const loadStoredToken = () => {
      try {
        const storedToken = localStorage.getItem(AUTH_CONFIG.tokenKey);
        if (storedToken) {
          setAuthState(prev => ({
            ...prev,
            token: storedToken,
            isAuthenticated: true,
            loading: false,
          }));
          
          // Validar token imediatamente
          validateToken(storedToken);
        } else {
          setAuthState(prev => ({
            ...prev,
            loading: false,
          }));
        }
      } catch (error) {
        console.error('Erro ao carregar token:', error);
        setAuthState(prev => ({
          ...prev,
          loading: false,
          error: 'Erro ao carregar autenticação',
        }));
      }
    };

    loadStoredToken();
  }, []);

  // Configurar refresh automático do token
  useEffect(() => {
    if (!authState.isAuthenticated) return;

    const interval = setInterval(() => {
      refreshToken();
    }, AUTH_CONFIG.refreshInterval);

    return () => clearInterval(interval);
  }, [authState.isAuthenticated]);

  // Função para validar token
  const validateToken = useCallback(async (token?: string): Promise<boolean> => {
    const tokenToValidate = token || authState.token;
    
    if (!tokenToValidate) {
      setAuthState(prev => ({
        ...prev,
        isAuthenticated: false,
        user: null,
        error: 'Token não encontrado',
      }));
      return false;
    }

    try {
      // Testar token fazendo uma requisição de teste
      // Baseado no código real do sistema
      const testRequest = {
        api_key: tokenToValidate,
        model_type: 'openai' as const,
        prompts: ['Teste de validação de token'],
        temperature: 0.1,
        max_tokens: 10,
      };

      // Tentar fazer uma requisição de teste
      await generation.generateArticles(testRequest);
      
      setAuthState(prev => ({
        ...prev,
        isAuthenticated: true,
        error: null,
      }));
      
      return true;
    } catch (error: any) {
      console.error('Erro na validação do token:', error);
      
      // Se o erro for de autenticação, limpar token
      if (error.response?.status === 401 || error.response?.status === 403) {
        logout();
        return false;
      }
      
      setAuthState(prev => ({
        ...prev,
        error: 'Erro na validação do token',
      }));
      
      return false;
    }
  }, [authState.token, generation]);

  // Função para fazer login
  const login = useCallback(async (credentials: LoginCredentials): Promise<boolean> => {
    setAuthState(prev => ({
      ...prev,
      loading: true,
      error: null,
    }));

    try {
      // Validar credenciais fazendo uma requisição de teste
      const testRequest = {
        api_key: credentials.api_key,
        model_type: 'openai' as const,
        prompts: ['Teste de login'],
        temperature: 0.1,
        max_tokens: 10,
      };

      await generation.generateArticles(testRequest);
      
      // Se chegou até aqui, o token é válido
      const token = credentials.api_key;
      
      // Salvar token no localStorage
      localStorage.setItem(AUTH_CONFIG.tokenKey, token);
      
      setAuthState({
        isAuthenticated: true,
        token,
        user: { api_key: token }, // Informações básicas do usuário
        loading: false,
        error: null,
      });
      
      return true;
    } catch (error: any) {
      console.error('Erro no login:', error);
      
      let errorMessage = 'Erro no login';
      
      if (error.response?.status === 401) {
        errorMessage = 'API key inválida';
      } else if (error.response?.status === 429) {
        errorMessage = 'Limite de requisições excedido';
      } else if (error.response?.status >= 500) {
        errorMessage = 'Erro no servidor';
      }
      
      setAuthState(prev => ({
        ...prev,
        isAuthenticated: false,
        token: null,
        user: null,
        loading: false,
        error: errorMessage,
      }));
      
      return false;
    }
  }, [generation]);

  // Função para fazer logout
  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_CONFIG.tokenKey);
    
    setAuthState({
      isAuthenticated: false,
      token: null,
      user: null,
      loading: false,
      error: null,
    });
  }, []);

  // Função para refresh do token
  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (!authState.token) return false;
    
    return await validateToken(authState.token);
  }, [authState.token, validateToken]);

  // Hook para verificar se token está próximo de expirar
  const isTokenExpiringSoon = useCallback(() => {
    // Como o sistema usa API keys simples, não há expiração real
    // Mas podemos implementar lógica de refresh baseada em tempo de uso
    const tokenAge = localStorage.getItem('token_created_at');
    if (tokenAge) {
      const age = Date.now() - parseInt(tokenAge);
      return age > AUTH_CONFIG.tokenExpiryThreshold;
    }
    return false;
  }, []);

  // Hook para obter headers de autenticação
  const getAuthHeaders = useCallback(() => {
    if (!authState.token) return {};
    
    return {
      'Authorization': `Bearer ${authState.token}`,
      'Content-Type': 'application/json',
    };
  }, [authState.token]);

  return {
    ...authState,
    login,
    logout,
    validateToken,
    refreshToken,
  };
};

// Hook para proteção de rotas
export const useRequireAuth = (redirectTo: string = '/login') => {
  const auth = useAuth();
  
  useEffect(() => {
    if (!auth.loading && !auth.isAuthenticated) {
      // Em uma aplicação real, redirecionaria aqui
      console.log(`Redirecionando para: ${redirectTo}`);
    }
  }, [auth.loading, auth.isAuthenticated, redirectTo]);
  
  return auth;
};

// Hook para verificar permissões
export const useHasPermission = (permission: string) => {
  const auth = useAuth();
  
  // Baseado no código real, o sistema usa API keys simples
  // Permissões podem ser implementadas baseadas no tipo de API key
  const hasPermission = useCallback(() => {
    if (!auth.isAuthenticated) return false;
    
    // Lógica de permissões baseada no token/API key
    // Por enquanto, retorna true se autenticado
    return auth.isAuthenticated;
  }, [auth.isAuthenticated]);
  
  return hasPermission();
}; 