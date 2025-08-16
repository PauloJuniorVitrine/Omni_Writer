import React, { createContext, useContext, useState, ReactNode } from 'react';

/**
 * Contexto de autenticação para login/logout/token/usuário com integração backend real.
 * O login executa POST em /token/rotate (ou /login, se disponível), armazena token e usuário.
 * O logout limpa o estado local.
 * Logs estruturados de autenticação (console.info/warn).
 * @example
 * const { user, token, login, logout } = useAuth();
 */
type AuthContextType = {
  user: string | null;
  token: string | null;
  login: (user: string, password: string) => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  // Exemplo: login via /token/rotate (substitua por /login se disponível)
  const login = async (userId: string, password: string) => {
    try {
      const res = await fetch('/token/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ user_id: userId }),
      });
      if (!res.ok) throw new Error(`Erro ${res.status}`);
      const json = await res.json();
      setUser(userId);
      setToken(json.token);
      console.info('[AuthContext] Login bem-sucedido', { user: userId });
    } catch (err: any) {
      setUser(null);
      setToken(null);
      console.warn('[AuthContext] Erro no login', { user: userId, error: err });
      throw err;
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    console.info('[AuthContext] Logout executado');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth deve ser usado dentro de AuthProvider');
  return ctx;
} 