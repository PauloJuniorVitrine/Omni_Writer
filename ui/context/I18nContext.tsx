import React, { createContext, useContext, ReactNode } from 'react';
import { useI18n } from '../hooks/use_i18n';

interface I18nContextType {
  t: (key: string, variables?: Record<string, any>) => string;
  lang: string;
  setLang: (lang: string) => void;
  languages: readonly string[];
  languageConfig: {
    name: string;
    nativeName: string;
    flag: string;
    direction: 'ltr' | 'rtl';
    dateFormat: string;
    timeFormat: string;
    currency: string;
  };
  availableLanguages: Array<{
    code: string;
    name: string;
    nativeName: string;
    flag: string;
    direction: 'ltr' | 'rtl';
    dateFormat: string;
    timeFormat: string;
    currency: string;
  }>;
  formatDate: (date: Date) => string;
  formatTime: (date: Date) => string;
  formatNumber: (number: number) => string;
  formatCurrency: (amount: number) => string;
  formatPlural: (count: number, singular: string, plural: string) => string;
  detectLanguage: (text: string) => string;
}

const I18nContext = createContext<I18nContextType | undefined>(undefined);

interface I18nProviderProps {
  children: ReactNode;
}

/**
 * Provider do contexto de internacionalização.
 * Fornece funcionalidades de i18n para toda a aplicação.
 */
export const I18nProvider: React.FC<I18nProviderProps> = ({ children }) => {
  const i18n = useI18n();

  return (
    <I18nContext.Provider value={i18n}>
      {children}
    </I18nContext.Provider>
  );
};

/**
 * Hook para usar o contexto de i18n.
 * Deve ser usado dentro de um I18nProvider.
 */
export const useI18nContext = (): I18nContextType => {
  const context = useContext(I18nContext);
  if (context === undefined) {
    throw new Error('useI18nContext deve ser usado dentro de um I18nProvider');
  }
  return context;
};

export default I18nProvider; 