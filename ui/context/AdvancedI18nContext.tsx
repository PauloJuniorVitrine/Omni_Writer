/**
 * AdvancedI18nContext - Contexto de Internacionalização Avançado
 * =============================================================
 * 
 * Implementa sistema de internacionalização avançado com:
 * - Troca de idioma em tempo real
 * - Detecção automática de idioma
 * - Formatação de datas e números
 * - Suporte a múltiplos idiomas
 * - Tradução de feedbacks e logs
 * 
 * Autor: Análise Técnica Omni Writer
 * Data: 2025-01-27
 * Versão: 1.0
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';

// Tipos de idiomas suportados
export type SupportedLanguage = 'pt-BR' | 'en-US' | 'es-ES' | 'fr-FR' | 'de-DE' | 'it-IT' | 'ja-JP' | 'ko-KR' | 'zh-CN';

// Configurações de idiomas
export interface LanguageConfig {
  code: SupportedLanguage;
  name: string;
  nativeName: string;
  flag: string;
  dateFormat: string;
  numberFormat: {
    decimal: string;
    thousands: string;
    currency: string;
  };
  direction: 'ltr' | 'rtl';
}

// Configurações de todos os idiomas
export const LANGUAGE_CONFIGS: Record<SupportedLanguage, LanguageConfig> = {
  'pt-BR': {
    code: 'pt-BR',
    name: 'Portuguese (Brazil)',
    nativeName: 'Português (Brasil)',
    flag: '🇧🇷',
    dateFormat: 'dd/MM/yyyy',
    numberFormat: {
      decimal: ',',
      thousands: '.',
      currency: 'R$'
    },
    direction: 'ltr'
  },
  'en-US': {
    code: 'en-US',
    name: 'English (US)',
    nativeName: 'English (US)',
    flag: '🇺🇸',
    dateFormat: 'MM/dd/yyyy',
    numberFormat: {
      decimal: '.',
      thousands: ',',
      currency: '$'
    },
    direction: 'ltr'
  },
  'es-ES': {
    code: 'es-ES',
    name: 'Spanish (Spain)',
    nativeName: 'Español (España)',
    flag: '🇪🇸',
    dateFormat: 'dd/MM/yyyy',
    numberFormat: {
      decimal: ',',
      thousands: '.',
      currency: '€'
    },
    direction: 'ltr'
  },
  'fr-FR': {
    code: 'fr-FR',
    name: 'French (France)',
    nativeName: 'Français (France)',
    flag: '🇫🇷',
    dateFormat: 'dd/MM/yyyy',
    numberFormat: {
      decimal: ',',
      thousands: ' ',
      currency: '€'
    },
    direction: 'ltr'
  },
  'de-DE': {
    code: 'de-DE',
    name: 'German (Germany)',
    nativeName: 'Deutsch (Deutschland)',
    flag: '🇩🇪',
    dateFormat: 'dd.MM.yyyy',
    numberFormat: {
      decimal: ',',
      thousands: '.',
      currency: '€'
    },
    direction: 'ltr'
  },
  'it-IT': {
    code: 'it-IT',
    name: 'Italian (Italy)',
    nativeName: 'Italiano (Italia)',
    flag: '🇮🇹',
    dateFormat: 'dd/MM/yyyy',
    numberFormat: {
      decimal: ',',
      thousands: '.',
      currency: '€'
    },
    direction: 'ltr'
  },
  'ja-JP': {
    code: 'ja-JP',
    name: 'Japanese (Japan)',
    nativeName: '日本語 (日本)',
    flag: '🇯🇵',
    dateFormat: 'yyyy/MM/dd',
    numberFormat: {
      decimal: '.',
      thousands: ',',
      currency: '¥'
    },
    direction: 'ltr'
  },
  'ko-KR': {
    code: 'ko-KR',
    name: 'Korean (South Korea)',
    nativeName: '한국어 (대한민국)',
    flag: '🇰🇷',
    dateFormat: 'yyyy-MM-dd',
    numberFormat: {
      decimal: '.',
      thousands: ',',
      currency: '₩'
    },
    direction: 'ltr'
  },
  'zh-CN': {
    code: 'zh-CN',
    name: 'Chinese (Simplified)',
    nativeName: '中文 (简体)',
    flag: '🇨🇳',
    dateFormat: 'yyyy-MM-dd',
    numberFormat: {
      decimal: '.',
      thousands: ',',
      currency: '¥'
    },
    direction: 'ltr'
  }
};

// Interface do contexto
interface AdvancedI18nContextType {
  currentLanguage: SupportedLanguage;
  languageConfig: LanguageConfig;
  translations: Record<string, any>;
  isLoading: boolean;
  changeLanguage: (language: SupportedLanguage) => Promise<void>;
  t: (key: string, params?: Record<string, any>) => string;
  formatDate: (date: Date | string, options?: Intl.DateTimeFormatOptions) => string;
  formatNumber: (number: number, options?: Intl.NumberFormatOptions) => string;
  formatCurrency: (amount: number, currency?: string) => string;
  formatRelativeTime: (date: Date | string) => string;
  detectLanguage: () => SupportedLanguage;
  getSupportedLanguages: () => LanguageConfig[];
  isRTL: boolean;
}

// Contexto
const AdvancedI18nContext = createContext<AdvancedI18nContextType | undefined>(undefined);

// Provider do contexto
interface AdvancedI18nProviderProps {
  children: ReactNode;
  defaultLanguage?: SupportedLanguage;
  fallbackLanguage?: SupportedLanguage;
}

export const AdvancedI18nProvider: React.FC<AdvancedI18nProviderProps> = ({
  children,
  defaultLanguage = 'pt-BR',
  fallbackLanguage = 'en-US'
}) => {
  const [currentLanguage, setCurrentLanguage] = useState<SupportedLanguage>(defaultLanguage);
  const [translations, setTranslations] = useState<Record<string, any>>({});
  const [isLoading, setIsLoading] = useState(true);

  // Configuração do idioma atual
  const languageConfig = LANGUAGE_CONFIGS[currentLanguage];
  const isRTL = languageConfig.direction === 'rtl';

  // Carrega traduções
  const loadTranslations = useCallback(async (language: SupportedLanguage) => {
    setIsLoading(true);
    try {
      // Simula carregamento de traduções (em produção seria uma API)
      const response = await fetch(`/api/translations/${language}`);
      if (response.ok) {
        const data = await response.json();
        setTranslations(data);
      } else {
        // Fallback para traduções locais
        const fallbackTranslations = await import(`../locales/${language}.json`);
        setTranslations(fallbackTranslations.default);
      }
    } catch (error) {
      console.warn(`Failed to load translations for ${language}:`, error);
      // Carrega traduções de fallback
      try {
        const fallbackTranslations = await import(`../locales/${fallbackLanguage}.json`);
        setTranslations(fallbackTranslations.default);
      } catch (fallbackError) {
        console.error('Failed to load fallback translations:', fallbackError);
        setTranslations({});
      }
    } finally {
      setIsLoading(false);
    }
  }, [fallbackLanguage]);

  // Detecta idioma do navegador
  const detectLanguage = useCallback((): SupportedLanguage => {
    const browserLanguage = navigator.language || navigator.languages?.[0] || 'en-US';
    const languageCode = browserLanguage.split('-')[0];
    
    // Mapeia códigos de idioma para idiomas suportados
    const languageMap: Record<string, SupportedLanguage> = {
      'pt': 'pt-BR',
      'en': 'en-US',
      'es': 'es-ES',
      'fr': 'fr-FR',
      'de': 'de-DE',
      'it': 'it-IT',
      'ja': 'ja-JP',
      'ko': 'ko-KR',
      'zh': 'zh-CN'
    };
    
    return languageMap[languageCode] || fallbackLanguage;
  }, [fallbackLanguage]);

  // Inicialização
  useEffect(() => {
    const savedLanguage = localStorage.getItem('omni-writer-language') as SupportedLanguage;
    const detectedLanguage = detectLanguage();
    const initialLanguage = savedLanguage || detectedLanguage;
    
    setCurrentLanguage(initialLanguage);
    loadTranslations(initialLanguage);
    
    // Aplica direção do texto
    document.documentElement.dir = LANGUAGE_CONFIGS[initialLanguage].direction;
    document.documentElement.lang = initialLanguage;
  }, [detectLanguage, loadTranslations]);

  // Função de tradução com interpolação
  const t = useCallback((key: string, params?: Record<string, any>): string => {
    const translation = translations[key] || key;
    
    if (params && typeof translation === 'string') {
      return translation.replace(/\{(\w+)\}/g, (match, param) => {
        return params[param] !== undefined ? String(params[param]) : match;
      });
    }
    
    return translation;
  }, [translations]);

  // Formatação de data
  const formatDate = useCallback((date: Date | string, options?: Intl.DateTimeFormatOptions): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const locale = currentLanguage.replace('-', '_');
    
    const defaultOptions: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      ...options
    };
    
    return new Intl.DateTimeFormat(locale, defaultOptions).format(dateObj);
  }, [currentLanguage]);

  // Formatação de números
  const formatNumber = useCallback((number: number, options?: Intl.NumberFormatOptions): string => {
    const locale = currentLanguage.replace('-', '_');
    
    const defaultOptions: Intl.NumberFormatOptions = {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
      ...options
    };
    
    return new Intl.NumberFormat(locale, defaultOptions).format(number);
  }, [currentLanguage]);

  // Formatação de moeda
  const formatCurrency = useCallback((amount: number, currency?: string): string => {
    const locale = currentLanguage.replace('-', '_');
    const currencyCode = currency || languageConfig.numberFormat.currency;
    
    return new Intl.NumberFormat(locale, {
      style: 'currency',
      currency: currencyCode
    }).format(amount);
  }, [currentLanguage, languageConfig.numberFormat.currency]);

  // Tempo relativo
  const formatRelativeTime = useCallback((date: Date | string): string => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);
    
    const locale = currentLanguage.replace('-', '_');
    const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
    
    if (diffInSeconds < 60) {
      return rtf.format(-diffInSeconds, 'second');
    } else if (diffInSeconds < 3600) {
      return rtf.format(-Math.floor(diffInSeconds / 60), 'minute');
    } else if (diffInSeconds < 86400) {
      return rtf.format(-Math.floor(diffInSeconds / 3600), 'hour');
    } else if (diffInSeconds < 2592000) {
      return rtf.format(-Math.floor(diffInSeconds / 86400), 'day');
    } else if (diffInSeconds < 31536000) {
      return rtf.format(-Math.floor(diffInSeconds / 2592000), 'month');
    } else {
      return rtf.format(-Math.floor(diffInSeconds / 31536000), 'year');
    }
  }, [currentLanguage]);

  // Troca de idioma
  const changeLanguage = useCallback(async (language: SupportedLanguage) => {
    if (language === currentLanguage) return;
    
    setCurrentLanguage(language);
    localStorage.setItem('omni-writer-language', language);
    
    // Aplica direção do texto
    document.documentElement.dir = LANGUAGE_CONFIGS[language].direction;
    document.documentElement.lang = language;
    
    // Carrega novas traduções
    await loadTranslations(language);
    
    // Dispara evento de mudança de idioma
    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { language } }));
  }, [currentLanguage, loadTranslations]);

  // Lista de idiomas suportados
  const getSupportedLanguages = useCallback((): LanguageConfig[] => {
    return Object.values(LANGUAGE_CONFIGS);
  }, []);

  const contextValue: AdvancedI18nContextType = {
    currentLanguage,
    languageConfig,
    translations,
    isLoading,
    changeLanguage,
    t,
    formatDate,
    formatNumber,
    formatCurrency,
    formatRelativeTime,
    detectLanguage,
    getSupportedLanguages,
    isRTL
  };

  return (
    <AdvancedI18nContext.Provider value={contextValue}>
      {children}
    </AdvancedI18nContext.Provider>
  );
};

// Hook para usar o contexto
export const useAdvancedI18n = (): AdvancedI18nContextType => {
  const context = useContext(AdvancedI18nContext);
  if (context === undefined) {
    throw new Error('useAdvancedI18n must be used within an AdvancedI18nProvider');
  }
  return context;
};

// Componente de carregamento de traduções
export const TranslationLoader: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { isLoading } = useAdvancedI18n();

  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        height: '100vh',
        fontSize: '16px',
        color: 'var(--color-primary)'
      }}>
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '12px'
        }}>
          <div style={{
            width: '32px',
            height: '32px',
            border: '3px solid var(--color-border)',
            borderTop: '3px solid var(--color-accent)',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite'
          }} />
          <span>Carregando traduções...</span>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

// Componente de seletor de idioma avançado
export const AdvancedLanguageSelector: React.FC = () => {
  const { 
    currentLanguage, 
    languageConfig, 
    changeLanguage, 
    getSupportedLanguages,
    t 
  } = useAdvancedI18n();
  
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const supportedLanguages = getSupportedLanguages();
  const filteredLanguages = supportedLanguages.filter(lang =>
    lang.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    lang.nativeName.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleLanguageChange = async (language: SupportedLanguage) => {
    await changeLanguage(language);
    setIsOpen(false);
    setSearchTerm('');
  };

  return (
    <div className="advanced-language-selector" style={{ position: 'relative' }}>
      {/* Botão principal */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 12px',
          border: '1px solid var(--color-border)',
          borderRadius: '6px',
          backgroundColor: 'var(--color-surface)',
          color: 'var(--color-primary)',
          cursor: 'pointer',
          fontSize: '14px',
          fontWeight: '500'
        }}
        aria-label={t('language.selector.label')}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
      >
        <span style={{ fontSize: '16px' }}>{languageConfig.flag}</span>
        <span>{languageConfig.nativeName}</span>
        <span style={{ fontSize: '12px' }}>▼</span>
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            right: 0,
            backgroundColor: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            borderRadius: '6px',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
            zIndex: 1000,
            maxHeight: '300px',
            overflow: 'hidden'
          }}
        >
          {/* Campo de busca */}
          <div style={{ padding: '8px' }}>
            <input
              type="text"
              placeholder={t('language.selector.search')}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 8px',
                border: '1px solid var(--color-border)',
                borderRadius: '4px',
                fontSize: '12px',
                backgroundColor: 'var(--color-background)',
                color: 'var(--color-primary)'
              }}
            />
          </div>

          {/* Lista de idiomas */}
          <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {filteredLanguages.map((lang) => (
              <button
                key={lang.code}
                onClick={() => handleLanguageChange(lang.code)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  width: '100%',
                  padding: '8px 12px',
                  border: 'none',
                  backgroundColor: lang.code === currentLanguage ? 'var(--color-accent)' : 'transparent',
                  color: lang.code === currentLanguage ? 'white' : 'var(--color-primary)',
                  cursor: 'pointer',
                  fontSize: '14px',
                  textAlign: 'left'
                }}
                role="option"
                aria-selected={lang.code === currentLanguage}
              >
                <span style={{ fontSize: '16px' }}>{lang.flag}</span>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
                  <span style={{ fontWeight: '500' }}>{lang.nativeName}</span>
                  <span style={{ fontSize: '12px', opacity: 0.7 }}>{lang.name}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Overlay para fechar */}
      {isOpen && (
        <div
          onClick={() => setIsOpen(false)}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 999
          }}
        />
      )}
    </div>
  );
};

export default AdvancedI18nContext; 