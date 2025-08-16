import { useState, useCallback, useEffect } from 'react';

const LANGS = ['pt_BR', 'en_US', 'es_ES', 'fr_FR'] as const;
type Lang = typeof LANGS[number];

const translations: Record<Lang, Record<string, string>> = {
  pt_BR: require('../../shared/i18n/pt_BR.json'),
  en_US: require('../../shared/i18n/en_US.json'),
  es_ES: require('../../shared/i18n/es_ES.json'),
  fr_FR: require('../../shared/i18n/fr_FR.json'),
};

// Configurações de idiomas
const languageConfig = {
  pt_BR: {
    name: "Português (Brasil)",
    nativeName: "Português (Brasil)",
    flag: "🇧🇷",
    direction: "ltr" as const,
    dateFormat: "dd/MM/yyyy",
    timeFormat: "HH:mm",
    currency: "BRL"
  },
  en_US: {
    name: "English (US)",
    nativeName: "English (US)",
    flag: "🇺🇸",
    direction: "ltr" as const,
    dateFormat: "MM/dd/yyyy",
    timeFormat: "HH:mm",
    currency: "USD"
  },
  es_ES: {
    name: "Español (España)",
    nativeName: "Español (España)",
    flag: "🇪🇸",
    direction: "ltr" as const,
    dateFormat: "dd/MM/yyyy",
    timeFormat: "HH:mm",
    currency: "EUR"
  },
  fr_FR: {
    name: "Français (France)",
    nativeName: "Français (France)",
    flag: "🇫🇷",
    direction: "ltr" as const,
    dateFormat: "dd/MM/yyyy",
    timeFormat: "HH:mm",
    currency: "EUR"
  }
};

/**
 * Hook de internacionalização (i18n) dinâmico para interface React.
 * Permite buscar traduções por chave, trocar idioma em tempo real e persistência.
 * 
 * @example
 * const { t, lang, setLang, languages, formatDate, formatCurrency } = useI18n();
 * t('login') // "Entrar", "Login", "Iniciar sesión", "Se connecter"
 * formatDate(new Date()) // "27/01/2025", "01/27/2025", etc.
 */
export function useI18n() {
  // Carrega idioma inicial do localStorage ou detecta automaticamente
  const getInitialLanguage = (): Lang => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('omni_writer_language');
      if (saved && LANGS.includes(saved as Lang)) {
        return saved as Lang;
      }
      
      // Detecta idioma do navegador
      const browserLang = navigator.language.replace('-', '_');
      if (LANGS.includes(browserLang as Lang)) {
        return browserLang as Lang;
      }
      
      // Fallback para português
      return 'pt_BR';
    }
    return 'pt_BR';
  };

  const [lang, setLangState] = useState<Lang>(getInitialLanguage);

  // Persiste mudança de idioma
  const setLang = useCallback((newLang: Lang) => {
    setLangState(newLang);
    if (typeof window !== 'undefined') {
      localStorage.setItem('omni_writer_language', newLang);
      
      // Atualiza direção do documento se necessário
      const config = languageConfig[newLang];
      document.documentElement.dir = config.direction;
      document.documentElement.lang = newLang;
    }
  }, []);

  // Função de tradução com fallback
  const t = useCallback((key: string, variables?: Record<string, any>): string => {
    let translation = translations[lang][key] || 
                     translations['pt_BR'][key] || 
                     translations['en_US'][key] || 
                     key;

    // Aplica interpolação de variáveis
    if (variables) {
      Object.entries(variables).forEach(([varKey, value]) => {
        translation = translation.replace(new RegExp(`\\{${varKey}\\}`, 'g'), String(value));
      });
    }

    return translation;
  }, [lang]);

  // Formatação de data
  const formatDate = useCallback((date: Date): string => {
    const config = languageConfig[lang];
    const formatter = new Intl.DateTimeFormat(lang.replace('_', '-'), {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
    return formatter.format(date);
  }, [lang]);

  // Formatação de hora
  const formatTime = useCallback((date: Date): string => {
    const formatter = new Intl.DateTimeFormat(lang.replace('_', '-'), {
      hour: '2-digit',
      minute: '2-digit'
    });
    return formatter.format(date);
  }, [lang]);

  // Formatação de número
  const formatNumber = useCallback((number: number): string => {
    const formatter = new Intl.NumberFormat(lang.replace('_', '-'));
    return formatter.format(number);
  }, [lang]);

  // Formatação de moeda
  const formatCurrency = useCallback((amount: number): string => {
    const config = languageConfig[lang];
    const formatter = new Intl.NumberFormat(lang.replace('_', '-'), {
      style: 'currency',
      currency: config.currency
    });
    return formatter.format(amount);
  }, [lang]);

  // Formatação de plural
  const formatPlural = useCallback((count: number, singular: string, plural: string): string => {
    const formatter = new Intl.PluralRules(lang.replace('_', '-'));
    const rule = formatter.select(count);
    return rule === 'one' ? singular : plural;
  }, [lang]);

  // Detecta idioma de um texto
  const detectLanguage = useCallback((text: string): Lang => {
    // Implementação básica de detecção
    const textLower = text.toLowerCase();
    
    const portugueseWords = ['de', 'da', 'do', 'para', 'com', 'não', 'que', 'seu', 'sua'];
    const spanishWords = ['de', 'la', 'el', 'para', 'con', 'no', 'que', 'su', 'por'];
    const frenchWords = ['de', 'la', 'le', 'pour', 'avec', 'non', 'que', 'son', 'sa'];
    
    const ptScore = portugueseWords.filter(word => textLower.includes(word)).length;
    const esScore = spanishWords.filter(word => textLower.includes(word)).length;
    const frScore = frenchWords.filter(word => textLower.includes(word)).length;
    
    if (ptScore > esScore && ptScore > frScore) return 'pt_BR';
    if (esScore > ptScore && esScore > frScore) return 'es_ES';
    if (frScore > ptScore && frScore > esScore) return 'fr_FR';
    
    return 'en_US';
  }, []);

  // Obtém configuração do idioma atual
  const getCurrentLanguageConfig = useCallback(() => {
    return languageConfig[lang];
  }, [lang]);

  // Obtém lista de idiomas disponíveis
  const getAvailableLanguages = useCallback(() => {
    return Object.entries(languageConfig).map(([code, config]) => ({
      code: code as Lang,
      ...config
    }));
  }, []);

  // Inicializa configurações do documento
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const config = languageConfig[lang];
      document.documentElement.dir = config.direction;
      document.documentElement.lang = lang;
    }
  }, [lang]);

  return {
    t,
    lang,
    setLang,
    languages: LANGS,
    languageConfig: getCurrentLanguageConfig(),
    availableLanguages: getAvailableLanguages(),
    formatDate,
    formatTime,
    formatNumber,
    formatCurrency,
    formatPlural,
    detectLanguage
  };
} 