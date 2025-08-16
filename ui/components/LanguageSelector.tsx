import React, { useState } from 'react';
import { useI18n } from '../hooks/use_i18n';

interface LanguageSelectorProps {
  className?: string;
  showFlags?: boolean;
  showNativeNames?: boolean;
  compact?: boolean;
}

/**
 * Componente de seletor de idioma dinâmico.
 * Permite trocar idioma em tempo real com persistência.
 */
export const LanguageSelector: React.FC<LanguageSelectorProps> = ({
  className = '',
  showFlags = true,
  showNativeNames = true,
  compact = false
}) => {
  const { lang, setLang, availableLanguages, t } = useI18n();
  const [isOpen, setIsOpen] = useState(false);

  const handleLanguageChange = (languageCode: string) => {
    setLang(languageCode as any);
    setIsOpen(false);
  };

  const currentLanguage = availableLanguages.find(l => l.code === lang);

  if (compact) {
    return (
      <div className={`relative ${className}`}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          {showFlags && <span>{currentLanguage?.flag}</span>}
          <span>{currentLanguage?.code.toUpperCase()}</span>
          <svg
            className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {isOpen && (
          <div className="absolute right-0 mt-2 w-48 bg-white border border-gray-300 rounded-md shadow-lg z-50">
            <div className="py-1">
              {availableLanguages.map((language) => (
                <button
                  key={language.code}
                  onClick={() => handleLanguageChange(language.code)}
                  className={`w-full text-left px-4 py-2 text-sm hover:bg-gray-100 flex items-center space-x-2 ${
                    language.code === lang ? 'bg-blue-50 text-blue-700' : 'text-gray-700'
                  }`}
                >
                  {showFlags && <span>{language.flag}</span>}
                  <span>{language.code.toUpperCase()}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={`relative ${className}`}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center space-x-3 px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
      >
        {showFlags && <span className="text-lg">{currentLanguage?.flag}</span>}
        <div className="text-left">
          <div className="font-medium">{currentLanguage?.name}</div>
          {showNativeNames && (
            <div className="text-xs text-gray-500">{currentLanguage?.nativeName}</div>
          )}
        </div>
        <svg
          className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-64 bg-white border border-gray-300 rounded-md shadow-lg z-50">
          <div className="py-1">
            {availableLanguages.map((language) => (
              <button
                key={language.code}
                onClick={() => handleLanguageChange(language.code)}
                className={`w-full text-left px-4 py-3 hover:bg-gray-100 flex items-center space-x-3 ${
                  language.code === lang ? 'bg-blue-50 text-blue-700' : 'text-gray-700'
                }`}
              >
                {showFlags && <span className="text-lg">{language.flag}</span>}
                <div className="flex-1">
                  <div className="font-medium">{language.name}</div>
                  {showNativeNames && (
                    <div className="text-xs text-gray-500">{language.nativeName}</div>
                  )}
                </div>
                {language.code === lang && (
                  <svg className="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Overlay para fechar ao clicar fora */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
};

export default LanguageSelector; 