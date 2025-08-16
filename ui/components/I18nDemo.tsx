import React, { useState } from 'react';
import { useI18n } from '../hooks/use_i18n';
import LanguageSelector from './LanguageSelector';

/**
 * Componente de demonstração das funcionalidades de i18n dinâmico.
 * Mostra exemplos de tradução, formatação e troca de idioma em tempo real.
 */
export const I18nDemo: React.FC = () => {
  const { 
    t, 
    lang, 
    formatDate, 
    formatTime, 
    formatNumber, 
    formatCurrency, 
    formatPlural,
    detectLanguage 
  } = useI18n();
  
  const [testText, setTestText] = useState('');
  const [detectedLang, setDetectedLang] = useState('');

  const handleDetectLanguage = () => {
    if (testText.trim()) {
      const detected = detectLanguage(testText);
      setDetectedLang(detected);
    }
  };

  const currentDate = new Date();
  const sampleNumber = 1234567.89;
  const sampleAmount = 99.99;
  const articleCount = 5;

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-8">
      {/* Header */}
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          {t('app_title')} - {t('select_language')}
        </h1>
        <p className="text-gray-600">
          {t('onboarding_welcome_desc')}
        </p>
      </div>

      {/* Language Selector */}
      <div className="flex justify-center">
        <LanguageSelector 
          showFlags={true}
          showNativeNames={true}
          compact={false}
        />
      </div>

      {/* Current Language Info */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h2 className="text-lg font-semibold text-blue-900 mb-2">
          Idioma Atual / Current Language / Idioma Actual / Langue Actuelle
        </h2>
        <p className="text-blue-800">
          <strong>Código:</strong> {lang}
        </p>
        <p className="text-blue-800">
          <strong>Data:</strong> {formatDate(currentDate)}
        </p>
        <p className="text-blue-800">
          <strong>Hora:</strong> {formatTime(currentDate)}
        </p>
      </div>

      {/* Translation Examples */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Basic Translations */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            {t('dashboard')} - Traduções Básicas
          </h3>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Login:</span>
              <span className="font-medium">{t('login')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Dashboard:</span>
              <span className="font-medium">{t('dashboard')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Blogs:</span>
              <span className="font-medium">{t('blogs')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Categories:</span>
              <span className="font-medium">{t('categories')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Generate:</span>
              <span className="font-medium">{t('generate')}</span>
            </div>
          </div>
        </div>

        {/* Formatting Examples */}
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            {t('export_data')} - Formatação
          </h3>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-gray-600">Número:</span>
              <span className="font-medium">{formatNumber(sampleNumber)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Moeda:</span>
              <span className="font-medium">{formatCurrency(sampleAmount)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Plural:</span>
              <span className="font-medium">
                {formatPlural(articleCount, t('new_article'), t('new_article') + 's')}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Data:</span>
              <span className="font-medium">{formatDate(currentDate)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Hora:</span>
              <span className="font-medium">{formatTime(currentDate)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Language Detection */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Detecção de Idioma / Language Detection
        </h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Digite um texto para detectar o idioma:
            </label>
            <textarea
              value={testText}
              onChange={(e) => setTestText(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              rows={3}
              placeholder="Digite texto em qualquer idioma suportado..."
            />
          </div>
          <div className="flex space-x-4">
            <button
              onClick={handleDetectLanguage}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {t('search')} - Detectar Idioma
            </button>
            <button
              onClick={() => {
                setTestText('');
                setDetectedLang('');
              }}
              className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
            >
              {t('cancel')} - Limpar
            </button>
          </div>
          {detectedLang && (
            <div className="bg-green-50 border border-green-200 rounded-md p-3">
              <p className="text-green-800">
                <strong>Idioma detectado:</strong> {detectedLang}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Variable Interpolation */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Interpolação de Variáveis / Variable Interpolation
        </h3>
        <div className="space-y-2">
          <div className="flex justify-between">
            <span className="text-gray-600">Blog Edit:</span>
            <span className="font-medium">{t('blog_edit_placeholder', { id: 123 })}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-600">Category Edit:</span>
            <span className="font-medium">{t('category_edit_placeholder', { id: 456 })}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-600">Token Rotate:</span>
            <span className="font-medium">{t('token_rotate_placeholder', { id: 'abc123' })}</span>
          </div>
        </div>
      </div>

      {/* Quick Language Switcher */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Troca Rápida / Quick Switch / Cambio Rápido / Changement Rapide
        </h3>
        <div className="flex flex-wrap gap-2 justify-center">
          {['pt_BR', 'en_US', 'es_ES', 'fr_FR'].map((languageCode) => (
            <button
              key={languageCode}
              onClick={() => {
                const { setLang } = useI18n();
                setLang(languageCode as any);
              }}
              className={`px-4 py-2 rounded-md border transition-colors ${
                lang === languageCode
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
              }`}
            >
              {languageCode.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="text-center text-gray-500 text-sm">
        <p>
          {t('system_operational')} {formatDate(currentDate)} {formatTime(currentDate)}
        </p>
        <p className="mt-2">
          {t('onboarding_ready_desc')}
        </p>
      </div>
    </div>
  );
};

export default I18nDemo; 