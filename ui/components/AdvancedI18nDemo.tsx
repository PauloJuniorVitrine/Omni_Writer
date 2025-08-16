/**
 * AdvancedI18nDemo - Demonstração da Internacionalização Avançada
 * ==============================================================
 * 
 * Componente de demonstração que mostra todas as funcionalidades
 * do sistema de internacionalização avançado:
 * - Troca de idioma em tempo real
 * - Formatação de datas, números e moedas
 * - Tempo relativo
 * - Interpolação de variáveis
 * 
 * Autor: Análise Técnica Omni Writer
 * Data: 2025-01-27
 * Versão: 1.0
 */

import React, { useState, useEffect } from 'react';
import { useAdvancedI18n, AdvancedLanguageSelector } from '../context/AdvancedI18nContext';

const AdvancedI18nDemo: React.FC = () => {
  const {
    t,
    formatDate,
    formatNumber,
    formatCurrency,
    formatRelativeTime,
    currentLanguage,
    languageConfig,
    isRTL
  } = useAdvancedI18n();

  const [currentTime, setCurrentTime] = useState(new Date());
  const [demoData] = useState({
    price: 1234.56,
    percentage: 85.5,
    date: new Date('2025-01-27T10:30:00'),
    oldDate: new Date('2025-01-20T15:45:00'),
    count: 42,
    name: 'João Silva'
  });

  // Atualiza o tempo a cada segundo para demonstrar tempo relativo
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div 
      className="advanced-i18n-demo"
      style={{
        padding: '24px',
        backgroundColor: 'var(--color-surface)',
        borderRadius: '12px',
        border: '1px solid var(--color-border)',
        direction: isRTL ? 'rtl' : 'ltr'
      }}
    >
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '8px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          🌍 {t('i18n.demo.title', { language: languageConfig.nativeName })}
        </h2>
        <p style={{ 
          color: 'var(--color-secondary)',
          fontSize: '14px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          {t('i18n.demo.subtitle')}
        </p>
      </div>

      {/* Seletor de Idioma */}
      <div style={{ marginBottom: '24px' }}>
        <h3 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '12px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          {t('i18n.demo.languageSelector')}
        </h3>
        <AdvancedLanguageSelector />
      </div>

      {/* Informações do Idioma Atual */}
      <div style={{ 
        marginBottom: '24px',
        padding: '16px',
        backgroundColor: 'var(--color-background)',
        borderRadius: '8px',
        border: '1px solid var(--color-border)'
      }}>
        <h3 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '12px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          {t('i18n.demo.currentLanguage')}
        </h3>
        <div style={{ 
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          <div>
            <strong>{t('i18n.demo.languageCode')}:</strong> {currentLanguage}
          </div>
          <div>
            <strong>{t('i18n.demo.languageName')}:</strong> {languageConfig.name}
          </div>
          <div>
            <strong>{t('i18n.demo.nativeName')}:</strong> {languageConfig.nativeName}
          </div>
          <div>
            <strong>{t('i18n.demo.direction')}:</strong> {isRTL ? 'RTL' : 'LTR'}
          </div>
          <div>
            <strong>{t('i18n.demo.flag')}:</strong> {languageConfig.flag}
          </div>
          <div>
            <strong>{t('i18n.demo.dateFormat')}:</strong> {languageConfig.dateFormat}
          </div>
        </div>
      </div>

      {/* Demonstrações de Formatação */}
      <div style={{ marginBottom: '24px' }}>
        <h3 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '16px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          {t('i18n.demo.formattingExamples')}
        </h3>
        
        <div style={{ 
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '16px'
        }}>
          {/* Formatação de Data */}
          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              📅 {t('i18n.demo.dateFormatting')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div><strong>{t('i18n.demo.currentTime')}:</strong> {formatDate(currentTime)}</div>
              <div><strong>{t('i18n.demo.sampleDate')}:</strong> {formatDate(demoData.date)}</div>
              <div><strong>{t('i18n.demo.shortDate')}:</strong> {formatDate(demoData.date, { 
                year: 'numeric', 
                month: '2-digit', 
                day: '2-digit' 
              })}</div>
              <div><strong>{t('i18n.demo.fullDate')}:</strong> {formatDate(demoData.date, { 
                weekday: 'long',
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
              })}</div>
            </div>
          </div>

          {/* Formatação de Números */}
          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              🔢 {t('i18n.demo.numberFormatting')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div><strong>{t('i18n.demo.decimal')}:</strong> {formatNumber(demoData.price)}</div>
              <div><strong>{t('i18n.demo.integer')}:</strong> {formatNumber(demoData.count)}</div>
              <div><strong>{t('i18n.demo.percentage')}:</strong> {formatNumber(demoData.percentage, { 
                style: 'percent',
                minimumFractionDigits: 1 
              })}</div>
              <div><strong>{t('i18n.demo.currency')}:</strong> {formatCurrency(demoData.price)}</div>
            </div>
          </div>

          {/* Tempo Relativo */}
          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              ⏰ {t('i18n.demo.relativeTime')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div><strong>{t('i18n.demo.now')}:</strong> {formatRelativeTime(currentTime)}</div>
              <div><strong>{t('i18n.demo.oldDate')}:</strong> {formatRelativeTime(demoData.oldDate)}</div>
              <div><strong>{t('i18n.demo.oneHourAgo')}:</strong> {formatRelativeTime(new Date(currentTime.getTime() - 3600000))}</div>
              <div><strong>{t('i18n.demo.oneDayAgo')}:</strong> {formatRelativeTime(new Date(currentTime.getTime() - 86400000))}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Interpolação de Variáveis */}
      <div style={{ marginBottom: '24px' }}>
        <h3 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '16px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          🔗 {t('i18n.demo.variableInterpolation')}
        </h3>
        
        <div style={{
          padding: '16px',
          backgroundColor: 'var(--color-background)',
          borderRadius: '8px',
          border: '1px solid var(--color-border)'
        }}>
          <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
            <div style={{ marginBottom: '8px' }}>
              {t('i18n.demo.welcomeMessage', { name: demoData.name })}
            </div>
            <div style={{ marginBottom: '8px' }}>
              {t('i18n.demo.itemsCount', { count: demoData.count })}
            </div>
            <div style={{ marginBottom: '8px' }}>
              {t('i18n.demo.priceInfo', { 
                price: formatCurrency(demoData.price),
                currency: languageConfig.numberFormat.currency 
              })}
            </div>
            <div>
              {t('i18n.demo.completionRate', { 
                percentage: formatNumber(demoData.percentage, { style: 'percent' }),
                completed: demoData.count,
                total: 50
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Exemplos de Tradução */}
      <div>
        <h3 style={{ 
          color: 'var(--color-primary)',
          marginBottom: '16px',
          textAlign: isRTL ? 'right' : 'left'
        }}>
          📝 {t('i18n.demo.translationExamples')}
        </h3>
        
        <div style={{ 
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '16px'
        }}>
          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              {t('common.actions')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div>• {t('common.save')}</div>
              <div>• {t('common.cancel')}</div>
              <div>• {t('common.delete')}</div>
              <div>• {t('common.edit')}</div>
            </div>
          </div>

          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              {t('navigation.title')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div>• {t('navigation.home')}</div>
              <div>• {t('navigation.dashboard')}</div>
              <div>• {t('navigation.settings')}</div>
              <div>• {t('navigation.profile')}</div>
            </div>
          </div>

          <div style={{
            padding: '16px',
            backgroundColor: 'var(--color-background)',
            borderRadius: '8px',
            border: '1px solid var(--color-border)'
          }}>
            <h4 style={{ 
              color: 'var(--color-accent)',
              marginBottom: '8px',
              textAlign: isRTL ? 'right' : 'left'
            }}>
              {t('errors.title')}
            </h4>
            <div style={{ fontSize: '14px', lineHeight: '1.6' }}>
              <div>• {t('errors.networkError')}</div>
              <div>• {t('errors.serverError')}</div>
              <div>• {t('errors.validationError')}</div>
              <div>• {t('errors.notFound')}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ 
        marginTop: '24px',
        padding: '16px',
        backgroundColor: 'var(--color-accent)',
        color: 'white',
        borderRadius: '8px',
        textAlign: 'center'
      }}>
        <p style={{ margin: 0, fontSize: '14px' }}>
          {t('i18n.demo.footer', { 
            language: languageConfig.nativeName,
            flag: languageConfig.flag
          })}
        </p>
      </div>
    </div>
  );
};

export default AdvancedI18nDemo; 