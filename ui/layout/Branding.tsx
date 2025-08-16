import React from 'react';
import { colors, typography } from '../theme';

export const Branding: React.FC = () => {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      {/* Logotipo (placeholder, substituir por <img src="/static/logo.svg" ... /> se disponível) */}
      <div
        style={{
          width: 36,
          height: 36,
          background: colors.primary,
          borderRadius: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
        aria-label="Logo Omni Writer"
      >
        <span style={{ color: '#fff', fontWeight: 700, fontSize: 22 }}>O</span>
      </div>
      <span
        style={{
          fontFamily: typography.fontFamily,
          fontWeight: typography.fontWeight.bold,
          fontSize: typography.fontSize.lg,
          color: colors.primary,
          letterSpacing: 1,
        }}
      >
        Omni Writer
      </span>
    </div>
  );
}; 