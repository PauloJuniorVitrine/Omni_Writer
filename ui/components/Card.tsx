import React from 'react';
import { colors, typography, shadows } from '../theme';

type CardProps = {
  title: string;
  description?: string;
  children?: React.ReactNode;
};

export const Card: React.FC<CardProps> = ({ title, description, children }) => {
  return (
    <div
      style={{
        background: colors.surface,
        border: `1px solid ${colors.border}`,
        borderRadius: 12,
        boxShadow: shadows.xs,
        padding: '1.5rem',
        minWidth: 240,
        minHeight: 160,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        justifyContent: 'space-between',
      }}
    >
      <div>
        <h2 style={{
          fontFamily: typography.fontFamily,
          fontWeight: typography.fontWeight.bold,
          fontSize: typography.fontSize.lg,
          color: colors.primary,
          margin: 0,
        }}>{title}</h2>
        {description && (
          <p style={{
            fontFamily: typography.fontFamily,
            fontSize: typography.fontSize.sm,
            color: colors.textSecondary,
            margin: '8px 0 0 0',
          }}>{description}</p>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}; 