import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeToggle } from '../ThemeToggle';
import { useTheme } from '../../hooks/use_theme';
import { useI18n } from '../../hooks/use_i18n';

// Mock dos hooks
jest.mock('../../hooks/use_theme');
jest.mock('../../hooks/use_i18n');

const mockUseTheme = useTheme as jest.MockedFunction<typeof useTheme>;
const mockUseI18n = useI18n as jest.MockedFunction<typeof useI18n>;

describe('ThemeToggle', () => {
  const mockToggleTheme = jest.fn();
  const mockT = jest.fn((key: string) => key);

  beforeEach(() => {
    mockUseI18n.mockReturnValue({ t: mockT });
    mockUseTheme.mockReturnValue({
      mode: 'light',
      isDark: false,
      colors: {
        primary: '#1e40af',
        primaryHover: '#1e3a8a',
        secondary: '#475569',
        error: '#dc2626',
        success: '#16a34a',
        warning: '#ea580c',
        info: '#0891b2',
        background: '#ffffff',
        surface: '#ffffff',
        surfaceHover: '#f8fafc',
        surfacePressed: '#f1f5f9',
        border: '#cbd5e1',
        borderHover: '#94a3b8',
        borderFocus: '#1e40af',
        text: '#0f172a',
        textSecondary: '#334155',
        textTertiary: '#64748b',
        textInverse: '#ffffff',
        link: '#1e40af',
        linkHover: '#1e3a8a',
        linkVisited: '#7c3aed',
        disabled: '#cbd5e1',
        disabledText: '#94a3b8',
        overlay: 'rgba(0, 0, 0, 0.5)',
        backdrop: 'rgba(0, 0, 0, 0.3)'
      },
      toggleTheme: mockToggleTheme,
      setThemeMode: jest.fn(),
      validateContrast: jest.fn(),
      getCurrentContrast: jest.fn()
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should render theme toggle button', () => {
    render(<ThemeToggle />);
    
    const button = screen.getByRole('switch');
    expect(button).toBeInTheDocument();
  });

  it('should have correct ARIA attributes for accessibility', () => {
    render(<ThemeToggle />);
    
    const button = screen.getByRole('switch');
    expect(button).toHaveAttribute('aria-checked', 'false');
    expect(button).toHaveAttribute('aria-label', 'theme_dark');
    expect(button).toHaveAttribute('title', 'theme_dark');
  });

  it('should show sun icon when in light mode', () => {
    render(<ThemeToggle />);
    
    const sunIcon = screen.getByLabelText('sun');
    expect(sunIcon).toBeInTheDocument();
    expect(sunIcon).toHaveTextContent('☀️');
  });

  it('should show moon icon when in dark mode', () => {
    mockUseTheme.mockReturnValue({
      ...mockUseTheme(),
      isDark: true,
      mode: 'dark'
    });

    render(<ThemeToggle />);
    
    const moonIcon = screen.getByLabelText('moon');
    expect(moonIcon).toBeInTheDocument();
    expect(moonIcon).toHaveTextContent('🌙');
  });

  it('should call toggleTheme when clicked', () => {
    render(<ThemeToggle />);
    
    const button = screen.getByRole('switch');
    fireEvent.click(button);
    
    expect(mockToggleTheme).toHaveBeenCalledTimes(1);
  });

  it('should show auto indicator when in auto mode', () => {
    mockUseTheme.mockReturnValue({
      ...mockUseTheme(),
      mode: 'auto'
    });

    render(<ThemeToggle />);
    
    const autoIndicator = screen.getByTitle('Modo automático');
    expect(autoIndicator).toBeInTheDocument();
    expect(autoIndicator).toHaveTextContent('A');
  });

  it('should show label when showLabel prop is true', () => {
    render(<ThemeToggle showLabel={true} />);
    
    expect(screen.getByText('theme_light')).toBeInTheDocument();
  });

  it('should not show label when showLabel prop is false', () => {
    render(<ThemeToggle showLabel={false} />);
    
    expect(screen.queryByText('theme_light')).not.toBeInTheDocument();
  });

  it('should have correct size based on size prop', () => {
    render(<ThemeToggle size="large" />);
    
    const button = screen.getByRole('switch');
    expect(button).toHaveStyle({ width: '48px', height: '48px' });
  });

  it('should support keyboard navigation', () => {
    render(<ThemeToggle />);
    
    const button = screen.getByRole('switch');
    
    // Test focus
    fireEvent.focus(button);
    expect(button).toHaveStyle({ outline: '2px solid var(--color-primary)' });
    
    // Test blur
    fireEvent.blur(button);
    expect(button).toHaveStyle({ outline: 'none' });
  });

  it('should have hover effects', () => {
    render(<ThemeToggle />);
    
    const button = screen.getByRole('switch');
    
    // Test hover
    fireEvent.mouseEnter(button);
    expect(button).toHaveStyle({ transform: 'scale(1.05)' });
    
    // Test leave
    fireEvent.mouseLeave(button);
    expect(button).toHaveStyle({ transform: 'scale(1)' });
  });

  it('should update ARIA attributes when theme changes', () => {
    const { rerender } = render(<ThemeToggle />);
    
    // Light mode
    let button = screen.getByRole('switch');
    expect(button).toHaveAttribute('aria-checked', 'false');
    expect(button).toHaveAttribute('aria-label', 'theme_dark');
    
    // Dark mode
    mockUseTheme.mockReturnValue({
      ...mockUseTheme(),
      isDark: true,
      mode: 'dark'
    });
    
    rerender(<ThemeToggle />);
    button = screen.getByRole('switch');
    expect(button).toHaveAttribute('aria-checked', 'true');
    expect(button).toHaveAttribute('aria-label', 'theme_light');
  });
}); 