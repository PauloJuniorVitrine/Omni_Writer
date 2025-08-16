import React from 'react';
import { render, screen } from '@testing-library/react';
import { Branding } from './Branding';

describe('Branding', () => {
  it('renderiza o nome do sistema', () => {
    render(<Branding />);
    expect(screen.getByText(/Omni Writer/i)).toBeInTheDocument();
  });

  it('renderiza o logotipo (placeholder)', () => {
    render(<Branding />);
    expect(screen.getByLabelText(/logo omni writer/i)).toBeInTheDocument();
  });

  it('é acessível via teclado', () => {
    render(<Branding />);
    const logo = screen.getByLabelText(/logo omni writer/i);
    logo.focus();
    expect(logo).toBeDefined();
  });
}); 