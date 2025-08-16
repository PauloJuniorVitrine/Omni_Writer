import React from 'react';
import { render, screen } from '@testing-library/react';
import { Header } from './Header';

describe('Header', () => {
  it('renderiza o branding corretamente', () => {
    render(<Header />);
    expect(screen.getByText(/Omni Writer/i)).toBeInTheDocument();
  });

  it('exibe o botão de toggle de tema', () => {
    render(<Header />);
    expect(screen.getByLabelText(/alternar tema/i)).toBeInTheDocument();
  });

  it('exibe a área do usuário', () => {
    render(<Header />);
    expect(screen.getByText(/usuário/i)).toBeInTheDocument();
  });

  it('é acessível via teclado', () => {
    render(<Header />);
    const btn = screen.getByLabelText(/alternar tema/i);
    btn.focus();
    expect(btn).toHaveFocus();
  });
}); 