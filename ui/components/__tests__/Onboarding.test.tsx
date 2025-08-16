import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Onboarding } from '../Onboarding';

describe('Onboarding Component', () => {
  it('deve renderizar o primeiro passo', () => {
    render(<Onboarding />);
    expect(screen.getByText('Bem-vindo ao Omni Writer!')).toBeInTheDocument();
  });

  it('deve avançar e voltar entre os passos', () => {
    render(<Onboarding />);
    fireEvent.click(screen.getByText('Avançar'));
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Voltar'));
    expect(screen.getByText('Bem-vindo ao Omni Writer!')).toBeInTheDocument();
  });

  it('deve desabilitar avançar no último passo', () => {
    render(<Onboarding />);
    for (let i = 0; i < 5; i++) {
      fireEvent.click(screen.getByText('Avançar'));
    }
    expect(screen.getByText('Pronto!')).toBeInTheDocument();
    expect(screen.getByText('Avançar')).toBeDisabled();
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Onboarding />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 