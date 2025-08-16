import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Tokens } from '../../pages/Tokens';

describe('Tokens Page', () => {
  it('deve renderizar lista de tokens', () => {
    render(<Tokens />);
    expect(screen.getByText('Token #1')).toBeInTheDocument();
    expect(screen.getByText('Token #2')).toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Rotacionar', () => {
    window.alert = jest.fn();
    render(<Tokens />);
    fireEvent.click(screen.getAllByText('Rotacionar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Rotação de token 1 em desenvolvimento.');
  });

  it('deve acionar placeholder ao clicar em Revogar', () => {
    window.alert = jest.fn();
    render(<Tokens />);
    fireEvent.click(screen.getAllByText('Revogar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Revogação de token 1 em desenvolvimento.');
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Tokens />);
    expect(screen.getByText('Nenhum token cadastrado.')).toBeInTheDocument();
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Tokens />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 