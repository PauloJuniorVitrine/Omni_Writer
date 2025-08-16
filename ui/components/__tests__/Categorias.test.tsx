import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Categorias } from '../../pages/Categorias';

describe('Categorias Page', () => {
  it('deve renderizar a lista mock de categorias', () => {
    render(<Categorias />);
    expect(screen.getByText('Tech')).toBeInTheDocument();
    expect(screen.getByText('Saúde')).toBeInTheDocument();
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Categorias />);
    expect(screen.getByText('Nenhuma categoria cadastrada.')).toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Nova Categoria', () => {
    window.alert = jest.fn();
    render(<Categorias />);
    fireEvent.click(screen.getByText('Nova Categoria'));
    expect(window.alert).toHaveBeenCalledWith('Funcionalidade de criação de categoria em desenvolvimento.');
  });

  it('deve acionar placeholder ao clicar em Editar', () => {
    window.alert = jest.fn();
    render(<Categorias />);
    fireEvent.click(screen.getAllByText('Editar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Editar categoria 1 (em desenvolvimento)');
  });

  it('deve acionar placeholder ao clicar em Excluir', () => {
    window.alert = jest.fn();
    render(<Categorias />);
    fireEvent.click(screen.getAllByText('Excluir')[0]);
    expect(window.alert).toHaveBeenCalledWith('Excluir categoria 1 (em desenvolvimento)');
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Categorias />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 