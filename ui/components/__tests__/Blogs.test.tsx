import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Blogs } from '../../pages/Blogs';

describe('Blogs Page', () => {
  it('deve renderizar a lista mock de blogs', () => {
    render(<Blogs />);
    expect(screen.getByText('Blog de Tecnologia')).toBeInTheDocument();
    expect(screen.getByText('Blog de Saúde')).toBeInTheDocument();
  });

  it('deve exibir mensagem de lista vazia', () => {
    // Mocka o useState para lista vazia
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Blogs />);
    expect(screen.getByText('Nenhum blog cadastrado.')).toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Novo Blog', () => {
    window.alert = jest.fn();
    render(<Blogs />);
    fireEvent.click(screen.getByText('Novo Blog'));
    expect(window.alert).toHaveBeenCalledWith('Funcionalidade de criação de blog em desenvolvimento.');
  });

  it('deve acionar placeholder ao clicar em Editar', () => {
    window.alert = jest.fn();
    render(<Blogs />);
    fireEvent.click(screen.getAllByText('Editar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Editar blog 1 (em desenvolvimento)');
  });

  it('deve acionar placeholder ao clicar em Excluir', () => {
    window.alert = jest.fn();
    render(<Blogs />);
    fireEvent.click(screen.getAllByText('Excluir')[0]);
    expect(window.alert).toHaveBeenCalledWith('Excluir blog 1 (em desenvolvimento)');
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Blogs />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 