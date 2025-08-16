import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Prompts } from '../../pages/Prompts';

describe('Prompts Page', () => {
  it('deve renderizar a lista mock de prompts', () => {
    render(<Prompts />);
    expect(screen.getByText('Prompt SEO')).toBeInTheDocument();
    expect(screen.getByText('Prompt Criativo')).toBeInTheDocument();
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Prompts />);
    expect(screen.getByText('Nenhum prompt cadastrado.')).toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Novo Prompt', () => {
    window.alert = jest.fn();
    render(<Prompts />);
    fireEvent.click(screen.getByText('Novo Prompt'));
    expect(window.alert).toHaveBeenCalledWith('Funcionalidade de criação de prompt em desenvolvimento.');
  });

  it('deve acionar placeholder ao clicar em Editar', () => {
    window.alert = jest.fn();
    render(<Prompts />);
    fireEvent.click(screen.getAllByText('Editar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Editar prompt 1 (em desenvolvimento)');
  });

  it('deve acionar placeholder ao clicar em Excluir', () => {
    window.alert = jest.fn();
    render(<Prompts />);
    fireEvent.click(screen.getAllByText('Excluir')[0]);
    expect(window.alert).toHaveBeenCalledWith('Excluir prompt 1 (em desenvolvimento)');
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Prompts />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 