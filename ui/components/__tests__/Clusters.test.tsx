import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Clusters } from '../../pages/Clusters';

describe('Clusters Page', () => {
  it('deve renderizar a lista mock de clusters', () => {
    render(<Clusters />);
    expect(screen.getByText('Cluster A')).toBeInTheDocument();
    expect(screen.getByText('Cluster B')).toBeInTheDocument();
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Clusters />);
    expect(screen.getByText('Nenhum cluster cadastrado.')).toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Novo Cluster', () => {
    window.alert = jest.fn();
    render(<Clusters />);
    fireEvent.click(screen.getByText('Novo Cluster'));
    expect(window.alert).toHaveBeenCalledWith('Funcionalidade de criação de cluster em desenvolvimento.');
  });

  it('deve acionar placeholder ao clicar em Editar', () => {
    window.alert = jest.fn();
    render(<Clusters />);
    fireEvent.click(screen.getAllByText('Editar')[0]);
    expect(window.alert).toHaveBeenCalledWith('Editar cluster 1 (em desenvolvimento)');
  });

  it('deve acionar placeholder ao clicar em Excluir', () => {
    window.alert = jest.fn();
    render(<Clusters />);
    fireEvent.click(screen.getAllByText('Excluir')[0]);
    expect(window.alert).toHaveBeenCalledWith('Excluir cluster 1 (em desenvolvimento)');
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Clusters />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 