import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { GeracaoArtigos } from '../../pages/GeracaoArtigos';

describe('Geração de Artigos Page', () => {
  it('deve renderizar o formulário de geração', () => {
    render(<GeracaoArtigos />);
    expect(screen.getByText('Geração de Artigos')).toBeInTheDocument();
    expect(screen.getByLabelText('Título do artigo:')).toBeInTheDocument();
  });

  it('deve desabilitar botão se campo estiver vazio', () => {
    render(<GeracaoArtigos />);
    expect(screen.getByText('Gerar Artigo')).toBeDisabled();
  });

  it('deve simular geração e exibir resultado', async () => {
    render(<GeracaoArtigos />);
    fireEvent.change(screen.getByLabelText('Título do artigo:'), { target: { value: 'Teste' } });
    fireEvent.click(screen.getByText('Gerar Artigo'));
    expect(screen.getByText('Gerando...')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Artigo gerado com sucesso! (mock)')).toBeInTheDocument(), { timeout: 2000 });
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<GeracaoArtigos />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 