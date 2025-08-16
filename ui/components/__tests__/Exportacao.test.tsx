import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Exportacao } from '../../pages/Exportacao';

describe('Exportacao Page', () => {
  it('deve renderizar os botões de exportação', () => {
    render(<Exportacao />);
    expect(screen.getByText('Exportar Artigos (CSV)')).toBeInTheDocument();
    expect(screen.getByText('Exportar Prompts (CSV)')).toBeInTheDocument();
  });

  it('deve simular exportação de artigos', async () => {
    render(<Exportacao />);
    fireEvent.click(screen.getByText('Exportar Artigos (CSV)'));
    expect(screen.getByText('Exportando artigos...')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Artigos exportados com sucesso! (mock)')).toBeInTheDocument(), { timeout: 1500 });
  });

  it('deve simular exportação de prompts', async () => {
    render(<Exportacao />);
    fireEvent.click(screen.getByText('Exportar Prompts (CSV)'));
    expect(screen.getByText('Exportando prompts...')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Prompts exportados com sucesso! (mock)')).toBeInTheDocument(), { timeout: 1500 });
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Exportacao />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 