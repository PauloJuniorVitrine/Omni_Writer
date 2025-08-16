import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Feedback } from '../../pages/Feedback';

describe('Feedback Page', () => {
  it('deve renderizar o formulário e lista de feedbacks', () => {
    render(<Feedback />);
    expect(screen.getByText('Envie seu feedback')).toBeInTheDocument();
    expect(screen.getByText('Ótimo sistema!')).toBeInTheDocument();
    expect(screen.getByText('Sugestão: exportar em PDF.')).toBeInTheDocument();
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<Feedback />);
    expect(screen.getByText('Nenhum feedback recebido.')).toBeInTheDocument();
  });

  it('deve simular envio de feedback', async () => {
    render(<Feedback />);
    fireEvent.change(screen.getByPlaceholderText('Digite seu feedback...'), { target: { value: 'Teste de feedback' } });
    fireEvent.click(screen.getByText('Enviar'));
    expect(screen.getByText('Enviando...')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText('Feedback enviado! (mock)')).toBeInTheDocument(), { timeout: 1500 });
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<Feedback />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 