import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { StatusLogs } from '../../pages/StatusLogs';

describe('StatusLogs Page', () => {
  it('deve renderizar painel de status e logs', () => {
    render(<StatusLogs />);
    expect(screen.getByText('Status Geral')).toBeInTheDocument();
    expect(screen.getByText('Logs Recentes')).toBeInTheDocument();
    expect(screen.getByText('Sistema iniciado')).toBeInTheDocument();
  });

  it('deve filtrar logs por tipo', () => {
    render(<StatusLogs />);
    fireEvent.change(screen.getByLabelText('Filtrar por tipo:'), { target: { value: 'ERROR' } });
    expect(screen.getByText('Falha ao exportar')).toBeInTheDocument();
    expect(screen.queryByText('Sistema iniciado')).not.toBeInTheDocument();
  });

  it('deve acionar placeholder ao clicar em Atualizar', () => {
    window.alert = jest.fn();
    render(<StatusLogs />);
    fireEvent.click(screen.getByText('Atualizar Status/Logs'));
    expect(window.alert).toHaveBeenCalledWith('Atualização de status/logs em desenvolvimento.');
  });

  it('deve exibir mensagem de lista vazia', () => {
    jest.spyOn(React, 'useState').mockImplementationOnce(() => [[], jest.fn()]);
    render(<StatusLogs />);
    expect(screen.getByText('Nenhum log encontrado.')).toBeInTheDocument();
  });

  it('snapshot da renderização principal', () => {
    const { asFragment } = render(<StatusLogs />);
    expect(asFragment()).toMatchSnapshot();
  });
}); 