import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from './Button';

describe('Button', () => {
  it('renderiza o texto corretamente', () => {
    render(<Button>Enviar</Button>);
    expect(screen.getByText('Enviar')).toBeInTheDocument();
  });

  it('aplica o estilo primário por padrão', () => {
    render(<Button>Primário</Button>);
    const btn = screen.getByRole('button');
    expect(btn).toHaveStyle(`background: #2563eb`);
  });

  it('aplica variantes corretamente', () => {
    render(<Button variant="error">Erro</Button>);
    const btn = screen.getByRole('button');
    expect(btn).toHaveStyle(`background: #ef4444`);
  });

  it('exibe loader quando loading=true', () => {
    render(<Button loading>Carregando</Button>);
    expect(screen.getByLabelText(/carregando/i)).toBeInTheDocument();
  });

  it('desabilita quando disabled=true', () => {
    render(<Button disabled>Desabilitado</Button>);
    const btn = screen.getByRole('button');
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute('aria-disabled', 'true');
  });

  it('desabilita quando loading=true', () => {
    render(<Button loading>Carregando</Button>);
    const btn = screen.getByRole('button');
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute('aria-disabled', 'true');
  });

  it('chama onClick quando clicado', () => {
    const onClick = jest.fn();
    render(<Button onClick={onClick}>Clique</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).toHaveBeenCalled();
  });

  it('não chama onClick quando disabled', () => {
    const onClick = jest.fn();
    render(<Button disabled onClick={onClick}>Clique</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('não chama onClick quando loading', () => {
    const onClick = jest.fn();
    render(<Button loading onClick={onClick}>Clique</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('é acessível via teclado', () => {
    render(<Button>Tab</Button>);
    const btn = screen.getByRole('button');
    btn.focus();
    expect(btn).toHaveFocus();
  });
}); 