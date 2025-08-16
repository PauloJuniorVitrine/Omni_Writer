/**
 * Testes Unitários - Tabela Avançada
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em funcionalidades reais:
 * - Paginação
 * - Filtros
 * - Ordenação
 * - Seleção múltipla
 * - Responsividade
 * - Acessibilidade
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DataTable } from '../DataTable';

interface TestData {
  id: number;
  name: string;
  email: string;
  status: string;
  createdAt: string;
}

const mockData: TestData[] = [
  { id: 1, name: 'João Silva', email: 'joao@example.com', status: 'Ativo', createdAt: '2024-01-01' },
  { id: 2, name: 'Maria Santos', email: 'maria@example.com', status: 'Inativo', createdAt: '2024-01-02' },
  { id: 3, name: 'Pedro Costa', email: 'pedro@example.com', status: 'Ativo', createdAt: '2024-01-03' },
  { id: 4, name: 'Ana Oliveira', email: 'ana@example.com', status: 'Pendente', createdAt: '2024-01-04' },
  { id: 5, name: 'Carlos Lima', email: 'carlos@example.com', status: 'Ativo', createdAt: '2024-01-05' },
];

const mockColumns = [
  { key: 'name' as keyof TestData, header: 'Nome', sortable: true, filterable: true },
  { key: 'email' as keyof TestData, header: 'Email', sortable: true, filterable: true },
  { key: 'status' as keyof TestData, header: 'Status', sortable: true, filterable: true },
  { key: 'createdAt' as keyof TestData, header: 'Data de Criação', sortable: true },
];

describe('DataTable Component', () => {
  const mockOnBulkAction = jest.fn();
  const mockOnRowClick = jest.fn();
  const mockOnRowSelect = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Renderização Básica', () => {
    it('deve renderizar a tabela com dados', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
        />
      );

      expect(screen.getByText('João Silva')).toBeInTheDocument();
      expect(screen.getByText('Maria Santos')).toBeInTheDocument();
      expect(screen.getByText('joao@example.com')).toBeInTheDocument();
    });

    it('deve renderizar cabeçalhos das colunas', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
        />
      );

      expect(screen.getByText('Nome')).toBeInTheDocument();
      expect(screen.getByText('Email')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Data de Criação')).toBeInTheDocument();
    });

    it('deve mostrar mensagem quando não há dados', () => {
      render(
        <DataTable
          data={[]}
          columns={mockColumns}
          emptyMessage="Nenhum usuário encontrado"
        />
      );

      expect(screen.getByText('Nenhum usuário encontrado')).toBeInTheDocument();
    });
  });

  describe('Paginação', () => {
    it('deve mostrar controles de paginação quando há mais de uma página', () => {
      const largeData = Array.from({ length: 25 }, (_, i) => ({
        id: i + 1,
        name: `Usuário ${i + 1}`,
        email: `user${i + 1}@example.com`,
        status: 'Ativo',
        createdAt: '2024-01-01'
      }));

      render(
        <DataTable
          data={largeData}
          columns={mockColumns}
          pageSize={10}
        />
      );

      expect(screen.getByText('Anterior')).toBeInTheDocument();
      expect(screen.getByText('Próxima')).toBeInTheDocument();
      expect(screen.getByText('Mostrando 1 a 10 de 25 resultados')).toBeInTheDocument();
    });

    it('deve navegar entre páginas', () => {
      const largeData = Array.from({ length: 25 }, (_, i) => ({
        id: i + 1,
        name: `Usuário ${i + 1}`,
        email: `user${i + 1}@example.com`,
        status: 'Ativo',
        createdAt: '2024-01-01'
      }));

      render(
        <DataTable
          data={largeData}
          columns={mockColumns}
          pageSize={10}
        />
      );

      // Verificar primeira página
      expect(screen.getByText('Usuário 1')).toBeInTheDocument();
      expect(screen.queryByText('Usuário 11')).not.toBeInTheDocument();

      // Ir para próxima página
      fireEvent.click(screen.getByText('Próxima'));

      // Verificar segunda página
      expect(screen.getByText('Usuário 11')).toBeInTheDocument();
      expect(screen.queryByText('Usuário 1')).not.toBeInTheDocument();
    });

    it('deve alterar itens por página', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          pageSize={2}
        />
      );

      const pageSizeSelect = screen.getByDisplayValue('2');
      fireEvent.change(pageSizeSelect, { target: { value: '5' } });

      // Deve mostrar todos os 5 itens
      expect(screen.getByText('João Silva')).toBeInTheDocument();
      expect(screen.getByText('Maria Santos')).toBeInTheDocument();
      expect(screen.getByText('Pedro Costa')).toBeInTheDocument();
      expect(screen.getByText('Ana Oliveira')).toBeInTheDocument();
      expect(screen.getByText('Carlos Lima')).toBeInTheDocument();
    });
  });

  describe('Ordenação', () => {
    it('deve ordenar por coluna quando cabeçalho é clicado', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
        />
      );

      // Clicar no cabeçalho "Nome" para ordenar
      fireEvent.click(screen.getByText('Nome'));

      // Verificar se a seta de ordenação aparece
      expect(screen.getByText('↑')).toBeInTheDocument();
    });

    it('deve alternar direção da ordenação', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
        />
      );

      const nameHeader = screen.getByText('Nome');
      
      // Primeira vez - ordenação ascendente
      fireEvent.click(nameHeader);
      expect(screen.getByText('↑')).toBeInTheDocument();

      // Segunda vez - ordenação descendente
      fireEvent.click(nameHeader);
      expect(screen.getByText('↓')).toBeInTheDocument();
    });
  });

  describe('Filtros', () => {
    it('deve filtrar dados por busca global', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showSearch={true}
        />
      );

      const searchInput = screen.getByPlaceholderText('Buscar em todas as colunas...');
      fireEvent.change(searchInput, { target: { value: 'João' } });

      expect(screen.getByText('João Silva')).toBeInTheDocument();
      expect(screen.queryByText('Maria Santos')).not.toBeInTheDocument();
    });

    it('deve filtrar por coluna específica', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showFilters={true}
        />
      );

      const statusFilter = screen.getByPlaceholderText('Filtrar status...');
      fireEvent.change(statusFilter, { target: { value: 'Ativo' } });

      expect(screen.getByText('João Silva')).toBeInTheDocument();
      expect(screen.getByText('Pedro Costa')).toBeInTheDocument();
      expect(screen.getByText('Carlos Lima')).toBeInTheDocument();
      expect(screen.queryByText('Maria Santos')).not.toBeInTheDocument();
    });
  });

  describe('Seleção Múltipla', () => {
    it('deve selecionar linha individual', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
          onRowSelect={mockOnRowSelect}
        />
      );

      const firstCheckbox = screen.getAllByRole('checkbox')[1]; // Primeira linha (após select all)
      fireEvent.click(firstCheckbox);

      expect(mockOnRowSelect).toHaveBeenCalledWith([mockData[0]]);
    });

    it('deve selecionar todas as linhas', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
          onRowSelect={mockOnRowSelect}
        />
      );

      const selectAllCheckbox = screen.getAllByRole('checkbox')[0];
      fireEvent.click(selectAllCheckbox);

      expect(mockOnRowSelect).toHaveBeenCalledWith(mockData);
    });

    it('deve mostrar ações em lote quando itens são selecionados', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
          onBulkAction={mockOnBulkAction}
        />
      );

      const firstCheckbox = screen.getAllByRole('checkbox')[1];
      fireEvent.click(firstCheckbox);

      expect(screen.getByText('1 item(s) selecionado(s)')).toBeInTheDocument();
      expect(screen.getByText('Excluir Selecionados')).toBeInTheDocument();
      expect(screen.getByText('Exportar Selecionados')).toBeInTheDocument();
    });

    it('deve executar ação em lote', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
          onBulkAction={mockOnBulkAction}
        />
      );

      const firstCheckbox = screen.getAllByRole('checkbox')[1];
      fireEvent.click(firstCheckbox);

      const deleteButton = screen.getByText('Excluir Selecionados');
      fireEvent.click(deleteButton);

      expect(mockOnBulkAction).toHaveBeenCalledWith([mockData[0]], 'delete');
    });
  });

  describe('Interação com Linhas', () => {
    it('deve chamar onRowClick quando linha é clicada', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          onRowClick={mockOnRowClick}
        />
      );

      const firstRow = screen.getByText('João Silva').closest('tr');
      fireEvent.click(firstRow!);

      expect(mockOnRowClick).toHaveBeenCalledWith(mockData[0]);
    });

    it('não deve chamar onRowClick quando checkbox é clicado', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
          onRowClick={mockOnRowClick}
        />
      );

      const firstCheckbox = screen.getAllByRole('checkbox')[1];
      fireEvent.click(firstCheckbox);

      expect(mockOnRowClick).not.toHaveBeenCalled();
    });
  });

  describe('Renderização Customizada', () => {
    it('deve renderizar coluna customizada', () => {
      const customColumns = [
        ...mockColumns,
        {
          key: 'status' as keyof TestData,
          header: 'Status Customizado',
          render: (value: string) => (
            <span className={`status-${value.toLowerCase()}`}>
              {value === 'Ativo' ? '✅' : '❌'} {value}
            </span>
          )
        }
      ];

      render(
        <DataTable
          data={mockData}
          columns={customColumns}
        />
      );

      expect(screen.getByText('✅ Ativo')).toBeInTheDocument();
      expect(screen.getByText('❌ Inativo')).toBeInTheDocument();
    });
  });

  describe('Estados de Loading', () => {
    it('deve mostrar estado de loading', () => {
      render(
        <DataTable
          data={[]}
          columns={mockColumns}
          loading={true}
        />
      );

      expect(screen.getByText('Carregando...')).toBeInTheDocument();
    });
  });

  describe('Configurações Opcionais', () => {
    it('deve ocultar paginação quando showPagination é false', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showPagination={false}
        />
      );

      expect(screen.queryByText('Anterior')).not.toBeInTheDocument();
      expect(screen.queryByText('Próxima')).not.toBeInTheDocument();
    });

    it('deve ocultar filtros quando showFilters é false', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showFilters={false}
        />
      );

      expect(screen.queryByPlaceholderText('Filtrar nome...')).not.toBeInTheDocument();
    });

    it('deve ocultar busca quando showSearch é false', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showSearch={false}
        />
      );

      expect(screen.queryByPlaceholderText('Buscar em todas as colunas...')).not.toBeInTheDocument();
    });

    it('deve ocultar ações em lote quando showBulkActions é false', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={false}
        />
      );

      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    });
  });

  describe('Acessibilidade', () => {
    it('deve ter cabeçalhos de tabela apropriados', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
        />
      );

      const headers = screen.getAllByRole('columnheader');
      expect(headers).toHaveLength(mockColumns.length);
    });

    it('deve ter checkboxes acessíveis', () => {
      render(
        <DataTable
          data={mockData}
          columns={mockColumns}
          showBulkActions={true}
        />
      );

      const checkboxes = screen.getAllByRole('checkbox');
      expect(checkboxes.length).toBeGreaterThan(0);
    });
  });
}); 