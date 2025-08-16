/**
 * Tabela Avançada - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Paginação
 * - Filtros
 * - Ordenação
 * - Seleção múltipla
 * - Responsividade
 * - Acessibilidade
 */

import React, { useState, useMemo, useCallback } from 'react';
import { Button } from './base/Button';
import { Input } from './base/Input';
import { Select } from './base/Select';
import { Card } from './base/Card';

interface Column<T> {
  key: keyof T;
  header: string;
  sortable?: boolean;
  filterable?: boolean;
  width?: string;
  render?: (value: any, row: T) => React.ReactNode;
  align?: 'left' | 'center' | 'right';
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  pageSize?: number;
  pageSizeOptions?: number[];
  showPagination?: boolean;
  showFilters?: boolean;
  showSearch?: boolean;
  showBulkActions?: boolean;
  onBulkAction?: (selectedRows: T[], action: string) => void;
  onRowClick?: (row: T) => void;
  onRowSelect?: (selectedRows: T[]) => void;
  className?: string;
  emptyMessage?: string;
  loading?: boolean;
}

interface SortConfig {
  key: keyof any;
  direction: 'asc' | 'desc';
}

interface FilterConfig {
  key: keyof any;
  value: string;
  operator: 'contains' | 'equals' | 'startsWith' | 'endsWith';
}

export function DataTable<T extends { id?: string | number }>({
  data,
  columns,
  pageSize = 10,
  pageSizeOptions = [5, 10, 25, 50],
  showPagination = true,
  showFilters = true,
  showSearch = true,
  showBulkActions = true,
  onBulkAction,
  onRowClick,
  onRowSelect,
  className = '',
  emptyMessage = 'Nenhum dado encontrado',
  loading = false,
}: DataTableProps<T>) {
  // Estados de paginação
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(pageSize);

  // Estados de ordenação
  const [sortConfig, setSortConfig] = useState<SortConfig | null>(null);

  // Estados de filtros
  const [filters, setFilters] = useState<FilterConfig[]>([]);
  const [searchTerm, setSearchTerm] = useState('');

  // Estados de seleção
  const [selectedRows, setSelectedRows] = useState<Set<string | number>>(new Set());
  const [selectAll, setSelectAll] = useState(false);

  // Filtrar dados
  const filteredData = useMemo(() => {
    let filtered = [...data];

    // Aplicar filtros específicos
    filters.forEach(filter => {
      filtered = filtered.filter(row => {
        const value = String(row[filter.key] || '').toLowerCase();
        const filterValue = filter.value.toLowerCase();

        switch (filter.operator) {
          case 'contains':
            return value.includes(filterValue);
          case 'equals':
            return value === filterValue;
          case 'startsWith':
            return value.startsWith(filterValue);
          case 'endsWith':
            return value.endsWith(filterValue);
          default:
            return true;
        }
      });
    });

    // Aplicar busca global
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      filtered = filtered.filter(row =>
        columns.some(column => {
          const value = String(row[column.key] || '').toLowerCase();
          return value.includes(searchLower);
        })
      );
    }

    return filtered;
  }, [data, filters, searchTerm, columns]);

  // Ordenar dados
  const sortedData = useMemo(() => {
    if (!sortConfig) return filteredData;

    return [...filteredData].sort((a, b) => {
      const aValue = a[sortConfig.key];
      const bValue = b[sortConfig.key];

      if (aValue === bValue) return 0;

      let comparison = 0;
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        comparison = aValue.localeCompare(bValue);
      } else if (typeof aValue === 'number' && typeof bValue === 'number') {
        comparison = aValue - bValue;
      } else {
        comparison = String(aValue).localeCompare(String(bValue));
      }

      return sortConfig.direction === 'asc' ? comparison : -comparison;
    });
  }, [filteredData, sortConfig]);

  // Paginar dados
  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return sortedData.slice(startIndex, endIndex);
  }, [sortedData, currentPage, itemsPerPage]);

  // Calcular métricas
  const totalItems = sortedData.length;
  const totalPages = Math.ceil(totalItems / itemsPerPage);
  const startItem = (currentPage - 1) * itemsPerPage + 1;
  const endItem = Math.min(currentPage * itemsPerPage, totalItems);

  // Handlers de ordenação
  const handleSort = useCallback((key: keyof T) => {
    setSortConfig(prev => {
      if (prev?.key === key) {
        return {
          key,
          direction: prev.direction === 'asc' ? 'desc' : 'asc'
        };
      }
      return { key, direction: 'asc' };
    });
  }, []);

  // Handlers de filtros
  const handleFilterChange = useCallback((key: keyof T, value: string, operator: FilterConfig['operator'] = 'contains') => {
    setFilters(prev => {
      const newFilters = prev.filter(f => f.key !== key);
      if (value.trim()) {
        newFilters.push({ key, value, operator });
      }
      return newFilters;
    });
  }, []);

  // Handlers de seleção
  const handleRowSelect = useCallback((row: T, checked: boolean) => {
    const rowId = row.id || JSON.stringify(row);
    setSelectedRows(prev => {
      const newSet = new Set(prev);
      if (checked) {
        newSet.add(rowId);
      } else {
        newSet.delete(rowId);
      }
      return newSet;
    });
  }, []);

  const handleSelectAll = useCallback((checked: boolean) => {
    if (checked) {
      const allIds = paginatedData.map(row => row.id || JSON.stringify(row));
      setSelectedRows(new Set(allIds));
      setSelectAll(true);
    } else {
      setSelectedRows(new Set());
      setSelectAll(false);
    }
  }, [paginatedData]);

  // Notificar mudanças na seleção
  React.useEffect(() => {
    const selectedData = data.filter(row => {
      const rowId = row.id || JSON.stringify(row);
      return selectedRows.has(rowId);
    });
    onRowSelect?.(selectedData);
  }, [selectedRows, data, onRowSelect]);

  // Resetar seleção quando dados mudam
  React.useEffect(() => {
    setSelectedRows(new Set());
    setSelectAll(false);
  }, [data]);

  // Resetar página quando filtros mudam
  React.useEffect(() => {
    setCurrentPage(1);
  }, [filters, searchTerm]);

  // Renderizar cabeçalho da tabela
  const renderHeader = () => (
    <thead className="bg-gray-50">
      <tr>
        {showBulkActions && (
          <th className="px-4 py-3 text-left">
            <input
              type="checkbox"
              checked={selectAll}
              onChange={(e) => handleSelectAll(e.target.checked)}
              className="rounded border-gray-300"
            />
          </th>
        )}
        {columns.map(column => (
          <th
            key={String(column.key)}
            className={`px-4 py-3 text-left text-sm font-medium text-gray-900 ${
              column.sortable ? 'cursor-pointer hover:bg-gray-100' : ''
            }`}
            style={{ width: column.width }}
            onClick={() => column.sortable && handleSort(column.key)}
          >
            <div className="flex items-center space-x-1">
              <span>{column.header}</span>
              {column.sortable && sortConfig?.key === column.key && (
                <span className="text-gray-500">
                  {sortConfig.direction === 'asc' ? '↑' : '↓'}
                </span>
              )}
            </div>
          </th>
        ))}
      </tr>
    </thead>
  );

  // Renderizar filtros
  const renderFilters = () => (
    <div className="bg-gray-50 p-4 border-b">
      <div className="flex flex-wrap gap-4 items-center">
        {showSearch && (
          <div className="flex-1 min-w-64">
            <Input
              placeholder="Buscar em todas as colunas..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        )}
        
        {showFilters && columns.filter(col => col.filterable).map(column => (
          <div key={String(column.key)} className="flex items-center space-x-2">
            <span className="text-sm text-gray-600">{column.header}:</span>
            <Input
              placeholder={`Filtrar ${column.header.toLowerCase()}...`}
              onChange={(e) => handleFilterChange(column.key, e.target.value)}
              className="w-32"
            />
          </div>
        ))}
        
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-600">Itens por página:</span>
          <Select
            value={itemsPerPage}
            onChange={(e) => setItemsPerPage(Number(e.target.value))}
            className="w-20"
          >
            {pageSizeOptions.map(size => (
              <option key={size} value={size}>{size}</option>
            ))}
          </Select>
        </div>
      </div>
    </div>
  );

  // Renderizar ações em lote
  const renderBulkActions = () => {
    if (!showBulkActions || selectedRows.size === 0) return null;

    return (
      <div className="bg-blue-50 p-4 border-b border-blue-200">
        <div className="flex items-center justify-between">
          <span className="text-sm text-blue-900">
            {selectedRows.size} item(s) selecionado(s)
          </span>
          <div className="flex space-x-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onBulkAction?.(paginatedData.filter(row => {
                const rowId = row.id || JSON.stringify(row);
                return selectedRows.has(rowId);
              }), 'delete')}
            >
              Excluir Selecionados
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => onBulkAction?.(paginatedData.filter(row => {
                const rowId = row.id || JSON.stringify(row);
                return selectedRows.has(rowId);
              }), 'export')}
            >
              Exportar Selecionados
            </Button>
          </div>
        </div>
      </div>
    );
  };

  // Renderizar corpo da tabela
  const renderBody = () => (
    <tbody className="bg-white divide-y divide-gray-200">
      {paginatedData.map((row, index) => {
        const rowId = row.id || JSON.stringify(row);
        const isSelected = selectedRows.has(rowId);
        
        return (
          <tr
            key={rowId}
            className={`hover:bg-gray-50 ${isSelected ? 'bg-blue-50' : ''} ${
              onRowClick ? 'cursor-pointer' : ''
            }`}
            onClick={() => onRowClick?.(row)}
          >
            {showBulkActions && (
              <td className="px-4 py-3">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={(e) => {
                    e.stopPropagation();
                    handleRowSelect(row, e.target.checked);
                  }}
                  className="rounded border-gray-300"
                />
              </td>
            )}
            {columns.map(column => (
              <td
                key={String(column.key)}
                className={`px-4 py-3 text-sm text-gray-900 ${
                  column.align === 'center' ? 'text-center' :
                  column.align === 'right' ? 'text-right' : 'text-left'
                }`}
              >
                {column.render
                  ? column.render(row[column.key], row)
                  : String(row[column.key] || '')
                }
              </td>
            ))}
          </tr>
        );
      })}
    </tbody>
  );

  // Renderizar paginação
  const renderPagination = () => {
    if (!showPagination || totalPages <= 1) return null;

    const getPageNumbers = (): (number | string)[] => {
      const pages: (number | string)[] = [];
      const maxVisible = 5;
      
      if (totalPages <= maxVisible) {
        for (let i = 1; i <= totalPages; i++) {
          pages.push(i);
        }
      } else {
        if (currentPage <= 3) {
          for (let i = 1; i <= 4; i++) pages.push(i);
          pages.push('...');
          pages.push(totalPages);
        } else if (currentPage >= totalPages - 2) {
          pages.push(1);
          pages.push('...');
          for (let i = totalPages - 3; i <= totalPages; i++) pages.push(i);
        } else {
          pages.push(1);
          pages.push('...');
          for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i);
          pages.push('...');
          pages.push(totalPages);
        }
      }
      
      return pages;
    };

    return (
      <div className="bg-white px-4 py-3 border-t border-gray-200">
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-700">
            Mostrando {startItem} a {endItem} de {totalItems} resultados
          </div>
          
          <div className="flex items-center space-x-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
            >
              Anterior
            </Button>
            
            {getPageNumbers().map((page, index) => (
              <React.Fragment key={index}>
                {page === '...' ? (
                  <span className="px-3 py-2 text-gray-500">...</span>
                ) : (
                  <Button
                    variant={currentPage === page ? "primary" : "secondary"}
                    size="sm"
                    onClick={() => setCurrentPage(page as number)}
                  >
                    {page}
                  </Button>
                )}
              </React.Fragment>
            ))}
            
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
            >
              Próxima
            </Button>
          </div>
        </div>
      </div>
    );
  };

  // Renderizar estado vazio
  const renderEmpty = () => (
    <tbody>
      <tr>
        <td
          colSpan={columns.length + (showBulkActions ? 1 : 0)}
          className="px-4 py-8 text-center text-gray-500"
        >
          {loading ? 'Carregando...' : emptyMessage}
        </td>
      </tr>
    </tbody>
  );

  return (
    <div className={`data-table ${className}`}>
      <Card className="overflow-hidden">
        {renderFilters()}
        {renderBulkActions()}
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            {renderHeader()}
            {paginatedData.length > 0 ? renderBody() : renderEmpty()}
          </table>
        </div>
        
        {renderPagination()}
      </Card>
    </div>
  );
}

export default DataTable; 