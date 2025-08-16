/**
 * Tabela Virtualizada - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-025.4
 * Data/Hora: 2025-01-28T02:37:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Tabela virtualizada com memoização
 * - Performance otimizada para muitos registros
 * - Sorting e filtering
 * - Paginação virtual
 * - Loading states
 */

import React, { useState, useEffect, useRef, useCallback, useMemo, memo } from 'react';
import { Loading } from './base/Loading';
import { VirtualizedList } from './VirtualizedList';

// ===== TIPOS =====

interface Column<T> {
  key: string;
  header: string;
  width?: number;
  sortable?: boolean;
  filterable?: boolean;
  render?: (value: any, item: T, index: number) => React.ReactNode;
  accessor: (item: T) => any;
}

interface VirtualizedTableProps<T> {
  data: T[];
  columns: Column<T>[];
  height: number;
  rowHeight: number;
  loading?: boolean;
  sortable?: boolean;
  filterable?: boolean;
  onSort?: (key: string, direction: 'asc' | 'desc') => void;
  onFilter?: (filters: Record<string, any>) => void;
  className?: string;
  emptyMessage?: string;
  keyExtractor: (item: T, index: number) => string | number;
}

interface SortConfig {
  key: string;
  direction: 'asc' | 'desc';
}

interface FilterConfig {
  [key: string]: any;
}

// ===== COMPONENTES MEMOIZADOS =====

/**
 * Cabeçalho da tabela memoizado
 */
const TableHeader = memo(<T extends any>({
  columns,
  sortConfig,
  onSort,
  sortable = false
}: {
  columns: Column<T>[];
  sortConfig?: SortConfig;
  onSort?: (key: string, direction: 'asc' | 'desc') => void;
  sortable?: boolean;
}) => {
  const handleSort = useCallback((key: string) => {
    if (!sortable || !onSort) return;
    
    const direction = sortConfig?.key === key && sortConfig.direction === 'asc' ? 'desc' : 'asc';
    onSort(key, direction);
  }, [sortable, onSort, sortConfig]);

  return (
    <div className="table-header flex border-b border-gray-200 bg-gray-50">
      {columns.map((column) => (
        <div
          key={column.key}
          className="table-cell px-4 py-3 font-semibold text-gray-700"
          style={{ width: column.width || 'auto', minWidth: column.width || 120 }}
        >
          <div className="flex items-center justify-between">
            <span>{column.header}</span>
            {sortable && column.sortable && (
              <button
                onClick={() => handleSort(column.key)}
                className="ml-2 p-1 hover:bg-gray-200 rounded"
              >
                <span className="text-xs">
                  {sortConfig?.key === column.key ? (
                    sortConfig.direction === 'asc' ? '↑' : '↓'
                  ) : (
                    '↕'
                  )}
                </span>
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
});

TableHeader.displayName = 'TableHeader';

/**
 * Linha da tabela memoizada
 */
const TableRow = memo(<T extends any>({
  item,
  columns,
  index,
  rowHeight
}: {
  item: T;
  columns: Column<T>[];
  index: number;
  rowHeight: number;
}) => {
  return (
    <div
      className="table-row flex border-b border-gray-100 hover:bg-gray-50 transition-colors"
      style={{ height: rowHeight }}
    >
      {columns.map((column) => (
        <div
          key={column.key}
          className="table-cell px-4 py-2 flex items-center"
          style={{ width: column.width || 'auto', minWidth: column.width || 120 }}
        >
          {column.render ? (
            column.render(column.accessor(item), item, index)
          ) : (
            <span className="text-gray-900">
              {column.accessor(item)}
            </span>
          )}
        </div>
      ))}
    </div>
  );
});

TableRow.displayName = 'TableRow';

/**
 * Filtros da tabela memoizados
 */
const TableFilters = memo(<T extends any>({
  columns,
  filters,
  onFilter,
  filterable = false
}: {
  columns: Column<T>[];
  filters: FilterConfig;
  onFilter?: (filters: FilterConfig) => void;
  filterable?: boolean;
}) => {
  const [localFilters, setLocalFilters] = useState<FilterConfig>(filters);

  const handleFilterChange = useCallback((key: string, value: any) => {
    const newFilters = { ...localFilters, [key]: value };
    setLocalFilters(newFilters);
    onFilter?.(newFilters);
  }, [localFilters, onFilter]);

  if (!filterable) return null;

  return (
    <div className="table-filters flex border-b border-gray-200 bg-gray-25 p-2">
      {columns.map((column) => (
        column.filterable && (
          <div
            key={column.key}
            className="filter-item mr-4"
            style={{ width: column.width || 120 }}
          >
            <input
              type="text"
              placeholder={`Filtrar ${column.header}...`}
              value={localFilters[column.key] || ''}
              onChange={(e) => handleFilterChange(column.key, e.target.value)}
              className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        )
      ))}
    </div>
  );
});

TableFilters.displayName = 'TableFilters';

// ===== COMPONENTE PRINCIPAL =====

/**
 * Tabela virtualizada com memoização para performance
 */
export const VirtualizedTable = <T extends any>({
  data,
  columns,
  height,
  rowHeight,
  loading = false,
  sortable = false,
  filterable = false,
  onSort,
  onFilter,
  className = '',
  emptyMessage = 'Nenhum dado encontrado',
  keyExtractor
}: VirtualizedTableProps<T>) => {
  const [sortConfig, setSortConfig] = useState<SortConfig | undefined>();
  const [filters, setFilters] = useState<FilterConfig>({});
  const [filteredData, setFilteredData] = useState<T[]>(data);

  // Aplicar filtros
  useEffect(() => {
    let result = data;

    // Aplicar filtros
    Object.entries(filters).forEach(([key, value]) => {
      if (value) {
        const column = columns.find(col => col.key === key);
        if (column) {
          result = result.filter(item => {
            const itemValue = column.accessor(item);
            return String(itemValue).toLowerCase().includes(String(value).toLowerCase());
          });
        }
      }
    });

    // Aplicar sorting
    if (sortConfig) {
      const column = columns.find(col => col.key === sortConfig.key);
      if (column) {
        result = [...result].sort((a, b) => {
          const aValue = column.accessor(a);
          const bValue = column.accessor(b);
          
          if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
          if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
          return 0;
        });
      }
    }

    setFilteredData(result);
  }, [data, filters, sortConfig, columns]);

  // Handler de sorting
  const handleSort = useCallback((key: string, direction: 'asc' | 'desc') => {
    setSortConfig({ key, direction });
    onSort?.(key, direction);
  }, [onSort]);

  // Handler de filtros
  const handleFilter = useCallback((newFilters: FilterConfig) => {
    setFilters(newFilters);
    onFilter?.(newFilters);
  }, [onFilter]);

  // Renderizar linha da tabela
  const renderRow = useCallback((item: T, index: number) => (
    <TableRow
      item={item}
      columns={columns}
      index={index}
      rowHeight={rowHeight}
    />
  ), [columns, rowHeight]);

  // Calcular altura da tabela sem cabeçalho
  const tableBodyHeight = height - (filterable ? 80 : 50);

  return (
    <div className={`virtualized-table ${className}`}>
      {/* Cabeçalho */}
      <TableHeader
        columns={columns}
        sortConfig={sortConfig}
        onSort={handleSort}
        sortable={sortable}
      />

      {/* Filtros */}
      <TableFilters
        columns={columns}
        filters={filters}
        onFilter={handleFilter}
        filterable={filterable}
      />

      {/* Corpo da tabela */}
      <div className="table-body" style={{ height: tableBodyHeight }}>
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <Loading size="lg" text="Carregando dados..." />
          </div>
        ) : filteredData.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {emptyMessage}
          </div>
        ) : (
          <VirtualizedList
            items={filteredData}
            itemHeight={rowHeight}
            containerHeight={tableBodyHeight}
            renderItem={renderRow}
            keyExtractor={keyExtractor}
            overscan={10}
          />
        )}
      </div>
    </div>
  );
};

// ===== HOOKS ADICIONAIS =====

/**
 * Hook para gerenciar estado da tabela virtualizada
 */
export const useVirtualizedTableState = <T extends any>(
  initialData: T[] = [],
  pageSize: number = 50
) => {
  const [data, setData] = useState<T[]>(initialData);
  const [loading, setLoading] = useState(false);
  const [sortConfig, setSortConfig] = useState<SortConfig | undefined>();
  const [filters, setFilters] = useState<FilterConfig>({});

  const loadData = useCallback(async (loadFunction: () => Promise<T[]>) => {
    setLoading(true);
    try {
      const newData = await loadFunction();
      setData(newData);
    } catch (error) {
      console.error('Erro ao carregar dados da tabela:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setData([]);
    setLoading(false);
    setSortConfig(undefined);
    setFilters({});
  }, []);

  return {
    data,
    loading,
    sortConfig,
    filters,
    loadData,
    reset,
    setData,
    setSortConfig,
    setFilters
  };
};

/**
 * Hook para memoização de dados da tabela
 */
export const useTableMemoization = <T extends any>(
  data: T[],
  dependencies: any[] = []
) => {
  return useMemo(() => data, [data, ...dependencies]);
};

export default VirtualizedTable; 