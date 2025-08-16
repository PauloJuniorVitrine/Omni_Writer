/**
 * Lista Virtualizada - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-025.4
 * Data/Hora: 2025-01-28T02:36:00Z
 * Tracing ID: UI_IMPLEMENTATION_FINAL_20250128_001
 * 
 * Funcionalidades:
 * - Virtualização de listas grandes
 * - Performance otimizada para 10k+ itens
 * - Scroll suave e responsivo
 * - Loading states para itens
 * - Infinite scroll
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Loading } from './base/Loading';

// ===== TIPOS =====

interface VirtualizedListProps<T> {
  items: T[];
  itemHeight: number;
  containerHeight: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  keyExtractor: (item: T, index: number) => string | number;
  loading?: boolean;
  onLoadMore?: () => void;
  hasMore?: boolean;
  overscan?: number;
  className?: string;
}

interface VirtualizedItem {
  index: number;
  top: number;
  height: number;
  visible: boolean;
}

// ===== HOOKS =====

/**
 * Hook para calcular itens visíveis na viewport
 */
const useVirtualization = (
  items: any[],
  itemHeight: number,
  containerHeight: number,
  overscan: number = 5
) => {
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  // Calcular itens visíveis
  const visibleItems = useMemo(() => {
    const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const endIndex = Math.min(
      items.length - 1,
      Math.floor((scrollTop + containerHeight) / itemHeight) + overscan
    );

    const visible: VirtualizedItem[] = [];
    for (let i = startIndex; i <= endIndex; i++) {
      visible.push({
        index: i,
        top: i * itemHeight,
        height: itemHeight,
        visible: true
      });
    }

    return visible;
  }, [items.length, itemHeight, containerHeight, scrollTop, overscan]);

  // Calcular altura total da lista
  const totalHeight = useMemo(() => items.length * itemHeight, [items.length, itemHeight]);

  // Handler de scroll
  const handleScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
  }, []);

  return {
    visibleItems,
    totalHeight,
    scrollTop,
    containerRef,
    handleScroll
  };
};

// ===== COMPONENTE PRINCIPAL =====

/**
 * Lista virtualizada para performance com muitos itens
 */
export const VirtualizedList = <T extends any>({
  items,
  itemHeight,
  containerHeight,
  renderItem,
  keyExtractor,
  loading = false,
  onLoadMore,
  hasMore = false,
  overscan = 5,
  className = ''
}: VirtualizedListProps<T>) => {
  const {
    visibleItems,
    totalHeight,
    scrollTop,
    containerRef,
    handleScroll
  } = useVirtualization(items, itemHeight, containerHeight, overscan);

  // Detectar quando chegar ao final da lista
  const handleScrollEnd = useCallback(() => {
    if (onLoadMore && hasMore && !loading) {
      const scrollElement = containerRef.current;
      if (scrollElement) {
        const { scrollTop, scrollHeight, clientHeight } = scrollElement;
        if (scrollTop + clientHeight >= scrollHeight - 100) {
          onLoadMore();
        }
      }
    }
  }, [onLoadMore, hasMore, loading, containerRef]);

  // Adicionar handler de scroll end
  useEffect(() => {
    const scrollElement = containerRef.current;
    if (scrollElement) {
      scrollElement.addEventListener('scroll', handleScrollEnd);
      return () => scrollElement.removeEventListener('scroll', handleScrollEnd);
    }
  }, [handleScrollEnd]);

  return (
    <div className={`virtualized-list ${className}`}>
      <div
        ref={containerRef}
        style={{
          height: containerHeight,
          overflow: 'auto',
          position: 'relative'
        }}
        onScroll={handleScroll}
        className="virtualized-container"
      >
        {/* Container com altura total para scroll */}
        <div
          style={{
            height: totalHeight,
            position: 'relative'
          }}
          className="virtualized-content"
        >
          {/* Renderizar apenas itens visíveis */}
          {visibleItems.map(({ index, top, height }) => {
            const item = items[index];
            if (!item) return null;

            return (
              <div
                key={keyExtractor(item, index)}
                style={{
                  position: 'absolute',
                  top,
                  height,
                  width: '100%'
                }}
                className="virtualized-item"
              >
                {renderItem(item, index)}
              </div>
            );
          })}
        </div>

        {/* Loading indicator no final */}
        {loading && hasMore && (
          <div
            style={{
              position: 'absolute',
              bottom: 0,
              left: 0,
              right: 0,
              padding: '1rem',
              background: 'rgba(255, 255, 255, 0.9)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}
            className="virtualized-loading"
          >
            <Loading size="sm" text="Carregando mais itens..." />
          </div>
        )}
      </div>
    </div>
  );
};

// ===== COMPONENTES ESPECIALIZADOS =====

/**
 * Lista virtualizada para dados com altura variável
 */
export const VariableHeightVirtualizedList = <T extends any>({
  items,
  containerHeight,
  renderItem,
  keyExtractor,
  getItemHeight,
  loading = false,
  onLoadMore,
  hasMore = false,
  overscan = 5,
  className = ''
}: Omit<VirtualizedListProps<T>, 'itemHeight'> & {
  getItemHeight: (item: T, index: number) => number;
}) => {
  const [itemHeights, setItemHeights] = useState<Map<number, number>>(new Map());
  const [totalHeight, setTotalHeight] = useState(0);

  // Calcular alturas dos itens
  useEffect(() => {
    const heights = new Map<number, number>();
    let total = 0;

    items.forEach((item, index) => {
      const height = getItemHeight(item, index);
      heights.set(index, height);
      total += height;
    });

    setItemHeights(heights);
    setTotalHeight(total);
  }, [items, getItemHeight]);

  // Calcular posições dos itens
  const getItemPosition = useCallback((index: number) => {
    let position = 0;
    for (let i = 0; i < index; i++) {
      position += itemHeights.get(i) || 0;
    }
    return position;
  }, [itemHeights]);

  // Calcular itens visíveis
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  const visibleItems = useMemo(() => {
    const startIndex = 0;
    const endIndex = items.length - 1;

    const visible: VirtualizedItem[] = [];
    for (let i = startIndex; i <= endIndex; i++) {
      const top = getItemPosition(i);
      const height = itemHeights.get(i) || 0;
      
      // Verificar se o item está visível
      const isVisible = top + height > scrollTop && top < scrollTop + containerHeight;
      
      if (isVisible || i < overscan || i > endIndex - overscan) {
        visible.push({
          index: i,
          top,
          height,
          visible: isVisible
        });
      }
    }

    return visible;
  }, [items.length, itemHeights, scrollTop, containerHeight, overscan, getItemPosition]);

  const handleScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
  }, []);

  return (
    <div className={`variable-height-virtualized-list ${className}`}>
      <div
        ref={containerRef}
        style={{
          height: containerHeight,
          overflow: 'auto',
          position: 'relative'
        }}
        onScroll={handleScroll}
        className="virtualized-container"
      >
        <div
          style={{
            height: totalHeight,
            position: 'relative'
          }}
          className="virtualized-content"
        >
          {visibleItems.map(({ index, top, height }) => {
            const item = items[index];
            if (!item) return null;

            return (
              <div
                key={keyExtractor(item, index)}
                style={{
                  position: 'absolute',
                  top,
                  height,
                  width: '100%'
                }}
                className="virtualized-item"
              >
                {renderItem(item, index)}
              </div>
            );
          })}
        </div>

        {loading && hasMore && (
          <div
            style={{
              position: 'absolute',
              bottom: 0,
              left: 0,
              right: 0,
              padding: '1rem',
              background: 'rgba(255, 255, 255, 0.9)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center'
            }}
            className="virtualized-loading"
          >
            <Loading size="sm" text="Carregando mais itens..." />
          </div>
        )}
      </div>
    </div>
  );
};

// ===== HOOKS ADICIONAIS =====

/**
 * Hook para gerenciar estado de loading e paginação
 */
export const useVirtualizedListState = <T extends any>(
  initialItems: T[] = [],
  pageSize: number = 20
) => {
  const [items, setItems] = useState<T[]>(initialItems);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [page, setPage] = useState(1);

  const loadMore = useCallback(async (loadFunction: (page: number) => Promise<T[]>) => {
    if (loading || !hasMore) return;

    setLoading(true);
    try {
      const newItems = await loadFunction(page);
      if (newItems.length < pageSize) {
        setHasMore(false);
      }
      setItems(prev => [...prev, ...newItems]);
      setPage(prev => prev + 1);
    } catch (error) {
      console.error('Erro ao carregar mais itens:', error);
    } finally {
      setLoading(false);
    }
  }, [loading, hasMore, page, pageSize]);

  const reset = useCallback(() => {
    setItems([]);
    setLoading(false);
    setHasMore(true);
    setPage(1);
  }, []);

  return {
    items,
    loading,
    hasMore,
    page,
    loadMore,
    reset,
    setItems
  };
};

export default VirtualizedList; 