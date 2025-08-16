/**
 * Sistema de Gráficos - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:45:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Funcionalidades:
 * - Line charts
 * - Bar charts
 * - Pie charts
 * - Real-time updates
 * - Responsividade
 * - Acessibilidade
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';

// Tipos base para dados de gráficos
interface ChartDataPoint {
  label: string;
  value: number;
  color?: string;
}

interface ChartDataset {
  label: string;
  data: number[];
  borderColor?: string;
  backgroundColor?: string;
  fill?: boolean;
}

interface ChartData {
  labels: string[];
  datasets: ChartDataset[];
}

interface ChartProps {
  data: ChartData | ChartDataPoint[];
  type: 'line' | 'bar' | 'pie';
  width?: number;
  height?: number;
  responsive?: boolean;
  showLegend?: boolean;
  showGrid?: boolean;
  showTooltip?: boolean;
  animate?: boolean;
  className?: string;
  onPointClick?: (point: any, index: number) => void;
}

// Cores padrão para gráficos
const DEFAULT_COLORS = [
  '#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6',
  '#06B6D4', '#84CC16', '#F97316', '#EC4899', '#6366F1'
];

/**
 * Componente base para gráficos
 */
const BaseChart: React.FC<ChartProps> = ({
  data,
  type,
  width = 400,
  height = 300,
  responsive = true,
  showLegend = true,
  showGrid = true,
  showTooltip = true,
  animate = true,
  className = '',
  onPointClick
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<number | null>(null);
  const [hoveredDataset, setHoveredDataset] = useState<number | null>(null);

  // Normalizar dados para diferentes tipos de gráfico
  const normalizedData = useMemo(() => {
    if (type === 'pie') {
      return Array.isArray(data) ? data : [];
    }
    return 'datasets' in data ? data : { labels: [], datasets: [] };
  }, [data, type]);

  // Calcular dimensões responsivas
  const chartDimensions = useMemo(() => {
    if (responsive) {
      return { width: '100%', height: '100%' };
    }
    return { width, height };
  }, [responsive, width, height]);

  // Calcular margens e área de desenho
  const margins = { top: 20, right: 20, bottom: 40, left: 40 };
  const chartWidth = typeof chartDimensions.width === 'number' ? chartDimensions.width : 400;
  const chartHeight = typeof chartDimensions.height === 'number' ? chartDimensions.height : 300;
  const drawWidth = chartWidth - margins.left - margins.right;
  const drawHeight = chartHeight - margins.top - margins.bottom;

  // Renderizar gráfico de linha
  const renderLineChart = () => {
    if (!('datasets' in normalizedData) || normalizedData.datasets.length === 0) return null;

    const dataset = normalizedData.datasets[0];
    const maxValue = Math.max(...dataset.data);
    const minValue = Math.min(...dataset.data);
    const range = maxValue - minValue || 1;

    const getX = (index: number) => {
      return margins.left + (index / (dataset.data.length - 1)) * drawWidth;
    };

    const getY = (value: number) => {
      return margins.top + drawHeight - ((value - minValue) / range) * drawHeight;
    };

    const generatePath = () => {
      const points = dataset.data.map((value, index) => {
        const x = getX(index);
        const y = getY(value);
        return `${x},${y}`;
      });
      
      return `M ${points.join(' L ')}`;
    };

    const generateAreaPath = () => {
      const points = dataset.data.map((value, index) => {
        const x = getX(index);
        const y = getY(value);
        return `${x},${y}`;
      });
      
      const bottomPoints = dataset.data.map((_, index) => {
        const x = getX(index);
        return `${x},${margins.top + drawHeight}`;
      }).reverse();
      
      return `M ${points.join(' L ')} L ${bottomPoints.join(' L ')} Z`;
    };

    return (
      <svg
        width={chartWidth}
        height={chartHeight}
        className={`chart-svg ${animate ? 'animate-chart' : ''}`}
        onMouseLeave={() => setHoveredPoint(null)}
      >
        {/* Grid */}
        {showGrid && (
          <g className="chart-grid">
            {[0, 25, 50, 75, 100].map((percent) => (
              <line
                key={percent}
                x1={margins.left + (percent / 100) * drawWidth}
                y1={margins.top}
                x2={margins.left + (percent / 100) * drawWidth}
                y2={margins.top + drawHeight}
                stroke="#e5e7eb"
                strokeWidth="1"
                opacity={0.5}
              />
            ))}
            {[0, 25, 50, 75, 100].map((percent) => (
              <line
                key={`h-${percent}`}
                x1={margins.left}
                y1={margins.top + (percent / 100) * drawHeight}
                x2={margins.left + drawWidth}
                y2={margins.top + (percent / 100) * drawHeight}
                stroke="#e5e7eb"
                strokeWidth="1"
                opacity={0.5}
              />
            ))}
          </g>
        )}

        {/* Área do gráfico */}
        {dataset.fill && (
          <path
            d={generateAreaPath()}
            fill={dataset.backgroundColor || 'rgba(59, 130, 246, 0.1)'}
            opacity={0.3}
          />
        )}

        {/* Linha do gráfico */}
        <path
          d={generatePath()}
          stroke={dataset.borderColor || '#3B82F6'}
          strokeWidth="2"
          fill="none"
          className="chart-line"
        />

        {/* Pontos do gráfico */}
        {dataset.data.map((value, index) => {
          const x = getX(index);
          const y = getY(value);
          const isHovered = hoveredPoint === index;
          
          return (
            <g key={index}>
              <circle
                cx={x}
                cy={y}
                r={isHovered ? 6 : 4}
                fill={dataset.borderColor || '#3B82F6'}
                className="chart-point"
                onMouseEnter={() => setHoveredPoint(index)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => onPointClick?.({ value, label: normalizedData.labels[index] }, index)}
                style={{ cursor: onPointClick ? 'pointer' : 'default' }}
              />
              
              {/* Tooltip */}
              {isHovered && showTooltip && (
                <g className="chart-tooltip">
                  <rect
                    x={x - 40}
                    y={y - 40}
                    width="80"
                    height="30"
                    rx="4"
                    fill="rgba(0, 0, 0, 0.8)"
                  />
                  <text
                    x={x}
                    y={y - 20}
                    textAnchor="middle"
                    fill="white"
                    fontSize="12"
                    fontWeight="bold"
                  >
                    {value}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Labels do eixo X */}
        <g className="chart-axis-x">
          {normalizedData.labels.map((label, index) => (
            <text
              key={index}
              x={getX(index)}
              y={margins.top + drawHeight + 20}
              textAnchor="middle"
              fontSize="12"
              fill="#6B7280"
            >
              {label}
            </text>
          ))}
        </g>

        {/* Labels do eixo Y */}
        <g className="chart-axis-y">
          {[maxValue, (maxValue + minValue) / 2, minValue].map((value, index) => (
            <text
              key={index}
              x={margins.left - 10}
              y={getY(value) + 4}
              textAnchor="end"
              fontSize="12"
              fill="#6B7280"
            >
              {Math.round(value)}
            </text>
          ))}
        </g>
      </svg>
    );
  };

  // Renderizar gráfico de barras
  const renderBarChart = () => {
    if (!('datasets' in normalizedData) || normalizedData.datasets.length === 0) return null;

    const dataset = normalizedData.datasets[0];
    const maxValue = Math.max(...dataset.data);
    const barWidth = drawWidth / dataset.data.length * 0.8;
    const barSpacing = drawWidth / dataset.data.length * 0.2;

    const getX = (index: number) => {
      return margins.left + index * (barWidth + barSpacing) + barSpacing / 2;
    };

    const getY = (value: number) => {
      return margins.top + drawHeight - (value / maxValue) * drawHeight;
    };

    const getHeight = (value: number) => {
      return (value / maxValue) * drawHeight;
    };

    return (
      <svg
        width={chartWidth}
        height={chartHeight}
        className={`chart-svg ${animate ? 'animate-chart' : ''}`}
        onMouseLeave={() => setHoveredPoint(null)}
      >
        {/* Grid */}
        {showGrid && (
          <g className="chart-grid">
            {[0, 25, 50, 75, 100].map((percent) => (
              <line
                key={percent}
                x1={margins.left}
                y1={margins.top + (percent / 100) * drawHeight}
                x2={margins.left + drawWidth}
                y2={margins.top + (percent / 100) * drawHeight}
                stroke="#e5e7eb"
                strokeWidth="1"
                opacity={0.5}
              />
            ))}
          </g>
        )}

        {/* Barras */}
        {dataset.data.map((value, index) => {
          const x = getX(index);
          const y = getY(value);
          const height = getHeight(value);
          const isHovered = hoveredPoint === index;
          
          return (
            <g key={index}>
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={height}
                fill={dataset.backgroundColor || '#3B82F6'}
                stroke={dataset.borderColor || '#2563EB'}
                strokeWidth="1"
                className="chart-bar"
                onMouseEnter={() => setHoveredPoint(index)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => onPointClick?.({ value, label: normalizedData.labels[index] }, index)}
                style={{ 
                  cursor: onPointClick ? 'pointer' : 'default',
                  opacity: isHovered ? 0.8 : 1
                }}
              />
              
              {/* Tooltip */}
              {isHovered && showTooltip && (
                <g className="chart-tooltip">
                  <rect
                    x={x - 30}
                    y={y - 40}
                    width="60"
                    height="30"
                    rx="4"
                    fill="rgba(0, 0, 0, 0.8)"
                  />
                  <text
                    x={x}
                    y={y - 20}
                    textAnchor="middle"
                    fill="white"
                    fontSize="12"
                    fontWeight="bold"
                  >
                    {value}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Labels do eixo X */}
        <g className="chart-axis-x">
          {normalizedData.labels.map((label, index) => (
            <text
              key={index}
              x={getX(index) + barWidth / 2}
              y={margins.top + drawHeight + 20}
              textAnchor="middle"
              fontSize="12"
              fill="#6B7280"
            >
              {label}
            </text>
          ))}
        </g>

        {/* Labels do eixo Y */}
        <g className="chart-axis-y">
          {[maxValue, maxValue * 0.75, maxValue * 0.5, maxValue * 0.25, 0].map((value, index) => (
            <text
              key={index}
              x={margins.left - 10}
              y={getY(value) + 4}
              textAnchor="end"
              fontSize="12"
              fill="#6B7280"
            >
              {Math.round(value)}
            </text>
          ))}
        </g>
      </svg>
    );
  };

  // Renderizar gráfico de pizza
  const renderPieChart = () => {
    if (!Array.isArray(normalizedData) || normalizedData.length === 0) return null;

    const total = normalizedData.reduce((sum, point) => sum + point.value, 0);
    const centerX = chartWidth / 2;
    const centerY = chartHeight / 2;
    const radius = Math.min(centerX, centerY) - 40;

    let currentAngle = -Math.PI / 2; // Começar do topo

    const generateArc = (startAngle: number, endAngle: number) => {
      const x1 = centerX + radius * Math.cos(startAngle);
      const y1 = centerY + radius * Math.sin(startAngle);
      const x2 = centerX + radius * Math.cos(endAngle);
      const y2 = centerY + radius * Math.sin(endAngle);
      
      const largeArcFlag = endAngle - startAngle > Math.PI ? 1 : 0;
      
      return `M ${centerX} ${centerY} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2} Z`;
    };

    return (
      <svg
        width={chartWidth}
        height={chartHeight}
        className={`chart-svg ${animate ? 'animate-chart' : ''}`}
        onMouseLeave={() => setHoveredPoint(null)}
      >
        {/* Fatias do gráfico */}
        {normalizedData.map((point, index) => {
          const angle = (point.value / total) * 2 * Math.PI;
          const startAngle = currentAngle;
          const endAngle = currentAngle + angle;
          const isHovered = hoveredPoint === index;
          
          currentAngle += angle;

          const color = point.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length];
          const midAngle = (startAngle + endAngle) / 2;
          const labelX = centerX + (radius * 0.7) * Math.cos(midAngle);
          const labelY = centerY + (radius * 0.7) * Math.sin(midAngle);

          return (
            <g key={index}>
              <path
                d={generateArc(startAngle, endAngle)}
                fill={color}
                stroke="white"
                strokeWidth="2"
                className="chart-pie-slice"
                onMouseEnter={() => setHoveredPoint(index)}
                onMouseLeave={() => setHoveredPoint(null)}
                onClick={() => onPointClick?.(point, index)}
                style={{ 
                  cursor: onPointClick ? 'pointer' : 'default',
                  opacity: isHovered ? 0.8 : 1,
                  transform: isHovered ? 'scale(1.05)' : 'scale(1)',
                  transformOrigin: `${centerX}px ${centerY}px`
                }}
              />
              
              {/* Label da fatia */}
              <text
                x={labelX}
                y={labelY}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize="12"
                fontWeight="bold"
                fill="white"
                className="chart-pie-label"
              >
                {Math.round((point.value / total) * 100)}%
              </text>
            </g>
          );
        })}

        {/* Tooltip */}
        {hoveredPoint !== null && showTooltip && (
          <g className="chart-tooltip">
            <rect
              x={10}
              y={10}
              width="120"
              height="60"
              rx="4"
              fill="rgba(0, 0, 0, 0.8)"
            />
            <text
              x={20}
              y={30}
              fill="white"
              fontSize="12"
              fontWeight="bold"
            >
              {normalizedData[hoveredPoint].label}
            </text>
            <text
              x={20}
              y={50}
              fill="white"
              fontSize="12"
            >
              {normalizedData[hoveredPoint].value}
            </text>
          </g>
        )}
      </svg>
    );
  };

  // Renderizar legenda
  const renderLegend = () => {
    if (!showLegend) return null;

    if (type === 'pie') {
      return (
        <div className="chart-legend">
          {normalizedData.map((point, index) => (
            <div key={index} className="legend-item">
              <div
                className="legend-color"
                style={{ backgroundColor: point.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length] }}
              />
              <span className="legend-label">{point.label}</span>
            </div>
          ))}
        </div>
      );
    }

    if ('datasets' in normalizedData) {
      return (
        <div className="chart-legend">
          {normalizedData.datasets.map((dataset, index) => (
            <div key={index} className="legend-item">
              <div
                className="legend-color"
                style={{ backgroundColor: dataset.backgroundColor || DEFAULT_COLORS[index % DEFAULT_COLORS.length] }}
              />
              <span className="legend-label">{dataset.label}</span>
            </div>
          ))}
        </div>
      );
    }

    return null;
  };

  // Renderizar gráfico baseado no tipo
  const renderChart = () => {
    switch (type) {
      case 'line':
        return renderLineChart();
      case 'bar':
        return renderBarChart();
      case 'pie':
        return renderPieChart();
      default:
        return null;
    }
  };

  return (
    <div className={`chart-container ${className}`} style={chartDimensions}>
      {renderChart()}
      {renderLegend()}
    </div>
  );
};

// Componentes específicos para cada tipo de gráfico
export const LineChart: React.FC<Omit<ChartProps, 'type'>> = (props) => (
  <BaseChart {...props} type="line" />
);

export const BarChart: React.FC<Omit<ChartProps, 'type'>> = (props) => (
  <BaseChart {...props} type="bar" />
);

export const PieChart: React.FC<Omit<ChartProps, 'type'>> = (props) => (
  <BaseChart {...props} type="pie" />
);

// Componente principal
export const Chart: React.FC<ChartProps> = (props) => (
  <BaseChart {...props} />
);

// Hook para dados em tempo real
export const useRealTimeData = (initialData: ChartData, updateInterval = 5000) => {
  const [data, setData] = useState<ChartData>(initialData);

  useEffect(() => {
    const interval = setInterval(() => {
      setData(prevData => {
        // Simular atualização de dados em tempo real
        const newData = { ...prevData };
        newData.datasets = newData.datasets.map(dataset => ({
          ...dataset,
          data: dataset.data.map(value => value + (Math.random() - 0.5) * 10)
        }));
        return newData;
      });
    }, updateInterval);

    return () => clearInterval(interval);
  }, [updateInterval]);

  return data;
};

// Componente de gráfico em tempo real
export const RealTimeChart: React.FC<ChartProps & { updateInterval?: number }> = ({
  updateInterval = 5000,
  ...props
}) => {
  const realTimeData = useRealTimeData(props.data as ChartData, updateInterval);
  
  return <BaseChart {...props} data={realTimeData} />;
};

export default Chart; 