/**
 * Componente PerformanceChart - Dashboard
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * Data: 2025-01-27T22:00:00Z
 * 
 * Funcionalidades:
 * - Gráfico de linha SVG nativo
 * - Responsivo e interativo
 * - Animações suaves
 * - Tooltip customizado
 */

import React, { useState } from 'react';

interface ChartData {
  labels: string[];
  datasets: Array<{
    label: string;
    data: number[];
    borderColor: string;
    backgroundColor: string;
  }>;
}

interface PerformanceChartProps {
  data: ChartData;
  height?: number;
}

/**
 * Componente de gráfico de performance
 */
const PerformanceChart: React.FC<PerformanceChartProps> = ({
  data,
  height = 300
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<number | null>(null);

  const maxValue = Math.max(...data.datasets[0].data);
  const minValue = Math.min(...data.datasets[0].data);
  const range = maxValue - minValue;

  const getY = (value: number) => {
    return height - ((value - minValue) / range) * (height - 40) - 20;
  };

  const getX = (index: number) => {
    return (index / (data.labels.length - 1)) * 100;
  };

  const generatePath = () => {
    const points = data.datasets[0].data.map((value, index) => {
      const x = getX(index);
      const y = getY(value);
      return `${x}% ${y}`;
    });
    
    return `M ${points.join(' L ')}`;
  };

  const generateAreaPath = () => {
    const points = data.datasets[0].data.map((value, index) => {
      const x = getX(index);
      const y = getY(value);
      return `${x}% ${y}`;
    });
    
    const bottomPoints = data.datasets[0].data.map((_, index) => {
      const x = getX(index);
      return `${x}% ${height - 20}`;
    }).reverse();
    
    return `M ${points.join(' L ')} L ${bottomPoints.join(' L ')} Z`;
  };

  return (
    <div className="relative" style={{ height }}>
      <svg
        width="100%"
        height={height}
        className="absolute inset-0"
        onMouseLeave={() => setHoveredPoint(null)}
      >
        {/* Área do gráfico */}
        <path
          d={generateAreaPath()}
          fill={data.datasets[0].backgroundColor}
          opacity={0.3}
        />
        
        {/* Linha do gráfico */}
        <path
          d={generatePath()}
          stroke={data.datasets[0].borderColor}
          strokeWidth="2"
          fill="none"
          className="transition-all duration-300"
        />
        
        {/* Pontos do gráfico */}
        {data.datasets[0].data.map((value, index) => {
          const x = getX(index);
          const y = getY(value);
          const isHovered = hoveredPoint === index;
          
          return (
            <g key={index}>
              <circle
                cx={`${x}%`}
                cy={y}
                r={isHovered ? 6 : 4}
                fill={data.datasets[0].borderColor}
                className="transition-all duration-200 cursor-pointer"
                onMouseEnter={() => setHoveredPoint(index)}
                onMouseLeave={() => setHoveredPoint(null)}
              />
              
              {/* Tooltip */}
              {isHovered && (
                <g>
                  <rect
                    x={`${x}%`}
                    y={y - 40}
                    width="80"
                    height="30"
                    rx="4"
                    fill="rgba(0, 0, 0, 0.8)"
                    transform={`translate(-40, 0)`}
                  />
                  <text
                    x={`${x}%`}
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
        
        {/* Linhas de grade */}
        {[0, 25, 50, 75, 100].map((percent) => (
          <line
            key={percent}
            x1={`${percent}%`}
            y1="0"
            x2={`${percent}%`}
            y2={height}
            stroke="#e5e7eb"
            strokeWidth="1"
            opacity={0.5}
          />
        ))}
      </svg>
      
      {/* Labels do eixo X */}
      <div className="absolute bottom-0 left-0 right-0 flex justify-between text-xs text-gray-500">
        {data.labels.map((label, index) => (
          <span key={index} className="text-center">
            {label}
          </span>
        ))}
      </div>
      
      {/* Labels do eixo Y */}
      <div className="absolute left-0 top-0 bottom-0 flex flex-col justify-between text-xs text-gray-500">
        {[maxValue, (maxValue + minValue) / 2, minValue].map((value, index) => (
          <span key={index} className="text-right">
            {Math.round(value)}
          </span>
        ))}
      </div>
    </div>
  );
};

export default PerformanceChart; 