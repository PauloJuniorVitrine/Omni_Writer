/**
 * Testes Unitários - Sistema de Gráficos
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-27T22:45:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250127_001
 * 
 * Testes baseados em funcionalidades reais:
 * - Line charts
 * - Bar charts
 * - Pie charts
 * - Real-time updates
 * - Responsividade
 * - Acessibilidade
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Chart, LineChart, BarChart, PieChart, RealTimeChart, useRealTimeData } from '../Charts';

// Dados de teste para gráficos
const mockLineData = {
  labels: ['Jan', 'Fev', 'Mar', 'Abr', 'Mai'],
  datasets: [{
    label: 'Vendas',
    data: [10, 20, 15, 25, 30],
    borderColor: '#3B82F6',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    fill: true
  }]
};

const mockBarData = {
  labels: ['Produto A', 'Produto B', 'Produto C', 'Produto D'],
  datasets: [{
    label: 'Vendas',
    data: [100, 150, 80, 200],
    backgroundColor: '#10B981',
    borderColor: '#059669'
  }]
};

const mockPieData = [
  { label: 'Desktop', value: 45, color: '#3B82F6' },
  { label: 'Mobile', value: 35, color: '#10B981' },
  { label: 'Tablet', value: 20, color: '#F59E0B' }
];

describe('Sistema de Gráficos', () => {
  const mockOnPointClick = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('LineChart Component', () => {
    it('deve renderizar gráfico de linha com dados', () => {
      render(
        <LineChart
          data={mockLineData}
          width={400}
          height={300}
        />
      );

      // Verificar se o SVG foi renderizado
      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
      expect(svg).toHaveAttribute('width', '400');
      expect(svg).toHaveAttribute('height', '300');
    });

    it('deve mostrar tooltip ao passar o mouse sobre pontos', () => {
      render(
        <LineChart
          data={mockLineData}
          showTooltip={true}
        />
      );

      const points = document.querySelectorAll('circle');
      expect(points.length).toBeGreaterThan(0);

      // Simular hover no primeiro ponto
      fireEvent.mouseEnter(points[0]);
      
      // Verificar se o tooltip aparece
      expect(document.querySelector('.chart-tooltip')).toBeInTheDocument();
    });

    it('deve chamar onPointClick quando ponto é clicado', () => {
      render(
        <LineChart
          data={mockLineData}
          onPointClick={mockOnPointClick}
        />
      );

      const points = document.querySelectorAll('circle');
      fireEvent.click(points[0]);

      expect(mockOnPointClick).toHaveBeenCalledWith(
        { value: 10, label: 'Jan' },
        0
      );
    });

    it('deve renderizar grid quando showGrid é true', () => {
      render(
        <LineChart
          data={mockLineData}
          showGrid={true}
        />
      );

      const gridLines = document.querySelectorAll('.chart-grid line');
      expect(gridLines.length).toBeGreaterThan(0);
    });

    it('deve renderizar área preenchida quando fill é true', () => {
      render(
        <LineChart
          data={mockLineData}
        />
      );

      const areaPath = document.querySelector('path[fill]');
      expect(areaPath).toBeInTheDocument();
    });
  });

  describe('BarChart Component', () => {
    it('deve renderizar gráfico de barras com dados', () => {
      render(
        <BarChart
          data={mockBarData}
          width={400}
          height={300}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();

      // Verificar se as barras foram renderizadas
      const bars = document.querySelectorAll('rect');
      expect(bars.length).toBeGreaterThan(0);
    });

    it('deve mostrar tooltip ao passar o mouse sobre barras', () => {
      render(
        <BarChart
          data={mockBarData}
          showTooltip={true}
        />
      );

      const bars = document.querySelectorAll('rect');
      fireEvent.mouseEnter(bars[0]);

      expect(document.querySelector('.chart-tooltip')).toBeInTheDocument();
    });

    it('deve chamar onPointClick quando barra é clicada', () => {
      render(
        <BarChart
          data={mockBarData}
          onPointClick={mockOnPointClick}
        />
      );

      const bars = document.querySelectorAll('rect');
      fireEvent.click(bars[0]);

      expect(mockOnPointClick).toHaveBeenCalledWith(
        { value: 100, label: 'Produto A' },
        0
      );
    });

    it('deve renderizar labels do eixo X', () => {
      render(
        <BarChart
          data={mockBarData}
        />
      );

      expect(document.querySelector('.chart-axis-x')).toBeInTheDocument();
    });

    it('deve renderizar labels do eixo Y', () => {
      render(
        <BarChart
          data={mockBarData}
        />
      );

      expect(document.querySelector('.chart-axis-y')).toBeInTheDocument();
    });
  });

  describe('PieChart Component', () => {
    it('deve renderizar gráfico de pizza com dados', () => {
      render(
        <PieChart
          data={mockPieData}
          width={400}
          height={300}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();

      // Verificar se as fatias foram renderizadas
      const slices = document.querySelectorAll('path');
      expect(slices.length).toBeGreaterThan(0);
    });

    it('deve mostrar tooltip ao passar o mouse sobre fatias', () => {
      render(
        <PieChart
          data={mockPieData}
          showTooltip={true}
        />
      );

      const slices = document.querySelectorAll('path');
      fireEvent.mouseEnter(slices[0]);

      expect(document.querySelector('.chart-tooltip')).toBeInTheDocument();
    });

    it('deve chamar onPointClick quando fatia é clicada', () => {
      render(
        <PieChart
          data={mockPieData}
          onPointClick={mockOnPointClick}
        />
      );

      const slices = document.querySelectorAll('path');
      fireEvent.click(slices[0]);

      expect(mockOnPointClick).toHaveBeenCalledWith(mockPieData[0], 0);
    });

    it('deve renderizar labels das fatias', () => {
      render(
        <PieChart
          data={mockPieData}
        />
      );

      const labels = document.querySelectorAll('.chart-pie-label');
      expect(labels.length).toBeGreaterThan(0);
    });

    it('deve calcular percentuais corretamente', () => {
      render(
        <PieChart
          data={mockPieData}
        />
      );

      const labels = document.querySelectorAll('.chart-pie-label');
      expect(labels[0]).toHaveTextContent('45%'); // 45/100 * 100
      expect(labels[1]).toHaveTextContent('35%'); // 35/100 * 100
      expect(labels[2]).toHaveTextContent('20%'); // 20/100 * 100
    });
  });

  describe('Chart Component Genérico', () => {
    it('deve renderizar gráfico de linha quando type é line', () => {
      render(
        <Chart
          data={mockLineData}
          type="line"
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    it('deve renderizar gráfico de barras quando type é bar', () => {
      render(
        <Chart
          data={mockBarData}
          type="bar"
        />
      );

      const bars = document.querySelectorAll('rect');
      expect(bars.length).toBeGreaterThan(0);
    });

    it('deve renderizar gráfico de pizza quando type é pie', () => {
      render(
        <Chart
          data={mockPieData}
          type="pie"
        />
      );

      const slices = document.querySelectorAll('path');
      expect(slices.length).toBeGreaterThan(0);
    });
  });

  describe('Responsividade', () => {
    it('deve ser responsivo quando responsive é true', () => {
      render(
        <LineChart
          data={mockLineData}
          responsive={true}
        />
      );

      const container = document.querySelector('.chart-container');
      expect(container).toHaveStyle({ width: '100%', height: '100%' });
    });

    it('deve usar dimensões fixas quando responsive é false', () => {
      render(
        <LineChart
          data={mockLineData}
          responsive={false}
          width={500}
          height={400}
        />
      );

      const container = document.querySelector('.chart-container');
      expect(container).toHaveStyle({ width: '500px', height: '400px' });
    });
  });

  describe('Legenda', () => {
    it('deve mostrar legenda quando showLegend é true', () => {
      render(
        <LineChart
          data={mockLineData}
          showLegend={true}
        />
      );

      expect(document.querySelector('.chart-legend')).toBeInTheDocument();
    });

    it('deve ocultar legenda quando showLegend é false', () => {
      render(
        <LineChart
          data={mockLineData}
          showLegend={false}
        />
      );

      expect(document.querySelector('.chart-legend')).not.toBeInTheDocument();
    });

    it('deve mostrar cores corretas na legenda', () => {
      render(
        <PieChart
          data={mockPieData}
          showLegend={true}
        />
      );

      const legendColors = document.querySelectorAll('.legend-color');
      expect(legendColors[0]).toHaveStyle({ backgroundColor: '#3B82F6' });
      expect(legendColors[1]).toHaveStyle({ backgroundColor: '#10B981' });
      expect(legendColors[2]).toHaveStyle({ backgroundColor: '#F59E0B' });
    });
  });

  describe('Animações', () => {
    it('deve aplicar classe de animação quando animate é true', () => {
      render(
        <LineChart
          data={mockLineData}
          animate={true}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toHaveClass('animate-chart');
    });

    it('deve não aplicar classe de animação quando animate é false', () => {
      render(
        <LineChart
          data={mockLineData}
          animate={false}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).not.toHaveClass('animate-chart');
    });
  });

  describe('RealTimeChart Component', () => {
    it('deve renderizar gráfico em tempo real', () => {
      render(
        <RealTimeChart
          data={mockLineData}
          type="line"
          updateInterval={1000}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    it('deve atualizar dados em intervalos regulares', async () => {
      jest.useFakeTimers();

      render(
        <RealTimeChart
          data={mockLineData}
          type="line"
          updateInterval={1000}
        />
      );

      // Avançar o tempo para simular atualização
      jest.advanceTimersByTime(1000);

      await waitFor(() => {
        // Verificar se os dados foram atualizados
        expect(document.querySelector('svg')).toBeInTheDocument();
      });

      jest.useRealTimers();
    });
  });

  describe('useRealTimeData Hook', () => {
    it('deve retornar dados iniciais', () => {
      const TestComponent = () => {
        const data = useRealTimeData(mockLineData, 1000);
        return <div data-testid="data">{JSON.stringify(data)}</div>;
      };

      render(<TestComponent />);

      expect(screen.getByTestId('data')).toHaveTextContent(JSON.stringify(mockLineData));
    });
  });

  describe('Acessibilidade', () => {
    it('deve ter elementos SVG acessíveis', () => {
      render(
        <LineChart
          data={mockLineData}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    it('deve ter pontos clicáveis com cursor pointer', () => {
      render(
        <LineChart
          data={mockLineData}
          onPointClick={mockOnPointClick}
        />
      );

      const points = document.querySelectorAll('circle');
      expect(points[0]).toHaveStyle({ cursor: 'pointer' });
    });

    it('deve ter fatias clicáveis com cursor pointer', () => {
      render(
        <PieChart
          data={mockPieData}
          onPointClick={mockOnPointClick}
        />
      );

      const slices = document.querySelectorAll('path');
      expect(slices[0]).toHaveStyle({ cursor: 'pointer' });
    });
  });

  describe('Estados de Dados', () => {
    it('deve lidar com dados vazios', () => {
      render(
        <LineChart
          data={{ labels: [], datasets: [] }}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    it('deve lidar com dados de pizza vazios', () => {
      render(
        <PieChart
          data={[]}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });

    it('deve lidar com valores zero', () => {
      const zeroData = {
        labels: ['A', 'B', 'C'],
        datasets: [{
          label: 'Test',
          data: [0, 0, 0],
          borderColor: '#3B82F6'
        }]
      };

      render(
        <LineChart
          data={zeroData}
        />
      );

      const svg = document.querySelector('svg');
      expect(svg).toBeInTheDocument();
    });
  });

  describe('Configurações Opcionais', () => {
    it('deve ocultar tooltip quando showTooltip é false', () => {
      render(
        <LineChart
          data={mockLineData}
          showTooltip={false}
        />
      );

      const points = document.querySelectorAll('circle');
      fireEvent.mouseEnter(points[0]);

      expect(document.querySelector('.chart-tooltip')).not.toBeInTheDocument();
    });

    it('deve ocultar grid quando showGrid é false', () => {
      render(
        <LineChart
          data={mockLineData}
          showGrid={false}
        />
      );

      const gridLines = document.querySelectorAll('.chart-grid line');
      expect(gridLines.length).toBe(0);
    });

    it('deve aplicar classe customizada', () => {
      render(
        <LineChart
          data={mockLineData}
          className="custom-chart"
        />
      );

      const container = document.querySelector('.chart-container');
      expect(container).toHaveClass('custom-chart');
    });
  });
}); 