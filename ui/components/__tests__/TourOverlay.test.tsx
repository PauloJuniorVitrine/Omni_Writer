import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { TourOverlay } from '../TourOverlay';
import { useI18n } from '../../hooks/use_i18n';

// Mock do hook useI18n
jest.mock('../../hooks/use_i18n');
const mockUseI18n = useI18n as jest.MockedFunction<typeof useI18n>;

describe('TourOverlay', () => {
  const mockT = jest.fn((key: string) => key);
  const mockOnClose = jest.fn();
  const mockOnComplete = jest.fn();

  beforeEach(() => {
    mockUseI18n.mockReturnValue({ t: mockT });
    
    // Mock do DOM para simular elementos alvo
    document.body.innerHTML = `
      <div class="dashboard-header">Dashboard</div>
      <div class="blogs-section">Blogs</div>
      <div class="generation-form">Generation</div>
      <div class="feedback-section">Feedback</div>
      <div class="security-section">Security</div>
      <div class="main-content">Main</div>
    `;
  });

  afterEach(() => {
    jest.clearAllMocks();
    document.body.innerHTML = '';
  });

  it('should not render when isOpen is false', () => {
    render(
      <TourOverlay 
        isOpen={false} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    expect(screen.queryByText('onboarding_welcome_title')).not.toBeInTheDocument();
  });

  it('should render tour overlay when isOpen is true', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    expect(screen.getByText('onboarding_welcome_title')).toBeInTheDocument();
    expect(screen.getByText('onboarding_welcome_desc')).toBeInTheDocument();
  });

  it('should show navigation buttons', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    expect(screen.getByText('back')).toBeInTheDocument();
    expect(screen.getByText('next')).toBeInTheDocument();
    expect(screen.getByText('skip')).toBeInTheDocument();
  });

  it('should show progress indicators', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    expect(screen.getByText('step 1 of 6')).toBeInTheDocument();
  });

  it('should call onComplete when finish button is clicked on last step', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    // Avança para o último passo (6 passos total)
    for (let i = 0; i < 5; i++) {
      fireEvent.click(screen.getByText('next'));
    }

    // No último passo, o botão deve ser "finish"
    fireEvent.click(screen.getByText('finish'));
    expect(mockOnComplete).toHaveBeenCalled();
  });

  it('should call onComplete when skip button is clicked', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    fireEvent.click(screen.getByText('skip'));
    expect(mockOnComplete).toHaveBeenCalled();
  });

  it('should highlight target element when tour step changes', () => {
    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    const dashboardHeader = document.querySelector('.dashboard-header');
    expect(dashboardHeader).toHaveStyle('outline: 3px solid #6366f1');
  });

  it('should scroll to target element when step changes', () => {
    const mockScrollIntoView = jest.fn();
    const dashboardHeader = document.querySelector('.dashboard-header') as HTMLElement;
    if (dashboardHeader) {
      dashboardHeader.scrollIntoView = mockScrollIntoView;
    }

    render(
      <TourOverlay 
        isOpen={true} 
        onClose={mockOnClose} 
        onComplete={mockOnComplete} 
      />
    );

    expect(mockScrollIntoView).toHaveBeenCalledWith({
      behavior: 'smooth',
      block: 'center'
    });
  });
}); 