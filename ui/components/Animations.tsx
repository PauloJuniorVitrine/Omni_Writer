/**
 * Sistema de Animações e Transições - Omni Writer
 * 
 * Prompt: Interface Gráfica v3.5 Enterprise+ - UI-020
 * Data/Hora: 2025-01-28T00:00:00Z
 * Tracing ID: UI_IMPLEMENTATION_20250128_001
 * 
 * Funcionalidades:
 * - Page transitions suaves
 * - Loading animations
 * - Micro-interactions
 * - Hover effects
 * - Animações de entrada/saída
 */

import React, { useState, useEffect, useRef, useCallback, ReactNode } from 'react';
import { useLocation } from 'react-router-dom';

// ===== TIPOS =====

interface AnimationProps {
  children: ReactNode;
  type?: 'fade' | 'slide' | 'scale' | 'rotate' | 'bounce' | 'shake' | 'pulse' | 'flip';
  direction?: 'up' | 'down' | 'left' | 'right';
  duration?: number;
  delay?: number;
  easing?: 'linear' | 'ease' | 'ease-in' | 'ease-out' | 'ease-in-out' | 'bounce' | 'elastic';
  trigger?: 'mount' | 'hover' | 'click' | 'scroll' | 'focus';
  disabled?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

interface PageTransitionProps {
  children: ReactNode;
  type?: 'fade' | 'slide' | 'zoom' | 'flip';
  duration?: number;
  className?: string;
}

interface LoadingAnimationProps {
  type?: 'spinner' | 'dots' | 'bars' | 'pulse' | 'skeleton' | 'progress';
  size?: 'sm' | 'md' | 'lg' | 'xl';
  color?: string;
  text?: string;
  className?: string;
}

interface MicroInteractionProps {
  children: ReactNode;
  type?: 'ripple' | 'bounce' | 'shake' | 'pulse' | 'glow';
  trigger?: 'hover' | 'click' | 'focus';
  duration?: number;
  className?: string;
}

interface HoverEffectProps {
  children: ReactNode;
  type?: 'lift' | 'glow' | 'scale' | 'rotate' | 'tilt' | 'morph';
  intensity?: 'light' | 'medium' | 'strong';
  className?: string;
}

// ===== HOOKS =====

export const useAnimation = (trigger: string = 'mount') => {
  const [isAnimating, setIsAnimating] = useState(false);
  const [hasAnimated, setHasAnimated] = useState(false);

  const startAnimation = useCallback(() => {
    if (trigger === 'mount' && hasAnimated) return;
    setIsAnimating(true);
    setHasAnimated(true);
  }, [trigger, hasAnimated]);

  const stopAnimation = useCallback(() => {
    setIsAnimating(false);
  }, []);

  useEffect(() => {
    if (trigger === 'mount') {
      startAnimation();
    }
  }, [trigger, startAnimation]);

  return { isAnimating, startAnimation, stopAnimation };
};

export const usePageTransition = () => {
  const location = useLocation();
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [previousPath, setPreviousPath] = useState('');

  useEffect(() => {
    if (location.pathname !== previousPath) {
      setIsTransitioning(true);
      setPreviousPath(location.pathname);
      
      const timer = setTimeout(() => {
        setIsTransitioning(false);
      }, 300);

      return () => clearTimeout(timer);
    }
  }, [location.pathname, previousPath]);

  return { isTransitioning };
};

export const useScrollAnimation = (threshold: number = 0.1) => {
  const [isVisible, setIsVisible] = useState(false);
  const elementRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold }
    );

    if (elementRef.current) {
      observer.observe(elementRef.current);
    }

    return () => {
      if (elementRef.current) {
        observer.unobserve(elementRef.current);
      }
    };
  }, [threshold]);

  return { isVisible, elementRef };
};

// ===== UTILITÁRIOS =====

const getEasingFunction = (easing: string) => {
  const easings = {
    linear: 'linear',
    ease: 'ease',
    'ease-in': 'ease-in',
    'ease-out': 'ease-out',
    'ease-in-out': 'ease-in-out',
    bounce: 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
    elastic: 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
  };
  return easings[easing as keyof typeof easings] || 'ease';
};

const getAnimationStyles = (
  type: string,
  direction: string,
  duration: number,
  easing: string,
  isActive: boolean
) => {
  const baseStyles = {
    transition: `all ${duration}ms ${getEasingFunction(easing)}`,
    willChange: 'transform, opacity',
  };

  const animations = {
    fade: {
      opacity: isActive ? 1 : 0,
    },
    slide: {
      transform: isActive 
        ? 'translateX(0) translateY(0)' 
        : direction === 'up' ? 'translateY(20px)' :
          direction === 'down' ? 'translateY(-20px)' :
          direction === 'left' ? 'translateX(20px)' :
          'translateX(-20px)',
      opacity: isActive ? 1 : 0,
    },
    scale: {
      transform: isActive ? 'scale(1)' : 'scale(0.8)',
      opacity: isActive ? 1 : 0,
    },
    rotate: {
      transform: isActive ? 'rotate(0deg)' : 'rotate(180deg)',
    },
    bounce: {
      transform: isActive ? 'scale(1)' : 'scale(0.3)',
      animation: isActive ? 'bounce 0.6s ease-out' : 'none',
    },
    shake: {
      animation: isActive ? 'shake 0.5s ease-in-out' : 'none',
    },
    pulse: {
      animation: isActive ? 'pulse 1s ease-in-out infinite' : 'none',
    },
    flip: {
      transform: isActive ? 'rotateY(0deg)' : 'rotateY(180deg)',
      transformStyle: 'preserve-3d' as const,
    },
  };

  return {
    ...baseStyles,
    ...animations[type as keyof typeof animations],
  };
};

// ===== COMPONENTES =====

export const Animation: React.FC<AnimationProps> = ({
  children,
  type = 'fade',
  direction = 'up',
  duration = 300,
  delay = 0,
  easing = 'ease-out',
  trigger = 'mount',
  disabled = false,
  className = '',
  style = {},
}) => {
  const [isActive, setIsActive] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  const [isClicked, setIsClicked] = useState(false);
  const [isFocused, setIsFocused] = useState(false);
  const elementRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (disabled) return;

    if (trigger === 'mount') {
      const timer = setTimeout(() => {
        setIsActive(true);
      }, delay);
      return () => clearTimeout(timer);
    }
  }, [trigger, delay, disabled]);

  useEffect(() => {
    if (trigger === 'scroll' && elementRef.current) {
      const observer = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) {
            setIsActive(true);
          }
        },
        { threshold: 0.1 }
      );

      observer.observe(elementRef.current);
      return () => observer.disconnect();
    }
  }, [trigger]);

  const handleMouseEnter = () => {
    if (trigger === 'hover') {
      setIsHovered(true);
      setIsActive(true);
    }
  };

  const handleMouseLeave = () => {
    if (trigger === 'hover') {
      setIsHovered(false);
      setIsActive(false);
    }
  };

  const handleClick = () => {
    if (trigger === 'click') {
      setIsClicked(true);
      setIsActive(true);
      setTimeout(() => {
        setIsClicked(false);
        setIsActive(false);
      }, duration);
    }
  };

  const handleFocus = () => {
    if (trigger === 'focus') {
      setIsFocused(true);
      setIsActive(true);
    }
  };

  const handleBlur = () => {
    if (trigger === 'focus') {
      setIsFocused(false);
      setIsActive(false);
    }
  };

  const animationStyles = getAnimationStyles(
    type,
    direction,
    duration,
    easing,
    isActive
  );

  return (
    <div
      ref={elementRef}
      className={`omni-animation omni-animation--${type} ${className}`}
      style={{
        ...animationStyles,
        ...style,
      }}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
      onFocus={handleFocus}
      onBlur={handleBlur}
    >
      {children}
    </div>
  );
};

export const PageTransition: React.FC<PageTransitionProps> = ({
  children,
  type = 'fade',
  duration = 300,
  className = '',
}) => {
  const { isTransitioning } = usePageTransition();
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    if (isTransitioning) {
      setIsVisible(false);
      const timer = setTimeout(() => {
        setIsVisible(true);
      }, duration / 2);
      return () => clearTimeout(timer);
    }
  }, [isTransitioning, duration]);

  const getTransitionStyles = () => {
    const baseStyles = {
      transition: `all ${duration}ms ease-in-out`,
      willChange: 'transform, opacity',
    };

    const transitions = {
      fade: {
        opacity: isVisible ? 1 : 0,
      },
      slide: {
        transform: isVisible ? 'translateX(0)' : 'translateX(20px)',
        opacity: isVisible ? 1 : 0,
      },
      zoom: {
        transform: isVisible ? 'scale(1)' : 'scale(0.95)',
        opacity: isVisible ? 1 : 0,
      },
      flip: {
        transform: isVisible ? 'rotateY(0deg)' : 'rotateY(90deg)',
        transformStyle: 'preserve-3d' as const,
      },
    };

    return {
      ...baseStyles,
      ...transitions[type as keyof typeof transitions],
    };
  };

  return (
    <div
      className={`omni-page-transition omni-page-transition--${type} ${className}`}
      style={getTransitionStyles()}
    >
      {children}
    </div>
  );
};

export const LoadingAnimation: React.FC<LoadingAnimationProps> = ({
  type = 'spinner',
  size = 'md',
  color = 'currentColor',
  text,
  className = '',
}) => {
  const sizeMap = {
    sm: { width: 16, height: 16 },
    md: { width: 24, height: 24 },
    lg: { width: 32, height: 32 },
    xl: { width: 48, height: 48 },
  };

  const currentSize = sizeMap[size];

  const renderSpinner = () => (
    <div
      style={{
        width: currentSize.width,
        height: currentSize.height,
        border: `2px solid transparent`,
        borderTop: `2px solid ${color}`,
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
      }}
    />
  );

  const renderDots = () => (
    <div style={{ display: 'flex', gap: 4 }}>
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          style={{
            width: 6,
            height: 6,
            backgroundColor: color,
            borderRadius: '50%',
            animation: `bounce 1.4s ease-in-out infinite both`,
            animationDelay: `${i * 0.16}s`,
          }}
        />
      ))}
    </div>
  );

  const renderBars = () => (
    <div style={{ display: 'flex', gap: 2 }}>
      {[0, 1, 2, 3].map((i) => (
        <div
          key={i}
          style={{
            width: 3,
            height: 20,
            backgroundColor: color,
            animation: `bars 1.2s ease-in-out infinite both`,
            animationDelay: `${i * 0.1}s`,
          }}
        />
      ))}
    </div>
  );

  const renderPulse = () => (
    <div
      style={{
        width: currentSize.width,
        height: currentSize.height,
        backgroundColor: color,
        borderRadius: '50%',
        animation: 'pulse 1.5s ease-in-out infinite',
      }}
    />
  );

  const renderSkeleton = () => (
    <div
      style={{
        width: currentSize.width * 3,
        height: currentSize.height,
        backgroundColor: '#e2e8f0',
        borderRadius: 4,
        animation: 'skeleton 1.5s ease-in-out infinite',
      }}
    />
  );

  const renderProgress = () => (
    <div
      style={{
        width: currentSize.width * 4,
        height: 4,
        backgroundColor: '#e2e8f0',
        borderRadius: 2,
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          width: '100%',
          height: '100%',
          backgroundColor: color,
          animation: 'progress 2s ease-in-out infinite',
        }}
      />
    </div>
  );

  const renderAnimation = () => {
    switch (type) {
      case 'spinner':
        return renderSpinner();
      case 'dots':
        return renderDots();
      case 'bars':
        return renderBars();
      case 'pulse':
        return renderPulse();
      case 'skeleton':
        return renderSkeleton();
      case 'progress':
        return renderProgress();
      default:
        return renderSpinner();
    }
  };

  return (
    <div
      className={`omni-loading-animation omni-loading-animation--${type} ${className}`}
      style={{ display: 'flex', alignItems: 'center', gap: 8 }}
    >
      {renderAnimation()}
      {text && (
        <span style={{ fontSize: 14, color: 'inherit' }}>{text}</span>
      )}
    </div>
  );
};

export const MicroInteraction: React.FC<MicroInteractionProps> = ({
  children,
  type = 'ripple',
  trigger = 'click',
  duration = 600,
  className = '',
}) => {
  const [isActive, setIsActive] = useState(false);
  const [ripples, setRipples] = useState<Array<{ id: number; x: number; y: number }>>([]);
  const elementRef = useRef<HTMLDivElement>(null);
  const rippleId = useRef(0);

  const handleTrigger = (event: React.MouseEvent | React.FocusEvent) => {
    if (trigger === 'click' && 'clientX' in event) {
      // Ripple effect
      const rect = elementRef.current?.getBoundingClientRect();
      if (rect) {
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        const newRipple = { id: rippleId.current++, x, y };
        
        setRipples(prev => [...prev, newRipple]);
        setTimeout(() => {
          setRipples(prev => prev.filter(r => r.id !== newRipple.id));
        }, duration);
      }
    }

    setIsActive(true);
    setTimeout(() => setIsActive(false), duration);
  };

  const getInteractionStyles = () => {
    const baseStyles = {
      position: 'relative' as const,
      overflow: 'hidden' as const,
    };

    const interactions = {
      ripple: baseStyles,
      bounce: {
        ...baseStyles,
        animation: isActive ? 'bounce 0.6s ease-out' : 'none',
      },
      shake: {
        ...baseStyles,
        animation: isActive ? 'shake 0.5s ease-in-out' : 'none',
      },
      pulse: {
        ...baseStyles,
        animation: isActive ? 'pulse 1s ease-in-out' : 'none',
      },
      glow: {
        ...baseStyles,
        boxShadow: isActive ? '0 0 20px rgba(59, 130, 246, 0.5)' : 'none',
        transition: 'box-shadow 0.3s ease',
      },
    };

    return interactions[type as keyof typeof interactions];
  };

  return (
    <div
      ref={elementRef}
      className={`omni-micro-interaction omni-micro-interaction--${type} ${className}`}
      style={getInteractionStyles()}
      onClick={trigger === 'click' ? handleTrigger : undefined}
      onMouseEnter={trigger === 'hover' ? handleTrigger : undefined}
      onFocus={trigger === 'focus' ? handleTrigger : undefined}
    >
      {children}
      
      {/* Ripple effect */}
      {type === 'ripple' && ripples.map((ripple) => (
        <div
          key={ripple.id}
          style={{
            position: 'absolute',
            left: ripple.x,
            top: ripple.y,
            width: 0,
            height: 0,
            borderRadius: '50%',
            backgroundColor: 'rgba(59, 130, 246, 0.3)',
            transform: 'translate(-50%, -50%)',
            animation: 'ripple 0.6s linear',
            pointerEvents: 'none',
          }}
        />
      ))}
    </div>
  );
};

export const HoverEffect: React.FC<HoverEffectProps> = ({
  children,
  type = 'lift',
  intensity = 'medium',
  className = '',
}) => {
  const [isHovered, setIsHovered] = useState(false);

  const getHoverStyles = () => {
    const baseStyles = {
      transition: 'all 0.3s ease-in-out',
      cursor: 'pointer',
    };

    const intensities = {
      light: { scale: 1.02, lift: 2, glow: '0 4px 12px rgba(0, 0, 0, 0.1)' },
      medium: { scale: 1.05, lift: 4, glow: '0 8px 24px rgba(0, 0, 0, 0.15)' },
      strong: { scale: 1.1, lift: 8, glow: '0 12px 36px rgba(0, 0, 0, 0.2)' },
    };

    const currentIntensity = intensities[intensity];

    const effects = {
      lift: {
        ...baseStyles,
        transform: isHovered ? `translateY(-${currentIntensity.lift}px) scale(${currentIntensity.scale})` : 'translateY(0) scale(1)',
        boxShadow: isHovered ? currentIntensity.glow : 'none',
      },
      glow: {
        ...baseStyles,
        boxShadow: isHovered ? currentIntensity.glow : 'none',
      },
      scale: {
        ...baseStyles,
        transform: isHovered ? `scale(${currentIntensity.scale})` : 'scale(1)',
      },
      rotate: {
        ...baseStyles,
        transform: isHovered ? 'rotate(5deg)' : 'rotate(0deg)',
      },
      tilt: {
        ...baseStyles,
        transform: isHovered ? 'perspective(1000px) rotateX(5deg) rotateY(5deg)' : 'perspective(1000px) rotateX(0deg) rotateY(0deg)',
      },
      morph: {
        ...baseStyles,
        borderRadius: isHovered ? '20px' : '8px',
        transform: isHovered ? `scale(${currentIntensity.scale})` : 'scale(1)',
      },
    };

    return effects[type as keyof typeof effects];
  };

  return (
    <div
      className={`omni-hover-effect omni-hover-effect--${type} ${className}`}
      style={getHoverStyles()}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {children}
    </div>
  );
};

// ===== CSS ANIMATIONS =====

export const AnimationStyles = `
  /* Keyframes */
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes bounce {
    0%, 20%, 53%, 80%, 100% {
      transform: translate3d(0, 0, 0);
    }
    40%, 43% {
      transform: translate3d(0, -30px, 0);
    }
    70% {
      transform: translate3d(0, -15px, 0);
    }
    90% {
      transform: translate3d(0, -4px, 0);
    }
  }

  @keyframes bars {
    0%, 40%, 100% {
      transform: scaleY(0.4);
    }
    20% {
      transform: scaleY(1);
    }
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  @keyframes skeleton {
    0% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
    100% {
      opacity: 1;
    }
  }

  @keyframes progress {
    0% {
      transform: translateX(-100%);
    }
    100% {
      transform: translateX(100%);
    }
  }

  @keyframes shake {
    0%, 100% {
      transform: translateX(0);
    }
    10%, 30%, 50%, 70%, 90% {
      transform: translateX(-10px);
    }
    20%, 40%, 60%, 80% {
      transform: translateX(10px);
    }
  }

  @keyframes ripple {
    0% {
      width: 0;
      height: 0;
      opacity: 1;
    }
    100% {
      width: 500px;
      height: 500px;
      opacity: 0;
    }
  }

  /* Reduced motion support */
  @media (prefers-reduced-motion: reduce) {
    .omni-animation,
    .omni-page-transition,
    .omni-loading-animation,
    .omni-micro-interaction,
    .omni-hover-effect {
      animation: none !important;
      transition: none !important;
      transform: none !important;
    }
  }

  /* Performance optimizations */
  .omni-animation,
  .omni-page-transition,
  .omni-loading-animation,
  .omni-micro-interaction,
  .omni-hover-effect {
    will-change: transform, opacity;
    backface-visibility: hidden;
    transform: translateZ(0);
  }
`;

// ===== EXPORTS =====

export default {
  Animation,
  PageTransition,
  LoadingAnimation,
  MicroInteraction,
  HoverEffect,
  useAnimation,
  usePageTransition,
  useScrollAnimation,
  AnimationStyles,
}; 