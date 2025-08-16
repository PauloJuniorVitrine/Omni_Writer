/**
 * A11YCoverageValidator - Validação de cobertura de acessibilidade
 * 
 * Prompt: CHECKLIST_100_CONFORMIDADE_E2E.md - Item 6.1
 * Ruleset: enterprise_control_layer.yaml
 * Data/Hora: 2025-01-28 10:30:00Z
 */

import { Page, ElementHandle } from 'playwright';

export interface A11YElement {
  selector: string;
  type: 'button' | 'link' | 'input' | 'select' | 'textarea' | 'nav' | 'main' | 'section' | 'article' | 'aside';
  hasLabel: boolean;
  hasAriaLabel: boolean;
  hasAriaDescribedby: boolean;
  hasRole: boolean;
  isFocusable: boolean;
  hasKeyboardSupport: boolean;
  contrastRatio?: number;
  violations: string[];
}

export interface A11YCoverageReport {
  executionId: string;
  timestamp: string;
  pageUrl: string;
  totalInteractiveElements: number;
  validatedElements: number;
  elementsWithViolations: number;
  coverageScore: number;
  elements: A11YElement[];
  violations: string[];
  recommendations: string[];
  overallStatus: 'excellent' | 'good' | 'warning' | 'critical';
}

export class A11YCoverageValidator {
  private readonly MIN_CONTRAST_RATIO = 4.5; // WCAG AA
  private readonly MIN_COVERAGE_SCORE = 90; // 90% mínimo

  /**
   * Calcula score de cobertura de acessibilidade
   */
  async calculateCoverage(page: Page): Promise<number> {
    const elements = await this.getAllInteractiveElements(page);
    const validatedElements = elements.filter(el => el.violations.length === 0);
    
    return elements.length > 0 ? (validatedElements.length / elements.length) * 100 : 100;
  }

  /**
   * Valida elementos interativos
   */
  async validateInteractiveElements(page: Page): Promise<A11YElement[]> {
    const elements: A11YElement[] = [];

    // Botões
    const buttons = await page.$$('button, [role="button"], input[type="button"], input[type="submit"]');
    for (const button of buttons) {
      const element = await this.validateButton(button);
      elements.push(element);
    }

    // Links
    const links = await page.$$('a[href]');
    for (const link of links) {
      const element = await this.validateLink(link);
      elements.push(element);
    }

    // Inputs
    const inputs = await page.$$('input:not([type="button"]):not([type="submit"]), textarea, select');
    for (const input of inputs) {
      const element = await this.validateInput(input);
      elements.push(element);
    }

    // Elementos de navegação
    const navElements = await page.$$('nav, [role="navigation"]');
    for (const nav of navElements) {
      const element = await this.validateNavigation(nav);
      elements.push(element);
    }

    return elements;
  }

  /**
   * Valida labels ARIA
   */
  async validateARIALabels(page: Page): Promise<{ valid: number; invalid: number; total: number }> {
    const elementsWithAria = await page.$$('[aria-label], [aria-labelledby], [aria-describedby]');
    let valid = 0;
    let invalid = 0;

    for (const element of elementsWithAria) {
      const ariaLabel = await element.getAttribute('aria-label');
      const ariaLabelledby = await element.getAttribute('aria-labelledby');
      const ariaDescribedby = await element.getAttribute('aria-describedby');

      if (ariaLabel && ariaLabel.trim() !== '') {
        valid++;
      } else if (ariaLabelledby && ariaLabelledby.trim() !== '') {
        valid++;
      } else if (ariaDescribedby && ariaDescribedby.trim() !== '') {
        valid++;
      } else {
        invalid++;
      }
    }

    return { valid, invalid, total: elementsWithAria.length };
  }

  /**
   * Valida gerenciamento de foco
   */
  async validateFocusManagement(page: Page): Promise<{ valid: number; invalid: number; total: number }> {
    const focusableElements = await page.$$('button, a[href], input, textarea, select, [tabindex]:not([tabindex="-1"])');
    let valid = 0;
    let invalid = 0;

    for (const element of focusableElements) {
      const isVisible = await element.isVisible();
      const tabIndex = await element.getAttribute('tabindex');
      
      if (isVisible && (!tabIndex || parseInt(tabIndex) >= 0)) {
        valid++;
      } else {
        invalid++;
      }
    }

    return { valid, invalid, total: focusableElements.length };
  }

  /**
   * Valida hierarquia semântica
   */
  async validateSemanticHierarchy(page: Page): Promise<{ valid: number; invalid: number; total: number }> {
    const semanticElements = await page.$$('main, nav, section, article, aside, header, footer, h1, h2, h3, h4, h5, h6');
    let valid = 0;
    let invalid = 0;

    for (const element of semanticElements) {
      const tagName = await element.evaluate((el: Element) => el.tagName.toLowerCase());
      
      if (tagName.startsWith('h')) {
        // Validar hierarquia de headings
        const level = parseInt(tagName.substring(1));
        const previousHeadings = await page.$$eval(`h1, h2, h3, h4, h5, h6`, (headings: Element[], currentLevel: number) => {
          return headings.filter(h => {
            const hLevel = parseInt(h.tagName.substring(1));
            return hLevel < currentLevel;
          }).length;
        }, level);

        if (previousHeadings > 0 || level === 1) {
          valid++;
        } else {
          invalid++;
        }
      } else {
        // Validar elementos semânticos
        valid++;
      }
    }

    return { valid, invalid, total: semanticElements.length };
  }

  /**
   * Gera relatório completo de cobertura A11Y
   */
  async generateA11YReport(page: Page, pageUrl: string): Promise<A11YCoverageReport> {
    const executionId = `A11Y_${Date.now()}`;
    const timestamp = new Date().toISOString();

    const elements = await this.validateInteractiveElements(page);
    const totalInteractiveElements = elements.length;
    const validatedElements = elements.filter(el => el.violations.length === 0).length;
    const elementsWithViolations = totalInteractiveElements - validatedElements;
    const coverageScore = await this.calculateCoverage(page);

    const ariaLabels = await this.validateARIALabels(page);
    const focusManagement = await this.validateFocusManagement(page);
    const semanticHierarchy = await this.validateSemanticHierarchy(page);

    const violations = this.collectAllViolations(elements);
    const recommendations = this.generateRecommendations(elements, ariaLabels, focusManagement, semanticHierarchy);
    const overallStatus = this.calculateOverallStatus(coverageScore, violations.length);

    return {
      executionId,
      timestamp,
      pageUrl,
      totalInteractiveElements,
      validatedElements,
      elementsWithViolations,
      coverageScore,
      elements,
      violations,
      recommendations,
      overallStatus
    };
  }

  /**
   * Obtém todos os elementos interativos da página
   */
  private async getAllInteractiveElements(page: Page): Promise<A11YElement[]> {
    return await this.validateInteractiveElements(page);
  }

  /**
   * Valida um botão
   */
  private async validateButton(button: ElementHandle): Promise<A11YElement> {
    const selector = await button.evaluate((el: Element) => {
      const tag = el.tagName.toLowerCase();
      const type = el.getAttribute('type');
      const role = el.getAttribute('role');
      
      if (tag === 'button') return 'button';
      if (tag === 'input' && type === 'button') return 'input[type="button"]';
      if (tag === 'input' && type === 'submit') return 'input[type="submit"]';
      if (role === 'button') return '[role="button"]';
      return 'button';
    });

    const text = await button.textContent();
    const ariaLabel = await button.getAttribute('aria-label');
    const ariaDescribedby = await button.getAttribute('aria-describedby');
    const role = await button.getAttribute('role');
    const isVisible = await button.isVisible();

    const violations: string[] = [];
    
    if (!text?.trim() && !ariaLabel?.trim()) {
      violations.push('Botão sem texto ou aria-label');
    }
    
    if (!isVisible) {
      violations.push('Botão não visível');
    }

    return {
      selector,
      type: 'button',
      hasLabel: !!(text?.trim() || ariaLabel?.trim()),
      hasAriaLabel: !!ariaLabel?.trim(),
      hasAriaDescribedby: !!ariaDescribedby?.trim(),
      hasRole: !!role,
      isFocusable: isVisible,
      hasKeyboardSupport: true,
      violations
    };
  }

  /**
   * Valida um link
   */
  private async validateLink(link: ElementHandle): Promise<A11YElement> {
    const text = await link.textContent();
    const ariaLabel = await link.getAttribute('aria-label');
    const ariaDescribedby = await link.getAttribute('aria-describedby');
    const href = await link.getAttribute('href');
    const isVisible = await link.isVisible();

    const violations: string[] = [];
    
    if (!text?.trim() && !ariaLabel?.trim()) {
      violations.push('Link sem texto ou aria-label');
    }
    
    if (!href || href === '#') {
      violations.push('Link sem href válido');
    }
    
    if (!isVisible) {
      violations.push('Link não visível');
    }

    return {
      selector: 'a[href]',
      type: 'link',
      hasLabel: !!(text?.trim() || ariaLabel?.trim()),
      hasAriaLabel: !!ariaLabel?.trim(),
      hasAriaDescribedby: !!ariaDescribedby?.trim(),
      hasRole: false,
      isFocusable: isVisible,
      hasKeyboardSupport: true,
      violations
    };
  }

  /**
   * Valida um input
   */
  private async validateInput(input: ElementHandle): Promise<A11YElement> {
    const type = await input.getAttribute('type');
    const tagName = await input.evaluate((el: Element) => el.tagName.toLowerCase());
    const id = await input.getAttribute('id');
    const ariaLabel = await input.getAttribute('aria-label');
    const ariaLabelledby = await input.getAttribute('aria-labelledby');
    const isVisible = await input.isVisible();

    const violations: string[] = [];
    
    if (!id && !ariaLabel && !ariaLabelledby) {
      violations.push('Input sem label associado');
    }
    
    if (!isVisible) {
      violations.push('Input não visível');
    }

    return {
      selector: tagName === 'textarea' ? 'textarea' : tagName === 'select' ? 'select' : 'input',
      type: tagName === 'textarea' ? 'textarea' : tagName === 'select' ? 'select' : 'input',
      hasLabel: !!(id || ariaLabel || ariaLabelledby),
      hasAriaLabel: !!ariaLabel?.trim(),
      hasAriaDescribedby: false,
      hasRole: false,
      isFocusable: isVisible,
      hasKeyboardSupport: true,
      violations
    };
  }

  /**
   * Valida navegação
   */
  private async validateNavigation(nav: ElementHandle): Promise<A11YElement> {
    const role = await nav.getAttribute('role');
    const ariaLabel = await nav.getAttribute('aria-label');
    const isVisible = await nav.isVisible();

    const violations: string[] = [];
    
    if (!isVisible) {
      violations.push('Navegação não visível');
    }

    return {
      selector: 'nav',
      type: 'nav',
      hasLabel: !!ariaLabel?.trim(),
      hasAriaLabel: !!ariaLabel?.trim(),
      hasAriaDescribedby: false,
      hasRole: !!role,
      isFocusable: false,
      hasKeyboardSupport: true,
      violations
    };
  }

  /**
   * Coleta todas as violações
   */
  private collectAllViolations(elements: A11YElement[]): string[] {
    const violations: string[] = [];
    elements.forEach(element => {
      violations.push(...element.violations);
    });
    return [...new Set(violations)]; // Remove duplicatas
  }

  /**
   * Gera recomendações baseadas nas violações
   */
  private generateRecommendations(
    elements: A11YElement[],
    ariaLabels: { valid: number; invalid: number; total: number },
    focusManagement: { valid: number; invalid: number; total: number },
    semanticHierarchy: { valid: number; invalid: number; total: number }
  ): string[] {
    const recommendations: string[] = [];

    // Análise de elementos
    const elementsWithoutLabels = elements.filter(el => !el.hasLabel).length;
    if (elementsWithoutLabels > 0) {
      recommendations.push(`Adicionar labels para ${elementsWithoutLabels} elementos interativos`);
    }

    // Análise de ARIA labels
    if (ariaLabels.invalid > 0) {
      recommendations.push(`Corrigir ${ariaLabels.invalid} elementos com ARIA labels inválidas`);
    }

    // Análise de foco
    if (focusManagement.invalid > 0) {
      recommendations.push(`Corrigir gerenciamento de foco para ${focusManagement.invalid} elementos`);
    }

    // Análise de hierarquia semântica
    if (semanticHierarchy.invalid > 0) {
      recommendations.push(`Corrigir hierarquia semântica para ${semanticHierarchy.invalid} elementos`);
    }

    return recommendations;
  }

  /**
   * Calcula status geral baseado no score e violações
   */
  private calculateOverallStatus(coverageScore: number, violationsCount: number): 'excellent' | 'good' | 'warning' | 'critical' {
    if (coverageScore >= 95 && violationsCount === 0) return 'excellent';
    if (coverageScore >= 90 && violationsCount <= 2) return 'good';
    if (coverageScore >= 80 && violationsCount <= 5) return 'warning';
    return 'critical';
  }
} 