/**
 * Page Object para Página de Geração de Artigos
 * - Abstração específica para interações com geração de artigos
 * - Baseado em código real da aplicação Omni Writer
 * - Métodos específicos para este domínio
 * 
 * 📐 CoCoT: Baseado em app/services/generation_service.py e templates
 * 🌲 ToT: Múltiplas estratégias de interação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de geração
 */

import { Page, expect } from '@playwright/test';
import { BasePage, PageConfig } from './BasePage';

export interface ArticleGenerationData {
  instanceName: string;
  apiKey: string;
  modelType: string;
  prompt: string;
  webhookUrl?: string;
}

export class ArticleGenerationPage extends BasePage {
  // Seletores baseados no código real da aplicação
  private readonly selectors = {
    // Campos de instância
    instanceName: '[data-testid="instance-name"], input[name="instance_name"]',
    apiKey: '[data-testid="api-key"], input[name="api_key"]',
    modelType: '[data-testid="model-type"], select[name="model_type"]',
    prompt: '[data-testid="prompt"], textarea[name="prompts"]',
    
    // Botões
    addInstance: 'button[type="submit"]:has-text("Adicionar Instância")',
    submitGeneration: '[data-testid="submit-btn"], button[type="submit"]:has-text("Gerar")',
    downloadLink: '[data-testid="download-link"], a[href*="download"]',
    
    // Elementos de status
    progressBar: '#progress-omni-writer, [data-testid="progress-bar"]',
    statusMessage: '[data-testid="status-message"], .status-message',
    errorMessage: '.error-message, .alert-danger',
    successMessage: '.success-message, .alert-success',
    
    // Lista de instâncias
    instancesList: '#instancias_lista, [data-testid="instances-list"]',
    instanceItem: '#instancias_lista li, [data-testid="instance-item"]',
    
    // Webhook
    webhookUrl: 'input[name="webhook_url"]',
    registerWebhook: 'button[type="submit"]:has-text("Registrar Webhook")',
    
    // Elementos de validação
    title: 'h1, .page-title',
    form: 'form',
    loadingSpinner: '.loading, .spinner'
  };

  constructor(page: Page, config: PageConfig) {
    super(page, config);
  }

  /**
   * Navega para a página de geração de artigos
   */
  async navigateToGenerationPage(): Promise<void> {
    await this.navigateTo('/');
    await this.validatePage();
  }

  /**
   * Valida se a página está carregada corretamente
   */
  async validatePage(): Promise<void> {
    await this.expectPageTitle(/Omni Gerador de Artigos/i);
    await this.expectElementVisible(this.selectors.title);
    await this.expectElementVisible(this.selectors.form);
    this.log('Página de geração validada');
  }

  /**
   * Preenche dados de uma instância
   */
  async fillInstanceData(data: ArticleGenerationData): Promise<void> {
    this.log(`Preenchendo instância: ${data.instanceName}`);
    
    await this.fillField(this.selectors.instanceName, data.instanceName);
    await this.fillField(this.selectors.apiKey, data.apiKey);
    await this.selectOption(this.selectors.modelType, data.modelType);
    await this.fillField(this.selectors.prompt, data.prompt);
    
    this.log('Dados da instância preenchidos');
  }

  /**
   * Adiciona uma instância
   */
  async addInstance(data: ArticleGenerationData): Promise<void> {
    await this.fillInstanceData(data);
    await this.clickElement(this.selectors.addInstance);
    
    // Aguarda instância ser adicionada à lista
    await this.waitForElement(this.selectors.instanceItem);
    this.log('Instância adicionada com sucesso');
  }

  /**
   * Registra webhook
   */
  async registerWebhook(webhookUrl: string): Promise<void> {
    this.log(`Registrando webhook: ${webhookUrl}`);
    
    await this.fillField(this.selectors.webhookUrl, webhookUrl);
    await this.clickElement(this.selectors.registerWebhook);
    
    // Aguarda confirmação
    await this.waitForElement(this.selectors.successMessage);
    this.log('Webhook registrado com sucesso');
  }

  /**
   * Inicia geração de artigo
   */
  async startGeneration(): Promise<void> {
    this.log('Iniciando geração de artigo');
    
    await this.clickElement(this.selectors.submitGeneration);
    
    // Aguarda início do processamento
    await this.waitForElement(this.selectors.progressBar);
    this.log('Geração iniciada');
  }

  /**
   * Aguarda conclusão da geração
   */
  async waitForGenerationComplete(timeout: number = this.config.timeouts.long): Promise<void> {
    this.log('Aguardando conclusão da geração');
    
    // Aguarda download link ou mensagem de conclusão
    await this.waitForElement(
      `${this.selectors.downloadLink}, ${this.selectors.successMessage}`,
      timeout
    );
    
    this.log('Geração concluída');
  }

  /**
   * Aguarda falha na geração
   */
  async waitForGenerationError(timeout: number = this.config.timeouts.long): Promise<void> {
    this.log('Aguardando erro na geração');
    
    await this.waitForElement(this.selectors.errorMessage, timeout);
    this.log('Erro na geração detectado');
  }

  /**
   * Valida se download está disponível
   */
  async expectDownloadAvailable(): Promise<void> {
    await this.expectElementVisible(this.selectors.downloadLink);
    this.log('Download disponível');
  }

  /**
   * Valida se erro está visível
   */
  async expectErrorVisible(): Promise<void> {
    await this.expectElementVisible(this.selectors.errorMessage);
    this.log('Erro visível');
  }

  /**
   * Valida se sucesso está visível
   */
  async expectSuccessVisible(): Promise<void> {
    await this.expectElementVisible(this.selectors.successMessage);
    this.log('Sucesso visível');
  }

  /**
   * Valida se progresso está visível
   */
  async expectProgressVisible(): Promise<void> {
    await this.expectElementVisible(this.selectors.progressBar);
    this.log('Progresso visível');
  }

  /**
   * Valida se instância está na lista
   */
  async expectInstanceInList(instanceName: string): Promise<void> {
    await this.expectElementContainsText(this.selectors.instancesList, instanceName);
    this.log(`Instância ${instanceName} encontrada na lista`);
  }

  /**
   * Valida se webhook está registrado
   */
  async expectWebhookRegistered(webhookUrl: string): Promise<void> {
    await this.expectElementContainsText('body', webhookUrl);
    this.log(`Webhook ${webhookUrl} registrado`);
  }

  /**
   * Executa fluxo completo de geração
   */
  async executeFullGenerationFlow(data: ArticleGenerationData, webhookUrl?: string): Promise<void> {
    this.log('Executando fluxo completo de geração');
    
    // Adiciona instância
    await this.addInstance(data);
    
    // Registra webhook se fornecido
    if (webhookUrl) {
      await this.registerWebhook(webhookUrl);
    }
    
    // Inicia geração
    await this.startGeneration();
    
    // Aguarda conclusão
    await this.waitForGenerationComplete();
    
    // Valida resultado
    await this.expectDownloadAvailable();
    
    this.log('Fluxo completo executado com sucesso');
  }

  /**
   * Executa fluxo com erro esperado
   */
  async executeGenerationWithError(data: ArticleGenerationData): Promise<void> {
    this.log('Executando fluxo com erro esperado');
    
    // Adiciona instância
    await this.addInstance(data);
    
    // Inicia geração
    await this.startGeneration();
    
    // Aguarda erro
    await this.waitForGenerationError();
    
    // Valida erro
    await this.expectErrorVisible();
    
    this.log('Erro na geração confirmado');
  }

  /**
   * Valida performance da página
   */
  async validatePerformance(): Promise<number> {
    const loadTime = await this.measurePageLoadTime();
    
    // Valida que carregamento foi rápido
    expect(loadTime).toBeLessThan(5000); // Máximo 5 segundos
    
    this.log(`Performance validada: ${loadTime}ms`);
    return loadTime;
  }

  /**
   * Valida acessibilidade da página
   */
  async validateAccessibility(): Promise<void> {
    await this.runAccessibilityCheck();
    this.log('Acessibilidade da página validada');
  }

  /**
   * Valida responsividade
   */
  async validateResponsiveness(): Promise<void> {
    // Valida elementos principais em diferentes tamanhos
    await this.expectElementVisible(this.selectors.form);
    await this.expectElementVisible(this.selectors.title);
    
    this.log('Responsividade validada');
  }

  /**
   * Limpa dados do formulário
   */
  async clearForm(): Promise<void> {
    await this.clearField(this.selectors.instanceName);
    await this.clearField(this.selectors.apiKey);
    await this.clearField(this.selectors.prompt);
    
    this.log('Formulário limpo');
  }

  /**
   * Valida se formulário está vazio
   */
  async expectFormEmpty(): Promise<void> {
    await this.expectElementEmpty(this.selectors.instanceName);
    await this.expectElementEmpty(this.selectors.apiKey);
    await this.expectElementEmpty(this.selectors.prompt);
    
    this.log('Formulário vazio validado');
  }

  /**
   * Valida se botão de submissão está habilitado
   */
  async expectSubmitButtonEnabled(): Promise<void> {
    await this.expectElementVisibleAndEnabled(this.selectors.submitGeneration);
    this.log('Botão de submissão habilitado');
  }

  /**
   * Valida se botão de submissão está desabilitado
   */
  async expectSubmitButtonDisabled(): Promise<void> {
    await this.expectElementVisibleAndDisabled(this.selectors.submitGeneration);
    this.log('Botão de submissão desabilitado');
  }

  /**
   * Executa validação completa da página
   */
  async runCompleteValidation(): Promise<void> {
    this.log('Executando validação completa da página');
    
    await this.validatePage();
    await this.validatePerformance();
    await this.validateAccessibility();
    await this.validateResponsiveness();
    
    this.log('Validação completa concluída');
  }

  /**
   * Obtém URL do download
   */
  async getDownloadUrl(): Promise<string> {
    const downloadElement = await this.waitForElement(this.selectors.downloadLink);
    const href = await downloadElement.getAttribute('href');
    
    if (!href) {
      throw new Error('URL de download não encontrada');
    }
    
    this.log(`URL de download obtida: ${href}`);
    return href;
  }

  /**
   * Obtém mensagem de status
   */
  async getStatusMessage(): Promise<string> {
    const statusElement = await this.waitForElement(this.selectors.statusMessage);
    const text = await statusElement.textContent();
    
    this.log(`Mensagem de status: ${text}`);
    return text || '';
  }

  /**
   * Obtém mensagem de erro
   */
  async getErrorMessage(): Promise<string> {
    const errorElement = await this.waitForElement(this.selectors.errorMessage);
    const text = await errorElement.textContent();
    
    this.log(`Mensagem de erro: ${text}`);
    return text || '';
  }
} 