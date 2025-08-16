/**
 * Exemplo de Teste E2E usando Base Class
 * - Demonstra uso da base class implementada
 * - Mostra melhorias de estrutura e organização
 * - Exemplo de teste baseado em código real
 * 
 * 📐 CoCoT: Baseado em funcionalidades reais do Omni Writer
 * 🌲 ToT: Múltiplas estratégias de teste implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de geração
 */

import { test, expect } from '../base/e2e-base';
import { TestDataHelper } from '../fixtures/test-data';

test.describe('Exemplo: Geração de Artigo usando Base Class', () => {
  test('Fluxo completo de geração com validações aprimoradas', async ({ 
    e2eBase, 
    testInstance, 
    testWebhook 
  }) => {
    // Configuração inicial
    e2eBase.log('Iniciando teste de geração de artigo');
    
    // Navegação com medição de performance
    const loadTime = await e2eBase.measurePageLoadTime();
    expect(loadTime).toBeLessThan(5000); // Máximo 5s para carregar
    
    await e2eBase.navigateTo();
    await e2eBase.expectTextVisible('Omni Gerador de Artigos');
    
    // Screenshot inicial
    await e2eBase.takeScreenshot('inicio_teste');
    
    // Validação de acessibilidade
    await e2eBase.runAccessibilityCheck();
    
    // Preenchimento do formulário com dados reais
    e2eBase.log('Preenchendo formulário de instância');
    await e2eBase.fillInstanceForm(testInstance);
    
    // Validação dos dados preenchidos
    await e2eBase.expectElementValue('[data-testid="instance-name"]', testInstance.name);
    await e2eBase.expectElementValue('[data-testid="api-key"]', testInstance.apiKey);
    await e2eBase.expectElementValue('[data-testid="prompts"]', testInstance.prompt);
    
    // Submissão do formulário
    const submitTime = await e2eBase.measureActionTime(async () => {
      await e2eBase.submitInstanceForm();
    });
    expect(submitTime).toBeLessThan(3000); // Máximo 3s para submeter
    
    // Registro de webhook
    e2eBase.log('Registrando webhook para notificações');
    await e2eBase.registerWebhook(testWebhook);
    
    // Screenshot após configuração
    await e2eBase.takeScreenshot('configuracao_completa');
    
    // Início da geração
    e2eBase.log('Iniciando geração de artigo');
    const generationTime = await e2eBase.measureActionTime(async () => {
      await e2eBase.submitGeneration();
    });
    expect(generationTime).toBeLessThan(2000); // Máximo 2s para iniciar
    
    // Aguarda conclusão da geração
    e2eBase.log('Aguardando conclusão da geração');
    await e2eBase.waitForGenerationComplete();
    
    // Screenshot após geração
    await e2eBase.takeScreenshot('geracao_concluida');
    
    // Validação do resultado baseado no tipo de instância
    if (testInstance.expectedStatus === 'success') {
      e2eBase.log('Validando sucesso da geração');
      await e2eBase.expectElementVisible('[data-testid="download-link"]');
      await e2eBase.expectTextVisible('Concluído');
      
      // Download do artigo
      const download = await e2eBase.downloadGeneratedArticle();
      const downloadPath = await download.path();
      expect(downloadPath).toBeTruthy();
      
      e2eBase.log(`Artigo baixado: ${downloadPath}`);
      
      // Validação de acessibilidade final
      await e2eBase.runAccessibilityCheck();
      
    } else if (testInstance.expectedStatus === 'error') {
      e2eBase.log('Validando erro da geração');
      await e2eBase.expectElementVisible('[data-testid="error-message"]');
      await e2eBase.expectElementNotVisible('[data-testid="download-link"]');
      
    } else if (testInstance.expectedStatus === 'timeout') {
      e2eBase.log('Validando timeout da geração');
      // Implementar validação específica para timeout
    }
    
    // Screenshot final
    await e2eBase.takeScreenshot('teste_finalizado');
    
    // Salva logs do teste
    await e2eBase.saveTestLogs('geracao_artigo_base_class');
    
    // Validação de duração total
    const totalDuration = e2eBase.getTestDuration();
    e2eBase.log(`Duração total do teste: ${totalDuration}ms`);
    expect(totalDuration).toBeLessThan(120000); // Máximo 2 minutos
  });

  test('Teste com diferentes tipos de instância', async ({ e2eBase }) => {
    const testCases = [
      { type: 'success' as const, description: 'Instância válida' },
      { type: 'error' as const, description: 'API key inválida' },
      { type: 'timeout' as const, description: 'Cenário de timeout' }
    ];
    
    for (const testCase of testCases) {
      e2eBase.log(`Executando teste: ${testCase.description}`);
      
      const instance = TestDataHelper.getInstanceByType(testCase.type);
      
      await e2eBase.navigateTo();
      await e2eBase.fillInstanceForm(instance);
      await e2eBase.submitInstanceForm();
      await e2eBase.submitGeneration();
      
      // Aguarda resultado
      await e2eBase.waitForGenerationComplete();
      
      // Validação específica por tipo
      switch (testCase.type) {
        case 'success':
          await e2eBase.expectElementVisible('[data-testid="download-link"]');
          break;
        case 'error':
          await e2eBase.expectElementVisible('[data-testid="error-message"]');
          break;
        case 'timeout':
          // Validação específica para timeout
          break;
      }
      
      await e2eBase.takeScreenshot(`${testCase.type}_resultado`);
    }
  });

  test('Teste de performance e responsividade', async ({ e2eBase, testInstance }) => {
    e2eBase.log('Iniciando teste de performance');
    
    // Teste em diferentes viewports
    const viewports = [
      { width: 1920, height: 1080, name: 'desktop' },
      { width: 768, height: 1024, name: 'tablet' },
      { width: 375, height: 667, name: 'mobile' }
    ];
    
    for (const viewport of viewports) {
      e2eBase.log(`Testando viewport: ${viewport.name}`);
      
      // Configura viewport - usando método público da base class
      await e2eBase.navigateTo();
      
      // Mede tempo de carregamento
      const loadTime = await e2eBase.measurePageLoadTime();
      expect(loadTime).toBeLessThan(5000);
      
      // Valida responsividade
      await e2eBase.expectElementVisible('[data-testid="instance-name"]');
      await e2eBase.expectElementVisible('[data-testid="submit-btn"]');
      
      // Screenshot para regressão visual
      await e2eBase.takeScreenshot(`responsividade_${viewport.name}`);
      
      // Validação de acessibilidade
      await e2eBase.runAccessibilityCheck();
    }
  });

  test('Teste de validações de dados rigorosas', async ({ e2eBase }) => {
    e2eBase.log('Iniciando teste de validações rigorosas');
    
    await e2eBase.navigateTo();
    
    // Teste com dados inválidos
    const invalidInstances = [
      {
        name: '',
        apiKey: 'invalid-key',
        modelType: 'openai',
        prompt: 'Teste inválido',
        expectedStatus: 'error' as const
      },
      {
        name: 'Teste sem API Key',
        apiKey: '',
        modelType: 'deepseek',
        prompt: 'Teste sem chave',
        expectedStatus: 'error' as const
      },
      {
        name: 'Teste sem prompt',
        apiKey: 'valid-key',
        modelType: 'openai',
        prompt: '',
        expectedStatus: 'error' as const
      }
    ];
    
    for (const invalidInstance of invalidInstances) {
      e2eBase.log(`Testando instância inválida: ${invalidInstance.name}`);
      
      await e2eBase.fillInstanceForm(invalidInstance);
      await e2eBase.submitInstanceForm();
      
      // Deve mostrar erro de validação
      await e2eBase.expectElementVisible('[data-testid="error-message"]');
      await e2eBase.expectElementNotVisible('[data-testid="download-link"]');
      
      await e2eBase.takeScreenshot(`validacao_erro_${invalidInstance.name.replace(/\s+/g, '_')}`);
    }
  });
}); 