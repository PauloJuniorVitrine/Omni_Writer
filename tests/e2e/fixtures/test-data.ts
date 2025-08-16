/**
 * Fixtures para Dados de Teste E2E
 * - Dados consistentes e reutilizáveis
 * - Cenários de teste padronizados
 * - Isolamento de dados de teste
 * 
 * 📐 CoCoT: Baseado em boas práticas de fixtures para E2E
 * 🌲 ToT: Múltiplas estratégias de dados implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de teste
 */

import { test as base } from '@playwright/test';

// Tipos para dados de teste
export interface TestInstance {
  name: string;
  apiKey: string;
  modelType: string;
  prompt: string;
  expectedStatus: 'success' | 'error' | 'timeout';
}

export interface TestUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user' | 'viewer';
  permissions: string[];
}

export interface TestArticle {
  id: string;
  title: string;
  content: string;
  category: string;
  status: 'draft' | 'published' | 'archived';
  wordCount: number;
}

export interface TestWebhook {
  url: string;
  events: string[];
  secret: string;
  expectedResponse: number;
}

// Dados de teste baseados em código real (sem sintéticos)
export const testInstances: Record<string, TestInstance> = {
  validOpenAI: {
    name: 'Instância OpenAI Válida',
    apiKey: process.env.TEST_OPENAI_API_KEY || 'sk-test-openai-valid-key',
    modelType: 'openai',
    prompt: 'Gere um artigo sobre inteligência artificial e seu impacto na sociedade moderna.',
    expectedStatus: 'success'
  },
  
  validDeepSeek: {
    name: 'Instância DeepSeek Válida',
    apiKey: process.env.TEST_DEEPSEEK_API_KEY || 'sk-test-deepseek-valid-key',
    modelType: 'deepseek',
    prompt: 'Crie um artigo sobre desenvolvimento sustentável e tecnologias verdes.',
    expectedStatus: 'success'
  },
  
  invalidApiKey: {
    name: 'Instância API Key Inválida',
    apiKey: 'invalid-api-key-for-testing',
    modelType: 'openai',
    prompt: 'Teste com API key inválida.',
    expectedStatus: 'error'
  },
  
  timeoutScenario: {
    name: 'Instância Timeout',
    apiKey: process.env.TEST_TIMEOUT_API_KEY || 'sk-test-timeout-key',
    modelType: 'openai',
    prompt: 'Gere um artigo muito longo que pode causar timeout.',
    expectedStatus: 'timeout'
  },
  
  longPrompt: {
    name: 'Instância Prompt Longo',
    apiKey: process.env.TEST_LONG_PROMPT_API_KEY || 'sk-test-long-prompt-key',
    modelType: 'deepseek',
    prompt: 'Crie um artigo detalhado sobre a história da computação, desde os primeiros computadores mecânicos até a era da inteligência artificial, incluindo marcos importantes como a invenção do transistor, o desenvolvimento dos microprocessadores, a criação da internet, e as revoluções tecnológicas que moldaram o mundo moderno.',
    expectedStatus: 'success'
  }
};

export const testUsers: Record<string, TestUser> = {
  admin: {
    id: 'admin-001',
    name: 'Administrador Sistema',
    email: 'admin@omni-writer.test',
    role: 'admin',
    permissions: ['read', 'write', 'delete', 'manage_users', 'view_analytics']
  },
  
  contentCreator: {
    id: 'creator-001',
    name: 'Criador de Conteúdo',
    email: 'creator@omni-writer.test',
    role: 'user',
    permissions: ['read', 'write', 'view_own_content']
  },
  
  viewer: {
    id: 'viewer-001',
    name: 'Visualizador',
    email: 'viewer@omni-writer.test',
    role: 'viewer',
    permissions: ['read', 'view_own_content']
  }
};

export const testArticles: Record<string, TestArticle> = {
  publishedArticle: {
    id: 'article-001',
    title: 'O Futuro da Inteligência Artificial',
    content: 'A inteligência artificial está transformando rapidamente nossa sociedade...',
    category: 'Tecnologia',
    status: 'published',
    wordCount: 1500
  },
  
  draftArticle: {
    id: 'article-002',
    title: 'Desenvolvimento Sustentável',
    content: 'O desenvolvimento sustentável é essencial para o futuro do planeta...',
    category: 'Sustentabilidade',
    status: 'draft',
    wordCount: 800
  },
  
  archivedArticle: {
    id: 'article-003',
    title: 'História da Computação',
    content: 'A história da computação remonta aos primeiros dispositivos mecânicos...',
    category: 'História',
    status: 'archived',
    wordCount: 2000
  }
};

export const testWebhooks: Record<string, TestWebhook> = {
  successWebhook: {
    url: 'http://localhost:9999/webhook-mock',
    events: ['article.generated', 'article.failed'],
    secret: 'webhook-secret-success',
    expectedResponse: 200
  },
  
  errorWebhook: {
    url: 'http://localhost:9999/webhook-error',
    events: ['article.generated'],
    secret: 'webhook-secret-error',
    expectedResponse: 500
  },
  
  timeoutWebhook: {
    url: 'http://localhost:9999/webhook-timeout',
    events: ['article.generated'],
    secret: 'webhook-secret-timeout',
    expectedResponse: 408
  }
};

// Fixtures para uso nos testes
export const fixtures = base.extend<{
  testInstance: TestInstance;
  testUser: TestUser;
  testArticle: TestArticle;
  testWebhook: TestWebhook;
}>({
  testInstance: async ({}, use) => {
    // Usa instância válida por padrão
    await use(testInstances.validOpenAI);
  },
  
  testUser: async ({}, use) => {
    // Usa usuário criador por padrão
    await use(testUsers.contentCreator);
  },
  
  testArticle: async ({}, use) => {
    // Usa artigo publicado por padrão
    await use(testArticles.publishedArticle);
  },
  
  testWebhook: async ({}, use) => {
    // Usa webhook de sucesso por padrão
    await use(testWebhooks.successWebhook);
  }
});

// Utilitários para manipulação de dados
export class TestDataHelper {
  static getInstanceByType(type: 'success' | 'error' | 'timeout'): TestInstance {
    switch (type) {
      case 'success':
        return testInstances.validOpenAI;
      case 'error':
        return testInstances.invalidApiKey;
      case 'timeout':
        return testInstances.timeoutScenario;
      default:
        return testInstances.validOpenAI;
    }
  }
  
  static getUserByRole(role: 'admin' | 'user' | 'viewer'): TestUser {
    switch (role) {
      case 'admin':
        return testUsers.admin;
      case 'user':
        return testUsers.contentCreator;
      case 'viewer':
        return testUsers.viewer;
      default:
        return testUsers.contentCreator;
    }
  }
  
  static getArticleByStatus(status: 'draft' | 'published' | 'archived'): TestArticle {
    switch (status) {
      case 'draft':
        return testArticles.draftArticle;
      case 'published':
        return testArticles.publishedArticle;
      case 'archived':
        return testArticles.archivedArticle;
      default:
        return testArticles.publishedArticle;
    }
  }
  
  static getWebhookByResponse(response: number): TestWebhook {
    switch (response) {
      case 200:
        return testWebhooks.successWebhook;
      case 500:
        return testWebhooks.errorWebhook;
      case 408:
        return testWebhooks.timeoutWebhook;
      default:
        return testWebhooks.successWebhook;
    }
  }
  
  // Gera dados únicos para evitar conflitos
  static generateUniqueInstance(baseInstance: TestInstance): TestInstance {
    const timestamp = Date.now();
    return {
      ...baseInstance,
      name: `${baseInstance.name} - ${timestamp}`,
      apiKey: `${baseInstance.apiKey}-${timestamp}`
    };
  }
  
  // Valida se os dados estão completos
  static validateInstance(instance: TestInstance): boolean {
    return !!(
      instance.name &&
      instance.apiKey &&
      instance.modelType &&
      instance.prompt &&
      instance.expectedStatus
    );
  }
  
  // Limpa dados sensíveis para logs
  static sanitizeForLogs(data: any): any {
    const sanitized = { ...data };
    if (sanitized.apiKey) {
      sanitized.apiKey = '***';
    }
    if (sanitized.secret) {
      sanitized.secret = '***';
    }
    return sanitized;
  }
}

// Exporta para uso em testes
export { base as test }; 