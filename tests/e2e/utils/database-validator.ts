/**
 * Validador de Estado do Banco de Dados para Testes E2E
 * - Verifica persistência de dados após operações
 * - Valida integridade referencial
 * - Confirma side effects no banco
 * - Baseado nos modelos reais da aplicação
 * 
 * 📐 CoCoT: Baseado em omni_writer/domain/orm_models.py e validation_service.py
 * 🌲 ToT: Múltiplas estratégias de validação implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de persistência
 */

import { Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// Interfaces baseadas nos modelos reais da aplicação
export interface BlogData {
  id?: number;
  nome: string;
  desc?: string;
  created_at?: string;
  updated_at?: string;
}

export interface CategoriaData {
  id?: number;
  nome: string;
  blog_id: number;
  created_at?: string;
  updated_at?: string;
}

export interface PromptData {
  id?: number;
  titulo: string;
  conteudo: string;
  categoria_id: number;
  created_at?: string;
  updated_at?: string;
}

export interface ClusterData {
  id?: number;
  nome: string;
  descricao?: string;
  created_at?: string;
  updated_at?: string;
}

export interface DatabaseState {
  blogs: BlogData[];
  categorias: CategoriaData[];
  prompts: PromptData[];
  clusters: ClusterData[];
  total_records: number;
  last_updated: string;
}

export interface ValidationResult {
  success: boolean;
  message: string;
  details?: any;
  timestamp: string;
}

export class DatabaseValidator {
  private page: Page;
  private logFile: string;

  constructor(page: Page) {
    this.page = page;
    this.logFile = `logs/e2e/database-validation-${Date.now()}.log`;
  }

  /**
   * Log estruturado para validações
   */
  private log(message: string, level: 'INFO' | 'WARN' | 'ERROR' = 'INFO') {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level}] [DatabaseValidator] ${message}`;
    
    console.log(logEntry);
    
    // Salva em arquivo para análise posterior
    fs.appendFileSync(this.logFile, logEntry + '\n');
  }

  /**
   * Obtém estado atual do banco via API
   */
  async getDatabaseState(): Promise<DatabaseState> {
    try {
      this.log('Iniciando obtenção do estado do banco de dados');
      
      // Obtém blogs via API
      const blogsResponse = await this.page.request.get('/api/blogs');
      const blogs = await blogsResponse.json();

      // Obtém categorias via API (se disponível)
      const categorias: CategoriaData[] = [];
      for (const blog of blogs) {
        try {
          const categoriasResponse = await this.page.request.get(`/api/blogs/${blog.id}/categorias`);
          const blogCategorias = await categoriasResponse.json();
          categorias.push(...blogCategorias);
        } catch (error) {
          this.log(`Erro ao obter categorias do blog ${blog.id}: ${error}`, 'WARN');
        }
      }

      // Obtém prompts via API (se disponível)
      const prompts: PromptData[] = [];
      for (const categoria of categorias) {
        try {
          const promptsResponse = await this.page.request.get(`/api/categorias/${categoria.id}/prompts`);
          const categoriaPrompts = await promptsResponse.json();
          prompts.push(...categoriaPrompts);
        } catch (error) {
          this.log(`Erro ao obter prompts da categoria ${categoria.id}: ${error}`, 'WARN');
        }
      }

      // Obtém clusters via API (se disponível)
      const clusters: ClusterData[] = [];
      try {
        const clustersResponse = await this.page.request.get('/api/clusters');
        const clustersData = await clustersResponse.json();
        clusters.push(...clustersData);
      } catch (error) {
        this.log(`Erro ao obter clusters: ${error}`, 'WARN');
      }

      const state: DatabaseState = {
        blogs,
        categorias,
        prompts,
        clusters,
        total_records: blogs.length + categorias.length + prompts.length + clusters.length,
        last_updated: new Date().toISOString()
      };

      this.log(`Estado do banco obtido: ${state.total_records} registros`);
      return state;
    } catch (error) {
      this.log(`Erro ao obter estado do banco: ${error}`, 'ERROR');
      throw error;
    }
  }

  /**
   * Valida integridade referencial
   */
  async validateReferentialIntegrity(): Promise<ValidationResult> {
    try {
      this.log('Iniciando validação de integridade referencial');
      
      const state = await this.getDatabaseState();
      const errors: string[] = [];

      // Valida se categorias referenciam blogs existentes
      for (const categoria of state.categorias) {
        const blogExists = state.blogs.some(blog => blog.id === categoria.blog_id);
        if (!blogExists) {
          errors.push(`Categoria ${categoria.id} referencia blog inexistente ${categoria.blog_id}`);
        }
      }

      // Valida se prompts referenciam categorias existentes
      for (const prompt of state.prompts) {
        const categoriaExists = state.categorias.some(cat => cat.id === prompt.categoria_id);
        if (!categoriaExists) {
          errors.push(`Prompt ${prompt.id} referencia categoria inexistente ${prompt.categoria_id}`);
        }
      }

      const success = errors.length === 0;
      const result: ValidationResult = {
        success,
        message: success ? 'Integridade referencial válida' : `Encontrados ${errors.length} problemas de integridade`,
        details: errors,
        timestamp: new Date().toISOString()
      };

      this.log(`Validação de integridade: ${result.message}`);
      return result;
    } catch (error) {
      this.log(`Erro na validação de integridade: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Valida rollback de transações
   */
  async validateTransactionRollback(): Promise<ValidationResult> {
    try {
      this.log('Iniciando validação de rollback de transações');
      
      const initialState = await this.getDatabaseState();
      const initialCount = initialState.total_records;
      
      // Simula uma operação que deve falhar
      try {
        await this.page.request.post('/api/blogs', {
          data: {
            nome: '', // Nome vazio deve causar falha
            desc: 'Teste de rollback'
          }
        });
      } catch (error) {
        // Esperado que falhe
      }
      
      const finalState = await this.getDatabaseState();
      const finalCount = finalState.total_records;
      
      const success = initialCount === finalCount;
      const result: ValidationResult = {
        success,
        message: success ? 'Rollback de transação funcionando corretamente' : 'Rollback de transação falhou',
        details: {
          initialCount,
          finalCount,
          difference: finalCount - initialCount
        },
        timestamp: new Date().toISOString()
      };

      this.log(`Validação de rollback: ${result.message}`);
      return result;
    } catch (error) {
      this.log(`Erro na validação de rollback: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação de rollback: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Valida acesso concorrente
   */
  async validateConcurrentAccess(): Promise<ValidationResult> {
    try {
      this.log('Iniciando validação de acesso concorrente');
      
      const initialState = await this.getDatabaseState();
      const initialBlogs = initialState.blogs.length;
      
      // Simula múltiplas requisições simultâneas
      const promises: Promise<any>[] = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          this.page.request.post('/api/blogs', {
            data: {
              nome: `Blog Concorrente ${i}`,
              desc: `Teste de concorrência ${i}`
            }
          })
        );
      }
      
      await Promise.all(promises);
      
      const finalState = await this.getDatabaseState();
      const finalBlogs = finalState.blogs.length;
      const expectedIncrease = 5;
      const actualIncrease = finalBlogs - initialBlogs;
      
      const success = actualIncrease === expectedIncrease;
      const result: ValidationResult = {
        success,
        message: success ? 'Acesso concorrente funcionando corretamente' : 'Problemas detectados no acesso concorrente',
        details: {
          initialBlogs,
          finalBlogs,
          expectedIncrease,
          actualIncrease
        },
        timestamp: new Date().toISOString()
      };

      this.log(`Validação de concorrência: ${result.message}`);
      return result;
    } catch (error) {
      this.log(`Erro na validação de concorrência: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação de concorrência: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Valida consistência de dados
   */
  async validateDataConsistency(): Promise<ValidationResult> {
    try {
      this.log('Iniciando validação de consistência de dados');
      
      const state = await this.getDatabaseState();
      const errors: string[] = [];

      // Valida se blogs têm nomes únicos
      const blogNames = state.blogs.map(blog => blog.nome);
      const uniqueBlogNames = new Set(blogNames);
      if (blogNames.length !== uniqueBlogNames.size) {
        errors.push('Blogs com nomes duplicados detectados');
      }

      // Valida se categorias têm nomes únicos por blog
      for (const blog of state.blogs) {
        const blogCategorias = state.categorias.filter(cat => cat.blog_id === blog.id);
        const categoriaNames = blogCategorias.map(cat => cat.nome);
        const uniqueCategoriaNames = new Set(categoriaNames);
        if (categoriaNames.length !== uniqueCategoriaNames.size) {
          errors.push(`Categorias duplicadas no blog ${blog.id}`);
        }
      }

      // Valida se prompts têm títulos únicos por categoria
      for (const categoria of state.categorias) {
        const categoriaPrompts = state.prompts.filter(prompt => prompt.categoria_id === categoria.id);
        const promptTitles = categoriaPrompts.map(prompt => prompt.titulo);
        const uniquePromptTitles = new Set(promptTitles);
        if (promptTitles.length !== uniquePromptTitles.size) {
          errors.push(`Prompts duplicados na categoria ${categoria.id}`);
        }
      }

      const success = errors.length === 0;
      const result: ValidationResult = {
        success,
        message: success ? 'Consistência de dados válida' : `Encontrados ${errors.length} problemas de consistência`,
        details: errors,
        timestamp: new Date().toISOString()
      };

      this.log(`Validação de consistência: ${result.message}`);
      return result;
    } catch (error) {
      this.log(`Erro na validação de consistência: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação de consistência: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Valida se dados foram persistidos após operação
   */
  async validateDataPersistence(operation: string, expectedData: any): Promise<ValidationResult> {
    try {
      this.log(`Validando persistência após: ${operation}`);
      
      // Aguarda um pouco para garantir que dados foram salvos
      await this.page.waitForTimeout(1000);
      
      const state = await this.getDatabaseState();
      
      // Validação específica baseada no tipo de operação
      switch (operation) {
        case 'create_blog':
          return await this.validateBlogCreated(expectedData);
        case 'create_categoria':
          return await this.validateCategoriaCreated(expectedData);
        case 'create_prompt':
          return await this.validatePromptCreated(expectedData);
        case 'update_blog':
          return await this.validateBlogUpdated(expectedData);
        case 'delete_blog':
          return await this.validateBlogDeleted(expectedData);
        default:
          this.log(`Operação não reconhecida: ${operation}`, 'WARN');
          return {
            success: false,
            message: `Operação não reconhecida: ${operation}`,
            timestamp: new Date().toISOString()
          };
      }
    } catch (error) {
      this.log(`Erro ao validar persistência: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Validações específicas por tipo de operação
   */
  private async validateBlogCreated(expectedData: BlogData): Promise<ValidationResult> {
    const state = await this.getDatabaseState();
    const blog = state.blogs.find(b => b.nome === expectedData.nome);
    
    if (!blog) {
      return {
        success: false,
        message: `Blog "${expectedData.nome}" não foi encontrado após criação`,
        timestamp: new Date().toISOString()
      };
    }

    return {
      success: true,
      message: `Blog "${expectedData.nome}" criado com sucesso (ID: ${blog.id})`,
      details: blog,
      timestamp: new Date().toISOString()
    };
  }

  private async validateCategoriaCreated(expectedData: CategoriaData): Promise<ValidationResult> {
    const state = await this.getDatabaseState();
    const categoria = state.categorias.find(c => c.nome === expectedData.nome && c.blog_id === expectedData.blog_id);
    
    if (!categoria) {
      return {
        success: false,
        message: `Categoria "${expectedData.nome}" não foi encontrada após criação`,
        timestamp: new Date().toISOString()
      };
    }

    return {
      success: true,
      message: `Categoria "${expectedData.nome}" criada com sucesso (ID: ${categoria.id})`,
      details: categoria,
      timestamp: new Date().toISOString()
    };
  }

  private async validatePromptCreated(expectedData: PromptData): Promise<ValidationResult> {
    const state = await this.getDatabaseState();
    const prompt = state.prompts.find(p => p.titulo === expectedData.titulo && p.categoria_id === expectedData.categoria_id);
    
    if (!prompt) {
      return {
        success: false,
        message: `Prompt "${expectedData.titulo}" não foi encontrado após criação`,
        timestamp: new Date().toISOString()
      };
    }

    return {
      success: true,
      message: `Prompt "${expectedData.titulo}" criado com sucesso (ID: ${prompt.id})`,
      details: prompt,
      timestamp: new Date().toISOString()
    };
  }

  private async validateBlogUpdated(expectedData: BlogData): Promise<ValidationResult> {
    const state = await this.getDatabaseState();
    const blog = state.blogs.find(b => b.id === expectedData.id);
    
    if (!blog) {
      return {
        success: false,
        message: `Blog com ID ${expectedData.id} não foi encontrado após atualização`,
        timestamp: new Date().toISOString()
      };
    }

    if (blog.nome !== expectedData.nome) {
      return {
        success: false,
        message: `Blog não foi atualizado corretamente. Esperado: "${expectedData.nome}", Encontrado: "${blog.nome}"`,
        timestamp: new Date().toISOString()
      };
    }

    return {
      success: true,
      message: `Blog "${expectedData.nome}" atualizado com sucesso`,
      details: blog,
      timestamp: new Date().toISOString()
    };
  }

  private async validateBlogDeleted(expectedData: BlogData): Promise<ValidationResult> {
    const state = await this.getDatabaseState();
    const blog = state.blogs.find(b => b.id === expectedData.id);
    
    if (blog) {
      return {
        success: false,
        message: `Blog "${expectedData.nome}" ainda existe após exclusão`,
        timestamp: new Date().toISOString()
      };
    }

    return {
      success: true,
      message: `Blog "${expectedData.nome}" excluído com sucesso`,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Valida side effects no banco (logs, métricas, etc.)
   */
  async validateSideEffects(operation: string): Promise<ValidationResult> {
    try {
      this.log(`Validando side effects para: ${operation}`);
      
      const sideEffects: string[] = [];
      
      // Verifica se logs foram criados
      try {
        const logsResponse = await this.page.request.get('/api/logs');
        const logs = await logsResponse.json();
        
        const relevantLogs = logs.filter((log: any) => 
          log.operation === operation || log.message?.includes(operation)
        );

        if (relevantLogs.length > 0) {
          sideEffects.push(`Logs criados: ${relevantLogs.length} entradas`);
        }
      } catch (error) {
        this.log(`Erro ao verificar logs: ${error}`, 'WARN');
      }

      // Verificar e-mails enviados (se aplicável)
      try {
        const emailsResponse = await this.page.request.get('/api/emails/recent');
        const emails = await emailsResponse.json();
        const operationEmails = emails.filter((email: any) => 
          email.trigger === operation && 
          new Date(email.timestamp) > new Date(Date.now() - 60000)
        );
        
        if (operationEmails.length > 0) {
          sideEffects.push(`E-mails enviados: ${operationEmails.length} mensagens`);
        }
      } catch (error) {
        this.log(`Erro ao verificar e-mails: ${error}`, 'WARN');
      }

      // Verificar notificações disparadas
      try {
        const notificationsResponse = await this.page.request.get('/api/notifications/recent');
        const notifications = await notificationsResponse.json();
        const operationNotifications = notifications.filter((notification: any) => 
          notification.trigger === operation && 
          new Date(notification.timestamp) > new Date(Date.now() - 60000)
        );
        
        if (operationNotifications.length > 0) {
          sideEffects.push(`Notificações disparadas: ${operationNotifications.length} alertas`);
        }
      } catch (error) {
        this.log(`Erro ao verificar notificações: ${error}`, 'WARN');
      }

      // Verificar webhooks chamados
      try {
        const webhooksResponse = await this.page.request.get('/api/webhooks/recent');
        const webhooks = await webhooksResponse.json();
        const operationWebhooks = webhooks.filter((webhook: any) => 
          webhook.trigger === operation && 
          new Date(webhook.timestamp) > new Date(Date.now() - 60000)
        );
        
        if (operationWebhooks.length > 0) {
          sideEffects.push(`Webhooks chamados: ${operationWebhooks.length} endpoints`);
        }
      } catch (error) {
        this.log(`Erro ao verificar webhooks: ${error}`, 'WARN');
      }

      // Verificar cache atualizado
      try {
        const cacheResponse = await this.page.request.get('/api/cache/status');
        const cacheStatus = await cacheResponse.json();
        
        if (cacheStatus.last_updated && 
            new Date(cacheStatus.last_updated) > new Date(Date.now() - 60000)) {
          sideEffects.push('Cache atualizado');
        }
      } catch (error) {
        this.log(`Erro ao verificar cache: ${error}`, 'WARN');
      }

      const success = sideEffects.length > 0;
      const result: ValidationResult = {
        success,
        message: success ? `Side effects detectados: ${sideEffects.join(', ')}` : 'Nenhum side effect detectado',
        details: sideEffects,
        timestamp: new Date().toISOString()
      };

      this.log(`Validação de side effects: ${result.message}`);
      return result;
    } catch (error) {
      this.log(`Erro ao validar side effects: ${error}`, 'ERROR');
      return {
        success: false,
        message: `Erro na validação de side effects: ${error}`,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Gera relatório completo de validação
   */
  async generateValidationReport(): Promise<string> {
    try {
      this.log('Gerando relatório completo de validação');
      
      const state = await this.getDatabaseState();
      const integrity = await this.validateReferentialIntegrity();
      
      const report = {
        timestamp: new Date().toISOString(),
        database_state: {
          total_records: state.total_records,
          blogs_count: state.blogs.length,
          categorias_count: state.categorias.length,
          prompts_count: state.prompts.length,
          clusters_count: state.clusters.length
        },
        integrity_validation: integrity,
        recommendations: this.generateRecommendations(state, integrity)
      };

      const reportPath = `test-results/database-validation-${Date.now()}.json`;
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      
      this.log(`Relatório salvo em: ${reportPath}`);
      return reportPath;
    } catch (error) {
      this.log(`Erro ao gerar relatório: ${error}`, 'ERROR');
      throw error;
    }
  }

  /**
   * Gera recomendações baseadas no estado atual
   */
  private generateRecommendations(state: DatabaseState, integrity: ValidationResult): string[] {
    const recommendations: string[] = [];

    if (state.total_records === 0) {
      recommendations.push('Banco de dados vazio - considere popular com dados de teste');
    }

    if (!integrity.success) {
      recommendations.push('Problemas de integridade detectados - revise operações de CRUD');
    }

    if (state.blogs.length === 0) {
      recommendations.push('Nenhum blog encontrado - valide fluxo de criação de blogs');
    }

    if (state.categorias.length === 0) {
      recommendations.push('Nenhuma categoria encontrada - valide fluxo de criação de categorias');
    }

    return recommendations;
  }
} 