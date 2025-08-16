/**
 * Mock Server para Testes E2E
 * - Simula webhooks e APIs externas
 * - Isola testes de dependências externas
 * - Fornece respostas controladas
 * 
 * 📐 CoCoT: Baseado em boas práticas de mock servers para E2E
 * 🌲 ToT: Múltiplas estratégias de mock implementadas
 * ♻️ ReAct: Simulado para diferentes cenários de resposta
 */

import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import fs from 'fs';
import path from 'path';

interface WebhookRequest {
  id: string;
  timestamp: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: any;
}

interface MockResponse {
  status: number;
  body: any;
  delay?: number;
}

class MockServer {
  private app: express.Application;
  private port: number;
  private webhookRequests: WebhookRequest[] = [];
  private mockResponses: Map<string, MockResponse> = new Map();
  private server: any;

  constructor(port: number = 9999) {
    this.port = port;
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware() {
    this.app.use(cors());
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: true }));
    
    // Logging middleware
    this.app.use((req, res, next) => {
      console.log(`[MOCK] ${req.method} ${req.url}`);
      next();
    });
  }

  private setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // Webhook endpoint
    this.app.post('/webhook-mock', (req, res) => {
      const webhookRequest: WebhookRequest = {
        id: Math.random().toString(36).substr(2, 9),
        timestamp: new Date().toISOString(),
        url: req.url,
        method: req.method,
        headers: req.headers as Record<string, string>,
        body: req.body
      };

      this.webhookRequests.push(webhookRequest);
      
      // Salva o request em arquivo para análise
      this.saveWebhookRequest(webhookRequest);
      
      console.log(`[MOCK] Webhook recebido: ${JSON.stringify(webhookRequest, null, 2)}`);
      
      // Simula processamento
      setTimeout(() => {
        res.status(200).json({
          success: true,
          message: 'Webhook processado com sucesso',
          requestId: webhookRequest.id,
          timestamp: new Date().toISOString()
        });
      }, 100);
    });

    // Endpoints específicos para diferentes webhooks
    this.app.post('/webhook-mock-1', (req, res) => {
      this.handleWebhookRequest(req, res, 'webhook-mock-1');
    });

    this.app.post('/webhook-mock-2', (req, res) => {
      this.handleWebhookRequest(req, res, 'webhook-mock-2');
    });

    this.app.post('/webhook-mock-3', (req, res) => {
      this.handleWebhookRequest(req, res, 'webhook-mock-3');
    });

    // Endpoint para consultar webhooks recebidos
    this.app.get('/webhooks', (req, res) => {
      res.json({
        total: this.webhookRequests.length,
        webhooks: this.webhookRequests
      });
    });

    // Endpoint para limpar webhooks
    this.app.delete('/webhooks', (req, res) => {
      this.webhookRequests = [];
      res.json({ message: 'Webhooks limpos com sucesso' });
    });

    // Mock de API externa (exemplo: OpenAI)
    this.app.post('/api/openai/chat/completions', (req, res) => {
      const mockResponse = this.mockResponses.get('openai') || {
        status: 200,
        body: {
          id: 'mock-chat-completion-id',
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          model: 'gpt-3.5-turbo',
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: 'Este é um mock de resposta da API OpenAI para testes E2E.'
              },
              finish_reason: 'stop'
            }
          ],
          usage: {
            prompt_tokens: 10,
            completion_tokens: 20,
            total_tokens: 30
          }
        }
      };

      setTimeout(() => {
        res.status(mockResponse.status).json(mockResponse.body);
      }, mockResponse.delay || 500);
    });

    // Mock de API de DeepSeek
    this.app.post('/api/deepseek/chat/completions', (req, res) => {
      const mockResponse = this.mockResponses.get('deepseek') || {
        status: 200,
        body: {
          id: 'mock-deepseek-completion-id',
          object: 'chat.completion',
          created: Math.floor(Date.now() / 1000),
          model: 'deepseek-chat',
          choices: [
            {
              index: 0,
              message: {
                role: 'assistant',
                content: 'Este é um mock de resposta da API DeepSeek para testes E2E.'
              },
              finish_reason: 'stop'
            }
          ],
          usage: {
            prompt_tokens: 15,
            completion_tokens: 25,
            total_tokens: 40
          }
        }
      };

      setTimeout(() => {
        res.status(mockResponse.status).json(mockResponse.body);
      }, mockResponse.delay || 300);
    });

    // Endpoint para configurar respostas mock
    this.app.post('/mock/configure', (req, res) => {
      const { endpoint, response } = req.body;
      this.mockResponses.set(endpoint, response);
      res.json({ message: `Mock configurado para ${endpoint}` });
    });

    // Endpoint para status do servidor
    this.app.get('/mock/status', (req, res) => {
      res.json({
        status: 'running',
        port: this.port,
        webhooksReceived: this.webhookRequests.length,
        mockResponses: Array.from(this.mockResponses.keys()),
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      });
    });

    // Endpoint para reset do servidor
    this.app.post('/mock/reset', (req, res) => {
      this.webhookRequests = [];
      this.mockResponses.clear();
      res.json({ message: 'Servidor mock resetado' });
    });
  }

  private handleWebhookRequest(req: express.Request, res: express.Response, endpoint: string) {
    const webhookRequest: WebhookRequest = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      url: req.url,
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: req.body
    };

    this.webhookRequests.push(webhookRequest);
    this.saveWebhookRequest(webhookRequest);
    
    console.log(`[MOCK] ${endpoint} recebido: ${JSON.stringify(webhookRequest, null, 2)}`);
    
    // Busca resposta configurada para este endpoint
    const mockResponse = this.mockResponses.get(endpoint) || {
      status: 200,
      body: { success: true, message: `${endpoint} processado` },
      delay: 100
    };

    setTimeout(() => {
      res.status(mockResponse.status).json(mockResponse.body);
    }, mockResponse.delay || 100);
  }

  private saveWebhookRequest(webhookRequest: WebhookRequest) {
    const logDir = 'logs/e2e/mock-server';
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    const filename = `webhook-${webhookRequest.id}-${Date.now()}.json`;
    const filepath = path.join(logDir, filename);
    
    fs.writeFileSync(filepath, JSON.stringify(webhookRequest, null, 2));
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(this.port, () => {
        console.log(`🚀 Mock Server iniciado na porta ${this.port}`);
        console.log(`📡 Endpoints disponíveis:`);
        console.log(`  - GET  /health`);
        console.log(`  - POST /webhook-mock`);
        console.log(`  - POST /webhook-mock-1`);
        console.log(`  - POST /webhook-mock-2`);
        console.log(`  - POST /webhook-mock-3`);
        console.log(`  - GET  /webhooks`);
        console.log(`  - DELETE /webhooks`);
        console.log(`  - POST /api/openai/chat/completions`);
        console.log(`  - POST /api/deepseek/chat/completions`);
        console.log(`  - POST /mock/configure`);
        console.log(`  - GET  /mock/status`);
        console.log(`  - POST /mock/reset`);
        resolve();
      });

      this.server.on('error', (error: any) => {
        console.error('❌ Erro ao iniciar Mock Server:', error);
        reject(error);
      });
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          console.log('🛑 Mock Server parado');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  public async getWebhooks(): Promise<WebhookRequest[]> {
    return this.webhookRequests;
  }

  public async clearWebhooks(): Promise<void> {
    this.webhookRequests = [];
  }

  public async configureMockResponse(endpoint: string, response: MockResponse): Promise<void> {
    this.mockResponses.set(endpoint, response);
  }

  public async getStatus(): Promise<any> {
    return {
      status: 'running',
      port: this.port,
      webhooksReceived: this.webhookRequests.length,
      mockResponses: Array.from(this.mockResponses.keys()),
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    };
  }
}

export { MockServer, WebhookRequest, MockResponse }; 