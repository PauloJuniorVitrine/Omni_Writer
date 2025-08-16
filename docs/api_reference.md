# 📚 API Reference - Omni Writer

**Versão:** 1.0.0  
**Data:** 2025-01-27  
**Tracing ID:** ENTERPRISE_20250127_009  

## 🔗 Visão Geral

A API do Omni Writer fornece endpoints para geração automatizada de artigos, gerenciamento de conteúdo e operações de sistema. Todos os endpoints seguem padrões RESTful e retornam respostas JSON estruturadas.

### Base URL
- **Desenvolvimento:** `http://localhost:5000`
- **Produção:** `https://api.omniwriter.com`

### Autenticação
A API suporta dois métodos de autenticação:

1. **Bearer Token:** `Authorization: Bearer <token>`
2. **API Key:** `X-API-Key: <key>`

### Headers Padrão
```http
Content-Type: application/json
Accept: application/json
User-Agent: OmniWriter-Client/1.0
```

---

## 🚀 Endpoints de Geração

### POST /generate
Gera artigos baseado em prompts fornecidos.

**Autenticação:** Obrigatória  
**Rate Limit:** 10 requests/minuto  

#### Request Body
```json
{
  "api_key": "string",
  "model_type": "openai|deepseek",
  "prompt_0": "string",
  "prompt_1": "string (opcional)",
  "instancias_json": "string (JSON opcional)"
}
```

#### Exemplo de Request
```bash
curl -X POST http://localhost:5000/generate \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sk-...",
    "model_type": "openai",
    "prompt_0": "Como criar um blog profissional"
  }'
```

#### Response (200)
```json
{
  "success": true,
  "trace_id": "trace_123456789",
  "message": "Geração iniciada com sucesso",
  "estimated_duration": 300
}
```

#### Response (400)
```json
{
  "success": false,
  "error": "Dados inválidos",
  "details": {
    "api_key": "API key é obrigatória"
  }
}
```

#### Response (401)
```json
{
  "success": false,
  "error": "Não autorizado",
  "code": "UNAUTHORIZED"
}
```

### GET /status/{trace_id}
Consulta o status de uma geração em andamento.

**Autenticação:** Obrigatória  
**Rate Limit:** 60 requests/minuto  

#### Path Parameters
- `trace_id` (string): ID único da geração

#### Response (200)
```json
{
  "trace_id": "trace_123456789",
  "status": "running|completed|failed",
  "progress": 75,
  "total_items": 10,
  "completed_items": 7,
  "estimated_remaining": 120,
  "errors": []
}
```

### GET /events/{trace_id}
Stream de eventos Server-Sent Events (SSE) para acompanhar geração em tempo real.

**Autenticação:** Obrigatória  
**Content-Type:** text/event-stream  

#### Exemplo de Uso
```javascript
const eventSource = new EventSource('/events/trace_123456789');
eventSource.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Progresso:', data.progress);
};
```

---

## 📥 Endpoints de Download

### GET /download
Download de arquivo ZIP com artigos gerados.

**Autenticação:** Obrigatória  
**Rate Limit:** 20 requests/minuto  

#### Query Parameters
- `trace_id` (string, opcional): ID específico da geração
- `format` (string, opcional): `zip` ou `csv` (padrão: `zip`)

#### Response (200)
- **Content-Type:** `application/zip` ou `text/csv`
- **Content-Disposition:** `attachment; filename="artigos_YYYYMMDD_HHMMSS.zip"`

### GET /download_multi
Download de múltiplos arquivos em lote.

**Autenticação:** Obrigatória  
**Rate Limit:** 10 requests/minuto  

#### Request Body
```json
{
  "trace_ids": ["trace_1", "trace_2", "trace_3"],
  "format": "zip"
}
```

---

## 📊 Endpoints de Exportação

### GET /export_artigos_csv
Exporta todos os artigos gerados em formato CSV.

**Autenticação:** Obrigatória  
**Rate Limit:** 30 requests/minuto  

#### Query Parameters
- `date_from` (string, opcional): Data inicial (YYYY-MM-DD)
- `date_to` (string, opcional): Data final (YYYY-MM-DD)
- `model_type` (string, opcional): Filtrar por modelo

#### Response (200)
```csv
trace_id,model_type,prompt,content,created_at,status
trace_123,openai,"Como criar blog","Artigo completo...",2025-01-27T10:00:00Z,completed
```

### GET /export_prompts
Exporta prompts utilizados em formato CSV.

**Autenticação:** Obrigatória  
**Rate Limit:** 30 requests/minuto  

---

## 🔐 Endpoints de Autenticação

### POST /token/rotate
Rotaciona token de API para um usuário.

**Autenticação:** Obrigatória  
**Rate Limit:** 5 requests/minuto  

#### Request Body
```json
{
  "user_id": "string"
}
```

#### Response (200)
```json
{
  "success": true,
  "new_token": "new_bearer_token_here",
  "expires_at": "2025-02-03T10:00:00Z"
}
```

### POST /api/protegido
Endpoint de teste para validação de autenticação.

**Autenticação:** Obrigatória  
**Rate Limit:** 100 requests/minuto  

#### Response (200)
```json
{
  "success": true,
  "message": "Acesso autorizado",
  "user_id": "user_123"
}
```

---

## 💬 Endpoints de Feedback

### POST /feedback
Envia feedback sobre artigos gerados.

**Autenticação:** Obrigatória  
**Rate Limit:** 20 requests/minuto  

#### Request Body
```json
{
  "user_id": "string",
  "artigo_id": "string",
  "tipo": "positivo|negativo|sugestao",
  "comentario": "string (opcional)"
}
```

#### Response (200)
```json
{
  "success": true,
  "message": "Feedback registrado com sucesso",
  "feedback_id": "feedback_123"
}
```

---

## 📈 Endpoints de Métricas

### GET /metrics
Métricas do sistema no formato Prometheus.

**Autenticação:** Não requerida  
**Rate Limit:** 60 requests/minuto  

#### Response (200)
```
# HELP omni_writer_requests_total Total de requisições
# TYPE omni_writer_requests_total counter
omni_writer_requests_total{endpoint="/generate",method="POST",status="200"} 150

# HELP omni_writer_generations_total Total de gerações
# TYPE omni_writer_generations_total counter
omni_writer_generations_total{model_type="openai",status="success"} 120
```

### GET /health
Status de saúde do sistema.

**Autenticação:** Não requerida  
**Rate Limit:** 60 requests/minuto  

#### Response (200)
```json
{
  "status": "healthy",
  "timestamp": "2025-01-27T10:00:00Z",
  "version": "1.0.0",
  "uptime": 86400,
  "components": {
    "database": "healthy",
    "cache": "healthy",
    "workers": "healthy"
  }
}
```

---

## 🚨 Códigos de Resposta

| Código | Descrição | Quando Ocorre |
|--------|-----------|---------------|
| 200 | OK | Operação realizada com sucesso |
| 201 | Created | Recurso criado com sucesso |
| 400 | Bad Request | Dados inválidos ou malformados |
| 401 | Unauthorized | Autenticação falhou ou ausente |
| 403 | Forbidden | Acesso negado (sem permissão) |
| 404 | Not Found | Recurso não encontrado |
| 429 | Too Many Requests | Rate limit excedido |
| 500 | Internal Server Error | Erro interno do servidor |
| 503 | Service Unavailable | Serviço temporariamente indisponível |

---

## ⚡ Rate Limiting

A API implementa rate limiting por IP e usuário:

| Endpoint | Limite | Janela |
|----------|--------|--------|
| `/generate` | 10 requests | 1 minuto |
| `/feedback` | 20 requests | 1 minuto |
| `/download` | 20 requests | 1 minuto |
| `/export_*` | 30 requests | 1 minuto |
| `/token/rotate` | 5 requests | 1 minuto |
| `/metrics`, `/health` | 60 requests | 1 minuto |
| Geral | 100 requests | 1 minuto |

### Headers de Rate Limiting
```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1643270400
```

---

## 🔄 Versionamento

A API segue versionamento semântico (SemVer):

- **Major:** Mudanças incompatíveis
- **Minor:** Novas funcionalidades compatíveis
- **Patch:** Correções de bugs compatíveis

### Versionamento de Endpoints
- Endpoints estáveis: `/v1/endpoint`
- Endpoints experimentais: `/beta/endpoint`
- Deprecação: Header `Deprecation: true` + data de remoção

---

## 📝 Schemas de Dados

### GenerationRequest
```json
{
  "type": "object",
  "properties": {
    "api_key": {
      "type": "string",
      "description": "Chave de API do provedor"
    },
    "model_type": {
      "type": "string",
      "enum": ["openai", "deepseek"],
      "description": "Tipo de modelo a ser utilizado"
    },
    "prompt_0": {
      "type": "string",
      "description": "Prompt principal"
    },
    "prompt_1": {
      "type": "string",
      "description": "Prompt secundário (opcional)"
    },
    "instancias_json": {
      "type": "string",
      "description": "JSON com configurações de instâncias"
    }
  },
  "required": ["api_key", "model_type", "prompt_0"]
}
```

### GenerationResponse
```json
{
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean",
      "description": "Indica se a operação foi bem-sucedida"
    },
    "trace_id": {
      "type": "string",
      "description": "ID único para rastreamento"
    },
    "message": {
      "type": "string",
      "description": "Mensagem descritiva"
    },
    "estimated_duration": {
      "type": "integer",
      "description": "Duração estimada em segundos"
    }
  },
  "required": ["success", "trace_id"]
}
```

### ErrorResponse
```json
{
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean",
      "const": false
    },
    "error": {
      "type": "string",
      "description": "Descrição do erro"
    },
    "code": {
      "type": "string",
      "description": "Código de erro interno"
    },
    "details": {
      "type": "object",
      "description": "Detalhes adicionais do erro"
    }
  },
  "required": ["success", "error"]
}
```

---

## 🛠️ Exemplos de Uso

### Geração Completa com Monitoramento
```javascript
// 1. Inicia geração
const response = await fetch('/generate', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer your-token',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    api_key: 'sk-...',
    model_type: 'openai',
    prompt_0: 'Como implementar Clean Architecture'
  })
});

const { trace_id } = await response.json();

// 2. Monitora progresso via SSE
const eventSource = new EventSource(`/events/${trace_id}`);
eventSource.onmessage = function(event) {
  const data = JSON.parse(event.data);
  updateProgress(data.progress);
  
  if (data.status === 'completed') {
    eventSource.close();
    downloadResults(trace_id);
  }
};

// 3. Download dos resultados
async function downloadResults(traceId) {
  const response = await fetch(`/download?trace_id=${traceId}`);
  const blob = await response.blob();
  
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `artigos_${traceId}.zip`;
  a.click();
}
```

### Tratamento de Erros
```javascript
async function makeApiCall(endpoint, data) {
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer your-token',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(`${error.error} (${error.code})`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Erro na API:', error.message);
    throw error;
  }
}
```

---

## 🔗 Links Úteis

- [Documentação OpenAPI](./openapi_v1.0.0.json)
- [Guia de Desenvolvimento](./development_guide.md)
- [Troubleshooting](./troubleshooting.md)
- [Changelog](../CHANGELOG.md)
- [Status da API](https://status.omniwriter.com)

---

*Documentação gerada em 2025-01-27T20:00:00Z* 