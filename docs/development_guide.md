# 🛠️ Guia de Desenvolvimento - Omni Writer

**Versão:** 1.0.0  
**Data:** 2025-01-27  
**Tracing ID:** ENTERPRISE_20250127_009  

## 📋 Índice

1. [Configuração do Ambiente](#configuração-do-ambiente)
2. [Arquitetura do Sistema](#arquitetura-do-sistema)
3. [Padrões de Código](#padrões-de-código)
4. [Estrutura de Diretórios](#estrutura-de-diretórios)
5. [Fluxo de Desenvolvimento](#fluxo-de-desenvolvimento)
6. [Testes](#testes)
7. [Documentação](#documentação)
8. [Deploy](#deploy)
9. [Troubleshooting](#troubleshooting)

---

## 🚀 Configuração do Ambiente

### Pré-requisitos
- Python 3.10+
- Node.js 18+
- Git
- Docker (opcional)

### Instalação Local

```bash
# 1. Clone o repositório
git clone https://github.com/omniwriter/omniwriter.git
cd omniwriter

# 2. Configure ambiente Python
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# 3. Instale dependências Python
pip install -r requirements.txt

# 4. Instale dependências Node.js
npm install

# 5. Configure variáveis de ambiente
cp .env.example .env
# Edite .env com suas configurações
```

### Configuração do .env
```bash
# Configurações da API
OPENAI_API_KEY=sk-your-openai-key
DEEPSEEK_API_KEY=your-deepseek-key
FLASK_SECRET_KEY=your-secret-key

# Configurações do banco
DATABASE_URL=sqlite:///omni_writer.db

# Configurações de cache
REDIS_URL=redis://localhost:6379

# Configurações de logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Configurações de segurança
JWT_SECRET_KEY=your-jwt-secret
CORS_ORIGINS=http://localhost:3000,http://localhost:5000
```

---

## 🏗️ Arquitetura do Sistema

### Clean Architecture (Hexagonal)

O Omni Writer segue os princípios da Clean Architecture com separação clara entre camadas:

```
┌─────────────────────────────────────────────────────────────┐
│                    Interface Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Web UI    │  │   REST API  │  │   CLI       │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Application Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Controllers │  │   Services  │  │   Use Cases │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Domain Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Entities   │  │  Value Obj  │  │  Business   │        │
│  │             │  │             │  │   Rules     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                 Infrastructure Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Database  │  │ External    │  │   Cache     │        │
│  │             │  │   APIs      │  │             │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Princípios Arquiteturais

1. **Dependency Inversion:** Dependências apontam para abstrações
2. **Single Responsibility:** Cada classe tem uma responsabilidade
3. **Open/Closed:** Aberto para extensão, fechado para modificação
4. **Interface Segregation:** Interfaces específicas para cada cliente
5. **Dependency Injection:** Injeção de dependências via construtor

---

## 📝 Padrões de Código

### Python (Backend)

#### Nomenclatura
```python
# Arquivos e diretórios: snake_case
user_service.py
api_controllers.py

# Classes: PascalCase
class UserService:
    pass

class ApiController:
    pass

# Funções e variáveis: snake_case
def generate_article():
    user_id = "user_123"
    pass

# Constantes: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30
```

#### Docstrings
```python
def generate_article(prompt: str, model_type: str) -> Article:
    """
    Gera um artigo baseado no prompt fornecido.
    
    Args:
        prompt: Texto do prompt para geração
        model_type: Tipo de modelo ('openai' ou 'deepseek')
        
    Returns:
        Article: Objeto contendo o artigo gerado
        
    Raises:
        ValidationError: Se o prompt for inválido
        ApiError: Se houver erro na API externa
        
    Example:
        >>> article = generate_article("Como criar um blog", "openai")
        >>> print(article.content)
    """
    pass
```

#### Type Hints
```python
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class GenerationConfig:
    prompt: str
    model_type: str
    max_tokens: Optional[int] = None

def process_generation(config: GenerationConfig) -> Dict[str, Any]:
    pass
```

### JavaScript (Frontend)

#### Nomenclatura
```javascript
// Arquivos: kebab-case
user-service.js
api-controller.js

// Classes: PascalCase
class UserService {
    constructor() {
        this.baseUrl = '/api';
    }
}

// Funções e variáveis: camelCase
function generateArticle(prompt, modelType) {
    const userId = 'user_123';
    return fetch('/api/generate', {
        method: 'POST',
        body: JSON.stringify({ prompt, modelType })
    });
}

// Constantes: UPPER_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 3;
const DEFAULT_TIMEOUT = 30000;
```

#### JSDoc
```javascript
/**
 * Gera um artigo baseado no prompt fornecido
 * @param {string} prompt - Texto do prompt para geração
 * @param {string} modelType - Tipo de modelo ('openai' ou 'deepseek')
 * @returns {Promise<Article>} Objeto contendo o artigo gerado
 * @throws {ValidationError} Se o prompt for inválido
 * @throws {ApiError} Se houver erro na API externa
 * @example
 * const article = await generateArticle("Como criar um blog", "openai");
 * console.log(article.content);
 */
async function generateArticle(prompt, modelType) {
    // Implementation
}
```

---

## 📁 Estrutura de Diretórios

```
omni_writer/
├── app/                    # Camada de aplicação
│   ├── __init__.py
│   ├── app_factory.py     # Factory da aplicação Flask
│   ├── routes.py          # Rotas da API
│   ├── controllers/       # Controladores
│   ├── services/          # Serviços de aplicação
│   ├── validators/        # Validadores de entrada
│   └── schemas/           # Schemas de request/response
├── domain/                # Camada de domínio
│   ├── __init__.py
│   ├── entities/          # Entidades de domínio
│   ├── value_objects/     # Objetos de valor
│   ├── repositories/      # Interfaces de repositório
│   └── services/          # Serviços de domínio
├── infrastructure/        # Camada de infraestrutura
│   ├── __init__.py
│   ├── database/          # Implementações de banco
│   ├── external_apis/     # Gateways para APIs externas
│   ├── cache/             # Implementações de cache
│   └── storage/           # Armazenamento de arquivos
├── shared/                # Utilitários compartilhados
│   ├── __init__.py
│   ├── logger.py          # Sistema de logging
│   ├── config.py          # Configurações
│   ├── exceptions.py      # Exceções customizadas
│   └── utils/             # Utilitários gerais
├── tests/                 # Testes
│   ├── unit/              # Testes unitários
│   ├── integration/       # Testes de integração
│   ├── e2e/               # Testes end-to-end
│   └── fixtures/          # Dados de teste
├── docs/                  # Documentação
├── scripts/               # Scripts utilitários
└── ui/                    # Interface do usuário
    ├── components/        # Componentes React
    ├── pages/             # Páginas
    ├── hooks/             # Custom hooks
    └── utils/             # Utilitários do frontend
```

---

## 🔄 Fluxo de Desenvolvimento

### 1. Setup do Projeto
```bash
# Clone e configure
git clone <repository>
cd omni_writer
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
npm install

# Configure pre-commit hooks
pre-commit install
```

### 2. Desenvolvimento de Features

#### Backend (Python)
```bash
# 1. Crie uma branch
git checkout -b feature/nova-funcionalidade

# 2. Implemente a feature seguindo TDD
# - Escreva testes primeiro
# - Implemente o código
# - Refatore se necessário

# 3. Execute testes
pytest tests/unit/
pytest tests/integration/

# 4. Verifique cobertura
pytest --cov=. --cov-report=html

# 5. Execute linting
flake8 .
black .
isort .
```

#### Frontend (JavaScript)
```bash
# 1. Desenvolva a feature
npm run dev

# 2. Execute testes
npm test

# 3. Verifique linting
npm run lint

# 4. Build de produção
npm run build
```

### 3. Pull Request

```bash
# 1. Commit suas mudanças
git add .
git commit -m "feat: adiciona nova funcionalidade

- Implementa geração de artigos em lote
- Adiciona validação de entrada
- Inclui testes unitários
- Atualiza documentação

Closes #123"

# 2. Push para o repositório
git push origin feature/nova-funcionalidade

# 3. Crie Pull Request
# - Descreva as mudanças
# - Referencie issues relacionadas
# - Adicione reviewers
```

### 4. Code Review

#### Checklist de Review
- [ ] Código segue padrões estabelecidos
- [ ] Testes cobrem funcionalidade
- [ ] Cobertura mínima atingida (98% unit, 95% integration)
- [ ] Documentação atualizada
- [ ] Logs estruturados implementados
- [ ] Tratamento de erros adequado
- [ ] Performance considerada
- [ ] Segurança verificada

---

## 🧪 Testes

### Estratégia de Testes

#### Pirâmide de Testes
```
        /\
       /  \     E2E Tests (5%)
      /____\    
     /      \   Integration Tests (15%)
    /________\  
   /          \ Unit Tests (80%)
  /____________\
```

### Testes Unitários

#### Estrutura de Teste
```python
# tests/unit/domain/test_article_generator.py
import pytest
from unittest.mock import Mock, patch
from domain.entities.article import Article
from domain.services.article_generator import ArticleGenerator

class TestArticleGenerator:
    """Testes para o gerador de artigos."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.generator = ArticleGenerator()
        self.sample_prompt = "Como criar um blog profissional"
    
    def test_generate_article_success(self):
        """Testa geração bem-sucedida de artigo."""
        # Arrange
        expected_content = "Artigo sobre como criar um blog..."
        
        with patch('domain.services.article_generator.openai_client') as mock_client:
            mock_client.generate.return_value = expected_content
            
            # Act
            result = self.generator.generate(self.sample_prompt)
            
            # Assert
            assert isinstance(result, Article)
            assert result.content == expected_content
            assert result.prompt == self.sample_prompt
            mock_client.generate.assert_called_once_with(self.sample_prompt)
    
    def test_generate_article_empty_prompt(self):
        """Testa geração com prompt vazio."""
        # Act & Assert
        with pytest.raises(ValueError, match="Prompt não pode ser vazio"):
            self.generator.generate("")
    
    def test_generate_article_api_error(self):
        """Testa tratamento de erro da API."""
        # Arrange
        with patch('domain.services.article_generator.openai_client') as mock_client:
            mock_client.generate.side_effect = Exception("API Error")
            
            # Act & Assert
            with pytest.raises(Exception, match="Erro na geração do artigo"):
                self.generator.generate(self.sample_prompt)
```

### Testes de Integração

```python
# tests/integration/test_generation_pipeline.py
import pytest
from app.app_factory import create_app
from domain.entities.generation_config import GenerationConfig

class TestGenerationPipeline:
    """Testes de integração para pipeline de geração."""
    
    @pytest.fixture
    def client(self):
        """Cliente de teste Flask."""
        app = create_app()
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_generation_pipeline_complete(self, client):
        """Testa pipeline completo de geração."""
        # Arrange
        config = GenerationConfig(
            prompt="Teste de integração",
            model_type="openai"
        )
        
        # Act
        response = client.post('/api/generate', json=config.to_dict())
        
        # Assert
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'trace_id' in data
```

### Testes E2E

```javascript
// tests/e2e/generation.spec.js
import { test, expect } from '@playwright/test';

test('Geração completa de artigo', async ({ page }) => {
  // Arrange
  await page.goto('/');
  
  // Act
  await page.fill('[data-testid="prompt-input"]', 'Como criar um blog');
  await page.selectOption('[data-testid="model-select"]', 'openai');
  await page.click('[data-testid="generate-button"]');
  
  // Assert
  await expect(page.locator('[data-testid="progress-bar"]')).toBeVisible();
  await expect(page.locator('[data-testid="download-button"]')).toBeVisible({ timeout: 30000 });
});
```

---

## 📚 Documentação

### Padrões de Documentação

#### Docstrings Python
```python
def complex_function(param1: str, param2: int) -> Dict[str, Any]:
    """
    Descrição breve da função.
    
    Descrição detalhada da função, incluindo contexto e uso.
    
    Args:
        param1: Descrição do primeiro parâmetro
        param2: Descrição do segundo parâmetro
        
    Returns:
        Dict contendo os resultados da operação
        
    Raises:
        ValueError: Quando param1 é vazio
        ApiError: Quando há erro na API externa
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result['status'])
        'success'
        
    Note:
        Esta função é thread-safe e pode ser chamada concorrentemente.
        
    See Also:
        :func:`related_function`: Função relacionada
        :class:`RelatedClass`: Classe relacionada
    """
    pass
```

#### JSDoc JavaScript
```javascript
/**
 * Descrição breve da função
 * 
 * Descrição detalhada da função, incluindo contexto e uso.
 * 
 * @param {string} param1 - Descrição do primeiro parâmetro
 * @param {number} param2 - Descrição do segundo parâmetro
 * @returns {Promise<Object>} Objeto contendo os resultados
 * @throws {Error} Quando param1 é vazio
 * @throws {ApiError} Quando há erro na API externa
 * 
 * @example
 * const result = await complexFunction("test", 42);
 * console.log(result.status); // 'success'
 * 
 * @since 1.0.0
 * @deprecated Use newFunction instead
 */
async function complexFunction(param1, param2) {
    // Implementation
}
```

### Documentação de API

#### OpenAPI/Swagger
```yaml
openapi: 3.0.3
info:
  title: Omni Writer API
  version: 1.0.0
  description: API para geração automatizada de artigos

paths:
  /generate:
    post:
      summary: Gera artigo
      description: Gera um artigo baseado no prompt fornecido
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/GenerationRequest'
      responses:
        '200':
          description: Artigo gerado com sucesso
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GenerationResponse'
```

---

## 🚀 Deploy

### Ambiente de Desenvolvimento

```bash
# Backend
export FLASK_APP=app.app_factory:create_app
export FLASK_ENV=development
flask run

# Frontend
npm run dev
```

### Ambiente de Produção

#### Docker
```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app.app_factory:create_app()"]
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
    depends_on:
      - redis
      - postgres
  
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
  
  postgres:
    image: postgres:13
    environment:
      POSTGRES_DB: omni_writer
      POSTGRES_USER: omni_writer
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.10
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          npm install
      
      - name: Run tests
        run: |
          pytest --cov=. --cov-report=xml
          npm test
      
      - name: Upload coverage
        uses: codecov/codecov-action@v1
        with:
          file: ./coverage.xml

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy to production
        run: |
          # Deploy steps
```

---

## 🔧 Troubleshooting

### Problemas Comuns

#### 1. Erro de Importação
```bash
# Erro: ModuleNotFoundError: No module named 'omni_writer'
# Solução: Configure PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

#### 2. Erro de Conexão com Banco
```bash
# Erro: sqlite3.OperationalError: database is locked
# Solução: Verifique permissões e conexões
chmod 666 omni_writer.db
```

#### 3. Erro de Cache Redis
```bash
# Erro: redis.exceptions.ConnectionError
# Solução: Inicie o Redis
redis-server
# ou use cache local
export USE_LOCAL_CACHE=true
```

#### 4. Erro de Testes
```bash
# Erro: pytest não encontra testes
# Solução: Verifique estrutura de diretórios
pytest --collect-only
```

### Logs e Debugging

#### Configuração de Logs
```python
import logging
from shared.logger import get_structured_logger

logger = get_structured_logger(__name__)

def debug_function():
    logger.debug("Iniciando função", extra={
        'function': 'debug_function',
        'params': {'param1': 'value1'}
    })
    
    try:
        # Código da função
        result = process_data()
        logger.info("Função executada com sucesso", extra={
            'result': result,
            'duration': 1.5
        })
    except Exception as e:
        logger.error("Erro na função", extra={
            'error': str(e),
            'traceback': traceback.format_exc()
        })
        raise
```

#### Debugging com pdb
```python
import pdb

def complex_function():
    # Código da função
    pdb.set_trace()  # Breakpoint
    # Mais código
```

---

## 📞 Suporte

### Recursos Úteis
- [Documentação da API](./api_reference.md)
- [Troubleshooting](./troubleshooting.md)
- [Changelog](../CHANGELOG.md)
- [Issues do GitHub](https://github.com/omniwriter/omniwriter/issues)

### Contato
- **Email:** dev@omniwriter.com
- **Slack:** #omni-writer-dev
- **Documentação:** [docs.omniwriter.com](https://docs.omniwriter.com)

---

*Guia atualizado em 2025-01-27T20:00:00Z* 