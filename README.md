# 🤖 **OMNI WRITER** - Sistema Avançado de Geração de Artigos via IA

[![CI](https://img.shields.io/github/actions/workflow/status/omniwriter/ci.yml?branch=main)](https://github.com/omniwriter/omniwriter/actions)
[![Cobertura](https://img.shields.io/badge/cobertura-%3E%3D98%25-brightgreen)](https://github.com/omniwriter/omniwriter)
[![Licença](https://img.shields.io/github/license/omniwriter/omniwriter)](https://github.com/omniwriter/omniwriter/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Node.js](https://img.shields.io/badge/node.js-18+-green.svg)](https://nodejs.org/)

## 📋 **VISÃO GERAL**

**Omni Writer** é um sistema enterprise completo para geração em massa de artigos longos via múltiplos modelos de IA (OpenAI GPT-4o, DeepSeek, Claude, Gemini). Desenvolvido com arquitetura limpa, monitoramento avançado e cobertura de testes abrangente.

### **🎯 Características Principais**
- **Geração Inteligente**: Múltiplas instâncias de API com distribuição automática
- **Interface Moderna**: Web responsiva com dark mode e acessibilidade completa
- **Arquitetura Robusta**: Clean Architecture com separação de responsabilidades
- **Monitoramento Avançado**: Prometheus, Grafana, Sentry e logs estruturados
- **Segurança Enterprise**: Autenticação, autorização e rotação de tokens
- **Testes Abrangentes**: Unitários, integração, E2E, carga e mutação

---

## 🚀 **FUNCIONALIDADES**

### **📝 Geração de Conteúdo**
- ✅ **Múltiplas APIs**: OpenAI, DeepSeek, Claude, Gemini
- ✅ **Distribuição Inteligente**: Até 15 instâncias simultâneas
- ✅ **Prompts Flexíveis**: Textarea, arquivos `.txt` ou `.csv` (até 105 prompts)
- ✅ **Geração Segura**: Sequencial com rate limiting automático
- ✅ **Organização Automática**: `/output/{instancia}/prompt_{n}/artigo_{variação}.txt`

### **🌐 Interface Web**
- ✅ **Dashboard Moderno**: Métricas em tempo real e status de operações
- ✅ **CRUD Completo**: Blogs, categorias, clusters, prompts
- ✅ **Responsividade**: Mobile-first com acessibilidade WCAG 2.1
- ✅ **Dark/Light Mode**: Tema adaptativo com microinterações
- ✅ **Onboarding Interativo**: Guia passo-a-passo integrado

### **📊 Exportação e Download**
- ✅ **ZIP Inteligente**: Estrutura organizada com subpastas
- ✅ **CSV Avançado**: Exportação de artigos e prompts
- ✅ **Progresso em Tempo Real**: SSE (Server-Sent Events)
- ✅ **Status Persistente**: Banco SQLite com trace_id único

### **🔒 Segurança e Monitoramento**
- ✅ **Autenticação JWT**: Tokens com expiração automática
- ✅ **Rate Limiting**: Proteção contra abuso
- ✅ **Logs Estruturados**: JSON com tracing completo
- ✅ **Métricas Prometheus**: Exposição automática em `/metrics`
- ✅ **Circuit Breaker**: Resiliência para APIs externas

---

## 🏗️ **ARQUITETURA**

### **Clean Architecture (Hexagonal)**
```
┌─────────────────────────────────────────────────────────────┐
│                    OMNI WRITER ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────┤
│  🌐 Interface Layer (Flask/FastAPI + React)                │
│  ├── Controllers, Routes, Middleware                       │
│  └── UI Components, Hooks, Context                         │
├─────────────────────────────────────────────────────────────┤
│  🧠 Application Layer (Services, Use Cases)                │
│  ├── Article Generation, Content Management                │
│  ├── Authentication, Authorization                         │
│  └── Export, Feedback, Monitoring                          │
├─────────────────────────────────────────────────────────────┤
│  🎯 Domain Layer (Business Logic)                          │
│  ├── Entities, Value Objects, Domain Services              │
│  ├── Commands, Queries, Event Handlers                     │
│  └── Business Rules, Validation                            │
├─────────────────────────────────────────────────────────────┤
│  🔧 Infrastructure Layer (External Dependencies)           │
│  ├── Database (PostgreSQL/SQLite), Cache (Redis)          │
│  ├── External APIs (OpenAI, DeepSeek, Stripe)             │
│  ├── Message Queue (Celery + Redis)                        │
│  └── Monitoring (Prometheus, Sentry, Grafana)              │
└─────────────────────────────────────────────────────────────┘
```

### **Camadas Principais**
- **Domain**: Regras de negócio puras, sem dependências externas
- **Application**: Orquestração de casos de uso e serviços
- **Infrastructure**: Implementações concretas (APIs, banco, cache)
- **Interface**: Controllers, rotas e componentes UI

---

## 📦 **INSTALAÇÃO**

### **Pré-requisitos**
- **Python**: 3.10+
- **Node.js**: 18+
- **PostgreSQL**: 12+ (opcional, SQLite por padrão)
- **Redis**: 6+ (para cache e filas)

### **Instalação Rápida**

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

### **Instalação por Ambiente**

```bash
# Desenvolvimento completo
pip install -e .[dev,test,ml]

# Apenas produção
pip install -r requirements_prod.txt

# Apenas testes
pip install -r requirements_test.txt

# Apenas Machine Learning
pip install -r requirements_ml.txt
```

### **Configuração do .env**
```bash
# APIs Externas
OPENAI_API_KEY=sk-your-openai-key
DEEPSEEK_API_KEY=your-deepseek-key
STRIPE_SECRET_KEY=sk_test_...

# Banco de Dados
DATABASE_URL=sqlite:///omni_writer.db
# ou PostgreSQL: postgresql://user:pass@localhost:5432/omni_writer

# Cache e Filas
REDIS_URL=redis://localhost:6379

# Segurança
FLASK_SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret

# Monitoramento
SENTRY_DSN=https://your-sentry-dsn
PROMETHEUS_ENABLED=true

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

---

## ▶️ **EXECUÇÃO**

### **Desenvolvimento Local**

```bash
# Backend (Flask)
python app/main.py

# Frontend (React)
npm run dev

# Worker Celery (opcional)
celery -A app.celery_worker worker --loglevel=info

# Monitor Celery (opcional)
celery -A app.celery_worker flower
```

### **Produção com Docker**

```bash
# Build e execução
docker-compose up --build

# Apenas backend
docker-compose up backend

# Apenas frontend
docker-compose up frontend
```

### **Acesso**
- **Interface Web**: [http://localhost:5000](http://localhost:5000)
- **API Docs**: [http://localhost:5000/docs](http://localhost:5000/docs)
- **Métricas**: [http://localhost:5000/metrics](http://localhost:5000/metrics)
- **Flower**: [http://localhost:5555](http://localhost:5555)

---

## 🧪 **TESTES**

### **Execução de Testes**

```bash
# Testes Python (unitários, integração)
pytest --cov=. --cov-report=html

# Testes de carga
locust -f tests/load/locustfile_generate.py

# Testes E2E (Playwright)
npm run test:e2e

# Testes de mutação
mutmut run

# Testes de segurança
bandit -r .
safety check
```

### **Cobertura de Testes**
- **Unitários**: 98%+ cobertura
- **Integração**: APIs, banco, cache
- **E2E**: Fluxos completos de usuário
- **Carga**: Performance e escalabilidade
- **Segurança**: Vulnerabilidades e penetração

### **Relatórios**
- **Cobertura HTML**: `coverage/lcov-report/index.html`
- **Testes E2E**: `test-results/html-report/`
- **Performance**: `tests/load/results/`

---

## 🔧 **CONFIGURAÇÃO AVANÇADA**

### **Machine Learning**
```bash
# Instalar dependências ML
pip install -r requirements_ml.txt

# Configurar NLTK
python -c "
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
nltk.download('averaged_perceptron_tagger')
"
```

### **Monitoramento**
```bash
# Prometheus (métricas)
curl http://localhost:5000/metrics

# Grafana (dashboards)
# Importe os dashboards de monitoring/grafana/dashboards/

# Sentry (erros)
# Configure SENTRY_DSN no .env
```

### **Segurança**
```bash
# Rotação de tokens
curl -X POST -d "user_id=usuario1" http://localhost:5000/token/rotate

# Verificação de segurança
bandit -r . -f json -o security-report.json
safety check --json --output security-vulns.json
```

---

## 📊 **MÉTRICAS E MONITORAMENTO**

### **Métricas Disponíveis**
- **Geração**: Artigos gerados, tempo médio, taxa de sucesso
- **APIs**: Latência, erros, rate limits
- **Sistema**: CPU, memória, disco, rede
- **Usuários**: Sessões ativas, operações por usuário

### **Dashboards**
- **Operacional**: Status de serviços e saúde do sistema
- **Performance**: Latência e throughput das APIs
- **Negócio**: Artigos gerados, uso por usuário
- **Segurança**: Tentativas de acesso, erros de autenticação

---

## 🔒 **SEGURANÇA**

### **Autenticação e Autorização**
- **JWT Tokens**: Com expiração automática (7 dias)
- **Rate Limiting**: Proteção contra abuso
- **CSRF Protection**: Tokens CSRF em formulários
- **Input Validation**: Sanitização e validação rigorosa

### **Dados Sensíveis**
- **Chaves de API**: Nunca salvas em disco
- **Senhas**: Hash bcrypt com salt
- **Logs**: Dados sensíveis mascarados
- **Comunicação**: HTTPS obrigatório em produção

### **Auditoria**
- **Logs Estruturados**: JSON com contexto completo
- **Tracing**: ID único para cada operação
- **Audit Trail**: Todas as ações rastreáveis
- **Compliance**: LGPD e GDPR ready

---

## 📚 **DOCUMENTAÇÃO**

### **Documentação Técnica**
- [📖 Arquitetura e Design](docs/architecture.md)
- [🔧 Guia de Desenvolvimento](docs/development_guide.md)
- [📦 Dependências](README_DEPENDENCIES.md)
- [🧪 Guia de Testes](docs/testing_guide.md)

### **APIs e Integração**
- [🌐 API Reference](docs/api_reference.md)
- [🔌 Webhooks](docs/webhooks.md)
- [📊 Métricas](docs/metrics.md)

### **Operações**
- [🚀 Deploy](docs/deployment.md)
- [📊 Monitoramento](docs/monitoring.md)
- [🔒 Segurança](docs/security.md)

---

## 🤝 **CONTRIBUIÇÃO**

### **Padrões de Desenvolvimento**
- **Clean Architecture**: Separação clara de responsabilidades
- **TDD/BDD**: Testes primeiro, código depois
- **Documentação**: Tudo documentado e rastreável
- **Logs Estruturados**: Contexto completo em todas as operações

### **Processo de Contribuição**
1. **Fork** o repositório
2. **Crie** uma branch para sua feature
3. **Desenvolva** seguindo os padrões
4. **Teste** completamente (unit, integration, e2e)
5. **Documente** suas mudanças
6. **Submeta** um Pull Request

### **Checklist de Qualidade**
- [ ] Código segue padrões PEP-8/ESLint
- [ ] Testes passando com cobertura >95%
- [ ] Documentação atualizada
- [ ] Logs estruturados implementados
- [ ] Métricas adicionadas se necessário

---

## 📈 **ROADMAP**

### **Versão 2.0 (Q2 2025)**
- [ ] **Multi-tenancy**: Suporte a múltiplos clientes
- [ ] **Templates Avançados**: Editor visual de prompts
- [ ] **Analytics**: Dashboard de insights e métricas
- [ ] **Integrações**: WordPress, Medium, LinkedIn

### **Versão 2.1 (Q3 2025)**
- [ ] **IA Avançada**: Fine-tuning de modelos
- [ ] **Colaboração**: Workflow em equipe
- [ ] **Versionamento**: Controle de versão de artigos
- [ ] **API GraphQL**: Query language avançada

### **Versão 2.2 (Q4 2025)**
- [ ] **Mobile App**: Aplicativo nativo iOS/Android
- [ ] **Real-time**: Colaboração em tempo real
- [ ] **Marketplace**: Templates e modelos compartilhados
- [ ] **Enterprise**: SSO, LDAP, auditoria avançada

---

## 📞 **SUPORTE**

### **Canais de Ajuda**
- **📧 Email**: support@omniwriter.com
- **💬 Discord**: [Omni Writer Community](https://discord.gg/omniwriter)
- **🐛 Issues**: [GitHub Issues](https://github.com/omniwriter/omniwriter/issues)
- **📖 Docs**: [Documentação Completa](https://docs.omniwriter.com)

### **Comunidade**
- **🌟 Stars**: Se o projeto te ajudou, considere dar uma estrela
- **🔄 Forks**: Contribua com melhorias
- **💡 Ideas**: Compartilhe ideias e sugestões
- **🐛 Bugs**: Reporte bugs com detalhes

---

## 📄 **LICENÇA**

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🙏 **AGRADECIMENTOS**

- **OpenAI** e **DeepSeek** pelos modelos de IA
- **Flask** e **React** pelas tecnologias base
- **Comunidade Open Source** pelas contribuições
- **Usuários** pelo feedback e suporte

---

**Tracing ID**: README_UPDATE_20250127_001  
**Versão**: 2.0.0  
**Data**: 2025-01-27  
**Status**: ✅ **ATUALIZADO**