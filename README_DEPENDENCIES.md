# 📦 **DEPENDÊNCIAS DO OMNI WRITER**

## 📋 **VISÃO GERAL**

Este documento descreve todas as dependências do sistema Omni Writer, organizadas por categoria e com instruções de instalação.

---

## 🎯 **ARQUIVOS DE DEPENDÊNCIAS**

### **Arquivos Principais**
- `requirements.txt` - Dependências principais com extras opcionais
- `requirements_prod.txt` - Dependências para produção
- `requirements_dev.txt` - Dependências para desenvolvimento
- `requirements_test.txt` - Dependências para testes
- `requirements_ml.txt` - Dependências específicas de Machine Learning

---

## 🚀 **INSTALAÇÃO RÁPIDA**

### **Instalação Completa**
```bash
# Instalar todas as dependências principais
pip install -r requirements.txt

# Instalar dependências de desenvolvimento
pip install -r requirements_dev.txt

# Instalar dependências de testes
pip install -r requirements_test.txt

# Instalar dependências de ML
pip install -r requirements_ml.txt
```

### **Instalação por Ambiente**

#### **Desenvolvimento**
```bash
pip install -e .[dev,test,ml]
```

#### **Produção**
```bash
pip install -r requirements_prod.txt
```

#### **Testes**
```bash
pip install -r requirements_test.txt
```

---

## 📊 **CATEGORIAS DE DEPENDÊNCIAS**

### **🔧 Core Frameworks**
- **Flask** - Framework web principal
- **Flask-WTF** - Formulários web
- **Flask-Limiter** - Rate limiting
- **Flask-RESTX** - APIs REST
- **Werkzeug** - Utilitários WSGI

### **🗄️ Banco de Dados**
- **SQLAlchemy** - ORM principal
- **SQLModel** - ORM moderno
- **Alembic** - Migrações
- **PostgreSQL** - Banco principal
- **Redis** - Cache e sessões

### **⚡ Tarefas Assíncronas**
- **Celery** - Worker de tarefas
- **APScheduler** - Agendamento
- **Kombu** - Mensageria
- **Billiard** - Multiprocessing

### **🔒 Segurança**
- **Cryptography** - Criptografia
- **Bcrypt** - Hash de senhas
- **Passlib** - Gerenciamento de senhas
- **Python-Jose** - JWT
- **Bleach** - Sanitização HTML

### **📊 Monitoramento**
- **Prometheus** - Métricas
- **Structlog** - Logging estruturado
- **PSUtil** - Monitoramento de sistema

### **🤖 Machine Learning**
- **Scikit-learn** - ML básico
- **NumPy** - Computação numérica
- **Pandas** - Manipulação de dados
- **Sentence-Transformers** - Embeddings
- **NLTK** - Processamento de linguagem

### **🧪 Testes**
- **Pytest** - Framework de testes
- **Locust** - Testes de carga
- **Selenium** - Testes visuais
- **Mutmut** - Testes de mutação

---

## 🔧 **CONFIGURAÇÃO ESPECÍFICA**

### **Machine Learning**
```bash
# Instalar dependências ML básicas
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

### **Testes E2E (Node.js)**
```bash
# Instalar dependências Node.js
npm install

# Instalar Playwright
npx playwright install --with-deps
```

### **Desenvolvimento**
```bash
# Configurar pre-commit hooks
pre-commit install

# Configurar ambiente de desenvolvimento
pip install -e .[dev]
```

---

## 📈 **MÉTRICAS DE DEPENDÊNCIAS**

### **Estatísticas**
- **Total de Dependências Python**: ~80
- **Dependências Críticas**: 25
- **Dependências de Segurança**: 8
- **Dependências de ML**: 12
- **Dependências de Testes**: 20

### **Distribuição por Camada**
```
┌─────────────────────────────────────────────────────────────┐
│                    DEPENDÊNCIAS POR CAMADA                  │
├─────────────────────────────────────────────────────────────┤
│ Interface Layer: 25% (20 dependências)                      │
│ Application Layer: 20% (16 dependências)                    │
│ Domain Layer: 5% (4 dependências)                           │
│ Infrastructure Layer: 35% (28 dependências)                 │
│ Shared/Utilities: 15% (12 dependências)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔍 **VERIFICAÇÃO DE INSTALAÇÃO**

### **Verificação Básica**
```bash
python -c "
import flask, sqlalchemy, celery, redis
print('✅ Core dependencies OK')
"
```

### **Verificação ML**
```bash
python -c "
import sklearn, numpy, pandas, sentence_transformers, nltk
print('✅ ML dependencies OK')
"
```

### **Verificação Testes**
```bash
python -c "
import pytest, locust, selenium
print('✅ Test dependencies OK')
"
```

---

## 🚨 **DEPENDÊNCIAS CRÍTICAS**

### **Segurança**
- `cryptography>=44.0.2` - Criptografia
- `bcrypt>=4.3.0` - Hash de senhas
- `python-jose>=3.4.0` - JWT

### **Performance**
- `redis>=4.0.0` - Cache
- `celery[redis]>=5.3.6` - Tarefas assíncronas
- `gunicorn>=21.0.0` - WSGI server

### **Monitoramento**
- `prometheus-client>=0.17.0` - Métricas
- `structlog>=23.1.0` - Logging
- `psutil>=5.9.0` - Sistema

---

## 🔄 **ATUALIZAÇÃO DE DEPENDÊNCIAS**

### **Verificar Atualizações**
```bash
# Verificar dependências desatualizadas
pip list --outdated

# Verificar vulnerabilidades
safety check
```

### **Atualizar Dependências**
```bash
# Atualizar dependências específicas
pip install --upgrade package_name

# Atualizar todas as dependências
pip install --upgrade -r requirements.txt
```

---

## 📝 **NOTAS IMPORTANTES**

### **Compatibilidade**
- **Python**: >= 3.10
- **Node.js**: >= 18.0.0 (para testes E2E)
- **PostgreSQL**: >= 12.0
- **Redis**: >= 6.0

### **Sistema Operacional**
- **Windows**: Suporte completo
- **Linux**: Suporte completo
- **macOS**: Suporte completo

### **GPU Support**
Para aceleração GPU em ML, descomente no `requirements_ml.txt`:
```bash
# torch>=2.0.0
# torchvision>=0.15.0
```

---

## 🆘 **TROUBLESHOOTING**

### **Problemas Comuns**

#### **Erro de Compilação no Windows**
```bash
# Instalar Visual C++ Build Tools
# Ou usar wheels pré-compilados
pip install --only-binary=all package_name
```

#### **Erro de Dependências ML**
```bash
# Verificar se scikit-learn está instalado
pip install scikit-learn

# Verificar se NLTK está configurado
python -c "import nltk; nltk.download('punkt')"
```

#### **Erro de Redis**
```bash
# Verificar se Redis está rodando
redis-cli ping

# Ou usar Redis em memória para testes
pip install fakeredis
```

---

## 📚 **REFERÊNCIAS**

- [Documentação Flask](https://flask.palletsprojects.com/)
- [Documentação SQLAlchemy](https://docs.sqlalchemy.org/)
- [Documentação Celery](https://docs.celeryproject.org/)
- [Documentação Scikit-learn](https://scikit-learn.org/)
- [Documentação Pytest](https://docs.pytest.org/)

---

**Tracing ID**: DEPS_DOC_20250127_001  
**Versão**: 1.0.0  
**Data**: 2025-01-27 