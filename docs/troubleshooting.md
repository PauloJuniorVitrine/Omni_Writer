# 🔧 Troubleshooting - Omni Writer

**Versão:** 1.0.0  
**Data:** 2025-01-27  
**Tracing ID:** ENTERPRISE_20250127_009  

## 📋 Índice

1. [Problemas de Instalação](#problemas-de-instalação)
2. [Problemas de Configuração](#problemas-de-configuração)
3. [Problemas de API](#problemas-de-api)
4. [Problemas de Banco de Dados](#problemas-de-banco-de-dados)
5. [Problemas de Cache](#problemas-de-cache)
6. [Problemas de Testes](#problemas-de-testes)
7. [Problemas de Performance](#problemas-de-performance)
8. [Problemas de Segurança](#problemas-de-segurança)
9. [Problemas de Deploy](#problemas-de-deploy)
10. [Logs e Debugging](#logs-e-debugging)

---

## 🚀 Problemas de Instalação

### Erro: ModuleNotFoundError

#### Sintoma
```bash
ModuleNotFoundError: No module named 'omni_writer'
```

#### Causas Possíveis
1. PYTHONPATH não configurado
2. Virtual environment não ativado
3. Dependências não instaladas

#### Soluções

**1. Configure PYTHONPATH**
```bash
# Linux/Mac
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Windows (PowerShell)
$env:PYTHONPATH = "$env:PYTHONPATH;$(Get-Location)"

# Windows (CMD)
set PYTHONPATH=%PYTHONPATH%;%CD%
```

**2. Ative o Virtual Environment**
```bash
# Linux/Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```

**3. Reinstale Dependências**
```bash
pip uninstall -r requirements.txt -y
pip install -r requirements.txt
```

### Erro: Node.js Dependencies

#### Sintoma
```bash
npm ERR! code ENOENT
npm ERR! syscall open
npm ERR! path package.json
```

#### Solução
```bash
# Verifique se está no diretório correto
pwd
ls package.json

# Se não existir, clone novamente
git clone https://github.com/omniwriter/omniwriter.git
cd omni_writer
npm install
```

---

## ⚙️ Problemas de Configuração

### Erro: Environment Variables

#### Sintoma
```bash
KeyError: 'OPENAI_API_KEY'
```

#### Solução
```bash
# 1. Copie o arquivo de exemplo
cp .env.example .env

# 2. Configure as variáveis
nano .env

# 3. Verifique se as variáveis estão sendo carregadas
python -c "import os; print(os.getenv('OPENAI_API_KEY'))"
```

#### Variáveis Obrigatórias
```bash
# API Keys
OPENAI_API_KEY=sk-your-openai-key
DEEPSEEK_API_KEY=your-deepseek-key

# Flask
FLASK_SECRET_KEY=your-secret-key
FLASK_ENV=development

# Database
DATABASE_URL=sqlite:///omni_writer.db

# Cache
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Erro: Configuração de Logging

#### Sintoma
```bash
PermissionError: [Errno 13] Permission denied: 'logs/'
```

#### Solução
```bash
# Crie o diretório de logs
mkdir -p logs
chmod 755 logs

# Ou configure logging para stdout
export LOG_TO_FILE=false
```

---

## 🔌 Problemas de API

### Erro: Rate Limiting

#### Sintoma
```bash
HTTP 429 Too Many Requests
X-RateLimit-Remaining: 0
```

#### Soluções

**1. Implemente Retry com Backoff**
```python
import time
import random
from functools import wraps

def retry_with_backoff(max_retries=3, base_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if "429" in str(e) and attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        time.sleep(delay)
                        continue
                    raise
            return func(*args, **kwargs)
        return wrapper
    return decorator

@retry_with_backoff(max_retries=3)
def api_call():
    # Sua chamada de API aqui
    pass
```

**2. Use Pool de API Keys**
```python
class ApiKeyPool:
    def __init__(self, keys):
        self.keys = keys
        self.current_index = 0
    
    def get_next_key(self):
        key = self.keys[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.keys)
        return key
```

### Erro: Timeout

#### Sintoma
```bash
requests.exceptions.Timeout: HTTPConnectionPool
```

#### Solução
```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("http://", adapter)
session.mount("https://", adapter)

# Use com timeout
response = session.get(url, timeout=(5, 30))  # (connect, read)
```

### Erro: Autenticação

#### Sintoma
```bash
HTTP 401 Unauthorized
{"error": "Invalid API key"}
```

#### Soluções

**1. Verifique a API Key**
```python
def validate_api_key(api_key):
    if not api_key or len(api_key) < 10:
        raise ValueError("API key inválida")
    
    # Teste a API key
    try:
        response = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        if response.status_code == 401:
            raise ValueError("API key inválida ou expirada")
    except Exception as e:
        raise ValueError(f"Erro ao validar API key: {e}")
```

**2. Implemente Rotação de Tokens**
```python
class TokenManager:
    def __init__(self):
        self.tokens = []
        self.current_token = None
    
    def add_token(self, token):
        self.tokens.append(token)
        if not self.current_token:
            self.current_token = token
    
    def rotate_token(self):
        if len(self.tokens) > 1:
            current_index = self.tokens.index(self.current_token)
            next_index = (current_index + 1) % len(self.tokens)
            self.current_token = self.tokens[next_index]
        return self.current_token
```

---

## 🗄️ Problemas de Banco de Dados

### Erro: Database Locked

#### Sintoma
```bash
sqlite3.OperationalError: database is locked
```

#### Soluções

**1. Verifique Conexões**
```python
import sqlite3
import threading

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.Lock()
    
    def get_connection(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=20.0)
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
```

**2. Use WAL Mode**
```python
def setup_database(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.close()
```

### Erro: Migration Failed

#### Sintoma
```bash
alembic.util.exc.CommandError: Can't locate revision identified by 'abc123'
```

#### Solução
```bash
# 1. Verifique o histórico de migrations
alembic history

# 2. Marque como revisado
alembic stamp head

# 3. Ou recrie o banco
rm omni_writer.db
alembic upgrade head
```

---

## 🗂️ Problemas de Cache

### Erro: Redis Connection

#### Sintoma
```bash
redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379
```

#### Soluções

**1. Inicie o Redis**
```bash
# Linux/Mac
redis-server

# Docker
docker run -d -p 6379:6379 redis:alpine

# Windows (WSL)
wsl redis-server
```

**2. Use Cache Local como Fallback**
```python
import os
from shared.intelligent_cache import IntelligentCache

def get_cache():
    if os.getenv('USE_LOCAL_CACHE', 'false').lower() == 'true':
        return IntelligentCache(strategy='local')
    else:
        return IntelligentCache(strategy='redis')
```

### Erro: Cache Miss Rate Alto

#### Sintoma
```
Cache miss rate: 85% (esperado: <30%)
```

#### Soluções

**1. Implemente Cache Warming**
```python
def warm_cache():
    """Preenche cache com dados frequentes."""
    cache = get_cache()
    
    # Dados frequentes
    frequent_prompts = [
        "Como criar um blog",
        "Dicas de SEO",
        "Marketing digital"
    ]
    
    for prompt in frequent_prompts:
        if not cache.get(f"prompt:{prompt}"):
            # Gera e armazena
            result = generate_article(prompt)
            cache.set(f"prompt:{prompt}", result, ttl=3600)
```

**2. Ajuste TTL**
```python
# Para dados que mudam pouco
cache.set(key, value, ttl=86400)  # 24 horas

# Para dados que mudam frequentemente
cache.set(key, value, ttl=300)    # 5 minutos
```

---

## 🧪 Problemas de Testes

### Erro: Testes Não Encontrados

#### Sintoma
```bash
pytest: no tests ran
```

#### Solução
```bash
# 1. Verifique estrutura de diretórios
find . -name "test_*.py" -o -name "*_test.py"

# 2. Execute com verbose
pytest -v

# 3. Execute testes específicos
pytest tests/unit/domain/test_article_generator.py -v
```

### Erro: Cobertura Baixa

#### Sintoma
```bash
Coverage: 45% (mínimo: 98%)
```

#### Solução
```bash
# 1. Identifique código não coberto
pytest --cov=. --cov-report=html

# 2. Abra o relatório
open htmlcov/index.html

# 3. Adicione testes para funções não cobertas
```

### Erro: Testes Lentos

#### Sintoma
```bash
test_generation_pipeline: 45.2s
```

#### Soluções

**1. Use Mocks para APIs Externas**
```python
@patch('domain.services.article_generator.openai_client')
def test_generation_fast(mock_client):
    mock_client.generate.return_value = "Artigo mock"
    # Teste rápido sem chamadas reais
```

**2. Configure Timeouts**
```python
@pytest.mark.timeout(5)  # 5 segundos máximo
def test_fast_function():
    # Teste que deve ser rápido
    pass
```

---

## ⚡ Problemas de Performance

### Erro: Geração Lenta

#### Sintoma
```
Geração de 10 artigos: 45 minutos (esperado: 15 minutos)
```

#### Soluções

**1. Implemente Paralelismo**
```python
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

async def generate_articles_parallel(prompts, max_workers=3):
    semaphore = asyncio.Semaphore(max_workers)
    
    async def generate_single(prompt):
        async with semaphore:
            return await generate_article(prompt)
    
    tasks = [generate_single(prompt) for prompt in prompts]
    return await asyncio.gather(*tasks)
```

**2. Use Cache Inteligente**
```python
from shared.intelligent_cache import IntelligentCache

cache = IntelligentCache(strategy='redis')

def generate_with_cache(prompt):
    cache_key = f"article:{hash(prompt)}"
    
    # Tenta cache primeiro
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    # Gera se não estiver em cache
    result = generate_article(prompt)
    cache.set(cache_key, result, ttl=3600)
    return result
```

### Erro: Memory Leak

#### Sintoma
```
Memory usage: 2.5GB (esperado: <500MB)
```

#### Solução
```python
import gc
import psutil
import tracemalloc

def monitor_memory():
    """Monitora uso de memória."""
    process = psutil.Process()
    memory_info = process.memory_info()
    
    if memory_info.rss > 500 * 1024 * 1024:  # 500MB
        gc.collect()
        tracemalloc.start()
        
        # Log memory usage
        logger.warning(f"Memory usage high: {memory_info.rss / 1024 / 1024:.2f}MB")
```

---

## 🔒 Problemas de Segurança

### Erro: SQL Injection

#### Sintoma
```
Database error: syntax error near "DROP"
```

#### Solução
```python
# ❌ Incorreto
query = f"SELECT * FROM articles WHERE title = '{user_input}'"

# ✅ Correto
query = "SELECT * FROM articles WHERE title = ?"
cursor.execute(query, (user_input,))
```

### Erro: XSS

#### Sintoma
```
<script>alert('XSS')</script> aparece no output
```

#### Solução
```python
import html

def sanitize_output(content):
    """Sanitiza output para prevenir XSS."""
    return html.escape(content)

# Use em todas as saídas
safe_content = sanitize_output(user_content)
```

### Erro: Rate Limiting Bypass

#### Sintoma
```
Múltiplas requisições simultâneas passam pelo rate limit
```

#### Solução
```python
import time
from collections import defaultdict
import threading

class RateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, client_id):
        with self.lock:
            now = time.time()
            client_requests = self.requests[client_id]
            
            # Remove requests antigas
            client_requests[:] = [req for req in client_requests 
                                if now - req < self.window_seconds]
            
            if len(client_requests) >= self.max_requests:
                return False
            
            client_requests.append(now)
            return True
```

---

## 🚀 Problemas de Deploy

### Erro: Port Already in Use

#### Sintoma
```bash
OSError: [Errno 98] Address already in use
```

#### Solução
```bash
# 1. Encontre o processo
lsof -i :5000

# 2. Mate o processo
kill -9 <PID>

# 3. Ou use porta diferente
export FLASK_RUN_PORT=5001
flask run
```

### Erro: Permission Denied

#### Sintoma
```bash
PermissionError: [Errno 13] Permission denied
```

#### Solução
```bash
# 1. Verifique permissões
ls -la

# 2. Ajuste permissões
chmod 755 .
chmod 644 *.py
chmod 755 logs/

# 3. Execute como usuário correto
sudo -u www-data python app.py
```

### Erro: Environment Variables Missing

#### Sintoma
```bash
KeyError: 'DATABASE_URL'
```

#### Solução
```bash
# 1. Configure variáveis no sistema
export DATABASE_URL="sqlite:///omni_writer.db"
export FLASK_ENV="production"

# 2. Ou use arquivo .env
echo "DATABASE_URL=sqlite:///omni_writer.db" >> .env
echo "FLASK_ENV=production" >> .env

# 3. Ou configure no sistema
sudo nano /etc/environment
```

---

## 📊 Logs e Debugging

### Configuração de Logs Detalhados

```python
import logging
from shared.logger import get_structured_logger

# Configure logging detalhado
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = get_structured_logger(__name__)

def debug_function():
    logger.debug("Iniciando função", extra={
        'function': 'debug_function',
        'params': {'param1': 'value1'},
        'trace_id': 'debug_123'
    })
    
    try:
        # Código da função
        result = process_data()
        logger.info("Função executada com sucesso", extra={
            'result': result,
            'duration': 1.5,
            'trace_id': 'debug_123'
        })
    except Exception as e:
        logger.error("Erro na função", extra={
            'error': str(e),
            'traceback': traceback.format_exc(),
            'trace_id': 'debug_123'
        })
        raise
```

### Debugging com pdb

```python
import pdb
import traceback

def complex_function():
    try:
        # Código da função
        pdb.set_trace()  # Breakpoint
        # Mais código
    except Exception as e:
        print(f"Erro: {e}")
        traceback.print_exc()
        pdb.post_mortem()
```

### Monitoramento de Performance

```python
import time
import functools
from shared.logger import get_structured_logger

logger = get_structured_logger(__name__)

def monitor_performance(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            logger.info("Função executada", extra={
                'function': func.__name__,
                'duration': duration,
                'success': True
            })
            
            return result
        except Exception as e:
            duration = time.time() - start_time
            
            logger.error("Erro na função", extra={
                'function': func.__name__,
                'duration': duration,
                'error': str(e),
                'success': False
            })
            raise
    
    return wrapper

@monitor_performance
def slow_function():
    time.sleep(2)
    return "result"
```

---

## 📞 Suporte Adicional

### Recursos Úteis
- [Documentação da API](./api_reference.md)
- [Guia de Desenvolvimento](./development_guide.md)
- [Changelog](../CHANGELOG.md)
- [Issues do GitHub](https://github.com/omniwriter/omniwriter/issues)

### Comandos Úteis

```bash
# Verificar status do sistema
python -c "from app.app_factory import create_app; app = create_app(); print('App OK')"

# Verificar conectividade
curl -X GET http://localhost:5000/health

# Verificar logs
tail -f logs/app.log

# Verificar métricas
curl -X GET http://localhost:5000/metrics

# Verificar cache
redis-cli ping

# Verificar banco
sqlite3 omni_writer.db ".tables"
```

### Contato
- **Email:** support@omniwriter.com
- **Slack:** #omni-writer-support
- **Documentação:** [docs.omniwriter.com](https://docs.omniwriter.com)

---

*Guia atualizado em 2025-01-27T20:00:00Z* 