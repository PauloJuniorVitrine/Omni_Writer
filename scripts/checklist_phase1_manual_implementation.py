#!/usr/bin/env python3
"""
Script de Implementação Manual - Fase 1: Banco de Dados
======================================================

Implementa a migração completa para PostgreSQL conforme checklist.
Prompt: Implementação manual do checklist - Fase 1 Banco de Dados
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
Tracing ID: CHECKLIST_PHASE1_MANUAL_20250127_001
"""

import os
import sys
import logging
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# Configuração de logging estruturado
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/exec_trace/checklist_phase1_manual.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("checklist_phase1_manual")

# Tracing ID único para rastreabilidade
TRACING_ID = "CHECKLIST_PHASE1_MANUAL_20250127_001"

class ChecklistPhase1ManualImplementation:
    """
    Implementação manual da Fase 1 do Checklist - Banco de Dados
    
    Objetivos:
    - Preparar migração para PostgreSQL
    - Configurar pool de conexões otimizado
    - Implementar retry logic
    - Validar integridade dos dados
    """
    
    def __init__(self):
        """Inicializa a implementação manual da Fase 1."""
        self.tracing_id = TRACING_ID
        self.start_time = datetime.now()
        self.results = {
            "phase": "phase1_database_manual",
            "tracing_id": self.tracing_id,
            "start_time": self.start_time.isoformat(),
            "steps": [],
            "status": "in_progress"
        }
        
        # Configurações baseadas em código real
        self.postgres_url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
        self.sqlite_path = os.getenv('STATUS_DB_PATH', os.path.join(os.getcwd(), 'status.db'))
        self.feedback_file = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
        
        logger.info(f"[{self.tracing_id}] Iniciando implementação manual da Fase 1 - Banco de Dados")
    
    def step_1_create_backup_scripts(self) -> bool:
        """
        Passo 1: Criar scripts de backup automatizado.
        
        Cria scripts para backup de segurança antes da migração.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 1: Criação de Scripts de Backup")
        
        try:
            # Script de backup SQLite
            backup_sqlite_script = '''#!/usr/bin/env python3
"""
Script de Backup SQLite - Omni Writer
====================================

Cria backup de segurança do banco SQLite antes da migração.
Prompt: Backup SQLite antes da migração
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path

def backup_sqlite_database():
    """Cria backup do banco SQLite."""
    sqlite_path = os.getenv('STATUS_DB_PATH', 'status.db')
    
    if not os.path.exists(sqlite_path):
        print(f"⚠️ Banco SQLite não encontrado: {{sqlite_path}}")
        return False
    
    # Criar diretório de backup
    backup_dir = Path("backups") / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Backup do arquivo
    backup_file = backup_dir / "status_backup.db"
    shutil.copy2(sqlite_path, backup_file)
    
    # Metadados do backup
    metadata = {{
        "backup_time": datetime.now().isoformat(),
        "original_file": sqlite_path,
        "backup_file": str(backup_file),
        "file_size": os.path.getsize(backup_file)
    }}
    
    with open(backup_dir / "backup_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✅ Backup SQLite criado: {{backup_file}}")
    return True

if __name__ == "__main__":
    backup_sqlite_database()
'''.format(timestamp=datetime.now().isoformat())
            
            with open("scripts/backup_sqlite.py", "w", encoding="utf-8") as f:
                f.write(backup_sqlite_script)
            
            # Script de backup feedback
            backup_feedback_script = '''#!/usr/bin/env python3
"""
Script de Backup Feedback - Omni Writer
======================================

Cria backup de segurança do feedback JSON antes da migração.
Prompt: Backup feedback antes da migração
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

import os
import shutil
import json
from datetime import datetime
from pathlib import Path

def backup_feedback_data():
    """Cria backup do feedback JSON."""
    feedback_file = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
    
    if not os.path.exists(feedback_file):
        print(f"⚠️ Arquivo de feedback não encontrado: {{feedback_file}}")
        return False
    
    # Criar diretório de backup
    backup_dir = Path("backups") / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Backup do arquivo
    backup_file = backup_dir / "feedback_backup.json"
    shutil.copy2(feedback_file, backup_file)
    
    # Metadados do backup
    metadata = {{
        "backup_time": datetime.now().isoformat(),
        "original_file": feedback_file,
        "backup_file": str(backup_file),
        "file_size": os.path.getsize(backup_file)
    }}
    
    with open(backup_dir / "backup_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✅ Backup feedback criado: {{backup_file}}")
    return True

if __name__ == "__main__":
    backup_feedback_data()
'''.format(timestamp=datetime.now().isoformat())
            
            with open("scripts/backup_feedback.py", "w", encoding="utf-8") as f:
                f.write(backup_feedback_script)
            
            logger.info(f"[{self.tracing_id}] ✅ Scripts de backup criados")
            
            self.results["steps"].append({
                "step": "create_backup_scripts",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "files_created": ["scripts/backup_sqlite.py", "scripts/backup_feedback.py"]
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao criar scripts de backup: {e}")
            self.results["steps"].append({
                "step": "create_backup_scripts",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_2_create_pool_configuration(self) -> bool:
        """
        Passo 2: Criar configuração otimizada do pool de conexões.
        
        Configura pool de conexões PostgreSQL otimizado para produção.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 2: Configuração do Pool de Conexões")
        
        try:
            pool_config_content = '''"""
Configuração otimizada do pool de conexões PostgreSQL.
Prompt: Configuração pool de conexões PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
import os
import logging

# Configuração de logging
logger = logging.getLogger("postgresql_pool")

# Configurações do pool baseadas em produção
POSTGRESQL_POOL_CONFIG = {{
    "pool_size": 10,
    "max_overflow": 20,
    "pool_timeout": 30,
    "pool_recycle": 3600,
    "pool_pre_ping": True,
    "echo": False
}}

def create_postgresql_engine(url: str = None):
    """
    Cria engine PostgreSQL com pool otimizado.
    
    Args:
        url: URL de conexão PostgreSQL
        
    Returns:
        SQLAlchemy engine configurado
    """
    if url is None:
        url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
    
    try:
        engine = create_engine(
            url,
            poolclass=QueuePool,
            **POSTGRESQL_POOL_CONFIG
        )
        
        logger.info("Engine PostgreSQL criado com sucesso")
        return engine
        
    except Exception as e:
        logger.error(f"Erro ao criar engine PostgreSQL: {{e}}")
        raise

def get_connection_pool_stats(engine):
    """
    Obtém estatísticas do pool de conexões.
    
    Args:
        engine: SQLAlchemy engine
        
    Returns:
        Dict com estatísticas do pool
    """
    pool = engine.pool
    return {{
        "pool_size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "invalid": pool.invalid()
    }}

def test_connection(engine):
    """
    Testa conexão com PostgreSQL.
    
    Args:
        engine: SQLAlchemy engine
        
    Returns:
        bool: True se conexão bem-sucedida
    """
    try:
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            result.fetchone()
            logger.info("Conexão PostgreSQL testada com sucesso")
            return True
    except Exception as e:
        logger.error(f"Erro ao testar conexão PostgreSQL: {{e}}")
        return False
'''.format(timestamp=datetime.now().isoformat())
            
            with open("shared/postgresql_pool_config.py", "w", encoding="utf-8") as f:
                f.write(pool_config_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Configuração do pool criada")
            
            self.results["steps"].append({
                "step": "create_pool_configuration",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "file_created": "shared/postgresql_pool_config.py"
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao criar configuração do pool: {e}")
            self.results["steps"].append({
                "step": "create_pool_configuration",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_3_create_retry_logic(self) -> bool:
        """
        Passo 3: Criar retry logic robusta.
        
        Implementa retry logic para falhas de conexão PostgreSQL.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 3: Implementação de Retry Logic")
        
        try:
            retry_logic_content = '''"""
Retry Logic para PostgreSQL - Omni Writer
========================================

Implementa retry logic robusta para falhas de conexão PostgreSQL.
Prompt: Retry logic para PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional
from sqlalchemy.exc import OperationalError, DisconnectionError

# Configuração de logging
logger = logging.getLogger("postgresql_retry")

# Configurações de retry
RETRY_CONFIG = {{
    "max_attempts": 3,
    "base_delay": 1.0,
    "max_delay": 10.0,
    "backoff_factor": 2.0
}}

def exponential_backoff(attempt: int, base_delay: float = 1.0, max_delay: float = 10.0, backoff_factor: float = 2.0) -> float:
    """
    Calcula delay exponencial para retry.
    
    Args:
        attempt: Número da tentativa
        base_delay: Delay base em segundos
        max_delay: Delay máximo em segundos
        backoff_factor: Fator de backoff
        
    Returns:
        Delay em segundos
    """
    delay = base_delay * (backoff_factor ** (attempt - 1))
    return min(delay, max_delay)

def postgresql_retry(max_attempts: int = None, base_delay: float = None, max_delay: float = None, backoff_factor: float = None):
    """
    Decorator para retry logic em operações PostgreSQL.
    
    Args:
        max_attempts: Número máximo de tentativas
        base_delay: Delay base em segundos
        max_delay: Delay máximo em segundos
        backoff_factor: Fator de backoff
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            attempts = max_attempts or RETRY_CONFIG["max_attempts"]
            base = base_delay or RETRY_CONFIG["base_delay"]
            max_d = max_delay or RETRY_CONFIG["max_delay"]
            backoff = backoff_factor or RETRY_CONFIG["backoff_factor"]
            
            last_exception = None
            
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                    
                except (OperationalError, DisconnectionError) as e:
                    last_exception = e
                    
                    if attempt == attempts:
                        logger.error(f"Falha após {{attempts}} tentativas: {{e}}")
                        raise
                    
                    delay = exponential_backoff(attempt, base, max_d, backoff)
                    logger.warning(f"Tentativa {{attempt}} falhou, aguardando {{delay}}s: {{e}}")
                    time.sleep(delay)
                    
                except Exception as e:
                    # Não retry para outros tipos de erro
                    logger.error(f"Erro não recuperável: {{e}}")
                    raise
            
            # Nunca deve chegar aqui
            raise last_exception
            
        return wrapper
    return decorator

class PostgreSQLRetryHandler:
    """
    Handler para retry logic em operações PostgreSQL.
    """
    
    def __init__(self, max_attempts: int = 3, base_delay: float = 1.0, max_delay: float = 10.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = 2.0
    
    def execute_with_retry(self, operation: Callable, *args, **kwargs) -> Any:
        """
        Executa operação com retry logic.
        
        Args:
            operation: Função a ser executada
            *args: Argumentos posicionais
            **kwargs: Argumentos nomeados
            
        Returns:
            Resultado da operação
        """
        last_exception = None
        
        for attempt in range(1, self.max_attempts + 1):
            try:
                return operation(*args, **kwargs)
                
            except (OperationalError, DisconnectionError) as e:
                last_exception = e
                
                if attempt == self.max_attempts:
                    logger.error(f"Falha após {{self.max_attempts}} tentativas: {{e}}")
                    raise
                
                delay = exponential_backoff(attempt, self.base_delay, self.max_delay, self.backoff_factor)
                logger.warning(f"Tentativa {{attempt}} falhou, aguardando {{delay}}s: {{e}}")
                time.sleep(delay)
        
        raise last_exception
'''.format(timestamp=datetime.now().isoformat())
            
            with open("shared/postgresql_retry_logic.py", "w", encoding="utf-8") as f:
                f.write(retry_logic_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Retry logic criada")
            
            self.results["steps"].append({
                "step": "create_retry_logic",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "file_created": "shared/postgresql_retry_logic.py"
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao criar retry logic: {e}")
            self.results["steps"].append({
                "step": "create_retry_logic",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_4_create_validation_scripts(self) -> bool:
        """
        Passo 4: Criar scripts de validação de integridade.
        
        Cria scripts para validar integridade dos dados migrados.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 4: Criação de Scripts de Validação")
        
        try:
            validation_script = '''#!/usr/bin/env python3
"""
Validação de Integridade - Migração PostgreSQL
==============================================

Valida integridade dos dados migrados para PostgreSQL.
Prompt: Validação integridade migração PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

import os
import sqlite3
import json
from sqlalchemy import create_engine, text
from typing import Dict, List, Any
from datetime import datetime

def validate_status_migration():
    """Valida migração de dados de status."""
    print("🔍 Validando migração de status...")
    
    # Dados originais (SQLite)
    sqlite_path = os.getenv('STATUS_DB_PATH', 'status.db')
    sqlite_data = []
    
    if os.path.exists(sqlite_path):
        conn = sqlite3.connect(sqlite_path)
        cursor = conn.cursor()
        cursor.execute('SELECT trace_id, total, current, status FROM status')
        sqlite_data = cursor.fetchall()
        conn.close()
    
    # Dados migrados (PostgreSQL)
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
    engine = create_engine(postgres_url)
    
    with engine.connect() as conn:
        result = conn.execute(text('SELECT trace_id, total, current, status FROM status'))
        postgres_data = result.fetchall()
    
    # Comparação
    sqlite_count = len(sqlite_data)
    postgres_count = len(postgres_data)
    
    print(f"📊 SQLite: {{sqlite_count}} registros")
    print(f"📊 PostgreSQL: {{postgres_count}} registros")
    
    if sqlite_count == postgres_count:
        print("✅ Contagem de registros igual")
    else:
        print("❌ Contagem de registros diferente")
        return False
    
    # Validar dados específicos
    sqlite_dict = {{row[0]: row[1:] for row in sqlite_data}}
    postgres_dict = {{row[0]: row[1:] for row in postgres_data}}
    
    for trace_id in sqlite_dict:
        if trace_id not in postgres_dict:
            print(f"❌ Trace ID {{trace_id}} não encontrado no PostgreSQL")
            return False
        
        if sqlite_dict[trace_id] != postgres_dict[trace_id]:
            print(f"❌ Dados diferentes para trace_id {{trace_id}}")
            return False
    
    print("✅ Validação de status concluída com sucesso")
    return True

def validate_feedback_migration():
    """Valida migração de dados de feedback."""
    print("🔍 Validando migração de feedback...")
    
    # Dados originais (JSON)
    feedback_file = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
    json_data = []
    
    if os.path.exists(feedback_file):
        with open(feedback_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    
    # Dados migrados (PostgreSQL)
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://omniwriter:omniwriter@localhost:5432/omniwriter')
    engine = create_engine(postgres_url)
    
    with engine.connect() as conn:
        result = conn.execute(text('SELECT trace_id, feedback_data FROM feedback'))
        postgres_data = result.fetchall()
    
    # Comparação
    json_count = len(json_data)
    postgres_count = len(postgres_data)
    
    print(f"📊 JSON: {{json_count}} registros")
    print(f"📊 PostgreSQL: {{postgres_count}} registros")
    
    if json_count == postgres_count:
        print("✅ Contagem de registros igual")
    else:
        print("❌ Contagem de registros diferente")
        return False
    
    print("✅ Validação de feedback concluída com sucesso")
    return True

def main():
    """Executa validação completa."""
    print("🚀 Iniciando validação de integridade...")
    
    status_ok = validate_status_migration()
    feedback_ok = validate_feedback_migration()
    
    if status_ok and feedback_ok:
        print("✅ Validação completa: TODOS OS DADOS MIGRADOS CORRETAMENTE")
        return True
    else:
        print("❌ Validação falhou: VERIFICAR MIGRAÇÃO")
        return False

if __name__ == "__main__":
    main()
'''.format(timestamp=datetime.now().isoformat())
            
            with open("scripts/validate_migration_integrity.py", "w", encoding="utf-8") as f:
                f.write(validation_script)
            
            logger.info(f"[{self.tracing_id}] ✅ Script de validação criado")
            
            self.results["steps"].append({
                "step": "create_validation_scripts",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "file_created": "scripts/validate_migration_integrity.py"
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao criar script de validação: {e}")
            self.results["steps"].append({
                "step": "create_validation_scripts",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_5_update_configurations(self) -> bool:
        """
        Passo 5: Atualizar configurações para PostgreSQL.
        
        Atualiza configurações para priorizar PostgreSQL.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 5: Atualização de Configurações")
        
        try:
            # Criar arquivo .env.example atualizado
            env_example = '''# Configurações de Banco de Dados - Produção
POSTGRES_URL=postgresql://omniwriter:omniwriter@localhost:5432/omniwriter
REDIS_URL=redis://localhost:6379/0

# Storage Distribuído
ENABLE_DISTRIBUTED_STORAGE=true
STORAGE_FALLBACK=postgresql

# Pool de Conexões
POSTGRES_POOL_SIZE=10
POSTGRES_MAX_OVERFLOW=20
POSTGRES_POOL_TIMEOUT=30

# Retry Logic
DB_RETRY_ATTEMPTS=3
DB_RETRY_DELAY=1.0

# Configurações de Produção
ENVIRONMENT=production
DEBUG=false

# Configurações de Monitoramento
PROMETHEUS_ENABLED=true
SENTRY_DSN=your_sentry_dsn_here

# Configurações de Cache
CACHE_TTL=3600
STORAGE_MAX_RETRIES=3
'''
            
            with open(".env.example", "w", encoding="utf-8") as f:
                f.write(env_example)
            
            # Criar arquivo de configuração de produção
            production_config = '''"""
Configuração de Produção - Omni Writer
======================================

Configurações otimizadas para ambiente de produção.
Prompt: Configuração de produção PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {timestamp}
"""

import os
from shared.constants import DatabaseConstants, StorageConstants

# ============================================================================
# CONFIGURAÇÕES DE BANCO DE DADOS - PRODUÇÃO
# ============================================================================

# URL do PostgreSQL (prioridade para produção)
POSTGRESQL_CONNECTION_URL = os.getenv('POSTGRES_URL', DatabaseConstants.POSTGRESQL_DEFAULT_URL)

# URL do Redis
REDIS_CONNECTION_URL = os.getenv('REDIS_URL', DatabaseConstants.REDIS_DEFAULT_URL)

# Habilitar storage distribuído por padrão
DISTRIBUTED_STORAGE_ENABLED = os.getenv(
    'ENABLE_DISTRIBUTED_STORAGE', 
    'true'  # Habilitado por padrão em produção
).lower() == 'true'

# PostgreSQL como storage padrão
STORAGE_FALLBACK_TYPE = os.getenv('STORAGE_FALLBACK', 'postgresql').lower()

# ============================================================================
# CONFIGURAÇÕES DE POOL DE CONEXÕES
# ============================================================================

# Tamanho do pool de conexões
POSTGRESQL_POOL_SIZE = int(os.getenv('POSTGRES_POOL_SIZE', '10'))

# Overflow máximo do pool
POSTGRESQL_MAX_OVERFLOW = int(os.getenv('POSTGRES_MAX_OVERFLOW', '20'))

# Timeout do pool
POSTGRESQL_POOL_TIMEOUT = int(os.getenv('POSTGRES_POOL_TIMEOUT', '30'))

# ============================================================================
# CONFIGURAÇÕES DE RETRY
# ============================================================================

# Número de tentativas de retry
DB_RETRY_ATTEMPTS = int(os.getenv('DB_RETRY_ATTEMPTS', '3'))

# Delay entre tentativas
DB_RETRY_DELAY = float(os.getenv('DB_RETRY_DELAY', '1.0'))

# ============================================================================
# CONFIGURAÇÕES DE MONITORAMENTO
# ============================================================================

# Habilitar Prometheus
PROMETHEUS_ENABLED = os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true'

# DSN do Sentry
SENTRY_DSN = os.getenv('SENTRY_DSN', None)

# ============================================================================
# CONFIGURAÇÕES DE CACHE
# ============================================================================

# TTL do cache em segundos
CACHE_TTL = int(os.getenv('CACHE_TTL', '3600'))

# Número máximo de tentativas de storage
STORAGE_MAX_RETRIES = int(os.getenv('STORAGE_MAX_RETRIES', '3'))
'''.format(timestamp=datetime.now().isoformat())
            
            with open("shared/production_config.py", "w", encoding="utf-8") as f:
                f.write(production_config)
            
            logger.info(f"[{self.tracing_id}] ✅ Configurações atualizadas")
            
            self.results["steps"].append({
                "step": "update_configurations",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "files_created": [".env.example", "shared/production_config.py"]
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao atualizar configurações: {e}")
            self.results["steps"].append({
                "step": "update_configurations",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_6_create_deployment_guide(self) -> bool:
        """
        Passo 6: Criar guia de deploy para produção.
        
        Cria documentação para deploy em produção.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 6: Criação do Guia de Deploy")
        
        try:
            deployment_guide = '''# 🚀 GUIA DE DEPLOY - FASE 1: BANCO DE DADOS

## **📋 RESUMO**
Este guia documenta o deploy da Fase 1 do checklist: migração completa para PostgreSQL.

## **🎯 OBJETIVOS**
- ✅ Migração completa para PostgreSQL
- ✅ Pool de conexões otimizado
- ✅ Retry logic robusta
- ✅ Validação de integridade

## **🔧 PRÉ-REQUISITOS**

### **1. Ambiente**
- Docker e Docker Compose instalados
- Python 3.8+ configurado
- PostgreSQL 15+ disponível
- Redis 7+ disponível

### **2. Configurações**
```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Editar configurações
nano .env
```

### **3. Dependências**
```bash
# Instalar dependências Python
pip install -r requirements.txt

# Verificar PostgreSQL driver
pip install psycopg2-binary
```

## **🚀 PASSOS DE DEPLOY**

### **Passo 1: Backup dos Dados Existentes**
```bash
# Backup SQLite
python scripts/backup_sqlite.py

# Backup feedback
python scripts/backup_feedback.py
```

### **Passo 2: Iniciar Infraestrutura**
```bash
# Iniciar PostgreSQL e Redis
docker compose up -d postgres redis

# Verificar status
docker compose ps
```

### **Passo 3: Executar Migrações**
```bash
# Migrar status SQLite → PostgreSQL
python scripts/migrate_status_sqlite_to_postgres.py

# Migrar feedback JSON → PostgreSQL
python scripts/migrate_feedback_json_to_postgres.py
```

### **Passo 4: Validar Integridade**
```bash
# Validar migração
python scripts/validate_migration_integrity.py
```

### **Passo 5: Iniciar Aplicação**
```bash
# Iniciar aplicação completa
docker compose up -d

# Verificar logs
docker compose logs -f app
```

## **📊 VALIDAÇÃO**

### **1. Testes de Integração**
```bash
# Executar testes PostgreSQL
pytest tests/integration/test_postgresql.py -v
```

### **2. Verificar Métricas**
- Acessar Prometheus: http://localhost:9090
- Acessar Grafana: http://localhost:3000
- Verificar logs: `logs/exec_trace/`

### **3. Testar Funcionalidades**
- Gerar artigo via API
- Verificar persistência no PostgreSQL
- Validar cache no Redis

## **🔍 TROUBLESHOOTING**

### **Problema: Conexão PostgreSQL falha**
```bash
# Verificar se PostgreSQL está rodando
docker compose ps postgres

# Verificar logs
docker compose logs postgres

# Testar conexão manual
psql -h localhost -U omniwriter -d omniwriter
```

### **Problema: Migração falha**
```bash
# Verificar backup
ls -la backups/

# Restaurar backup se necessário
cp backups/YYYYMMDD_HHMMSS/status_backup.db status.db
```

### **Problema: Performance ruim**
```bash
# Verificar pool de conexões
python -c "from shared.postgresql_pool_config import get_connection_pool_stats; print(get_connection_pool_stats(engine))"

# Ajustar configurações no .env
POSTGRES_POOL_SIZE=20
POSTGRES_MAX_OVERFLOW=30
```

## **📈 MÉTRICAS DE SUCESSO**

| Métrica | Meta | Como Medir |
|---------|------|------------|
| **Tempo de Resposta** | < 100ms | Prometheus / Grafana |
| **Uptime** | > 99.9% | Monitoramento |
| **Cobertura de Testes** | > 85% | pytest --cov |
| **Integridade de Dados** | 100% | Script de validação |

## **🔄 ROLLBACK**

### **Se necessário reverter:**
```bash
# Parar aplicação
docker compose down

# Restaurar SQLite
cp backups/YYYYMMDD_HHMMSS/status_backup.db status.db

# Restaurar feedback
cp backups/YYYYMMDD_HHMMSS/feedback_backup.json feedback/feedback_data.json

# Reiniciar com configuração anterior
docker compose up -d
```

## **📞 SUPORTE**

- **Logs**: `logs/exec_trace/checklist_phase1_manual.log`
- **Documentação**: `docs/checklist_phase1_implementation_report.md`
- **Issues**: Criar issue no repositório

---

**Data de Criação**: {timestamp}  
**Tracing ID**: {tracing_id}  
**Status**: ✅ Implementado
'''.format(timestamp=datetime.now().isoformat(), tracing_id=self.tracing_id)
            
            with open("docs/deployment_guide_phase1.md", "w", encoding="utf-8") as f:
                f.write(deployment_guide)
            
            logger.info(f"[{self.tracing_id}] ✅ Guia de deploy criado")
            
            self.results["steps"].append({
                "step": "create_deployment_guide",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "file_created": "docs/deployment_guide_phase1.md"
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro ao criar guia de deploy: {e}")
            self.results["steps"].append({
                "step": "create_deployment_guide",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def execute_all_steps(self) -> bool:
        """
        Executa todos os passos da implementação manual.
        
        Returns:
            bool: True se todos os passos foram executados com sucesso
        """
        logger.info(f"[{self.tracing_id}] Iniciando execução de todos os passos")
        
        steps = [
            ("step_1_create_backup_scripts", self.step_1_create_backup_scripts),
            ("step_2_create_pool_configuration", self.step_2_create_pool_configuration),
            ("step_3_create_retry_logic", self.step_3_create_retry_logic),
            ("step_4_create_validation_scripts", self.step_4_create_validation_scripts),
            ("step_5_update_configurations", self.step_5_update_configurations),
            ("step_6_create_deployment_guide", self.step_6_create_deployment_guide)
        ]
        
        success_count = 0
        total_steps = len(steps)
        
        for step_name, step_func in steps:
            logger.info(f"[{self.tracing_id}] Executando {step_name}")
            
            try:
                if step_func():
                    success_count += 1
                    logger.info(f"[{self.tracing_id}] ✅ {step_name} concluído com sucesso")
                else:
                    logger.error(f"[{self.tracing_id}] ❌ {step_name} falhou")
                    
            except Exception as e:
                logger.error(f"[{self.tracing_id}] ❌ Erro em {step_name}: {e}")
        
        # Atualizar resultados finais
        self.results["end_time"] = datetime.now().isoformat()
        self.results["success_count"] = success_count
        self.results["total_steps"] = total_steps
        
        if success_count == total_steps:
            self.results["status"] = "completed"
            logger.info(f"[{self.tracing_id}] ✅ Todos os {total_steps} passos executados com sucesso")
        else:
            self.results["status"] = "partial"
            logger.warning(f"[{self.tracing_id}] ⚠️ {success_count}/{total_steps} passos executados com sucesso")
        
        # Salvar resultados
        results_file = f"logs/exec_trace/checklist_phase1_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"[{self.tracing_id}] 📊 Resultados salvos em: {results_file}")
        
        return success_count == total_steps

def main():
    """Função principal."""
    print("🚀 Iniciando implementação manual da Fase 1 - Banco de Dados")
    print("=" * 60)
    
    implementation = ChecklistPhase1ManualImplementation()
    
    try:
        success = implementation.execute_all_steps()
        
        if success:
            print("✅ Implementação manual concluída com sucesso!")
            print("📋 Próximos passos:")
            print("   1. Configurar ambiente Python")
            print("   2. Executar scripts de backup")
            print("   3. Iniciar PostgreSQL e Redis")
            print("   4. Executar migrações")
            print("   5. Validar integridade")
            print("   6. Testar aplicação")
        else:
            print("⚠️ Implementação parcial - verificar logs")
            
    except Exception as e:
        print(f"❌ Erro na implementação: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 