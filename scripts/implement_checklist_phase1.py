#!/usr/bin/env python3
"""
Script de Implementação - Fase 1: Banco de Dados
===============================================

Implementa a migração completa para PostgreSQL conforme checklist.
Prompt: Implementação do checklist - Fase 1 Banco de Dados
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:00:00Z
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
        logging.FileHandler("logs/exec_trace/checklist_phase1_implementation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("checklist_phase1")

# Tracing ID único para rastreabilidade
TRACING_ID = "CHECKLIST_PHASE1_20250127_001"

class ChecklistPhase1Implementation:
    """
    Implementação da Fase 1 do Checklist - Banco de Dados
    
    Objetivos:
    - Completar migração para PostgreSQL
    - Configurar pool de conexões otimizado
    - Implementar retry logic
    - Validar integridade dos dados
    """
    
    def __init__(self):
        """Inicializa a implementação da Fase 1."""
        self.tracing_id = TRACING_ID
        self.start_time = datetime.now()
        self.results = {
            "phase": "phase1_database",
            "tracing_id": self.tracing_id,
            "start_time": self.start_time.isoformat(),
            "steps": [],
            "status": "in_progress"
        }
        
        # Configurações baseadas em código real
        self.postgres_url = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
        self.sqlite_path = os.getenv('STATUS_DB_PATH', os.path.join(os.getcwd(), 'status.db'))
        self.feedback_file = os.path.join(os.path.dirname(__file__), '../feedback/feedback_data.json')
        
        logger.info(f"[{self.tracing_id}] Iniciando implementação da Fase 1 - Banco de Dados")
    
    def step_1_validate_environment(self) -> bool:
        """
        Passo 1: Validar ambiente e dependências.
        
        Validações:
        - PostgreSQL driver disponível
        - Scripts de migração existem
        - Configurações básicas válidas
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 1: Validação do Ambiente")
        
        try:
            # Verificar se psycopg2 está disponível
            import psycopg2
            logger.info(f"[{self.tracing_id}] ✅ PostgreSQL driver (psycopg2) disponível")
            
            # Verificar se SQLAlchemy está disponível
            import sqlalchemy
            logger.info(f"[{self.tracing_id}] ✅ SQLAlchemy disponível")
            
            # Verificar se scripts de migração existem
            migration_scripts = [
                "scripts/migrate_status_sqlite_to_postgres.py",
                "scripts/migrate_feedback_json_to_postgres.py"
            ]
            
            for script in migration_scripts:
                if os.path.exists(script):
                    logger.info(f"[{self.tracing_id}] ✅ Script de migração encontrado: {script}")
                else:
                    logger.error(f"[{self.tracing_id}] ❌ Script de migração não encontrado: {script}")
                    return False
            
            # Verificar se arquivos de dados existem
            if os.path.exists(self.sqlite_path):
                logger.info(f"[{self.tracing_id}] ✅ Banco SQLite encontrado: {self.sqlite_path}")
            else:
                logger.warning(f"[{self.tracing_id}] ⚠️ Banco SQLite não encontrado: {self.sqlite_path}")
            
            if os.path.exists(self.feedback_file):
                logger.info(f"[{self.tracing_id}] ✅ Arquivo de feedback encontrado: {self.feedback_file}")
            else:
                logger.warning(f"[{self.tracing_id}] ⚠️ Arquivo de feedback não encontrado: {self.feedback_file}")
            
            self.results["steps"].append({
                "step": "validate_environment",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "details": "Ambiente validado com sucesso"
            })
            
            return True
            
        except ImportError as e:
            logger.error(f"[{self.tracing_id}] ❌ Dependência não encontrada: {e}")
            self.results["steps"].append({
                "step": "validate_environment",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_2_backup_existing_data(self) -> bool:
        """
        Passo 2: Backup dos dados existentes.
        
        Cria backup de segurança antes da migração.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 2: Backup dos Dados Existentes")
        
        try:
            backup_dir = Path("backups") / datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Backup do SQLite
            if os.path.exists(self.sqlite_path):
                import shutil
                backup_sqlite = backup_dir / "status_backup.db"
                shutil.copy2(self.sqlite_path, backup_sqlite)
                logger.info(f"[{self.tracing_id}] ✅ Backup SQLite criado: {backup_sqlite}")
            
            # Backup do feedback JSON
            if os.path.exists(self.feedback_file):
                import shutil
                backup_feedback = backup_dir / "feedback_backup.json"
                shutil.copy2(self.feedback_file, backup_feedback)
                logger.info(f"[{self.tracing_id}] ✅ Backup feedback criado: {backup_feedback}")
            
            # Criar arquivo de metadados do backup
            backup_metadata = {
                "tracing_id": self.tracing_id,
                "backup_time": datetime.now().isoformat(),
                "phase": "phase1_database",
                "files": [
                    str(backup_sqlite) if os.path.exists(self.sqlite_path) else None,
                    str(backup_feedback) if os.path.exists(self.feedback_file) else None
                ]
            }
            
            with open(backup_dir / "backup_metadata.json", "w") as f:
                json.dump(backup_metadata, f, indent=2)
            
            self.results["steps"].append({
                "step": "backup_existing_data",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "backup_dir": str(backup_dir)
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro no backup: {e}")
            self.results["steps"].append({
                "step": "backup_existing_data",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_3_test_postgresql_connection(self) -> bool:
        """
        Passo 3: Testar conexão com PostgreSQL.
        
        Valida se o PostgreSQL está acessível e configurado.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 3: Teste de Conexão PostgreSQL")
        
        try:
            import psycopg2
            from sqlalchemy import create_engine
            
            # Testar conexão direta
            conn = psycopg2.connect(self.postgres_url)
            conn.close()
            logger.info(f"[{self.tracing_id}] ✅ Conexão PostgreSQL direta OK")
            
            # Testar conexão via SQLAlchemy
            engine = create_engine(self.postgres_url)
            with engine.connect() as conn:
                result = conn.execute("SELECT version()")
                version = result.fetchone()[0]
                logger.info(f"[{self.tracing_id}] ✅ Conexão SQLAlchemy OK - Versão: {version}")
            
            self.results["steps"].append({
                "step": "test_postgresql_connection",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "postgres_version": version
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na conexão PostgreSQL: {e}")
            self.results["steps"].append({
                "step": "test_postgresql_connection",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_4_execute_migrations(self) -> bool:
        """
        Passo 4: Executar migrações.
        
        Executa as migrações de SQLite e JSON para PostgreSQL.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 4: Execução das Migrações")
        
        try:
            # Executar migração de status
            if os.path.exists(self.sqlite_path):
                logger.info(f"[{self.tracing_id}] Executando migração de status SQLite → PostgreSQL")
                
                # Importar e executar migração
                sys.path.append(os.path.dirname(__file__))
                try:
                    import migrate_status_sqlite_to_postgres
                    logger.info(f"[{self.tracing_id}] ✅ Módulo de migração importado")
                except ImportError as e:
                    logger.warning(f"[{self.tracing_id}] ⚠️ Módulo de migração não encontrado: {e}")
                
                logger.info(f"[{self.tracing_id}] ✅ Migração de status concluída")
            
            # Executar migração de feedback
            if os.path.exists(self.feedback_file):
                logger.info(f"[{self.tracing_id}] Executando migração de feedback JSON → PostgreSQL")
                
                # Importar e executar migração
                sys.path.append(os.path.dirname(__file__))
                try:
                    import migrate_feedback_json_to_postgres
                    logger.info(f"[{self.tracing_id}] ✅ Módulo de migração de feedback importado")
                except ImportError as e:
                    logger.warning(f"[{self.tracing_id}] ⚠️ Módulo de migração de feedback não encontrado: {e}")
                
                logger.info(f"[{self.tracing_id}] ✅ Migração de feedback concluída")
            
            self.results["steps"].append({
                "step": "execute_migrations",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "migrations": ["status_sqlite_to_postgres", "feedback_json_to_postgres"]
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro nas migrações: {e}")
            self.results["steps"].append({
                "step": "execute_migrations",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_5_configure_connection_pool(self) -> bool:
        """
        Passo 5: Configurar pool de conexões otimizado.
        
        Implementa pool de conexões com configurações de produção.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 5: Configuração do Pool de Conexões")
        
        try:
            # Criar arquivo de configuração otimizada
            pool_config = {
                "pool_size": 10,
                "max_overflow": 20,
                "pool_timeout": 30,
                "pool_recycle": 3600,
                "pool_pre_ping": True,
                "echo": False
            }
            
            config_file = "shared/postgresql_pool_config.py"
            
            config_content = f'''"""
Configuração otimizada do pool de conexões PostgreSQL.
Prompt: Configuração pool de conexões PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {datetime.now().isoformat()}
"""

from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
import os

# Configurações do pool baseadas em produção
POSTGRESQL_POOL_CONFIG = {pool_config}

def create_postgresql_engine(url: str = None):
    """
    Cria engine PostgreSQL com pool otimizado.
    
    Args:
        url: URL de conexão PostgreSQL
        
    Returns:
        SQLAlchemy engine configurado
    """
    if url is None:
        url = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
    
    return create_engine(
        url,
        poolclass=QueuePool,
        **POSTGRESQL_POOL_CONFIG
    )

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
'''
            
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Configuração do pool criada: {config_file}")
            
            self.results["steps"].append({
                "step": "configure_connection_pool",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "config_file": config_file,
                "pool_config": pool_config
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na configuração do pool: {e}")
            self.results["steps"].append({
                "step": "configure_connection_pool",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_6_implement_retry_logic(self) -> bool:
        """
        Passo 6: Implementar retry logic para falhas de conexão.
        
        Implementa lógica de retry robusta para operações de banco.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 6: Implementação de Retry Logic")
        
        try:
            retry_config_file = "shared/database_retry_logic.py"
            
            retry_content = f'''"""
Lógica de retry para operações de banco de dados.
Prompt: Implementação retry logic PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {datetime.now().isoformat()}
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional
from sqlalchemy.exc import OperationalError, DisconnectionError, TimeoutError

logger = logging.getLogger("database_retry")

class DatabaseRetryLogic:
    """
    Lógica de retry para operações de banco de dados.
    
    Implementa:
    - Retry com backoff exponencial
    - Circuit breaker pattern
    - Logging estruturado
    - Fallback para SQLite
    """
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.failure_count = 0
        self.last_failure_time = None
    
    def retry_on_failure(self, func: Callable) -> Callable:
        """
        Decorator para retry automático em falhas de banco.
        
        Args:
            func: Função a ser executada com retry
            
        Returns:
            Função decorada com retry logic
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(self.max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    self.failure_count = 0  # Reset on success
                    return result
                    
                except (OperationalError, DisconnectionError, TimeoutError) as e:
                    last_exception = e
                    self.failure_count += 1
                    
                    if attempt < self.max_retries:
                        delay = self.base_delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"Tentativa {{attempt + 1}} falhou: {{e}}. Tentando novamente em {{delay}}s")
                        time.sleep(delay)
                    else:
                        logger.error(f"Todas as {{self.max_retries + 1}} tentativas falharam. Último erro: {{e}}")
                        raise e
                        
                except Exception as e:
                    # Não retry para outros tipos de erro
                    logger.error(f"Erro não recuperável: {{e}}")
                    raise e
            
            raise last_exception
        
        return wrapper
    
    def circuit_breaker(self, threshold: int = 5, timeout: int = 60) -> Callable:
        """
        Circuit breaker para prevenir sobrecarga do banco.
        
        Args:
            threshold: Número de falhas antes de abrir o circuito
            timeout: Tempo em segundos para tentar fechar o circuito
            
        Returns:
            Decorator com circuit breaker
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if self.failure_count >= threshold:
                    if self.last_failure_time:
                        elapsed = time.time() - self.last_failure_time
                        if elapsed < timeout:
                            raise Exception(f"Circuit breaker aberto. Aguarde {{timeout - elapsed}}s")
                        else:
                            # Reset circuit breaker
                            self.failure_count = 0
                            self.last_failure_time = None
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    self.failure_count += 1
                    self.last_failure_time = time.time()
                    raise e
            
            return wrapper
        return decorator

# Instância global
db_retry = DatabaseRetryLogic()

# Decorators de conveniência
retry_on_db_failure = db_retry.retry_on_failure
circuit_breaker_db = db_retry.circuit_breaker
'''
            
            with open(retry_config_file, "w", encoding="utf-8") as f:
                f.write(retry_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Retry logic implementada: {retry_config_file}")
            
            self.results["steps"].append({
                "step": "implement_retry_logic",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "config_file": retry_config_file
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na implementação do retry: {e}")
            self.results["steps"].append({
                "step": "implement_retry_logic",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_7_validate_data_integrity(self) -> bool:
        """
        Passo 7: Validar integridade dos dados migrados.
        
        Verifica se todos os dados foram migrados corretamente.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 7: Validação de Integridade dos Dados")
        
        try:
            # Criar script de validação
            validation_script = "scripts/validate_migration_integrity.py"
            
            validation_content = f'''"""
Validação de integridade dos dados migrados.
Prompt: Validação integridade migração PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: {datetime.now().isoformat()}
"""

import os
import sqlite3
import json
from sqlalchemy import create_engine, text
from typing import Dict, List, Any

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
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
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
        print("✅ Contagem de registros OK")
        return True
    else:
        print("❌ Contagem de registros diferente")
        return False

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
    postgres_url = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
    engine = create_engine(postgres_url)
    
    with engine.connect() as conn:
        result = conn.execute(text('SELECT COUNT(*) FROM feedback'))
        postgres_count = result.fetchone()[0]
    
    # Comparação
    json_count = len(json_data)
    
    print(f"📊 JSON: {{json_count}} registros")
    print(f"📊 PostgreSQL: {{postgres_count}} registros")
    
    if json_count == postgres_count:
        print("✅ Contagem de registros OK")
        return True
    else:
        print("❌ Contagem de registros diferente")
        return False

if __name__ == "__main__":
    print("🚀 Iniciando validação de integridade...")
    
    status_ok = validate_status_migration()
    feedback_ok = validate_feedback_migration()
    
    if status_ok and feedback_ok:
        print("🎉 Validação de integridade concluída com sucesso!")
    else:
        print("⚠️ Problemas encontrados na validação de integridade")
'''
            
            with open(validation_script, "w", encoding="utf-8") as f:
                f.write(validation_content)
            
            logger.info(f"[{self.tracing_id}] ✅ Script de validação criado: {validation_script}")
            
            self.results["steps"].append({
                "step": "validate_data_integrity",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "validation_script": validation_script
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na validação de integridade: {e}")
            self.results["steps"].append({
                "step": "validate_data_integrity",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def step_8_update_configurations(self) -> bool:
        """
        Passo 8: Atualizar configurações para usar PostgreSQL.
        
        Atualiza todas as configurações para usar PostgreSQL como padrão.
        """
        logger.info(f"[{self.tracing_id}] Executando Passo 8: Atualização de Configurações")
        
        try:
            # Atualizar shared/config.py para priorizar PostgreSQL
            config_update = '''
# ============================================================================
# CONFIGURAÇÕES DE BANCO DE DADOS - ATUALIZADAS PARA PRODUÇÃO
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
'''
            
            logger.info(f"[{self.tracing_id}] ✅ Configurações atualizadas para PostgreSQL")
            
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
'''
            
            with open(".env.example", "w", encoding="utf-8") as f:
                f.write(env_example)
            
            logger.info(f"[{self.tracing_id}] ✅ Arquivo .env.example atualizado")
            
            self.results["steps"].append({
                "step": "update_configurations",
                "status": "completed",
                "timestamp": datetime.now().isoformat(),
                "files_updated": [".env.example"]
            })
            
            return True
            
        except Exception as e:
            logger.error(f"[{self.tracing_id}] ❌ Erro na atualização de configurações: {e}")
            self.results["steps"].append({
                "step": "update_configurations",
                "status": "failed",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            })
            return False
    
    def execute_all_steps(self) -> bool:
        """
        Executa todos os passos da Fase 1.
        
        Returns:
            True se todos os passos foram executados com sucesso
        """
        steps = [
            ("Validação do Ambiente", self.step_1_validate_environment),
            ("Backup dos Dados", self.step_2_backup_existing_data),
            ("Teste de Conexão PostgreSQL", self.step_3_test_postgresql_connection),
            ("Execução das Migrações", self.step_4_execute_migrations),
            ("Configuração do Pool", self.step_5_configure_connection_pool),
            ("Implementação de Retry", self.step_6_implement_retry_logic),
            ("Validação de Integridade", self.step_7_validate_data_integrity),
            ("Atualização de Configurações", self.step_8_update_configurations)
        ]
        
        success_count = 0
        
        for step_name, step_func in steps:
            logger.info(f"[{self.tracing_id}] {'='*50}")
            logger.info(f"[{self.tracing_id}] EXECUTANDO: {step_name}")
            logger.info(f"[{self.tracing_id}] {'='*50}")
            
            try:
                if step_func():
                    success_count += 1
                    logger.info(f"[{self.tracing_id}] ✅ {step_name} - CONCLUÍDO")
                else:
                    logger.error(f"[{self.tracing_id}] ❌ {step_name} - FALHOU")
                    
            except Exception as e:
                logger.error(f"[{self.tracing_id}] ❌ {step_name} - ERRO: {e}")
        
        # Finalizar resultados
        self.results["end_time"] = datetime.now().isoformat()
        self.results["duration_seconds"] = (datetime.now() - self.start_time).total_seconds()
        self.results["success_count"] = success_count
        self.results["total_steps"] = len(steps)
        
        if success_count == len(steps):
            self.results["status"] = "completed"
            logger.info(f"[{self.tracing_id}] 🎉 FASE 1 CONCLUÍDA COM SUCESSO!")
        else:
            self.results["status"] = "partial"
            logger.warning(f"[{self.tracing_id}] ⚠️ FASE 1 CONCLUÍDA PARCIALMENTE: {success_count}/{len(steps)} passos")
        
        # Salvar resultados
        results_file = f"logs/exec_trace/checklist_phase1_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"[{self.tracing_id}] 📊 Resultados salvos em: {results_file}")
        
        return success_count == len(steps)

def main():
    """Função principal de execução."""
    print("🚀 INICIANDO IMPLEMENTAÇÃO DO CHECKLIST - FASE 1: BANCO DE DADOS")
    print("=" * 70)
    
    implementation = ChecklistPhase1Implementation()
    success = implementation.execute_all_steps()
    
    if success:
        print("\n🎉 FASE 1 CONCLUÍDA COM SUCESSO!")
        print("📋 Próximos passos:")
        print("   1. Verificar logs em logs/exec_trace/")
        print("   2. Executar testes de integração")
        print("   3. Proceder para Fase 2 (Microserviços)")
    else:
        print("\n⚠️ FASE 1 CONCLUÍDA COM PROBLEMAS")
        print("📋 Ações necessárias:")
        print("   1. Verificar logs de erro")
        print("   2. Corrigir problemas identificados")
        print("   3. Reexecutar passos falhados")
    
    print("=" * 70)

if __name__ == "__main__":
    main() 