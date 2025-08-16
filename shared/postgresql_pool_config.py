"""
Configuração otimizada do pool de conexões PostgreSQL.
Prompt: Configuração pool de conexões PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
"""

from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from typing import Optional
import os
import logging

# Configuração de logging
logger = logging.getLogger("postgresql_pool")

# Configurações do pool baseadas em produção
POSTGRESQL_POOL_CONFIG = {
    "pool_size": 10,
    "max_overflow": 20,
    "pool_timeout": 30,
    "pool_recycle": 3600,
    "pool_pre_ping": True,
    "echo": False
}

def create_postgresql_engine(url: Optional[str] = None):
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
        logger.error(f"Erro ao criar engine PostgreSQL: {e}")
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
    return {
        "pool_size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "invalid": pool.invalid()
    }

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
        logger.error(f"Erro ao testar conexão PostgreSQL: {e}")
        return False
