"""
Configuração de Produção - Omni Writer
======================================

Configurações otimizadas para ambiente de produção.
Prompt: Configuração de produção PostgreSQL
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T12:30:00Z
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