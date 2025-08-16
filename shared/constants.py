"""
Constantes semânticas organizadas por domínio funcional.
Centraliza todas as constantes do sistema com nomenclatura clara e consistente.

Prompt: Nomenclatura Semântica - IMP-010
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:15:00Z
Tracing ID: ENTERPRISE_20250127_010
"""

from typing import List, Dict, Any
from enum import Enum


class StorageType(Enum):
    """Tipos de storage suportados"""
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    REDIS = "redis"


class ModelProvider(Enum):
    """Provedores de modelos de IA suportados"""
    OPENAI = "openai"
    DEEPSEEK = "deepseek"


class CacheStrategy(Enum):
    """Estratégias de cache disponíveis"""
    TTL = "ttl"
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"


# ============================================================================
# CONSTANTES DE STORAGE E PERSISTÊNCIA
# ============================================================================

class StorageConstants:
    """Constantes relacionadas ao sistema de storage"""
    
    # Diretórios de saída
    GENERATED_ARTICLES_DIRECTORY = "generated_articles"
    OUTPUT_BASE_DIRECTORY = "output"
    
    # Arquivos de saída
    ARTICLES_ZIP_FILENAME = "articles.zip"
    
    # Configurações de storage distribuído
    DEFAULT_STORAGE_TYPE = StorageType.SQLITE
    DISTRIBUTED_STORAGE_ENABLED = True
    MAX_STORAGE_RETRIES = 3
    
    # Configurações de cache
    DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hora
    CACHE_COMPRESSION_ENABLED = True
    CACHE_ENCRYPTION_ENABLED = False


# ============================================================================
# CONSTANTES DE PROVEDORES DE IA
# ============================================================================

class AIProviderConstants:
    """Constantes relacionadas aos provedores de IA"""
    
    # URLs das APIs
    OPENAI_API_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    DEEPSEEK_API_ENDPOINT = "https://api.deepseek.com/v1/chat/completions"
    
    # Provedores suportados
    SUPPORTED_PROVIDERS: List[str] = [
        ModelProvider.OPENAI.value,
        ModelProvider.DEEPSEEK.value
    ]
    
    # Configurações padrão por provedor
    PROVIDER_CONFIGS: Dict[str, Dict[str, Any]] = {
        ModelProvider.OPENAI.value: {
            "max_tokens": 4096,
            "temperature": 0.7,
            "timeout": 30.0
        },
        ModelProvider.DEEPSEEK.value: {
            "max_tokens": 4096,
            "temperature": 0.7,
            "timeout": 30.0
        }
    }


# ============================================================================
# CONSTANTES DE MONITORAMENTO E OBSERVABILIDADE
# ============================================================================

class MonitoringConstants:
    """Constantes relacionadas ao monitoramento e observabilidade"""
    
    # Configurações do Sentry
    SENTRY_ERROR_TRACKING_ENABLED = True
    
    # Configurações do Prometheus
    PROMETHEUS_METRICS_ENABLED = False
    
    # Configurações de logging
    LOG_LEVEL_DEFAULT = "INFO"
    LOG_FORMAT_STRUCTURED = True
    LOG_FILE_ENABLED = True
    
    # Configurações de métricas
    METRICS_COLLECTION_INTERVAL = 60  # segundos
    HEALTH_CHECK_INTERVAL = 30  # segundos


# ============================================================================
# CONSTANTES DE BANCO DE DADOS
# ============================================================================

class DatabaseConstants:
    """Constantes relacionadas ao banco de dados"""
    
    # URLs de conexão padrão
    POSTGRESQL_DEFAULT_URL = "postgresql://user:password@localhost:5432/omniwriter"
    REDIS_DEFAULT_URL = "redis://localhost:6379/0"
    
    # Configurações de pool de conexões
    DEFAULT_POOL_SIZE = 10
    DEFAULT_MAX_OVERFLOW = 20
    DEFAULT_POOL_TIMEOUT = 30
    
    # Configurações de retry
    DEFAULT_RETRY_ATTEMPTS = 3
    DEFAULT_RETRY_DELAY = 1.0  # segundos


# ============================================================================
# CONSTANTES DE VALIDAÇÃO E SEGURANÇA
# ============================================================================

class ValidationConstants:
    """Constantes relacionadas à validação e segurança"""
    
    # Limites de entrada
    MAX_PROMPT_LENGTH = 10000
    MIN_PROMPT_LENGTH = 10
    MAX_TITLE_LENGTH = 200
    MIN_TITLE_LENGTH = 5
    
    # Limites de configuração
    MAX_TEMPERATURE = 2.0
    MIN_TEMPERATURE = 0.0
    MAX_TOKENS = 8192
    MIN_TOKENS = 256
    
    # Configurações de rate limiting
    DEFAULT_RATE_LIMIT_PER_MINUTE = 60
    DEFAULT_RATE_LIMIT_PER_HOUR = 1000
    
    # Configurações de timeout
    DEFAULT_REQUEST_TIMEOUT = 30.0
    DEFAULT_GENERATION_TIMEOUT = 120.0


# ============================================================================
# CONSTANTES DE INTERNACIONALIZAÇÃO
# ============================================================================

class InternationalizationConstants:
    """Constantes relacionadas à internacionalização"""
    
    # Idiomas suportados
    SUPPORTED_LANGUAGES: List[str] = [
        "pt-BR",  # Português do Brasil
        "en-US",  # Inglês dos EUA
        "es-ES",  # Espanhol
        "fr-FR"   # Francês
    ]
    
    # Idioma padrão
    DEFAULT_LANGUAGE = "pt-BR"
    
    # Configurações de formatação
    DEFAULT_DATE_FORMAT = "%Y-%m-%d"
    DEFAULT_TIME_FORMAT = "%H:%M:%S"
    DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# ============================================================================
# CONSTANTES DE PERFORMANCE E OTIMIZAÇÃO
# ============================================================================

class PerformanceConstants:
    """Constantes relacionadas à performance e otimização"""
    
    # Configurações de paralelismo
    DEFAULT_MAX_CONCURRENT_REQUESTS = 5
    DEFAULT_THREAD_POOL_SIZE = 10
    
    # Configurações de cache
    CACHE_HIT_RATE_THRESHOLD = 0.8  # 80%
    CACHE_WARMING_ENABLED = True
    
    # Configurações de compressão
    COMPRESSION_THRESHOLD_BYTES = 1024  # 1KB
    COMPRESSION_ALGORITHM = "gzip"
    
    # Configurações de batch processing
    DEFAULT_BATCH_SIZE = 10
    MAX_BATCH_SIZE = 100


# ============================================================================
# CONSTANTES DE ARQUIVOS E FORMATOS
# ============================================================================

class FileFormatConstants:
    """Constantes relacionadas a arquivos e formatos"""
    
    # Extensões suportadas
    SUPPORTED_ARTICLE_FORMATS: List[str] = [
        ".txt",
        ".md",
        ".html",
        ".json"
    ]
    
    # Configurações de encoding
    DEFAULT_ENCODING = "utf-8"
    FALLBACK_ENCODING = "latin-1"
    
    # Configurações de ZIP
    ZIP_COMPRESSION_LEVEL = 6
    ZIP_COMPRESSION_METHOD = "deflate"
    
    # Configurações de backup
    BACKUP_RETENTION_DAYS = 30
    BACKUP_COMPRESSION_ENABLED = True


# ============================================================================
# CONSTANTES DE STATUS E ESTADOS
# ============================================================================

class StatusConstants:
    """Constantes relacionadas a status e estados"""
    
    # Status de geração
    GENERATION_STATUS_PENDING = "pending"
    GENERATION_STATUS_PROCESSING = "processing"
    GENERATION_STATUS_COMPLETED = "completed"
    GENERATION_STATUS_FAILED = "failed"
    GENERATION_STATUS_CANCELLED = "cancelled"
    
    # Status de cache
    CACHE_STATUS_HIT = "hit"
    CACHE_STATUS_MISS = "miss"
    CACHE_STATUS_EXPIRED = "expired"
    
    # Status de health check
    HEALTH_STATUS_HEALTHY = "healthy"
    HEALTH_STATUS_DEGRADED = "degraded"
    HEALTH_STATUS_UNHEALTHY = "unhealthy"


# ============================================================================
# CONSTANTES DE MENSAGENS E LOGS
# ============================================================================

class MessageConstants:
    """Constantes relacionadas a mensagens e logs"""
    
    # Níveis de log
    LOG_LEVEL_DEBUG = "DEBUG"
    LOG_LEVEL_INFO = "INFO"
    LOG_LEVEL_WARNING = "WARNING"
    LOG_LEVEL_ERROR = "ERROR"
    LOG_LEVEL_CRITICAL = "CRITICAL"
    
    # Categorias de log
    LOG_CATEGORY_SECURITY = "security"
    LOG_CATEGORY_PERFORMANCE = "performance"
    LOG_CATEGORY_BUSINESS = "business"
    LOG_CATEGORY_AUDIT = "audit"
    LOG_CATEGORY_ERROR = "error"
    
    # Configurações de trace
    TRACE_ID_LENGTH = 32
    SPAN_ID_LENGTH = 16
    CORRELATION_ID_LENGTH = 24


# ============================================================================
# CONSTANTES DE CONFIGURAÇÃO DE AMBIENTE
# ============================================================================

class EnvironmentConstants:
    """Constantes relacionadas ao ambiente de execução"""
    
    # Ambientes suportados
    ENVIRONMENT_DEVELOPMENT = "development"
    ENVIRONMENT_STAGING = "staging"
    ENVIRONMENT_PRODUCTION = "production"
    ENVIRONMENT_TESTING = "testing"
    
    # Configurações por ambiente
    ENVIRONMENT_CONFIGS: Dict[str, Dict[str, Any]] = {
        ENVIRONMENT_DEVELOPMENT: {
            "debug_enabled": True,
            "log_level": "DEBUG",
            "cache_enabled": False,
            "metrics_enabled": False
        },
        ENVIRONMENT_STAGING: {
            "debug_enabled": False,
            "log_level": "INFO",
            "cache_enabled": True,
            "metrics_enabled": True
        },
        ENVIRONMENT_PRODUCTION: {
            "debug_enabled": False,
            "log_level": "WARNING",
            "cache_enabled": True,
            "metrics_enabled": True
        },
        ENVIRONMENT_TESTING: {
            "debug_enabled": True,
            "log_level": "DEBUG",
            "cache_enabled": False,
            "metrics_enabled": False
        }
    } 