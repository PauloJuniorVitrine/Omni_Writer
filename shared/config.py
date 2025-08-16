"""
Configuration variables for article generation system.
Defines directories, API URLs, supported models, and feature toggles.
Uses semantic naming conventions for better maintainability.

Prompt: Nomenclatura Semântica - IMP-010
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:15:00Z
Tracing ID: ENTERPRISE_20250127_010
"""
import os
from dotenv import load_dotenv
from shared.constants import (
    StorageConstants,
    AIProviderConstants,
    MonitoringConstants,
    DatabaseConstants,
    ValidationConstants,
    InternationalizationConstants,
    PerformanceConstants,
    FileFormatConstants,
    StatusConstants,
    MessageConstants,
    EnvironmentConstants
)

load_dotenv()

# ============================================================================
# CONFIGURAÇÕES DE STORAGE E PERSISTÊNCIA
# ============================================================================

# Diretório onde artigos gerados serão salvos
GENERATED_ARTICLES_DIRECTORY = os.getenv(
    'GENERATED_ARTICLES_DIRECTORY', 
    os.path.join(os.getcwd(), StorageConstants.GENERATED_ARTICLES_DIRECTORY)
)

# Caminho para o arquivo ZIP de artigos
ARTICLES_ZIP_FILE_PATH = os.getenv(
    'ARTICLES_ZIP_FILE_PATH', 
    os.path.join(GENERATED_ARTICLES_DIRECTORY, StorageConstants.ARTICLES_ZIP_FILENAME)
)

# Diretório base de saída para múltiplas instâncias
OUTPUT_BASE_DIRECTORY = os.getenv(
    'OUTPUT_BASE_DIRECTORY', 
    os.path.join(os.getcwd(), StorageConstants.OUTPUT_BASE_DIRECTORY)
)

# ============================================================================
# CONFIGURAÇÕES DE PROVEDORES DE IA
# ============================================================================

# URL da API OpenAI
OPENAI_API_ENDPOINT = os.getenv('OPENAI_API_ENDPOINT', AIProviderConstants.OPENAI_API_ENDPOINT)

# URL da API DeepSeek
DEEPSEEK_API_ENDPOINT = os.getenv('DEEPSEEK_API_ENDPOINT', AIProviderConstants.DEEPSEEK_API_ENDPOINT)

# Modelos suportados pelo sistema
SUPPORTED_AI_PROVIDERS = AIProviderConstants.SUPPORTED_PROVIDERS

# ============================================================================
# CONFIGURAÇÕES DE MONITORAMENTO E OBSERVABILIDADE
# ============================================================================

# DSN do Sentry para rastreamento de erros
SENTRY_ERROR_TRACKING_DSN = os.getenv('SENTRY_DSN', None)

# Habilitar Prometheus para métricas
PROMETHEUS_METRICS_ENABLED = os.getenv(
    'PROMETHEUS_METRICS_ENABLED', 
    str(MonitoringConstants.PROMETHEUS_METRICS_ENABLED)
).lower() == 'true'

# ============================================================================
# CONFIGURAÇÕES DE BANCO DE DADOS
# ============================================================================

# URL do PostgreSQL
POSTGRESQL_CONNECTION_URL = os.getenv('POSTGRES_URL', DatabaseConstants.POSTGRESQL_DEFAULT_URL)

# URL do Redis
REDIS_CONNECTION_URL = os.getenv('REDIS_URL', DatabaseConstants.REDIS_DEFAULT_URL)

# ============================================================================
# CONFIGURAÇÕES DE STORAGE DISTRIBUÍDO
# ============================================================================

# Habilitar storage distribuído
DISTRIBUTED_STORAGE_ENABLED = os.getenv(
    'ENABLE_DISTRIBUTED_STORAGE', 
    str(StorageConstants.DISTRIBUTED_STORAGE_ENABLED)
).lower() == 'true'

# Tipo de storage de fallback
STORAGE_FALLBACK_TYPE = os.getenv('STORAGE_FALLBACK', StorageConstants.DEFAULT_STORAGE_TYPE.value).lower()

# TTL do cache em segundos
CACHE_TIME_TO_LIVE_SECONDS = int(os.getenv('CACHE_TTL', str(StorageConstants.DEFAULT_CACHE_TTL_SECONDS)))

# Número máximo de tentativas de storage
STORAGE_MAX_RETRY_ATTEMPTS = int(os.getenv('STORAGE_MAX_RETRIES', str(StorageConstants.MAX_STORAGE_RETRIES)))

# ============================================================================
# CONFIGURAÇÕES DE VALIDAÇÃO E SEGURANÇA
# ============================================================================

# Limites de entrada
MAX_PROMPT_LENGTH = ValidationConstants.MAX_PROMPT_LENGTH
MIN_PROMPT_LENGTH = ValidationConstants.MIN_PROMPT_LENGTH
MAX_TITLE_LENGTH = ValidationConstants.MAX_TITLE_LENGTH
MIN_TITLE_LENGTH = ValidationConstants.MIN_TITLE_LENGTH

# Limites de configuração
MAX_TEMPERATURE = ValidationConstants.MAX_TEMPERATURE
MIN_TEMPERATURE = ValidationConstants.MIN_TEMPERATURE
MAX_TOKENS = ValidationConstants.MAX_TOKENS
MIN_TOKENS = ValidationConstants.MIN_TOKENS

# Configurações de rate limiting
DEFAULT_RATE_LIMIT_PER_MINUTE = ValidationConstants.DEFAULT_RATE_LIMIT_PER_MINUTE
DEFAULT_RATE_LIMIT_PER_HOUR = ValidationConstants.DEFAULT_RATE_LIMIT_PER_HOUR

# Configurações de timeout
DEFAULT_REQUEST_TIMEOUT = ValidationConstants.DEFAULT_REQUEST_TIMEOUT
DEFAULT_GENERATION_TIMEOUT = ValidationConstants.DEFAULT_GENERATION_TIMEOUT

# ============================================================================
# CONFIGURAÇÕES DE INTERNACIONALIZAÇÃO
# ============================================================================

# Idioma padrão
DEFAULT_LANGUAGE = InternationalizationConstants.DEFAULT_LANGUAGE

# Idiomas suportados
SUPPORTED_LANGUAGES = InternationalizationConstants.SUPPORTED_LANGUAGES

# ============================================================================
# CONFIGURAÇÕES DE PERFORMANCE
# ============================================================================

# Configurações de paralelismo
DEFAULT_MAX_CONCURRENT_REQUESTS = PerformanceConstants.DEFAULT_MAX_CONCURRENT_REQUESTS
DEFAULT_THREAD_POOL_SIZE = PerformanceConstants.DEFAULT_THREAD_POOL_SIZE

# Configurações de cache
CACHE_HIT_RATE_THRESHOLD = PerformanceConstants.CACHE_HIT_RATE_THRESHOLD
CACHE_WARMING_ENABLED = PerformanceConstants.CACHE_WARMING_ENABLED

# ============================================================================
# CONFIGURAÇÕES DE ARQUIVOS
# ============================================================================

# Formatos de artigo suportados
SUPPORTED_ARTICLE_FORMATS = FileFormatConstants.SUPPORTED_ARTICLE_FORMATS

# Encoding padrão
DEFAULT_FILE_ENCODING = FileFormatConstants.DEFAULT_ENCODING

# ============================================================================
# CONFIGURAÇÕES DE STATUS
# ============================================================================

# Status de geração
GENERATION_STATUS_PENDING = StatusConstants.GENERATION_STATUS_PENDING
GENERATION_STATUS_PROCESSING = StatusConstants.GENERATION_STATUS_PROCESSING
GENERATION_STATUS_COMPLETED = StatusConstants.GENERATION_STATUS_COMPLETED
GENERATION_STATUS_FAILED = StatusConstants.GENERATION_STATUS_FAILED
GENERATION_STATUS_CANCELLED = StatusConstants.GENERATION_STATUS_CANCELLED

# ============================================================================
# CONFIGURAÇÕES DE LOGGING
# ============================================================================

# Níveis de log
LOG_LEVEL_DEBUG = MessageConstants.LOG_LEVEL_DEBUG
LOG_LEVEL_INFO = MessageConstants.LOG_LEVEL_INFO
LOG_LEVEL_WARNING = MessageConstants.LOG_LEVEL_WARNING
LOG_LEVEL_ERROR = MessageConstants.LOG_LEVEL_ERROR
LOG_LEVEL_CRITICAL = MessageConstants.LOG_LEVEL_CRITICAL

# Categorias de log
LOG_CATEGORY_SECURITY = MessageConstants.LOG_CATEGORY_SECURITY
LOG_CATEGORY_PERFORMANCE = MessageConstants.LOG_CATEGORY_PERFORMANCE
LOG_CATEGORY_BUSINESS = MessageConstants.LOG_CATEGORY_BUSINESS
LOG_CATEGORY_AUDIT = MessageConstants.LOG_CATEGORY_AUDIT
LOG_CATEGORY_ERROR = MessageConstants.LOG_CATEGORY_ERROR

# ============================================================================
# CONFIGURAÇÕES MULTI-REGION
# ============================================================================

# Habilitar multi-region
MULTI_REGION_ENABLED = os.getenv('MULTI_REGION_ENABLED', 'false').lower() == 'true'

# Região padrão
DEFAULT_REGION = os.getenv('DEFAULT_REGION', 'sa-east-1')

# Região de fallback
FALLBACK_REGION = os.getenv('FALLBACK_REGION', 'us-east-1')

# Caminho para database GeoIP
GEOIP_DATABASE_PATH = os.getenv('GEOIP_DATABASE_PATH', None)

# Configurações de compliance
COMPLIANCE_STRICT_MODE = os.getenv('COMPLIANCE_STRICT_MODE', 'true').lower() == 'true'

# Audit logging para todas as operações
AUDIT_ALL_OPERATIONS = os.getenv('AUDIT_ALL_OPERATIONS', 'true').lower() == 'true'

# ============================================================================
# CONFIGURAÇÕES DE AMBIENTE
# ============================================================================

# Ambiente atual
CURRENT_ENVIRONMENT = os.getenv('ENVIRONMENT', EnvironmentConstants.ENVIRONMENT_DEVELOPMENT)

# Configurações do ambiente atual
ENVIRONMENT_CONFIG = EnvironmentConstants.ENVIRONMENT_CONFIGS.get(
    CURRENT_ENVIRONMENT, 
    EnvironmentConstants.ENVIRONMENT_CONFIGS[EnvironmentConstants.ENVIRONMENT_DEVELOPMENT]
)

# ============================================================================
# COMPATIBILIDADE COM CÓDIGO LEGADO
# ============================================================================

# Alias para compatibilidade com código existente
ARTIGOS_DIR = GENERATED_ARTICLES_DIRECTORY
ARTIGOS_ZIP = ARTICLES_ZIP_FILE_PATH
OUTPUT_BASE_DIR = OUTPUT_BASE_DIRECTORY
OPENAI_API_URL = OPENAI_API_ENDPOINT
DEEPSEEK_API_URL = DEEPSEEK_API_ENDPOINT
MODELOS_SUPORTADOS = SUPPORTED_AI_PROVIDERS
SENTRY_DSN = SENTRY_ERROR_TRACKING_DSN
PROMETHEUS_ENABLED = PROMETHEUS_METRICS_ENABLED
POSTGRES_URL = POSTGRESQL_CONNECTION_URL
REDIS_URL = REDIS_CONNECTION_URL
ENABLE_DISTRIBUTED_STORAGE = DISTRIBUTED_STORAGE_ENABLED
STORAGE_FALLBACK = STORAGE_FALLBACK_TYPE
CACHE_TTL = CACHE_TIME_TO_LIVE_SECONDS
STORAGE_MAX_RETRIES = STORAGE_MAX_RETRY_ATTEMPTS

# Alias para multi-region
MULTI_REGION_ENABLED_LEGACY = MULTI_REGION_ENABLED
DEFAULT_REGION_LEGACY = DEFAULT_REGION
FALLBACK_REGION_LEGACY = FALLBACK_REGION

# ============================================================================
# CONFIGURAÇÕES SERVICE MESH
# ============================================================================

# Habilitar service mesh
SERVICE_MESH_ENABLED = os.getenv('SERVICE_MESH_ENABLED', 'false').lower() == 'true'

# Configurações do service mesh
SERVICE_MESH_TYPE = os.getenv('SERVICE_MESH_TYPE', 'istio')  # istio, linkerd, consul
SERVICE_NAME = os.getenv('SERVICE_NAME', 'omni-writer-api')
SERVICE_VERSION = os.getenv('SERVICE_VERSION', '1.0.0')
NAMESPACE = os.getenv('NAMESPACE', 'production')

# Configurações de observabilidade
JAEGER_ENDPOINT = os.getenv('JAEGER_ENDPOINT', 'http://jaeger:14268/api/traces')
PROMETHEUS_ENDPOINT = os.getenv('PROMETHEUS_ENDPOINT', 'http://prometheus:9090')
GRAFANA_ENDPOINT = os.getenv('GRAFANA_ENDPOINT', 'http://grafana:3000')

# Configurações de mTLS
MTLS_ENABLED = os.getenv('MTLS_ENABLED', 'true').lower() == 'true'
CERT_DIR = os.getenv('CERT_DIR', '/etc/certs')
KEY_FILE = os.getenv('KEY_FILE', f'{CERT_DIR}/service.key')
CERT_FILE = os.getenv('CERT_FILE', f'{CERT_DIR}/service.crt')
CA_FILE = os.getenv('CA_FILE', f'{CERT_DIR}/ca.crt')

# Alias para service mesh
SERVICE_MESH_ENABLED_LEGACY = SERVICE_MESH_ENABLED
SERVICE_NAME_LEGACY = SERVICE_NAME
SERVICE_VERSION_LEGACY = SERVICE_VERSION 