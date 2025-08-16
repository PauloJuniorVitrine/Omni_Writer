"""
Testes para configurações semânticas do sistema.

Prompt: Nomenclatura Semântica - IMP-010
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T20:20:00Z
Tracing ID: ENTERPRISE_20250127_010
"""

import os
import pytest
import importlib
from unittest.mock import patch, MagicMock


class TestConfigSemanticNaming:
    """Testes para nomenclatura semântica das configurações"""
    
    def test_storage_constants_are_semantic(self):
        """Testa se as constantes de storage têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'GENERATED_ARTICLES_DIRECTORY')
        assert hasattr(config, 'ARTICLES_ZIP_FILE_PATH')
        assert hasattr(config, 'OUTPUT_BASE_DIRECTORY')
        
        # Verifica se os valores são strings válidas
        assert isinstance(config.GENERATED_ARTICLES_DIRECTORY, str)
        assert isinstance(config.ARTICLES_ZIP_FILE_PATH, str)
        assert isinstance(config.OUTPUT_BASE_DIRECTORY, str)
        
        # Verifica se os caminhos são construídos corretamente
        assert 'generated_articles' in config.GENERATED_ARTICLES_DIRECTORY
        assert 'articles.zip' in config.ARTICLES_ZIP_FILE_PATH
        assert 'output' in config.OUTPUT_BASE_DIRECTORY
    
    def test_ai_provider_constants_are_semantic(self):
        """Testa se as constantes de provedores de IA têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'OPENAI_API_ENDPOINT')
        assert hasattr(config, 'DEEPSEEK_API_ENDPOINT')
        assert hasattr(config, 'SUPPORTED_AI_PROVIDERS')
        
        # Verifica se os valores são válidos
        assert isinstance(config.OPENAI_API_ENDPOINT, str)
        assert isinstance(config.DEEPSEEK_API_ENDPOINT, str)
        assert isinstance(config.SUPPORTED_AI_PROVIDERS, list)
        
        # Verifica se as URLs são válidas
        assert 'api.openai.com' in config.OPENAI_API_ENDPOINT
        assert 'api.deepseek.com' in config.DEEPSEEK_API_ENDPOINT
        assert 'openai' in config.SUPPORTED_AI_PROVIDERS
        assert 'deepseek' in config.SUPPORTED_AI_PROVIDERS
    
    def test_monitoring_constants_are_semantic(self):
        """Testa se as constantes de monitoramento têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'SENTRY_ERROR_TRACKING_DSN')
        assert hasattr(config, 'PROMETHEUS_METRICS_ENABLED')
        
        # Verifica se os valores são do tipo correto
        assert config.SENTRY_ERROR_TRACKING_DSN is None or isinstance(config.SENTRY_ERROR_TRACKING_DSN, str)
        assert isinstance(config.PROMETHEUS_METRICS_ENABLED, bool)
    
    def test_database_constants_are_semantic(self):
        """Testa se as constantes de banco de dados têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'POSTGRESQL_CONNECTION_URL')
        assert hasattr(config, 'REDIS_CONNECTION_URL')
        
        # Verifica se os valores são strings válidas
        assert isinstance(config.POSTGRESQL_CONNECTION_URL, str)
        assert isinstance(config.REDIS_CONNECTION_URL, str)
        
        # Verifica se as URLs contêm os protocolos corretos
        assert config.POSTGRESQL_CONNECTION_URL.startswith('postgresql://')
        assert config.REDIS_CONNECTION_URL.startswith('redis://')
    
    def test_storage_distributed_constants_are_semantic(self):
        """Testa se as constantes de storage distribuído têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'DISTRIBUTED_STORAGE_ENABLED')
        assert hasattr(config, 'STORAGE_FALLBACK_TYPE')
        assert hasattr(config, 'CACHE_TIME_TO_LIVE_SECONDS')
        assert hasattr(config, 'STORAGE_MAX_RETRY_ATTEMPTS')
        
        # Verifica se os valores são do tipo correto
        assert isinstance(config.DISTRIBUTED_STORAGE_ENABLED, bool)
        assert isinstance(config.STORAGE_FALLBACK_TYPE, str)
        assert isinstance(config.CACHE_TIME_TO_LIVE_SECONDS, int)
        assert isinstance(config.STORAGE_MAX_RETRY_ATTEMPTS, int)
        
        # Verifica se os valores estão dentro de limites razoáveis
        assert config.CACHE_TIME_TO_LIVE_SECONDS > 0
        assert config.STORAGE_MAX_RETRY_ATTEMPTS > 0
        assert config.STORAGE_FALLBACK_TYPE in ['sqlite', 'postgresql', 'redis']
    
    def test_validation_constants_are_semantic(self):
        """Testa se as constantes de validação têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'MAX_PROMPT_LENGTH')
        assert hasattr(config, 'MIN_PROMPT_LENGTH')
        assert hasattr(config, 'MAX_TITLE_LENGTH')
        assert hasattr(config, 'MIN_TITLE_LENGTH')
        assert hasattr(config, 'MAX_TEMPERATURE')
        assert hasattr(config, 'MIN_TEMPERATURE')
        assert hasattr(config, 'MAX_TOKENS')
        assert hasattr(config, 'MIN_TOKENS')
        
        # Verifica se os valores são inteiros ou floats válidos
        assert isinstance(config.MAX_PROMPT_LENGTH, int)
        assert isinstance(config.MIN_PROMPT_LENGTH, int)
        assert isinstance(config.MAX_TITLE_LENGTH, int)
        assert isinstance(config.MIN_TITLE_LENGTH, int)
        assert isinstance(config.MAX_TEMPERATURE, float)
        assert isinstance(config.MIN_TEMPERATURE, float)
        assert isinstance(config.MAX_TOKENS, int)
        assert isinstance(config.MIN_TOKENS, int)
        
        # Verifica se os limites fazem sentido
        assert config.MAX_PROMPT_LENGTH > config.MIN_PROMPT_LENGTH
        assert config.MAX_TITLE_LENGTH > config.MIN_TITLE_LENGTH
        assert config.MAX_TEMPERATURE > config.MIN_TEMPERATURE
        assert config.MAX_TOKENS > config.MIN_TOKENS
    
    def test_internationalization_constants_are_semantic(self):
        """Testa se as constantes de internacionalização têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'DEFAULT_LANGUAGE')
        assert hasattr(config, 'SUPPORTED_LANGUAGES')
        
        # Verifica se os valores são válidos
        assert isinstance(config.DEFAULT_LANGUAGE, str)
        assert isinstance(config.SUPPORTED_LANGUAGES, list)
        
        # Verifica se o idioma padrão está na lista de suportados
        assert config.DEFAULT_LANGUAGE in config.SUPPORTED_LANGUAGES
        assert 'pt-BR' in config.SUPPORTED_LANGUAGES
        assert 'en-US' in config.SUPPORTED_LANGUAGES
    
    def test_performance_constants_are_semantic(self):
        """Testa se as constantes de performance têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'DEFAULT_MAX_CONCURRENT_REQUESTS')
        assert hasattr(config, 'DEFAULT_THREAD_POOL_SIZE')
        assert hasattr(config, 'CACHE_HIT_RATE_THRESHOLD')
        assert hasattr(config, 'CACHE_WARMING_ENABLED')
        
        # Verifica se os valores são do tipo correto
        assert isinstance(config.DEFAULT_MAX_CONCURRENT_REQUESTS, int)
        assert isinstance(config.DEFAULT_THREAD_POOL_SIZE, int)
        assert isinstance(config.CACHE_HIT_RATE_THRESHOLD, float)
        assert isinstance(config.CACHE_WARMING_ENABLED, bool)
        
        # Verifica se os valores estão dentro de limites razoáveis
        assert config.DEFAULT_MAX_CONCURRENT_REQUESTS > 0
        assert config.DEFAULT_THREAD_POOL_SIZE > 0
        assert 0.0 <= config.CACHE_HIT_RATE_THRESHOLD <= 1.0
    
    def test_file_format_constants_are_semantic(self):
        """Testa se as constantes de formato de arquivo têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'SUPPORTED_ARTICLE_FORMATS')
        assert hasattr(config, 'DEFAULT_FILE_ENCODING')
        
        # Verifica se os valores são válidos
        assert isinstance(config.SUPPORTED_ARTICLE_FORMATS, list)
        assert isinstance(config.DEFAULT_FILE_ENCODING, str)
        
        # Verifica se os formatos suportados são válidos
        assert '.txt' in config.SUPPORTED_ARTICLE_FORMATS
        assert '.md' in config.SUPPORTED_ARTICLE_FORMATS
        assert '.html' in config.SUPPORTED_ARTICLE_FORMATS
        assert '.json' in config.SUPPORTED_ARTICLE_FORMATS
        assert config.DEFAULT_FILE_ENCODING == 'utf-8'
    
    def test_status_constants_are_semantic(self):
        """Testa se as constantes de status têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'GENERATION_STATUS_PENDING')
        assert hasattr(config, 'GENERATION_STATUS_PROCESSING')
        assert hasattr(config, 'GENERATION_STATUS_COMPLETED')
        assert hasattr(config, 'GENERATION_STATUS_FAILED')
        assert hasattr(config, 'GENERATION_STATUS_CANCELLED')
        
        # Verifica se os valores são strings válidas
        assert isinstance(config.GENERATION_STATUS_PENDING, str)
        assert isinstance(config.GENERATION_STATUS_PROCESSING, str)
        assert isinstance(config.GENERATION_STATUS_COMPLETED, str)
        assert isinstance(config.GENERATION_STATUS_FAILED, str)
        assert isinstance(config.GENERATION_STATUS_CANCELLED, str)
        
        # Verifica se os status são únicos
        statuses = [
            config.GENERATION_STATUS_PENDING,
            config.GENERATION_STATUS_PROCESSING,
            config.GENERATION_STATUS_COMPLETED,
            config.GENERATION_STATUS_FAILED,
            config.GENERATION_STATUS_CANCELLED
        ]
        assert len(statuses) == len(set(statuses))
    
    def test_logging_constants_are_semantic(self):
        """Testa se as constantes de logging têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'LOG_LEVEL_DEBUG')
        assert hasattr(config, 'LOG_LEVEL_INFO')
        assert hasattr(config, 'LOG_LEVEL_WARNING')
        assert hasattr(config, 'LOG_LEVEL_ERROR')
        assert hasattr(config, 'LOG_LEVEL_CRITICAL')
        
        # Verifica se os valores são strings válidas
        assert isinstance(config.LOG_LEVEL_DEBUG, str)
        assert isinstance(config.LOG_LEVEL_INFO, str)
        assert isinstance(config.LOG_LEVEL_WARNING, str)
        assert isinstance(config.LOG_LEVEL_ERROR, str)
        assert isinstance(config.LOG_LEVEL_CRITICAL, str)
        
        # Verifica se os níveis são padrão
        assert config.LOG_LEVEL_DEBUG == 'DEBUG'
        assert config.LOG_LEVEL_INFO == 'INFO'
        assert config.LOG_LEVEL_WARNING == 'WARNING'
        assert config.LOG_LEVEL_ERROR == 'ERROR'
        assert config.LOG_LEVEL_CRITICAL == 'CRITICAL'
    
    def test_environment_constants_are_semantic(self):
        """Testa se as constantes de ambiente têm nomenclatura semântica"""
        import shared.config as config
        
        # Verifica se os nomes são semânticos e descritivos
        assert hasattr(config, 'CURRENT_ENVIRONMENT')
        assert hasattr(config, 'ENVIRONMENT_CONFIG')
        
        # Verifica se os valores são válidos
        assert isinstance(config.CURRENT_ENVIRONMENT, str)
        assert isinstance(config.ENVIRONMENT_CONFIG, dict)
        
        # Verifica se o ambiente atual é válido
        valid_environments = ['development', 'staging', 'production', 'testing']
        assert config.CURRENT_ENVIRONMENT in valid_environments
    
    def test_legacy_compatibility_aliases(self):
        """Testa se os aliases de compatibilidade com código legado funcionam"""
        import shared.config as config
        
        # Verifica se os aliases existem e apontam para os valores corretos
        assert config.ARTIGOS_DIR == config.GENERATED_ARTICLES_DIRECTORY
        assert config.ARTIGOS_ZIP == config.ARTICLES_ZIP_FILE_PATH
        assert config.OUTPUT_BASE_DIR == config.OUTPUT_BASE_DIRECTORY
        assert config.OPENAI_API_URL == config.OPENAI_API_ENDPOINT
        assert config.DEEPSEEK_API_URL == config.DEEPSEEK_API_ENDPOINT
        assert config.MODELOS_SUPORTADOS == config.SUPPORTED_AI_PROVIDERS
        assert config.SENTRY_DSN == config.SENTRY_ERROR_TRACKING_DSN
        assert config.PROMETHEUS_ENABLED == config.PROMETHEUS_METRICS_ENABLED
        assert config.POSTGRES_URL == config.POSTGRESQL_CONNECTION_URL
        assert config.REDIS_URL == config.REDIS_CONNECTION_URL
        assert config.ENABLE_DISTRIBUTED_STORAGE == config.DISTRIBUTED_STORAGE_ENABLED
        assert config.STORAGE_FALLBACK == config.STORAGE_FALLBACK_TYPE
        assert config.CACHE_TTL == config.CACHE_TIME_TO_LIVE_SECONDS
        assert config.STORAGE_MAX_RETRIES == config.STORAGE_MAX_RETRY_ATTEMPTS


class TestConfigEnvironmentVariables:
    """Testes para carregamento de variáveis de ambiente"""
    
    def test_environment_variable_loading(self, monkeypatch):
        """Testa se as variáveis de ambiente são carregadas corretamente"""
        # Configura variáveis de ambiente de teste
        monkeypatch.setenv('GENERATED_ARTICLES_DIRECTORY', '/tmp/test_articles')
        monkeypatch.setenv('ARTICLES_ZIP_FILE_PATH', '/tmp/test_articles/test.zip')
        monkeypatch.setenv('OUTPUT_BASE_DIRECTORY', '/tmp/test_output')
        monkeypatch.setenv('OPENAI_API_ENDPOINT', 'http://test.openai.com')
        monkeypatch.setenv('DEEPSEEK_API_ENDPOINT', 'http://test.deepseek.com')
        monkeypatch.setenv('SENTRY_DSN', 'test-dsn')
        monkeypatch.setenv('PROMETHEUS_METRICS_ENABLED', 'true')
        monkeypatch.setenv('POSTGRES_URL', 'postgresql://test:test@localhost:5432/test')
        monkeypatch.setenv('REDIS_URL', 'redis://localhost:6379/1')
        monkeypatch.setenv('ENABLE_DISTRIBUTED_STORAGE', 'false')
        monkeypatch.setenv('STORAGE_FALLBACK', 'postgresql')
        monkeypatch.setenv('CACHE_TTL', '7200')
        monkeypatch.setenv('STORAGE_MAX_RETRIES', '5')
        
        # Recarrega o módulo para aplicar as variáveis de ambiente
        import sys
        if 'shared.config' in sys.modules:
            del sys.modules['shared.config']
        import shared.config as config
        
        # Verifica se as variáveis foram carregadas corretamente
        assert config.GENERATED_ARTICLES_DIRECTORY == '/tmp/test_articles'
        assert config.ARTICLES_ZIP_FILE_PATH == '/tmp/test_articles/test.zip'
        assert config.OUTPUT_BASE_DIRECTORY == '/tmp/test_output'
        assert config.OPENAI_API_ENDPOINT == 'http://test.openai.com'
        assert config.DEEPSEEK_API_ENDPOINT == 'http://test.deepseek.com'
        assert config.SENTRY_ERROR_TRACKING_DSN == 'test-dsn'
        assert config.PROMETHEUS_METRICS_ENABLED is True
        assert config.POSTGRESQL_CONNECTION_URL == 'postgresql://test:test@localhost:5432/test'
        assert config.REDIS_CONNECTION_URL == 'redis://localhost:6379/1'
        assert config.DISTRIBUTED_STORAGE_ENABLED is False
        assert config.STORAGE_FALLBACK_TYPE == 'postgresql'
        assert config.CACHE_TIME_TO_LIVE_SECONDS == 7200
        assert config.STORAGE_MAX_RETRY_ATTEMPTS == 5
    
    def test_default_values_when_env_not_set(self, monkeypatch):
        """Testa se os valores padrão são usados quando variáveis de ambiente não estão definidas"""
        # Remove variáveis de ambiente específicas
        monkeypatch.delenv('GENERATED_ARTICLES_DIRECTORY', raising=False)
        monkeypatch.delenv('OPENAI_API_ENDPOINT', raising=False)
        monkeypatch.delenv('PROMETHEUS_METRICS_ENABLED', raising=False)
        
        # Recarrega o módulo
        import sys
        if 'shared.config' in sys.modules:
            del sys.modules['shared.config']
        import shared.config as config
        
        # Verifica se os valores padrão são usados
        assert 'generated_articles' in config.GENERATED_ARTICLES_DIRECTORY
        assert 'api.openai.com' in config.OPENAI_API_ENDPOINT
        assert config.PROMETHEUS_METRICS_ENABLED is False


class TestConfigConstantsModule:
    """Testes para o módulo de constantes"""
    
    def test_storage_constants_class(self):
        """Testa a classe StorageConstants"""
        from shared.constants import StorageConstants
        
        # Verifica se os atributos existem
        assert hasattr(StorageConstants, 'GENERATED_ARTICLES_DIRECTORY')
        assert hasattr(StorageConstants, 'OUTPUT_BASE_DIRECTORY')
        assert hasattr(StorageConstants, 'ARTICLES_ZIP_FILENAME')
        assert hasattr(StorageConstants, 'DEFAULT_STORAGE_TYPE')
        assert hasattr(StorageConstants, 'DISTRIBUTED_STORAGE_ENABLED')
        assert hasattr(StorageConstants, 'MAX_STORAGE_RETRIES')
        assert hasattr(StorageConstants, 'DEFAULT_CACHE_TTL_SECONDS')
        
        # Verifica se os valores são válidos
        assert StorageConstants.GENERATED_ARTICLES_DIRECTORY == 'generated_articles'
        assert StorageConstants.OUTPUT_BASE_DIRECTORY == 'output'
        assert StorageConstants.ARTICLES_ZIP_FILENAME == 'articles.zip'
        assert StorageConstants.MAX_STORAGE_RETRIES == 3
        assert StorageConstants.DEFAULT_CACHE_TTL_SECONDS == 3600
    
    def test_ai_provider_constants_class(self):
        """Testa a classe AIProviderConstants"""
        from shared.constants import AIProviderConstants, ModelProvider
        
        # Verifica se os atributos existem
        assert hasattr(AIProviderConstants, 'OPENAI_API_ENDPOINT')
        assert hasattr(AIProviderConstants, 'DEEPSEEK_API_ENDPOINT')
        assert hasattr(AIProviderConstants, 'SUPPORTED_PROVIDERS')
        assert hasattr(AIProviderConstants, 'PROVIDER_CONFIGS')
        
        # Verifica se os valores são válidos
        assert 'api.openai.com' in AIProviderConstants.OPENAI_API_ENDPOINT
        assert 'api.deepseek.com' in AIProviderConstants.DEEPSEEK_API_ENDPOINT
        assert ModelProvider.OPENAI.value in AIProviderConstants.SUPPORTED_PROVIDERS
        assert ModelProvider.DEEPSEEK.value in AIProviderConstants.SUPPORTED_PROVIDERS
        
        # Verifica se as configurações dos provedores existem
        assert ModelProvider.OPENAI.value in AIProviderConstants.PROVIDER_CONFIGS
        assert ModelProvider.DEEPSEEK.value in AIProviderConstants.PROVIDER_CONFIGS
    
    def test_validation_constants_class(self):
        """Testa a classe ValidationConstants"""
        from shared.constants import ValidationConstants
        
        # Verifica se os atributos existem
        assert hasattr(ValidationConstants, 'MAX_PROMPT_LENGTH')
        assert hasattr(ValidationConstants, 'MIN_PROMPT_LENGTH')
        assert hasattr(ValidationConstants, 'MAX_TEMPERATURE')
        assert hasattr(ValidationConstants, 'MIN_TEMPERATURE')
        assert hasattr(ValidationConstants, 'MAX_TOKENS')
        assert hasattr(ValidationConstants, 'MIN_TOKENS')
        
        # Verifica se os valores fazem sentido
        assert ValidationConstants.MAX_PROMPT_LENGTH > ValidationConstants.MIN_PROMPT_LENGTH
        assert ValidationConstants.MAX_TEMPERATURE > ValidationConstants.MIN_TEMPERATURE
        assert ValidationConstants.MAX_TOKENS > ValidationConstants.MIN_TOKENS
        assert ValidationConstants.MIN_TEMPERATURE >= 0.0
        assert ValidationConstants.MAX_TEMPERATURE <= 2.0
    
    def test_enum_values(self):
        """Testa os enums definidos"""
        from shared.constants import StorageType, ModelProvider, CacheStrategy
        
        # Verifica StorageType
        assert StorageType.SQLITE.value == 'sqlite'
        assert StorageType.POSTGRESQL.value == 'postgresql'
        assert StorageType.REDIS.value == 'redis'
        
        # Verifica ModelProvider
        assert ModelProvider.OPENAI.value == 'openai'
        assert ModelProvider.DEEPSEEK.value == 'deepseek'
        
        # Verifica CacheStrategy
        assert CacheStrategy.TTL.value == 'ttl'
        assert CacheStrategy.LRU.value == 'lru'
        assert CacheStrategy.LFU.value == 'lfu'
        assert CacheStrategy.FIFO.value == 'fifo'


class TestConfigConsistency:
    """Testes para consistência das configurações"""
    
    def test_config_consistency_across_modules(self):
        """Testa se as configurações são consistentes entre módulos"""
        import shared.config as config
        from shared.constants import StorageConstants, AIProviderConstants
        
        # Verifica consistência de storage
        assert config.GENERATED_ARTICLES_DIRECTORY.endswith(StorageConstants.GENERATED_ARTICLES_DIRECTORY)
        assert config.OUTPUT_BASE_DIRECTORY.endswith(StorageConstants.OUTPUT_BASE_DIRECTORY)
        assert config.ARTICLES_ZIP_FILE_PATH.endswith(StorageConstants.ARTICLES_ZIP_FILENAME)
        
        # Verifica consistência de provedores de IA
        assert config.OPENAI_API_ENDPOINT == AIProviderConstants.OPENAI_API_ENDPOINT
        assert config.DEEPSEEK_API_ENDPOINT == AIProviderConstants.DEEPSEEK_API_ENDPOINT
        assert config.SUPPORTED_AI_PROVIDERS == AIProviderConstants.SUPPORTED_PROVIDERS
    
    def test_config_type_consistency(self):
        """Testa se os tipos das configurações são consistentes"""
        import shared.config as config
        
        # Verifica se todas as configurações de diretório são strings
        directory_configs = [
            config.GENERATED_ARTICLES_DIRECTORY,
            config.OUTPUT_BASE_DIRECTORY,
            config.ARTICLES_ZIP_FILE_PATH
        ]
        for config_value in directory_configs:
            assert isinstance(config_value, str)
            assert len(config_value) > 0
        
        # Verifica se todas as configurações de URL são strings
        url_configs = [
            config.OPENAI_API_ENDPOINT,
            config.DEEPSEEK_API_ENDPOINT,
            config.POSTGRESQL_CONNECTION_URL,
            config.REDIS_CONNECTION_URL
        ]
        for config_value in url_configs:
            assert isinstance(config_value, str)
            assert len(config_value) > 0
        
        # Verifica se todas as configurações booleanas são booleanos
        boolean_configs = [
            config.PROMETHEUS_METRICS_ENABLED,
            config.DISTRIBUTED_STORAGE_ENABLED,
            config.CACHE_WARMING_ENABLED
        ]
        for config_value in boolean_configs:
            assert isinstance(config_value, bool)
        
        # Verifica se todas as configurações numéricas são números
        numeric_configs = [
            config.CACHE_TIME_TO_LIVE_SECONDS,
            config.STORAGE_MAX_RETRY_ATTEMPTS,
            config.MAX_PROMPT_LENGTH,
            config.MIN_PROMPT_LENGTH,
            config.MAX_TOKENS,
            config.MIN_TOKENS
        ]
        for config_value in numeric_configs:
            assert isinstance(config_value, (int, float))
            assert config_value >= 0 