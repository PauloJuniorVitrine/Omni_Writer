import os
import importlib

def test_config_variaveis_ambiente(monkeypatch):
    """Testa carregamento de variáveis de ambiente com nomenclatura semântica"""
    # Configura variáveis de ambiente de teste
    monkeypatch.setenv('GENERATED_ARTICLES_DIRECTORY', '/tmp/artigos')
    monkeypatch.setenv('ARTICLES_ZIP_FILE_PATH', '/tmp/artigos/zipado.zip')
    monkeypatch.setenv('OUTPUT_BASE_DIRECTORY', '/tmp/output')
    monkeypatch.setenv('OPENAI_API_ENDPOINT', 'http://custom.openai')
    monkeypatch.setenv('DEEPSEEK_API_ENDPOINT', 'http://custom.deepseek')
    monkeypatch.setenv('SENTRY_ERROR_TRACKING_DSN', 'dsn')
    monkeypatch.setenv('PROMETHEUS_METRICS_ENABLED', 'true')
    
    # Recarrega o módulo para aplicar as variáveis
    import sys
    if 'shared.config' in sys.modules:
        del sys.modules['shared.config']
    import shared.config as config
    
    # Verifica se as variáveis foram carregadas corretamente
    assert config.GENERATED_ARTICLES_DIRECTORY == '/tmp/artigos'
    assert config.ARTICLES_ZIP_FILE_PATH == '/tmp/artigos/zipado.zip'
    assert config.OUTPUT_BASE_DIRECTORY == '/tmp/output'
    assert config.OPENAI_API_ENDPOINT == 'http://custom.openai'
    assert config.DEEPSEEK_API_ENDPOINT == 'http://custom.deepseek'
    assert config.SENTRY_ERROR_TRACKING_DSN == 'dsn'
    assert config.PROMETHEUS_METRICS_ENABLED is True
    assert 'openai' in config.SUPPORTED_AI_PROVIDERS and 'deepseek' in config.SUPPORTED_AI_PROVIDERS

def test_config_legacy_compatibility(monkeypatch):
    """Testa compatibilidade com código legado usando aliases"""
    # Configura variáveis de ambiente de teste
    monkeypatch.setenv('ARTIGOS_DIR', '/tmp/legacy_artigos')
    monkeypatch.setenv('ARTIGOS_ZIP', '/tmp/legacy_artigos/legacy.zip')
    monkeypatch.setenv('OUTPUT_BASE_DIR', '/tmp/legacy_output')
    monkeypatch.setenv('OPENAI_API_URL', 'http://legacy.openai')
    monkeypatch.setenv('DEEPSEEK_API_URL', 'http://legacy.deepseek')
    monkeypatch.setenv('SENTRY_DSN', 'legacy-dsn')
    monkeypatch.setenv('PROMETHEUS_ENABLED', 'true')
    
    # Recarrega o módulo para aplicar as variáveis
    import sys
    if 'shared.config' in sys.modules:
        del sys.modules['shared.config']
    import shared.config as config
    
    # Verifica se os aliases de compatibilidade funcionam
    assert config.ARTIGOS_DIR == '/tmp/legacy_artigos'
    assert config.ARTIGOS_ZIP == '/tmp/legacy_artigos/legacy.zip'
    assert config.OUTPUT_BASE_DIR == '/tmp/legacy_output'
    assert config.OPENAI_API_URL == 'http://legacy.openai'
    assert config.DEEPSEEK_API_URL == 'http://legacy.deepseek'
    assert config.SENTRY_DSN == 'legacy-dsn'
    assert config.PROMETHEUS_ENABLED is True
    assert 'openai' in config.MODELOS_SUPORTADOS and 'deepseek' in config.MODELOS_SUPORTADOS

def test_config_semantic_naming_validation():
    """Testa se a nomenclatura semântica está implementada corretamente"""
    import shared.config as config
    
    # Verifica se os nomes antigos foram substituídos por nomes semânticos
    assert hasattr(config, 'GENERATED_ARTICLES_DIRECTORY')  # Antes: ARTIGOS_DIR
    assert hasattr(config, 'ARTICLES_ZIP_FILE_PATH')       # Antes: ARTIGOS_ZIP
    assert hasattr(config, 'OUTPUT_BASE_DIRECTORY')        # Antes: OUTPUT_BASE_DIR
    assert hasattr(config, 'OPENAI_API_ENDPOINT')          # Antes: OPENAI_API_URL
    assert hasattr(config, 'DEEPSEEK_API_ENDPOINT')        # Antes: DEEPSEEK_API_URL
    assert hasattr(config, 'SENTRY_ERROR_TRACKING_DSN')    # Antes: SENTRY_DSN
    assert hasattr(config, 'PROMETHEUS_METRICS_ENABLED')   # Antes: PROMETHEUS_ENABLED
    assert hasattr(config, 'SUPPORTED_AI_PROVIDERS')       # Antes: MODELOS_SUPORTADOS
    
    # Verifica se os valores são do tipo correto
    assert isinstance(config.GENERATED_ARTICLES_DIRECTORY, str)
    assert isinstance(config.ARTICLES_ZIP_FILE_PATH, str)
    assert isinstance(config.OUTPUT_BASE_DIRECTORY, str)
    assert isinstance(config.OPENAI_API_ENDPOINT, str)
    assert isinstance(config.DEEPSEEK_API_ENDPOINT, str)
    assert isinstance(config.SUPPORTED_AI_PROVIDERS, list)
    assert isinstance(config.PROMETHEUS_METRICS_ENABLED, bool)
    
    # Verifica se os valores contêm informações semânticas
    assert 'generated_articles' in config.GENERATED_ARTICLES_DIRECTORY
    assert 'articles.zip' in config.ARTICLES_ZIP_FILE_PATH
    assert 'output' in config.OUTPUT_BASE_DIRECTORY
    assert 'api.openai.com' in config.OPENAI_API_ENDPOINT
    assert 'api.deepseek.com' in config.DEEPSEEK_API_ENDPOINT 