"""
Testes de Configuração Dinâmica - Omni Writer
============================================

Implementa testes para cenários de configuração dinâmica:
- Hot reload de configuração sem restart
- Validação de configurações inválidas
- Fallback de configurações
- Configuração específica por ambiente
- Configuração baseada em variáveis de ambiente

Autor: Análise Técnica Omni Writer
Data: 2025-01-27
Versão: 1.0
"""

import pytest
import os
import json
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Importações do sistema real
from shared.config import ConfigManager, load_config, validate_config
from shared.cache_config import CacheConfig
from app.performance_config import get_performance_config


class TestHotReloadConfiguration:
    """Testa hot reload de configuração."""
    
    def test_hot_reload_configuration(self):
        """Testa reload de configuração sem restart."""
        # Setup baseado no código real
        config_manager = ConfigManager()
        
        # Configuração inicial
        initial_config = {
            "api_key": "initial-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 1000,
            "temperature": 0.7,
            "cache_enabled": True,
            "log_level": "INFO"
        }
        
        # Carrega configuração inicial
        config_manager.load_config(initial_config)
        assert config_manager.get("api_key") == "initial-key"
        assert config_manager.get("max_tokens") == 1000
        
        # Simula mudança de configuração
        updated_config = {
            "api_key": "updated-key",
            "model": "gpt-4",
            "max_tokens": 2000,
            "temperature": 0.8,
            "cache_enabled": False,
            "log_level": "DEBUG"
        }
        
        # Aplica hot reload
        reload_result = config_manager.hot_reload(updated_config)
        assert reload_result["success"] is True
        assert reload_result["changes"] > 0
        
        # Valida que configuração foi atualizada
        assert config_manager.get("api_key") == "updated-key"
        assert config_manager.get("model") == "gpt-4"
        assert config_manager.get("max_tokens") == 2000
        assert config_manager.get("temperature") == 0.8
        assert config_manager.get("cache_enabled") is False
        assert config_manager.get("log_level") == "DEBUG"
    
    def test_hot_reload_file_monitoring(self):
        """Testa monitoramento de arquivo de configuração."""
        # Setup
        config_manager = ConfigManager()
        
        # Cria arquivo de configuração temporário
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            initial_config = {
                "api_key": "file-key",
                "model": "gpt-3.5-turbo",
                "max_tokens": 1000
            }
            json.dump(initial_config, f)
            config_file = f.name
        
        try:
            # Carrega configuração do arquivo
            config_manager.load_from_file(config_file)
            assert config_manager.get("api_key") == "file-key"
            
            # Simula mudança no arquivo
            updated_config = {
                "api_key": "updated-file-key",
                "model": "gpt-4",
                "max_tokens": 2000
            }
            
            # Escreve configuração atualizada
            with open(config_file, 'w') as f:
                json.dump(updated_config, f)
            
            # Simula detecção de mudança
            file_changed = config_manager.detect_file_change(config_file)
            assert file_changed is True
            
            # Aplica hot reload
            reload_result = config_manager.hot_reload_from_file(config_file)
            assert reload_result["success"] is True
            
            # Valida que configuração foi atualizada
            assert config_manager.get("api_key") == "updated-file-key"
            assert config_manager.get("model") == "gpt-4"
            assert config_manager.get("max_tokens") == 2000
            
        finally:
            # Limpa arquivo temporário
            os.unlink(config_file)
    
    def test_hot_reload_validation(self):
        """Testa validação durante hot reload."""
        # Setup
        config_manager = ConfigManager()
        
        # Configuração inicial válida
        initial_config = {
            "api_key": "valid-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 1000
        }
        config_manager.load_config(initial_config)
        
        # Testa hot reload com configuração inválida
        invalid_config = {
            "api_key": "",  # Inválido: vazio
            "model": "invalid-model",  # Inválido: modelo inexistente
            "max_tokens": -1  # Inválido: valor negativo
        }
        
        # Hot reload deve falhar com configuração inválida
        reload_result = config_manager.hot_reload(invalid_config)
        assert reload_result["success"] is False
        assert len(reload_result["errors"]) > 0
        
        # Configuração original deve permanecer
        assert config_manager.get("api_key") == "valid-key"
        assert config_manager.get("model") == "gpt-3.5-turbo"
        assert config_manager.get("max_tokens") == 1000
    
    def test_hot_reload_notifications(self):
        """Testa notificações de hot reload."""
        # Setup
        config_manager = ConfigManager()
        
        # Lista para capturar notificações
        notifications = []
        
        def notification_callback(event_type, details):
            notifications.append({
                "type": event_type,
                "details": details,
                "timestamp": time.time()
            })
        
        # Registra callback de notificação
        config_manager.register_notification_callback(notification_callback)
        
        # Configuração inicial
        initial_config = {"api_key": "initial", "model": "gpt-3.5-turbo"}
        config_manager.load_config(initial_config)
        
        # Aplica hot reload
        updated_config = {"api_key": "updated", "model": "gpt-4"}
        config_manager.hot_reload(updated_config)
        
        # Valida notificações
        assert len(notifications) > 0
        
        # Deve ter notificação de configuração carregada
        load_notifications = [n for n in notifications if n["type"] == "config_loaded"]
        assert len(load_notifications) > 0
        
        # Deve ter notificação de hot reload
        reload_notifications = [n for n in notifications if n["type"] == "hot_reload"]
        assert len(reload_notifications) > 0


class TestInvalidConfigurationValidation:
    """Testa validação de configurações inválidas."""
    
    def test_invalid_configuration_validation(self):
        """Testa validação de configurações inválidas."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações inválidas para teste
        invalid_configs = [
            # API key vazia
            {
                "config": {"api_key": ""},
                "expected_errors": ["api_key_empty"]
            },
            # API key inválida
            {
                "config": {"api_key": "invalid-key"},
                "expected_errors": ["api_key_invalid_format"]
            },
            # Modelo inexistente
            {
                "config": {"model": "non-existent-model"},
                "expected_errors": ["model_not_supported"]
            },
            # Max tokens negativo
            {
                "config": {"max_tokens": -1},
                "expected_errors": ["max_tokens_negative"]
            },
            # Max tokens muito alto
            {
                "config": {"max_tokens": 100000},
                "expected_errors": ["max_tokens_too_high"]
            },
            # Temperature fora do range
            {
                "config": {"temperature": 2.0},
                "expected_errors": ["temperature_out_of_range"]
            },
            # Configuração incompleta
            {
                "config": {"api_key": "valid-key"},  # Falta outros campos obrigatórios
                "expected_errors": ["missing_required_fields"]
            }
        ]
        
        # Testa cada configuração inválida
        for test_case in invalid_configs:
            config = test_case["config"]
            expected_errors = test_case["expected_errors"]
            
            # Valida configuração
            validation_result = config_manager.validate_config(config)
            assert validation_result["valid"] is False
            assert len(validation_result["errors"]) > 0
            
            # Verifica se erros esperados estão presentes
            for expected_error in expected_errors:
                error_found = any(expected_error in error for error in validation_result["errors"])
                assert error_found, f"Erro esperado '{expected_error}' não encontrado"
    
    def test_configuration_schema_validation(self):
        """Testa validação de schema de configuração."""
        # Setup
        config_manager = ConfigManager()
        
        # Schema esperado
        expected_schema = {
            "type": "object",
            "required": ["api_key", "model", "max_tokens"],
            "properties": {
                "api_key": {"type": "string", "minLength": 1},
                "model": {"type": "string", "enum": ["gpt-3.5-turbo", "gpt-4", "deepseek-chat"]},
                "max_tokens": {"type": "integer", "minimum": 1, "maximum": 32000},
                "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                "cache_enabled": {"type": "boolean"},
                "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]}
            }
        }
        
        # Configuração com tipo incorreto
        invalid_type_config = {
            "api_key": 123,  # Deve ser string
            "model": "gpt-3.5-turbo",
            "max_tokens": "1000"  # Deve ser integer
        }
        
        # Valida schema
        schema_result = config_manager.validate_schema(invalid_type_config, expected_schema)
        assert schema_result["valid"] is False
        assert "type_error" in str(schema_result["errors"]).lower()
    
    def test_configuration_dependency_validation(self):
        """Testa validação de dependências de configuração."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações com dependências
        dependency_configs = [
            # Cache habilitado mas sem configuração de cache
            {
                "config": {
                    "cache_enabled": True,
                    "cache_config": None
                },
                "expected_errors": ["cache_config_required"]
            },
            # Log level DEBUG mas sem arquivo de log
            {
                "config": {
                    "log_level": "DEBUG",
                    "log_file": None
                },
                "expected_errors": ["log_file_required_for_debug"]
            },
            # Modelo GPT-4 mas sem API key premium
            {
                "config": {
                    "model": "gpt-4",
                    "api_key": "sk-free-tier-key"
                },
                "expected_errors": ["premium_api_key_required_for_gpt4"]
            }
        ]
        
        # Testa validação de dependências
        for test_case in dependency_configs:
            config = test_case["config"]
            expected_errors = test_case["expected_errors"]
            
            dependency_result = config_manager.validate_dependencies(config)
            assert dependency_result["valid"] is False
            
            for expected_error in expected_errors:
                error_found = any(expected_error in error for error in dependency_result["errors"])
                assert error_found, f"Erro de dependência '{expected_error}' não encontrado"


class TestConfigurationFallback:
    """Testa fallback de configurações."""
    
    def test_configuration_fallback(self):
        """Testa fallback de configurações."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações em ordem de prioridade
        config_sources = [
            # Configuração de ambiente (mais alta prioridade)
            {
                "source": "environment",
                "config": {
                    "api_key": "env-key",
                    "model": "gpt-4",
                    "max_tokens": 2000
                }
            },
            # Configuração de arquivo
            {
                "source": "file",
                "config": {
                    "api_key": "file-key",
                    "model": "gpt-3.5-turbo",
                    "max_tokens": 1000,
                    "temperature": 0.7
                }
            },
            # Configuração padrão (menor prioridade)
            {
                "source": "default",
                "config": {
                    "api_key": "default-key",
                    "model": "gpt-3.5-turbo",
                    "max_tokens": 500,
                    "temperature": 0.5,
                    "cache_enabled": True
                }
            }
        ]
        
        # Aplica fallback
        final_config = config_manager.apply_fallback(config_sources)
        
        # Valida que configuração de maior prioridade prevalece
        assert final_config["api_key"] == "env-key"  # Do ambiente
        assert final_config["model"] == "gpt-4"      # Do ambiente
        assert final_config["max_tokens"] == 2000    # Do ambiente
        assert final_config["temperature"] == 0.7    # Do arquivo (ambiente não tem)
        assert final_config["cache_enabled"] is True # Do padrão (outros não têm)
    
    def test_configuration_fallback_with_invalid_values(self):
        """Testa fallback com valores inválidos."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações com valores inválidos
        config_sources = [
            # Configuração de ambiente com valores inválidos
            {
                "source": "environment",
                "config": {
                    "api_key": "",  # Inválido
                    "model": "invalid-model",  # Inválido
                    "max_tokens": -1  # Inválido
                }
            },
            # Configuração de arquivo válida
            {
                "source": "file",
                "config": {
                    "api_key": "valid-file-key",
                    "model": "gpt-3.5-turbo",
                    "max_tokens": 1000
                }
            },
            # Configuração padrão
            {
                "source": "default",
                "config": {
                    "api_key": "default-key",
                    "model": "gpt-3.5-turbo",
                    "max_tokens": 500
                }
            }
        ]
        
        # Aplica fallback com validação
        final_config = config_manager.apply_fallback_with_validation(config_sources)
        
        # Valida que valores válidos de menor prioridade são usados
        assert final_config["api_key"] == "valid-file-key"  # Do arquivo (ambiente inválido)
        assert final_config["model"] == "gpt-3.5-turbo"     # Do arquivo (ambiente inválido)
        assert final_config["max_tokens"] == 1000           # Do arquivo (ambiente inválido)
    
    def test_configuration_fallback_chain(self):
        """Testa cadeia de fallback de configurações."""
        # Setup
        config_manager = ConfigManager()
        
        # Simula diferentes cenários de fallback
        fallback_scenarios = [
            # Cenário 1: Ambiente -> Arquivo -> Padrão
            {
                "environment": {"api_key": "env-key"},
                "file": {"api_key": "file-key"},
                "default": {"api_key": "default-key"},
                "expected": "env-key"
            },
            # Cenário 2: Ambiente vazio -> Arquivo -> Padrão
            {
                "environment": {"api_key": ""},
                "file": {"api_key": "file-key"},
                "default": {"api_key": "default-key"},
                "expected": "file-key"
            },
            # Cenário 3: Ambiente e arquivo vazios -> Padrão
            {
                "environment": {"api_key": ""},
                "file": {"api_key": ""},
                "default": {"api_key": "default-key"},
                "expected": "default-key"
            },
            # Cenário 4: Todos vazios -> Erro
            {
                "environment": {"api_key": ""},
                "file": {"api_key": ""},
                "default": {"api_key": ""},
                "expected": None
            }
        ]
        
        # Testa cada cenário
        for scenario in fallback_scenarios:
            fallback_result = config_manager.fallback_chain(
                scenario["environment"],
                scenario["file"],
                scenario["default"]
            )
            
            if scenario["expected"] is None:
                assert fallback_result["success"] is False
                assert "no_valid_config" in fallback_result["error"]
            else:
                assert fallback_result["success"] is True
                assert fallback_result["api_key"] == scenario["expected"]


class TestEnvironmentSpecificConfig:
    """Testa configuração específica por ambiente."""
    
    def test_environment_specific_config(self):
        """Testa configuração específica por ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações por ambiente
        environment_configs = {
            "development": {
                "api_key": "dev-key",
                "model": "gpt-3.5-turbo",
                "max_tokens": 500,
                "log_level": "DEBUG",
                "cache_enabled": False
            },
            "staging": {
                "api_key": "staging-key",
                "model": "gpt-3.5-turbo",
                "max_tokens": 1000,
                "log_level": "INFO",
                "cache_enabled": True
            },
            "production": {
                "api_key": "prod-key",
                "model": "gpt-4",
                "max_tokens": 2000,
                "log_level": "WARNING",
                "cache_enabled": True
            }
        }
        
        # Testa cada ambiente
        for environment, expected_config in environment_configs.items():
            # Define variável de ambiente
            with patch.dict(os.environ, {"NODE_ENV": environment}):
                # Carrega configuração específica do ambiente
                config = config_manager.load_environment_config(environment_configs)
                
                # Valida configuração
                assert config["api_key"] == expected_config["api_key"]
                assert config["model"] == expected_config["model"]
                assert config["max_tokens"] == expected_config["max_tokens"]
                assert config["log_level"] == expected_config["log_level"]
                assert config["cache_enabled"] == expected_config["cache_enabled"]
    
    def test_environment_config_validation(self):
        """Testa validação de configuração por ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Configurações com validações específicas por ambiente
        environment_validations = {
            "development": {
                "config": {
                    "api_key": "dev-key",
                    "log_level": "DEBUG"
                },
                "valid": True
            },
            "production": {
                "config": {
                    "api_key": "prod-key",
                    "log_level": "DEBUG"  # Inválido para produção
                },
                "valid": False,
                "expected_error": "debug_log_not_allowed_in_production"
            }
        }
        
        # Testa validações específicas por ambiente
        for environment, test_case in environment_validations.items():
            config = test_case["config"]
            expected_valid = test_case["valid"]
            
            validation_result = config_manager.validate_environment_config(config, environment)
            assert validation_result["valid"] == expected_valid
            
            if not expected_valid:
                expected_error = test_case["expected_error"]
                assert expected_error in str(validation_result["errors"])
    
    def test_environment_config_override(self):
        """Testa override de configuração por ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Configuração base
        base_config = {
            "api_key": "base-key",
            "model": "gpt-3.5-turbo",
            "max_tokens": 1000,
            "temperature": 0.7
        }
        
        # Overrides específicos por ambiente
        environment_overrides = {
            "development": {
                "max_tokens": 500,
                "temperature": 0.9
            },
            "production": {
                "model": "gpt-4",
                "max_tokens": 2000,
                "temperature": 0.5
            }
        }
        
        # Testa override para cada ambiente
        for environment, overrides in environment_overrides.items():
            # Aplica override
            final_config = config_manager.apply_environment_override(base_config, overrides)
            
            # Valida que override foi aplicado
            for key, value in overrides.items():
                assert final_config[key] == value
            
            # Valida que valores não sobrescritos permanecem
            for key, value in base_config.items():
                if key not in overrides:
                    assert final_config[key] == value


class TestEnvironmentVariableConfig:
    """Testa configuração baseada em variáveis de ambiente."""
    
    def test_environment_variable_config(self):
        """Testa configuração baseada em variáveis de ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Mapeamento de variáveis de ambiente
        env_mapping = {
            "OPENAI_API_KEY": "api_key",
            "OPENAI_MODEL": "model",
            "OPENAI_MAX_TOKENS": "max_tokens",
            "OPENAI_TEMPERATURE": "temperature",
            "CACHE_ENABLED": "cache_enabled",
            "LOG_LEVEL": "log_level"
        }
        
        # Simula variáveis de ambiente
        env_vars = {
            "OPENAI_API_KEY": "env-api-key",
            "OPENAI_MODEL": "gpt-4",
            "OPENAI_MAX_TOKENS": "2000",
            "OPENAI_TEMPERATURE": "0.8",
            "CACHE_ENABLED": "true",
            "LOG_LEVEL": "INFO"
        }
        
        # Carrega configuração das variáveis de ambiente
        with patch.dict(os.environ, env_vars):
            config = config_manager.load_from_environment(env_mapping)
            
            # Valida configuração
            assert config["api_key"] == "env-api-key"
            assert config["model"] == "gpt-4"
            assert config["max_tokens"] == 2000
            assert config["temperature"] == 0.8
            assert config["cache_enabled"] is True
            assert config["log_level"] == "INFO"
    
    def test_environment_variable_validation(self):
        """Testa validação de variáveis de ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Variáveis de ambiente com valores inválidos
        invalid_env_vars = {
            "OPENAI_API_KEY": "",  # Vazio
            "OPENAI_MAX_TOKENS": "invalid",  # Não é número
            "OPENAI_TEMPERATURE": "3.0",  # Fora do range
            "CACHE_ENABLED": "maybe"  # Não é boolean
        }
        
        # Testa validação
        with patch.dict(os.environ, invalid_env_vars):
            validation_result = config_manager.validate_environment_variables()
            assert validation_result["valid"] is False
            assert len(validation_result["errors"]) > 0
            
            # Verifica erros específicos
            errors = validation_result["errors"]
            assert any("api_key_empty" in error for error in errors)
            assert any("max_tokens_invalid" in error for error in errors)
            assert any("temperature_out_of_range" in error for error in errors)
            assert any("cache_enabled_invalid" in error for error in errors)
    
    def test_environment_variable_sensitivity(self):
        """Testa sensibilidade de variáveis de ambiente."""
        # Setup
        config_manager = ConfigManager()
        
        # Variáveis sensíveis
        sensitive_vars = [
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "DATABASE_PASSWORD",
            "JWT_SECRET"
        ]
        
        # Testa mascaramento de variáveis sensíveis
        for var_name in sensitive_vars:
            env_value = f"sensitive-value-{var_name}"
            
            # Simula variável de ambiente
            with patch.dict(os.environ, {var_name: env_value}):
                # Carrega configuração
                config = config_manager.load_from_environment({var_name: "config_key"})
                
                # Valida que valor sensível foi mascarado nos logs
                masked_value = config_manager.mask_sensitive_value(env_value)
                assert masked_value != env_value
                assert "***" in masked_value or len(masked_value) < len(env_value) 