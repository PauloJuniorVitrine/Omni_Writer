"""
Testes para Sistema de Configuração Centralizada - Gargalo Baixo

Prompt: Testes para gargalos baixos - CONFIGURAÇÃO DISTRIBUÍDA
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T11:15:00Z
Tracing ID: GARGALO_BAIXO_TEST_20250127_002

Testes baseados no código real implementado em shared/centralized_config_manager.py
"""

import pytest
import tempfile
import shutil
import json
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import hashlib

from shared.centralized_config_manager import (
    ConfigFormat,
    ConfigChange,
    ConfigValidator,
    ConfigBackupManager,
    CentralizedConfigManager,
    get_centralized_config,
    load_config_from_file,
    save_config_to_file
)


class TestConfigValidator:
    """Testes para ConfigValidator."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.validator = ConfigValidator()
        
    def test_validate_section_valid_database(self):
        """Testa validação de seção database válida."""
        config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'test_db',
            'username': 'test_user',
            'password': 'test_pass',
            'pool_size': 10
        }
        
        errors = self.validator.validate_section('database', config)
        assert len(errors) == 0
        
    def test_validate_section_invalid_database_missing_required(self):
        """Testa validação de seção database com campo obrigatório ausente."""
        config = {
            'host': 'localhost',
            'port': 5432,
            # 'database' ausente
            'username': 'test_user'
        }
        
        errors = self.validator.validate_section('database', config)
        assert len(errors) == 1
        assert "Campo obrigatório ausente: database" in errors[0]
        
    def test_validate_section_invalid_database_wrong_type(self):
        """Testa validação de seção database com tipo incorreto."""
        config = {
            'host': 'localhost',
            'port': 'invalid_port',  # Deveria ser int
            'database': 'test_db',
            'username': 'test_user'
        }
        
        errors = self.validator.validate_section('database', config)
        assert len(errors) == 1
        assert "Tipo incorreto para port" in errors[0]
        
    def test_validate_section_unknown_section(self):
        """Testa validação de seção desconhecida."""
        config = {'key': 'value'}
        
        errors = self.validator.validate_section('unknown_section', config)
        assert len(errors) == 1
        assert "Schema não definido para seção: unknown_section" in errors[0]
        
    def test_validate_config_valid(self):
        """Testa validação de configuração completa válida."""
        config = {
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'test_db',
                'username': 'test_user'
            },
            'logging': {
                'level': 'INFO',
                'format': 'json'
            }
        }
        
        errors = self.validator.validate_config(config)
        assert len(errors) == 0
        
    def test_validate_config_invalid(self):
        """Testa validação de configuração completa inválida."""
        config = {
            'database': {
                'host': 'localhost',
                'port': 'invalid',  # Tipo incorreto
                # 'database' ausente
                'username': 'test_user'
            }
        }
        
        errors = self.validator.validate_config(config)
        assert 'database' in errors
        assert len(errors['database']) == 2


class TestConfigBackupManager:
    """Testes para ConfigBackupManager."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.backup_manager = ConfigBackupManager(backup_dir=self.temp_dir)
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        shutil.rmtree(self.temp_dir)
        
    def test_create_backup(self):
        """Testa criação de backup."""
        config = {
            'database': {'host': 'localhost'},
            'logging': {'level': 'INFO'}
        }
        
        backup_hash = self.backup_manager.create_backup(config, "test backup")
        
        # Verificar se arquivo de backup foi criado
        backup_files = list(Path(self.temp_dir).glob("backup_*.json"))
        assert len(backup_files) == 1
        
        # Verificar conteúdo do backup
        with open(backup_files[0], 'r') as f:
            backup_data = json.load(f)
            
        assert backup_data['hash'] == backup_hash
        assert backup_data['reason'] == "test backup"
        assert backup_data['config'] == config
        assert 'timestamp' in backup_data
        
    def test_restore_backup(self):
        """Testa restauração de backup."""
        config = {
            'database': {'host': 'localhost'},
            'logging': {'level': 'INFO'}
        }
        
        # Criar backup
        backup_hash = self.backup_manager.create_backup(config, "test backup")
        
        # Restaurar backup
        restored_config = self.backup_manager.restore_backup(backup_hash)
        
        assert restored_config == config
        
    def test_restore_backup_not_found(self):
        """Testa restauração de backup inexistente."""
        restored_config = self.backup_manager.restore_backup("invalid_hash")
        
        assert restored_config is None
        
    def test_list_backups(self):
        """Testa listagem de backups."""
        config1 = {'key1': 'value1'}
        config2 = {'key2': 'value2'}
        
        # Criar backups
        self.backup_manager.create_backup(config1, "backup 1")
        self.backup_manager.create_backup(config2, "backup 2")
        
        backups = self.backup_manager.list_backups()
        
        assert len(backups) == 2
        assert all('timestamp' in backup for backup in backups)
        assert all('hash' in backup for backup in backups)
        assert all('reason' in backup for backup in backups)
        
    def test_calculate_config_hash(self):
        """Testa cálculo de hash de configuração."""
        config = {'key': 'value'}
        
        hash1 = self.backup_manager._calculate_config_hash(config)
        hash2 = self.backup_manager._calculate_config_hash(config)
        
        # Hash deve ser consistente
        assert hash1 == hash2
        
        # Hash deve ser diferente para configurações diferentes
        config2 = {'key': 'different_value'}
        hash3 = self.backup_manager._calculate_config_hash(config2)
        
        assert hash1 != hash3
        
    def test_cleanup_old_backups(self):
        """Testa limpeza de backups antigos."""
        # Criar mais backups que o limite
        for i in range(15):  # Mais que max_backups (10)
            config = {'key': f'value{i}'}
            self.backup_manager.create_backup(config, f"backup {i}")
            
        # Verificar que apenas os mais recentes foram mantidos
        backup_files = list(Path(self.temp_dir).glob("backup_*.json"))
        assert len(backup_files) == 10  # max_backups


class TestCentralizedConfigManager:
    """Testes para CentralizedConfigManager."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = Path(self.temp_dir) / "test_config.json"
        self.config_manager = CentralizedConfigManager(str(self.config_file))
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.config_manager.stop_monitoring()
        shutil.rmtree(self.temp_dir)
        
    def test_load_config_new_file(self):
        """Testa carregamento de configuração em arquivo novo."""
        # Configuração padrão deve ser criada
        assert self.config_file.exists()
        
        with open(self.config_file, 'r') as f:
            config_data = json.load(f)
            
        # Verificar se tem seções padrão
        assert 'database' in config_data
        assert 'logging' in config_data
        assert 'api' in config_data
        assert 'cache' in config_data
        
    def test_load_config_existing_file(self):
        """Testa carregamento de configuração existente."""
        # Criar arquivo de configuração
        config_data = {
            'database': {'host': 'test_host'},
            'custom_section': {'key': 'value'}
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config_data, f)
            
        # Recarregar configuração
        self.config_manager.load_config()
        
        assert self.config_manager.config == config_data
        
    def test_save_config(self):
        """Testa salvamento de configuração."""
        config_data = {
            'database': {'host': 'test_host'},
            'logging': {'level': 'DEBUG'}
        }
        
        self.config_manager.config = config_data
        
        success = self.config_manager.save_config("test_user", "test reason")
        
        assert success is True
        
        # Verificar se arquivo foi salvo
        with open(self.config_file, 'r') as f:
            saved_config = json.load(f)
            
        assert saved_config == config_data
        
    def test_save_config_validation_error(self):
        """Testa salvamento com erro de validação."""
        # Configuração inválida
        invalid_config = {
            'database': {
                'host': 'localhost',
                'port': 'invalid_port'  # Tipo incorreto
            }
        }
        
        self.config_manager.config = invalid_config
        
        success = self.config_manager.save_config()
        
        assert success is False
        
    def test_get_config_full(self):
        """Testa obtenção de configuração completa."""
        config_data = {
            'database': {'host': 'test_host'},
            'logging': {'level': 'INFO'}
        }
        
        self.config_manager.config = config_data
        
        result = self.config_manager.get_config()
        
        assert result == config_data
        
    def test_get_config_section(self):
        """Testa obtenção de seção de configuração."""
        config_data = {
            'database': {'host': 'test_host'},
            'logging': {'level': 'INFO'}
        }
        
        self.config_manager.config = config_data
        
        result = self.config_manager.get_config('database')
        
        assert result == {'host': 'test_host'}
        
    def test_get_config_key(self):
        """Testa obtenção de chave específica."""
        config_data = {
            'database': {'host': 'test_host', 'port': 5432}
        }
        
        self.config_manager.config = config_data
        
        result = self.config_manager.get_config('database', 'host')
        
        assert result == 'test_host'
        
    def test_set_config(self):
        """Testa definição de configuração."""
        success = self.config_manager.set_config(
            'database', 'host', 'new_host',
            user='test_user',
            reason='test reason'
        )
        
        assert success is True
        assert self.config_manager.get_config('database', 'host') == 'new_host'
        
        # Verificar se mudança foi registrada
        changes = self.config_manager.get_change_history()
        assert len(changes) == 1
        assert changes[0].config_key == 'database.host'
        assert changes[0].new_value == 'new_host'
        assert changes[0].user == 'test_user'
        assert changes[0].reason == 'test reason'
        
    def test_merge_config(self):
        """Testa mesclagem de configuração."""
        original_config = {
            'database': {'host': 'old_host'},
            'logging': {'level': 'INFO'}
        }
        
        new_config = {
            'database': {'host': 'new_host', 'port': 5432},
            'api': {'timeout': 30}
        }
        
        self.config_manager.config = original_config
        
        success = self.config_manager.merge_config(
            new_config,
            user='test_user',
            reason='merge test'
        )
        
        assert success is True
        
        # Verificar configuração mesclada
        expected_config = {
            'database': {'host': 'new_host', 'port': 5432},
            'logging': {'level': 'INFO'},
            'api': {'timeout': 30}
        }
        
        assert self.config_manager.config == expected_config
        
    def test_rollback_config(self):
        """Testa rollback de configuração."""
        # Configuração inicial
        initial_config = {'database': {'host': 'initial_host'}}
        self.config_manager.config = initial_config
        self.config_manager.save_config("user1", "initial")
        
        # Mudar configuração
        self.config_manager.set_config('database', 'host', 'changed_host', "user2", "change")
        
        # Obter hash do backup
        backups = self.config_manager.backup_manager.list_backups()
        backup_hash = backups[0]['hash']
        
        # Fazer rollback
        success = self.config_manager.rollback_config(backup_hash, "user3")
        
        assert success is True
        assert self.config_manager.get_config('database', 'host') == 'initial_host'
        
    def test_get_change_history(self):
        """Testa obtenção de histórico de mudanças."""
        # Fazer algumas mudanças
        self.config_manager.set_config('key1', 'value1', 'old_value1', "user1", "change1")
        self.config_manager.set_config('key2', 'value2', 'old_value2', "user2", "change2")
        
        # Obter histórico
        history = self.config_manager.get_change_history()
        
        assert len(history) == 2
        assert history[0].config_key == 'key1.value1'
        assert history[1].config_key == 'key2.value2'
        
    def test_get_change_history_with_limit(self):
        """Testa obtenção de histórico com limite."""
        # Fazer várias mudanças
        for i in range(10):
            self.config_manager.set_config(f'key{i}', f'value{i}', f'old_value{i}', f"user{i}", f"change{i}")
            
        # Obter histórico com limite
        history = self.config_manager.get_change_history(limit=5)
        
        assert len(history) == 5
        # Deve retornar as mudanças mais recentes
        assert history[-1].config_key == 'key9.value9'


class TestConvenienceFunctions:
    """Testes para funções de conveniência."""
    
    def test_get_centralized_config(self):
        """Testa função get_centralized_config."""
        with patch('shared.centralized_config_manager.CentralizedConfigManager') as mock_class:
            mock_instance = MagicMock()
            mock_class.return_value = mock_instance
            
            result = get_centralized_config()
            
            mock_class.assert_called_once()
            assert result == mock_instance
            
    def test_load_config_from_file_json(self):
        """Testa carregamento de configuração JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {'key': 'value'}
            json.dump(config_data, f)
            file_path = f.name
            
        try:
            result = load_config_from_file(file_path, ConfigFormat.JSON)
            assert result == config_data
        finally:
            Path(file_path).unlink()
            
    def test_load_config_from_file_yaml(self):
        """Testa carregamento de configuração YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_data = {'key': 'value'}
            yaml.dump(config_data, f)
            file_path = f.name
            
        try:
            result = load_config_from_file(file_path, ConfigFormat.YAML)
            assert result == config_data
        finally:
            Path(file_path).unlink()
            
    def test_load_config_from_file_not_found(self):
        """Testa carregamento de arquivo inexistente."""
        result = load_config_from_file("nonexistent_file.json")
        assert result == {}
        
    def test_save_config_to_file_json(self):
        """Testa salvamento de configuração JSON."""
        config_data = {'key': 'value'}
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            file_path = f.name
            
        try:
            success = save_config_to_file(config_data, file_path, ConfigFormat.JSON)
            
            assert success is True
            
            with open(file_path, 'r') as f:
                saved_data = json.load(f)
                
            assert saved_data == config_data
        finally:
            Path(file_path).unlink()
            
    def test_save_config_to_file_yaml(self):
        """Testa salvamento de configuração YAML."""
        config_data = {'key': 'value'}
        
        with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False) as f:
            file_path = f.name
            
        try:
            success = save_config_to_file(config_data, file_path, ConfigFormat.YAML)
            
            assert success is True
            
            with open(file_path, 'r') as f:
                saved_data = yaml.safe_load(f)
                
            assert saved_data == config_data
        finally:
            Path(file_path).unlink()


class TestIntegration:
    """Testes de integração."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        shutil.rmtree(self.temp_dir)
        
    def test_full_config_workflow(self):
        """Testa workflow completo de configuração."""
        config_file = Path(self.temp_dir) / "config.json"
        config_manager = CentralizedConfigManager(str(config_file))
        
        # Configuração inicial
        initial_config = {
            'database': {'host': 'localhost', 'port': 5432},
            'logging': {'level': 'INFO'}
        }
        
        config_manager.config = initial_config
        config_manager.save_config("admin", "initial setup")
        
        # Fazer mudanças
        config_manager.set_config('database', 'host', 'prod_host', "admin", "production setup")
        config_manager.set_config('logging', 'level', 'WARNING', "admin", "production logging")
        
        # Verificar configuração final
        final_config = config_manager.get_config()
        assert final_config['database']['host'] == 'prod_host'
        assert final_config['logging']['level'] == 'WARNING'
        
        # Verificar histórico
        history = config_manager.get_change_history()
        assert len(history) == 3  # initial + 2 changes
        
        # Verificar backups
        backups = config_manager.backup_manager.list_backups()
        assert len(backups) >= 3
        
    def test_config_validation_workflow(self):
        """Testa workflow de validação de configuração."""
        config_manager = CentralizedConfigManager()
        
        # Configuração válida
        valid_config = {
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'test_db',
                'username': 'test_user'
            },
            'logging': {
                'level': 'INFO',
                'format': 'json'
            }
        }
        
        config_manager.config = valid_config
        success = config_manager.save_config()
        assert success is True
        
        # Configuração inválida
        invalid_config = {
            'database': {
                'host': 'localhost',
                'port': 'invalid_port',  # Tipo incorreto
                # 'database' ausente
                'username': 'test_user'
            }
        }
        
        config_manager.config = invalid_config
        success = config_manager.save_config()
        assert success is False
        
    def test_backup_restore_workflow(self):
        """Testa workflow de backup e restore."""
        config_manager = CentralizedConfigManager()
        
        # Configuração inicial
        config_manager.set_config('database', 'host', 'initial_host', "admin", "initial")
        
        # Fazer mudanças
        config_manager.set_config('database', 'host', 'changed_host', "admin", "change")
        config_manager.set_config('database', 'port', 5432, "admin", "change")
        
        # Listar backups
        backups = config_manager.backup_manager.list_backups()
        assert len(backups) >= 3
        
        # Fazer rollback para backup inicial
        initial_backup = backups[-1]  # Backup mais antigo
        success = config_manager.rollback_config(initial_backup['hash'], "admin")
        
        assert success is True
        assert config_manager.get_config('database', 'host') == 'initial_host'
        assert config_manager.get_config('database', 'port') is None  # Não existia no backup inicial 