"""
Testes para Sistema de Logging Otimizado - Gargalo Baixo

Prompt: Testes para gargalos baixos - LOGGING EXCESSIVO
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T11:00:00Z
Tracing ID: GARGALO_BAIXO_TEST_20250127_001

Testes baseados no código real implementado em shared/optimized_logging_config.py
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
import logging
import gzip
import json
from datetime import datetime
import os

from shared.optimized_logging_config import (
    OptimizedLogFormatter,
    CompressedRotatingFileHandler,
    LogSampler,
    OptimizedLoggingConfig,
    LogMonitor,
    get_optimized_logger,
    setup_logging_monitoring,
    log_with_sampling
)


class TestOptimizedLogFormatter:
    """Testes para OptimizedLogFormatter."""
    
    def test_format_basic_log(self):
        """Testa formatação básica de log."""
        formatter = OptimizedLogFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        result = formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['level'] == 'INFO'
        assert log_data['logger'] == 'test_logger'
        assert log_data['message'] == 'Test message'
        assert 'timestamp' in log_data
        
    def test_format_with_trace_id(self):
        """Testa formatação com trace_id."""
        formatter = OptimizedLogFormatter(include_trace_id=True)
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.trace_id = "test-trace-123"
        
        result = formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['trace_id'] == "test-trace-123"
        
    def test_format_with_context(self):
        """Testa formatação com contexto."""
        formatter = OptimizedLogFormatter(include_context=True)
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.context = {"user_id": 123, "action": "test"}
        
        result = formatter.format(record)
        log_data = json.loads(result)
        
        assert log_data['context'] == {"user_id": 123, "action": "test"}
        
    def test_format_with_exception(self):
        """Testa formatação com exceção."""
        formatter = OptimizedLogFormatter()
        
        try:
            raise ValueError("Test error")
        except ValueError:
            record = logging.LogRecord(
                name="test_logger",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Test error message",
                args=(),
                exc_info=(ValueError, ValueError("Test error"), None)
            )
        
        result = formatter.format(record)
        log_data = json.loads(result)
        
        assert 'exception' in log_data
        assert log_data['exception']['type'] == 'ValueError'
        assert 'Test error' in log_data['exception']['message']


class TestCompressedRotatingFileHandler:
    """Testes para CompressedRotatingFileHandler."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test.log"
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        shutil.rmtree(self.temp_dir)
        
    def test_do_rollover_creates_compressed_file(self):
        """Testa que rollover cria arquivo comprimido."""
        handler = CompressedRotatingFileHandler(
            str(self.log_file),
            maxBytes=100,
            backupCount=2
        )
        
        # Escrever dados suficientes para trigger rollover
        handler.emit(logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="A" * 200,  # Mensagem grande
            args=(),
            exc_info=None
        ))
        
        # Verificar se arquivo comprimido foi criado
        compressed_file = self.log_file.parent / f"{self.log_file.name}.1.gz"
        assert compressed_file.exists()
        
        # Verificar se arquivo comprimido pode ser lido
        with gzip.open(compressed_file, 'rt') as f:
            content = f.read()
            assert "A" * 200 in content


class TestLogSampler:
    """Testes para LogSampler."""
    
    def test_should_log_critical_levels(self):
        """Testa que níveis críticos sempre são logados."""
        sampler = LogSampler(sample_rate=0.1, critical_levels=['ERROR', 'CRITICAL'])
        
        # Níveis críticos devem sempre retornar True
        assert sampler.should_log('ERROR') is True
        assert sampler.should_log('CRITICAL') is True
        
    def test_should_log_sampling(self):
        """Testa sampling de logs."""
        sampler = LogSampler(sample_rate=0.5, critical_levels=['ERROR'])
        
        # Com sample_rate=0.5, aproximadamente metade deve retornar True
        results = [sampler.should_log('INFO') for _ in range(100)]
        true_count = sum(results)
        
        # Deve estar próximo de 50% (com tolerância)
        assert 40 <= true_count <= 60
        
    def test_should_log_counter_increment(self):
        """Testa que contador é incrementado."""
        sampler = LogSampler(sample_rate=0.1)
        
        initial_counter = sampler._counter
        sampler.should_log('INFO')
        
        assert sampler._counter == initial_counter + 1


class TestOptimizedLoggingConfig:
    """Testes para OptimizedLoggingConfig."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = OptimizedLoggingConfig({
            'logs_dir': self.temp_dir,
            'log_level': 'INFO',
            'max_file_size': '1MB',
            'backup_count': 3,
            'retention_days': 7,
            'compression_enabled': True,
            'sampling_enabled': True,
            'sample_rate': 0.5,
            'critical_levels': ['ERROR', 'CRITICAL'],
            'rotation_strategy': 'size',
            'rotation_interval': '1 day',
            'monitoring_enabled': False
        })
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        shutil.rmtree(self.temp_dir)
        
    def test_get_optimized_logger(self):
        """Testa obtenção de logger otimizado."""
        logger = self.config.get_optimized_logger("test_logger")
        
        assert logger.name == "test_logger"
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 3  # console, file, error
        
    def test_get_optimized_logger_custom_level(self):
        """Testa logger com nível customizado."""
        logger = self.config.get_optimized_logger("test_logger", "DEBUG")
        
        assert logger.level == logging.DEBUG
        
    def test_get_optimized_logger_caching(self):
        """Testa que loggers são cacheados."""
        logger1 = self.config.get_optimized_logger("test_logger")
        logger2 = self.config.get_optimized_logger("test_logger")
        
        assert logger1 is logger2
        
    def test_cleanup_old_logs(self):
        """Testa limpeza de logs antigos."""
        # Criar arquivo de log "antigo"
        old_log = Path(self.temp_dir) / "old.log"
        old_log.touch()
        
        # Modificar timestamp para simular arquivo antigo
        old_timestamp = datetime.now().timestamp() - (10 * 24 * 3600)  # 10 dias atrás
        os.utime(old_log, (old_timestamp, old_timestamp))
        
        # Criar arquivo de log "recente"
        new_log = Path(self.temp_dir) / "new.log"
        new_log.touch()
        
        self.config.cleanup_old_logs()
        
        # Arquivo antigo deve ser removido
        assert not old_log.exists()
        # Arquivo recente deve permanecer
        assert new_log.exists()
        
    def test_get_log_stats(self):
        """Testa obtenção de estatísticas de logs."""
        # Criar alguns arquivos de log
        log1 = Path(self.temp_dir) / "app.log"
        log1.write_text("test content")
        
        log2 = Path(self.temp_dir) / "errors.log.gz"
        log2.write_text("compressed content")
        
        stats = self.config.get_log_stats()
        
        assert stats['total_files'] == 2
        assert stats['compressed_files'] == 1
        assert stats['total_size'] > 0
        assert stats['oldest_file'] is not None
        assert stats['newest_file'] is not None
        
    def test_parse_size(self):
        """Testa parsing de strings de tamanho."""
        assert self.config._parse_size("1KB") == 1024
        assert self.config._parse_size("1MB") == 1024 * 1024
        assert self.config._parse_size("1GB") == 1024 * 1024 * 1024


class TestLogMonitor:
    """Testes para LogMonitor."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = OptimizedLoggingConfig({
            'logs_dir': self.temp_dir,
            'monitoring_enabled': True
        })
        self.monitor = LogMonitor(self.config)
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.monitor.stop_monitoring()
        shutil.rmtree(self.temp_dir)
        
    def test_start_monitoring(self):
        """Testa início do monitoramento."""
        with patch('threading.Thread') as mock_thread:
            self.monitor.start_monitoring()
            
            mock_thread.assert_called_once()
            mock_thread.return_value.start.assert_called_once()
            
    def test_stop_monitoring(self):
        """Testa parada do monitoramento."""
        self.monitor.start_monitoring()
        self.monitor.stop_monitoring()
        
        assert self.monitor.stop_monitoring is True


class TestConvenienceFunctions:
    """Testes para funções de conveniência."""
    
    def test_get_optimized_logger_function(self):
        """Testa função get_optimized_logger."""
        with patch('shared.optimized_logging_config.OptimizedLoggingConfig') as mock_config_class:
            mock_config = MagicMock()
            mock_config_class.return_value = mock_config
            
            logger = get_optimized_logger("test_logger")
            
            mock_config.get_optimized_logger.assert_called_once_with("test_logger", None)
            
    def test_setup_logging_monitoring(self):
        """Testa função setup_logging_monitoring."""
        with patch('shared.optimized_logging_config.OptimizedLoggingConfig') as mock_config_class:
            with patch('shared.optimized_logging_config.LogMonitor') as mock_monitor_class:
                mock_config = MagicMock()
                mock_config_class.return_value = mock_config
                
                mock_monitor = MagicMock()
                mock_monitor_class.return_value = mock_monitor
                
                result = setup_logging_monitoring()
                
                mock_monitor.start_monitoring.assert_called_once()
                assert result == mock_monitor
                
    def test_log_with_sampling(self):
        """Testa função log_with_sampling."""
        logger = MagicMock()
        
        log_with_sampling(
            logger=logger,
            level="INFO",
            message="Test message",
            trace_id="test-123",
            context={"user_id": 456}
        )
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args
        assert call_args[0][0] == "Test message"
        assert call_args[1]['extra']['trace_id'] == "test-123"
        assert call_args[1]['extra']['context'] == {"user_id": 456}


class TestIntegration:
    """Testes de integração."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.temp_dir = tempfile.mkdtemp()
        
    def teardown_method(self):
        """Cleanup após cada teste."""
        shutil.rmtree(self.temp_dir)
        
    def test_full_logging_workflow(self):
        """Testa workflow completo de logging."""
        config = OptimizedLoggingConfig({
            'logs_dir': self.temp_dir,
            'log_level': 'INFO',
            'max_file_size': '1MB',
            'backup_count': 2,
            'sampling_enabled': False,  # Desabilitar sampling para teste
            'monitoring_enabled': False
        })
        
        logger = config.get_optimized_logger("integration_test")
        
        # Fazer alguns logs
        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")
        
        # Verificar se arquivos foram criados
        app_log = Path(self.temp_dir) / "app.log"
        error_log = Path(self.temp_dir) / "errors.log"
        
        assert app_log.exists()
        assert error_log.exists()
        
        # Verificar conteúdo dos logs
        app_content = app_log.read_text()
        error_content = error_log.read_text()
        
        assert "Test info message" in app_content
        assert "Test warning message" in app_content
        assert "Test error message" in app_content
        assert "Test error message" in error_content
        
    def test_configuration_validation(self):
        """Testa validação de configuração."""
        # Configuração válida
        valid_config = {
            'logs_dir': self.temp_dir,
            'log_level': 'INFO',
            'max_file_size': '1MB',
            'backup_count': 3
        }
        
        config = OptimizedLoggingConfig(valid_config)
        assert config.config == valid_config
        
        # Configuração inválida (deve usar defaults)
        invalid_config = {
            'invalid_key': 'invalid_value'
        }
        
        config = OptimizedLoggingConfig(invalid_config)
        # Deve ter mesclado com defaults
        assert 'logs_dir' in config.config
        assert 'log_level' in config.config 