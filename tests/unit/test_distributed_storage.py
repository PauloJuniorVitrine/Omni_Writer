"""
Testes unitários para o sistema de storage distribuído.

Prompt: Testes para storage distribuído
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import pytest
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Importa o módulo de storage distribuído
from shared.distributed_storage import (
    DistributedStorage, DistributedStatus, DistributedFeedback, DistributedArticle,
    update_status, get_status, save_feedback, get_feedbacks, save_article, get_article
)

class TestDistributedStorage:
    """Testes para a classe DistributedStorage."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        # Mock das variáveis de ambiente
        self.env_patcher = patch.dict(os.environ, {
            'ENABLE_DISTRIBUTED_STORAGE': 'false',
            'STORAGE_FALLBACK': 'sqlite'
        })
        self.env_patcher.start()
        
        # Cria instância de teste
        self.storage = DistributedStorage()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        self.env_patcher.stop()
    
    def test_init_with_disabled_storage(self):
        """Testa inicialização com storage desabilitado."""
        assert self.storage.enabled is False
        assert self.storage.fallback_type == 'sqlite'
    
    @patch('shared.distributed_storage.ENABLE_DISTRIBUTED_STORAGE', True)
    @patch('shared.distributed_storage.create_engine')
    @patch('shared.distributed_storage.redis.from_url')
    def test_init_with_enabled_storage(self, mock_redis, mock_engine):
        """Testa inicialização com storage habilitado."""
        # Mock do PostgreSQL
        mock_engine_instance = Mock()
        mock_engine.return_value = mock_engine_instance
        
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.ping.return_value = True
        mock_redis.return_value = mock_redis_instance
        
        storage = DistributedStorage()
        
        assert storage.enabled is True
        mock_engine.assert_called_once()
        mock_redis.assert_called_once()
    
    def test_cache_key_generation(self):
        """Testa geração de chaves de cache."""
        key = self.storage._get_cache_key('status', 'test123')
        assert key == 'omniwriter:status:test123'
    
    @patch('shared.distributed_storage.redis.from_url')
    def test_cache_operations(self, mock_redis):
        """Testa operações de cache."""
        # Mock do Redis
        mock_redis_instance = Mock()
        mock_redis_instance.get.return_value = '{"test": "data"}'
        mock_redis.return_value = mock_redis_instance
        
        self.storage.redis_client = mock_redis_instance
        
        # Testa get
        result = self.storage._cache_get('test', 'key')
        assert result == {'test': 'data'}
        
        # Testa set
        self.storage._cache_set('test', 'key', {'data': 'value'})
        mock_redis_instance.setex.assert_called_once()
        
        # Testa delete
        self.storage._cache_delete('test', 'key')
        mock_redis_instance.delete.assert_called_once()
    
    @patch('shared.status_repository.update_status')
    def test_fallback_update_status(self, mock_update):
        """Testa fallback para atualização de status."""
        self.storage._fallback_update_status('test123', 10, 5, 'in_progress')
        mock_update.assert_called_once_with('test123', 10, 5, 'in_progress')
    
    @patch('shared.status_repository.get_status')
    def test_fallback_get_status(self, mock_get):
        """Testa fallback para obtenção de status."""
        mock_get.return_value = {'trace_id': 'test123', 'status': 'done'}
        
        result = self.storage._fallback_get_status('test123')
        assert result == {'trace_id': 'test123', 'status': 'done'}
        mock_get.assert_called_once_with('test123')
    
    @patch('feedback.storage.save_feedback')
    def test_fallback_save_feedback(self, mock_save):
        """Testa fallback para salvamento de feedback."""
        mock_save.return_value = 'ok'
        
        result = self.storage._fallback_save_feedback('user1', 'artigo1', 'positivo', 'ótimo!')
        assert result is True
        mock_save.assert_called_once_with('user1', 'artigo1', 'positivo', 'ótimo!')
    
    @patch('feedback.storage.get_feedbacks')
    def test_fallback_get_feedbacks(self, mock_get):
        """Testa fallback para obtenção de feedbacks."""
        mock_get.return_value = [{'id': 1, 'user_id': 'user1'}]
        
        result = self.storage._fallback_get_feedbacks('artigo1')
        assert result == [{'id': 1, 'user_id': 'user1'}]
        mock_get.assert_called_once_with('artigo1')
    
    @patch('os.makedirs')
    @patch('builtins.open', create=True)
    def test_fallback_save_article(self, mock_open, mock_makedirs):
        """Testa fallback para salvamento de artigo."""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = self.storage._fallback_save_article('test123', 'artigo.md', 'conteúdo do artigo')
        assert result is True
        mock_makedirs.assert_called_once_with('output', exist_ok=True)
        mock_file.write.assert_called_once_with('conteúdo do artigo')
    
    @patch('os.path.exists')
    @patch('builtins.open', create=True)
    def test_fallback_get_article(self, mock_open, mock_exists):
        """Testa fallback para obtenção de artigo."""
        mock_exists.return_value = True
        mock_file = Mock()
        mock_file.read.return_value = 'conteúdo do artigo'
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = self.storage._fallback_get_article('test123', 'artigo.md')
        assert result == {
            'trace_id': 'test123',
            'filename': 'artigo.md',
            'content': 'conteúdo do artigo'
        }

class TestDistributedStorageModels:
    """Testes para os modelos de dados."""
    
    def test_distributed_status_model(self):
        """Testa modelo DistributedStatus."""
        status = DistributedStatus(
            trace_id='test123',
            total=10,
            current=5,
            status='in_progress',
            user_id='user1',
            model_type='gpt-4'
        )
        
        assert status.trace_id == 'test123'
        assert status.total == 10
        assert status.current == 5
        assert status.status == 'in_progress'
        assert status.user_id == 'user1'
        assert status.model_type == 'gpt-4'
    
    def test_distributed_feedback_model(self):
        """Testa modelo DistributedFeedback."""
        feedback = DistributedFeedback(
            user_id='user1',
            artigo_id='artigo1',
            tipo='positivo',
            comentario='Excelente artigo!',
            rating=5
        )
        
        assert feedback.user_id == 'user1'
        assert feedback.artigo_id == 'artigo1'
        assert feedback.tipo == 'positivo'
        assert feedback.comentario == 'Excelente artigo!'
        assert feedback.rating == 5
    
    def test_distributed_article_model(self):
        """Testa modelo DistributedArticle."""
        article = DistributedArticle(
            trace_id='test123',
            filename='artigo.md',
            content_hash='abc123',
            content='conteúdo do artigo',
            model_type='gpt-4',
            prompt='Escreva um artigo sobre IA'
        )
        
        assert article.trace_id == 'test123'
        assert article.filename == 'artigo.md'
        assert article.content_hash == 'abc123'
        assert article.content == 'conteúdo do artigo'
        assert article.model_type == 'gpt-4'
        assert article.prompt == 'Escreva um artigo sobre IA'

class TestDistributedStorageIntegration:
    """Testes de integração para o storage distribuído."""
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_update_status_function(self, mock_storage):
        """Testa função de conveniência update_status."""
        update_status('test123', 10, 5, 'in_progress', 'user1', 'gpt-4')
        mock_storage.update_status.assert_called_once_with(
            'test123', 10, 5, 'in_progress', 'user1', 'gpt-4', None
        )
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_get_status_function(self, mock_storage):
        """Testa função de conveniência get_status."""
        mock_storage.get_status.return_value = {'status': 'done'}
        
        result = get_status('test123')
        assert result == {'status': 'done'}
        mock_storage.get_status.assert_called_once_with('test123')
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_save_feedback_function(self, mock_storage):
        """Testa função de conveniência save_feedback."""
        mock_storage.save_feedback.return_value = True
        
        result = save_feedback('user1', 'artigo1', 'positivo', 'ótimo!', 5)
        assert result is True
        mock_storage.save_feedback.assert_called_once_with(
            'user1', 'artigo1', 'positivo', 'ótimo!', 5, None
        )
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_get_feedbacks_function(self, mock_storage):
        """Testa função de conveniência get_feedbacks."""
        mock_storage.get_feedbacks.return_value = [{'id': 1}]
        
        result = get_feedbacks('artigo1')
        assert result == [{'id': 1}]
        mock_storage.get_feedbacks.assert_called_once_with('artigo1', None)
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_save_article_function(self, mock_storage):
        """Testa função de conveniência save_article."""
        mock_storage.save_article.return_value = True
        
        result = save_article('test123', 'artigo.md', 'conteúdo', 'gpt-4', 'prompt')
        assert result is True
        mock_storage.save_article.assert_called_once_with(
            'test123', 'artigo.md', 'conteúdo', 'gpt-4', 'prompt', None
        )
    
    @patch('shared.distributed_storage.distributed_storage')
    def test_get_article_function(self, mock_storage):
        """Testa função de conveniência get_article."""
        mock_storage.get_article.return_value = {'content': 'artigo'}
        
        result = get_article('test123', 'artigo.md')
        assert result == {'content': 'artigo'}
        mock_storage.get_article.assert_called_once_with('test123', 'artigo.md')

class TestDistributedStorageErrorHandling:
    """Testes para tratamento de erros."""
    
    def setup_method(self):
        """Configuração antes de cada teste."""
        self.env_patcher = patch.dict(os.environ, {
            'ENABLE_DISTRIBUTED_STORAGE': 'false'
        })
        self.env_patcher.start()
        self.storage = DistributedStorage()
    
    def teardown_method(self):
        """Limpeza após cada teste."""
        self.env_patcher.stop()
    
    @patch('shared.status_repository.update_status')
    def test_error_handling_in_fallback_update_status(self, mock_update):
        """Testa tratamento de erro no fallback de status."""
        mock_update.side_effect = Exception("Database error")
        
        # Não deve levantar exceção
        self.storage._fallback_update_status('test123', 10, 5, 'in_progress')
    
    @patch('shared.status_repository.get_status')
    def test_error_handling_in_fallback_get_status(self, mock_get):
        """Testa tratamento de erro no fallback de status."""
        mock_get.side_effect = Exception("Database error")
        
        result = self.storage._fallback_get_status('test123')
        assert result is None
    
    @patch('feedback.storage.save_feedback')
    def test_error_handling_in_fallback_save_feedback(self, mock_save):
        """Testa tratamento de erro no fallback de feedback."""
        mock_save.side_effect = Exception("Storage error")
        
        result = self.storage._fallback_save_feedback('user1', 'artigo1', 'positivo', 'ótimo!')
        assert result is False
    
    @patch('feedback.storage.get_feedbacks')
    def test_error_handling_in_fallback_get_feedbacks(self, mock_get):
        """Testa tratamento de erro no fallback de feedbacks."""
        mock_get.side_effect = Exception("Storage error")
        
        result = self.storage._fallback_get_feedbacks('artigo1')
        assert result == []

class TestDistributedStorageConfiguration:
    """Testes para configuração do storage distribuído."""
    
    def test_environment_variables(self):
        """Testa leitura de variáveis de ambiente."""
        with patch.dict(os.environ, {
            'POSTGRES_URL': 'postgresql://test:test@localhost:5432/test',
            'REDIS_URL': 'redis://localhost:6379/1',
            'ENABLE_DISTRIBUTED_STORAGE': 'true',
            'STORAGE_FALLBACK': 'files',
            'CACHE_TTL': '7200',
            'STORAGE_MAX_RETRIES': '5'
        }):
            from shared.distributed_storage import (
                POSTGRES_URL, REDIS_URL, ENABLE_DISTRIBUTED_STORAGE, 
                STORAGE_FALLBACK
            )
            
            assert POSTGRES_URL == 'postgresql://test:test@localhost:5432/test'
            assert REDIS_URL == 'redis://localhost:6379/1'
            assert ENABLE_DISTRIBUTED_STORAGE is True
            assert STORAGE_FALLBACK == 'files'
    
    def test_default_configuration(self):
        """Testa configurações padrão."""
        with patch.dict(os.environ, {}, clear=True):
            from shared.distributed_storage import (
                POSTGRES_URL, REDIS_URL, ENABLE_DISTRIBUTED_STORAGE, 
                STORAGE_FALLBACK
            )
            
            assert 'postgresql://user:password@localhost:5432/omniwriter' in POSTGRES_URL
            assert REDIS_URL == 'redis://localhost:6379/0'
            assert ENABLE_DISTRIBUTED_STORAGE is True
            assert STORAGE_FALLBACK == 'sqlite'

class TestDistributedStorageLogging:
    """Testes para logging do storage distribuído."""
    
    @patch('shared.distributed_storage.storage_logger')
    def test_logging_in_operations(self, mock_logger):
        """Testa logging em operações."""
        with patch.dict(os.environ, {'ENABLE_DISTRIBUTED_STORAGE': 'false'}):
            storage = DistributedStorage()
            
            # Testa logging de erro
            storage._fallback_update_status('test123', 10, 5, 'in_progress')
            
            # Verifica se o logger foi chamado
            assert mock_logger.error.called or mock_logger.info.called

if __name__ == '__main__':
    pytest.main([__file__]) 