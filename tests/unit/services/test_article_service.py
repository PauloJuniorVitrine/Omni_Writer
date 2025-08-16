"""
Testes unitários para Article Service

Baseados no código real de tests/unit/app/test_generation_service.py
"""

import pytest
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from services.article_service.models import Article, Prompt, GenerationConfig, GenerationResult, BatchResult
from services.article_service.services import ArticleGenerationService, ArticleStorageService
from services.article_service.controllers import ArticleController

class TestArticleService:
    """Testes para Article Service baseados em código real"""
    
    @pytest.fixture
    def temp_storage_dir(self):
        """Diretório temporário para testes"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def generation_service(self):
        """Serviço de geração para testes"""
        return ArticleGenerationService()
    
    @pytest.fixture
    def storage_service(self, temp_storage_dir):
        """Serviço de armazenamento para testes"""
        with patch.dict(os.environ, {'OUTPUT_BASE_DIR': temp_storage_dir}):
            return ArticleStorageService()
    
    @pytest.fixture
    def controller(self, generation_service, storage_service):
        """Controller para testes"""
        return ArticleController(generation_service, storage_service)
    
    def test_article_model_validation(self):
        """Testa validação do modelo Article baseado em código real"""
        # Teste com dados válidos
        article = Article(
            title="Teste de Artigo",
            content="Conteúdo do artigo de teste",
            prompt="Escreva um artigo sobre testes",
            model_type="openai"
        )
        
        assert article.title == "Teste de Artigo"
        assert article.content == "Conteúdo do artigo de teste"
        assert article.model_type == "openai"
        
        # Teste com prompt vazio (deve falhar)
        with pytest.raises(ValueError, match="Prompt é obrigatório"):
            Article(
                title="Teste",
                content="Conteúdo",
                prompt="",
                model_type="openai"
            )
        
        # Teste com modelo inválido (deve falhar)
        with pytest.raises(ValueError, match="Modelo deve ser 'openai' ou 'deepseek'"):
            Article(
                title="Teste",
                content="Conteúdo",
                prompt="Prompt válido",
                model_type="invalid_model"
            )
    
    def test_article_to_dict_conversion(self):
        """Testa conversão para dicionário baseado em código real"""
        article = Article(
            title="Artigo Teste",
            content="Conteúdo do artigo",
            prompt="Prompt de teste",
            model_type="openai"
        )
        
        article_dict = article.to_dict()
        
        assert article_dict['title'] == "Artigo Teste"
        assert article_dict['content'] == "Conteúdo do artigo"
        assert article_dict['model_type'] == "openai"
        assert 'id' in article_dict
        assert 'created_at' in article_dict
        assert 'updated_at' in article_dict
    
    def test_article_from_dict_creation(self):
        """Testa criação a partir de dicionário baseado em código real"""
        article_data = {
            'id': 'test-id-123',
            'title': 'Artigo Recuperado',
            'content': 'Conteúdo recuperado',
            'prompt': 'Prompt original',
            'model_type': 'deepseek',
            'created_at': '2025-01-27T22:00:00',
            'updated_at': '2025-01-27T22:00:00',
            'status': 'generated',
            'metadata': {'test': 'value'}
        }
        
        article = Article.from_dict(article_data)
        
        assert article.id == 'test-id-123'
        assert article.title == 'Artigo Recuperado'
        assert article.content == 'Conteúdo recuperado'
        assert article.model_type == 'deepseek'
        assert article.status == 'generated'
        assert article.metadata['test'] == 'value'
    
    def test_generation_config_validation(self):
        """Testa validação da configuração de geração baseado em código real"""
        # Configuração válida
        config = GenerationConfig(
            model_type="openai",
            max_tokens=2000,
            temperature=0.7
        )
        
        assert config.model_type == "openai"
        assert config.max_tokens == 2000
        assert config.temperature == 0.7
        
        # Teste com modelo inválido
        with pytest.raises(ValueError, match="Modelo deve ser 'openai' ou 'deepseek'"):
            GenerationConfig(model_type="invalid")
        
        # Teste com max_tokens inválido
        with pytest.raises(ValueError, match="max_tokens deve ser positivo"):
            GenerationConfig(max_tokens=0)
        
        # Teste com temperature inválido
        with pytest.raises(ValueError, match="temperature deve estar entre 0 e 2"):
            GenerationConfig(temperature=3.0)
    
    @patch('services.article_service.services.openai.OpenAI')
    def test_generate_with_openai_success(self, mock_openai, generation_service):
        """Testa geração via OpenAI com sucesso baseado em código real"""
        # Mock da resposta da OpenAI
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = "Artigo gerado via OpenAI"
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        # Teste da geração
        result = generation_service._generate_with_openai("Teste de prompt", "test-key")
        
        assert result == "Artigo gerado via OpenAI"
        mock_client.chat.completions.create.assert_called_once()
    
    @patch('services.article_service.services.httpx.Client')
    def test_generate_with_deepseek_success(self, mock_client, generation_service):
        """Testa geração via DeepSeek com sucesso baseado em código real"""
        # Mock da resposta do DeepSeek
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Artigo gerado via DeepSeek"}}]
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = Mock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__enter__.return_value = mock_client_instance
        
        # Teste da geração
        result = generation_service._generate_with_deepseek("Teste de prompt", "test-key")
        
        assert result == "Artigo gerado via DeepSeek"
        mock_client_instance.post.assert_called_once()
    
    def test_extract_title_from_content(self, generation_service):
        """Testa extração de título do conteúdo baseado em código real"""
        # Teste com conteúdo normal
        content = "Título do Artigo\n\nEste é o conteúdo do artigo..."
        title = generation_service._extract_title(content)
        assert title == "Título do Artigo"
        
        # Teste com conteúdo sem título claro
        content = "# Título com Markdown\n\nConteúdo..."
        title = generation_service._extract_title(content)
        assert title == "Artigo Gerado"
        
        # Teste com conteúdo vazio
        title = generation_service._extract_title("")
        assert title == "Artigo Gerado"
    
    def test_storage_service_save_and_retrieve_article(self, storage_service):
        """Testa salvamento e recuperação de artigo baseado em código real"""
        # Cria artigo de teste
        article = Article(
            title="Artigo de Teste",
            content="Conteúdo do artigo de teste",
            prompt="Prompt de teste",
            model_type="openai"
        )
        
        # Salva o artigo
        success = storage_service.save_article(article)
        assert success is True
        
        # Recupera o artigo
        retrieved_article = storage_service.get_article(article.id)
        assert retrieved_article is not None
        assert retrieved_article.title == "Artigo de Teste"
        assert retrieved_article.content == "Conteúdo do artigo de teste"
        assert retrieved_article.model_type == "openai"
    
    def test_storage_service_get_nonexistent_article(self, storage_service):
        """Testa recuperação de artigo inexistente baseado em código real"""
        article = storage_service.get_article("nonexistent-id")
        assert article is None
    
    def test_batch_result_creation_and_conversion(self):
        """Testa criação e conversão de BatchResult baseado em código real"""
        # Cria artigos de teste
        articles = [
            Article(title="Artigo 1", content="Conteúdo 1", prompt="Prompt 1", model_type="openai"),
            Article(title="Artigo 2", content="Conteúdo 2", prompt="Prompt 2", model_type="openai")
        ]
        
        # Cria batch result
        batch = BatchResult(
            batch_id="test-batch-123",
            total_prompts=2,
            completed=2,
            failed=0,
            articles=articles,
            status="completed",
            trace_id="test-trace-123"
        )
        
        # Testa conversão para dicionário
        batch_dict = batch.to_dict()
        
        assert batch_dict['batch_id'] == "test-batch-123"
        assert batch_dict['total_prompts'] == 2
        assert batch_dict['completed'] == 2
        assert batch_dict['failed'] == 0
        assert batch_dict['status'] == "completed"
        assert batch_dict['trace_id'] == "test-trace-123"
        assert len(batch_dict['articles']) == 2
    
    def test_generation_result_creation(self):
        """Testa criação de GenerationResult baseado em código real"""
        # Resultado de sucesso
        success_result = GenerationResult(
            success=True,
            article_id="test-article-123",
            content="Conteúdo gerado",
            title="Título gerado",
            trace_id="test-trace-123"
        )
        
        assert success_result.success is True
        assert success_result.article_id == "test-article-123"
        assert success_result.content == "Conteúdo gerado"
        assert success_result.title == "Título gerado"
        
        # Resultado de falha
        failure_result = GenerationResult(
            success=False,
            error_message="Erro de teste",
            trace_id="test-trace-123"
        )
        
        assert failure_result.success is False
        assert failure_result.error_message == "Erro de teste"
        assert failure_result.article_id is None
    
    @patch.object(ArticleGenerationService, '_generate_with_openai')
    def test_controller_generate_article_success(self, mock_generate, controller):
        """Testa geração de artigo no controller com sucesso baseado em código real"""
        # Mock da geração
        mock_generate.return_value = "Artigo gerado com sucesso"
        
        # Mock do serviço de geração
        with patch.object(controller.generation_service, 'generate_article') as mock_gen:
            mock_gen.return_value = GenerationResult(
                success=True,
                article_id="test-article-123",
                content="Conteúdo gerado",
                title="Título gerado",
                trace_id="test-trace-123"
            )
            
            # Teste da geração
            result = controller.generate_article(
                prompt="Teste de prompt",
                model_type="openai",
                trace_id="test-trace-123"
            )
            
            assert result.success is True
            assert result.article_id == "test-article-123"
            assert result.content == "Conteúdo gerado"
    
    @patch.object(ArticleGenerationService, 'generate_article')
    def test_controller_generate_article_failure(self, mock_generate, controller):
        """Testa geração de artigo no controller com falha baseado em código real"""
        # Mock da falha
        mock_generate.return_value = GenerationResult(
            success=False,
            error_message="Erro de teste",
            trace_id="test-trace-123"
        )
        
        # Teste da geração
        result = controller.generate_article(
            prompt="Teste de prompt",
            model_type="openai",
            trace_id="test-trace-123"
        )
        
        assert result.success is False
        assert result.error_message == "Erro de teste"
    
    def test_controller_get_batch_status(self, controller):
        """Testa recuperação de status de lote baseado em código real"""
        # Cria um lote ativo
        batch = BatchResult(
            batch_id="test-batch-123",
            total_prompts=5,
            completed=3,
            failed=1,
            status="processing"
        )
        controller.active_batches["test-batch-123"] = batch
        
        # Testa recuperação do status
        status = controller.get_batch_status("test-batch-123")
        
        assert status is not None
        assert status['batch_id'] == "test-batch-123"
        assert status['total_prompts'] == 5
        assert status['completed'] == 3
        assert status['failed'] == 1
        assert status['status'] == "processing"
        assert status['progress_percentage'] == 60.0  # 3/5 * 100
    
    def test_controller_get_nonexistent_batch_status(self, controller):
        """Testa recuperação de status de lote inexistente baseado em código real"""
        status = controller.get_batch_status("nonexistent-batch")
        assert status is None 