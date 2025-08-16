"""
Testes para o serviço de validação de blogs, categorias e prompts.
"""
import pytest
from unittest.mock import Mock, patch
from sqlalchemy.orm import Session
from omni_writer.domain.validation_service import ValidationService
from omni_writer.domain.orm_models import Blog, Categoria, Prompt


class TestValidationService:
    """Testes para ValidationService."""
    
    @pytest.fixture
    def mock_session(self):
        """Mock da sessão do banco."""
        return Mock(spec=Session)
    
    @pytest.fixture
    def validation_service(self, mock_session):
        """Instância do ValidationService com mock."""
        return ValidationService(mock_session)
    
    @pytest.fixture
    def mock_blog(self):
        """Mock de um blog."""
        blog = Mock(spec=Blog)
        blog.id = 1
        blog.nome = "Blog Teste"
        return blog
    
    @pytest.fixture
    def mock_categoria(self):
        """Mock de uma categoria."""
        categoria = Mock(spec=Categoria)
        categoria.id = 1
        categoria.nome = "Categoria Teste"
        categoria.blog_id = 1
        return categoria
    
    @pytest.fixture
    def mock_prompt(self):
        """Mock de um prompt."""
        prompt = Mock(spec=Prompt)
        prompt.id = 1
        prompt.text = "Prompt teste"
        prompt.categoria_id = 1
        return prompt
    
    def test_validate_blog_creation_success(self, validation_service, mock_session):
        """Testa validação bem-sucedida de criação de blog."""
        # Arrange
        nome = "Novo Blog"
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 5
        
        # Act
        is_valid, error_message = validation_service.validate_blog_creation(nome)
        
        # Assert
        assert is_valid is True
        assert error_message is None
        mock_session.query.assert_called()
    
    def test_validate_blog_creation_duplicate_name(self, validation_service, mock_session, mock_blog):
        """Testa validação falhando por nome duplicado."""
        # Arrange
        nome = "Blog Existente"
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_blog
        
        # Act
        is_valid, error_message = validation_service.validate_blog_creation(nome)
        
        # Assert
        assert is_valid is False
        assert "Já existe um blog com o nome" in error_message
    
    def test_validate_blog_creation_max_limit(self, validation_service, mock_session):
        """Testa validação falhando por limite máximo de blogs."""
        # Arrange
        nome = "Novo Blog"
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 15
        
        # Act
        is_valid, error_message = validation_service.validate_blog_creation(nome)
        
        # Assert
        assert is_valid is False
        assert "Limite máximo de 15 blogs" in error_message
    
    def test_validate_categoria_creation_success(self, validation_service, mock_session, mock_blog):
        """Testa validação bem-sucedida de criação de categoria."""
        # Arrange
        blog_id = 1
        nome = "Nova Categoria"
        mock_session.query.return_value.get.return_value = mock_blog
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 3
        
        # Act
        is_valid, error_message = validation_service.validate_categoria_creation(blog_id, nome)
        
        # Assert
        assert is_valid is True
        assert error_message is None
    
    def test_validate_categoria_creation_blog_not_found(self, validation_service, mock_session):
        """Testa validação falhando por blog não encontrado."""
        # Arrange
        blog_id = 999
        nome = "Nova Categoria"
        mock_session.query.return_value.get.return_value = None
        
        # Act
        is_valid, error_message = validation_service.validate_categoria_creation(blog_id, nome)
        
        # Assert
        assert is_valid is False
        assert "Blog não encontrado" in error_message
    
    def test_validate_categoria_creation_duplicate_name(self, validation_service, mock_session, mock_blog, mock_categoria):
        """Testa validação falhando por nome duplicado na categoria."""
        # Arrange
        blog_id = 1
        nome = "Categoria Existente"
        mock_session.query.return_value.get.return_value = mock_blog
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_categoria
        
        # Act
        is_valid, error_message = validation_service.validate_categoria_creation(blog_id, nome)
        
        # Assert
        assert is_valid is False
        assert "Já existe uma categoria" in error_message
    
    def test_validate_categoria_creation_max_limit(self, validation_service, mock_session, mock_blog):
        """Testa validação falhando por limite máximo de categorias."""
        # Arrange
        blog_id = 1
        nome = "Nova Categoria"
        mock_session.query.return_value.get.return_value = mock_blog
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 7
        
        # Act
        is_valid, error_message = validation_service.validate_categoria_creation(blog_id, nome)
        
        # Assert
        assert is_valid is False
        assert "Limite máximo de 7 categorias" in error_message
    
    def test_validate_prompt_creation_success(self, validation_service, mock_session, mock_categoria):
        """Testa validação bem-sucedida de criação de prompt."""
        # Arrange
        categoria_id = 1
        text = "Novo prompt"
        mock_session.query.return_value.get.return_value = mock_categoria
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 2
        
        # Act
        is_valid, error_message = validation_service.validate_prompt_creation(categoria_id, text)
        
        # Assert
        assert is_valid is True
        assert error_message is None
    
    def test_validate_prompt_creation_categoria_not_found(self, validation_service, mock_session):
        """Testa validação falhando por categoria não encontrada."""
        # Arrange
        categoria_id = 999
        text = "Novo prompt"
        mock_session.query.return_value.get.return_value = None
        
        # Act
        is_valid, error_message = validation_service.validate_prompt_creation(categoria_id, text)
        
        # Assert
        assert is_valid is False
        assert "Categoria não encontrada" in error_message
    
    def test_validate_prompt_creation_duplicate_text(self, validation_service, mock_session, mock_categoria, mock_prompt):
        """Testa validação falhando por texto duplicado."""
        # Arrange
        categoria_id = 1
        text = "Prompt existente"
        mock_session.query.return_value.get.return_value = mock_categoria
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_prompt
        
        # Act
        is_valid, error_message = validation_service.validate_prompt_creation(categoria_id, text)
        
        # Assert
        assert is_valid is False
        assert "Já existe um prompt com este texto" in error_message
    
    def test_validate_prompt_creation_max_limit(self, validation_service, mock_session, mock_categoria):
        """Testa validação falhando por limite máximo de prompts."""
        # Arrange
        categoria_id = 1
        text = "Novo prompt"
        mock_session.query.return_value.get.return_value = mock_categoria
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.query.return_value.count.return_value = 3
        
        # Act
        is_valid, error_message = validation_service.validate_prompt_creation(categoria_id, text)
        
        # Assert
        assert is_valid is False
        assert "Limite máximo de 3 prompts" in error_message
    
    def test_validate_prompt_upload_success(self, validation_service, mock_session, mock_categoria):
        """Testa validação bem-sucedida de upload de prompts."""
        # Arrange
        categoria_id = 1
        file_content = "Prompt 1\nPrompt 2\nPrompt 3"
        mock_session.query.return_value.get.return_value = mock_categoria
        mock_session.query.return_value.filter_by.return_value.all.return_value = []
        
        # Act
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria_id, file_content)
        
        # Assert
        assert is_valid is True
        assert error_message is None
        assert len(prompts) == 3
        assert "Prompt 1" in prompts
        assert "Prompt 2" in prompts
        assert "Prompt 3" in prompts
    
    def test_validate_prompt_upload_empty_file(self, validation_service, mock_session, mock_categoria):
        """Testa validação falhando por arquivo vazio."""
        # Arrange
        categoria_id = 1
        file_content = ""
        mock_session.query.return_value.get.return_value = mock_categoria
        
        # Act
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria_id, file_content)
        
        # Assert
        assert is_valid is False
        assert "Arquivo não contém prompts válidos" in error_message
        assert len(prompts) == 0
    
    def test_validate_prompt_upload_too_many_prompts(self, validation_service, mock_session, mock_categoria):
        """Testa validação falhando por muitos prompts."""
        # Arrange
        categoria_id = 1
        file_content = "Prompt 1\nPrompt 2\nPrompt 3\nPrompt 4"
        mock_session.query.return_value.get.return_value = mock_categoria
        
        # Act
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria_id, file_content)
        
        # Assert
        assert is_valid is False
        assert "Arquivo contém 4 prompts, máximo permitido é 3" in error_message
    
    def test_validate_prompt_upload_duplicates(self, validation_service, mock_session, mock_categoria, mock_prompt):
        """Testa validação falhando por prompts duplicados."""
        # Arrange
        categoria_id = 1
        file_content = "Prompt existente\nPrompt novo"
        mock_session.query.return_value.get.return_value = mock_categoria
        mock_session.query.return_value.filter_by.return_value.all.return_value = [mock_prompt]
        mock_prompt.text = "Prompt existente"
        
        # Act
        is_valid, error_message, prompts = validation_service.validate_prompt_upload(categoria_id, file_content)
        
        # Assert
        assert is_valid is False
        assert "Prompts duplicados encontrados" in error_message
    
    def test_get_blog_stats(self, validation_service, mock_session):
        """Testa obtenção de estatísticas do blog."""
        # Arrange
        blog_id = 1
        mock_session.query.return_value.filter_by.return_value.count.side_effect = [3, 9]
        
        # Act
        stats = validation_service.get_blog_stats(blog_id)
        
        # Assert
        assert stats["categorias_count"] == 3
        assert stats["prompts_count"] == 9
        assert stats["max_categorias"] == 7
        assert stats["max_prompts_per_categoria"] == 3
    
    def test_get_system_stats(self, validation_service, mock_session):
        """Testa obtenção de estatísticas do sistema."""
        # Arrange
        mock_session.query.return_value.count.side_effect = [10, 35, 105]
        
        # Act
        stats = validation_service.get_system_stats()
        
        # Assert
        assert stats["total_blogs"] == 10
        assert stats["total_categorias"] == 35
        assert stats["total_prompts"] == 105
        assert stats["max_blogs"] == 15
        assert stats["max_categorias_per_blog"] == 7
        assert stats["max_prompts_per_categoria"] == 3
    
    def test_validation_service_constants(self, validation_service):
        """Testa se as constantes estão corretas."""
        assert validation_service.MAX_BLOGS == 15
        assert validation_service.MAX_CATEGORIAS_PER_BLOG == 7
        assert validation_service.MAX_PROMPTS_PER_CATEGORIA == 3 