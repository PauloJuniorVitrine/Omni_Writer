"""
Testes unitários para implementação CQRS.

Baseados no código real existente do domínio Omni Writer.
Testes seguem as regras enterprise: apenas código real, sem dados fictícios.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import pytest
import logging
from unittest.mock import Mock, patch
from datetime import datetime
from omni_writer.domain.commands import BaseCommand, CommandResult
from omni_writer.domain.commands.blog_commands import CreateBlogCommand, UpdateBlogCommand, DeleteBlogCommand
from omni_writer.domain.commands.article_commands import GenerateArticleCommand, GenerateArticlesForCategoriaCommand
from omni_writer.domain.command_handlers import CommandHandler
from omni_writer.domain.orm_models import Blog, Categoria, Cluster, Prompt
from omni_writer.domain.data_models import GenerationConfig, PromptInput, ArticleOutput

logger = logging.getLogger("test_cqrs")

class TestBaseCommand:
    """Testes para classe base de comandos baseados no código real."""
    
    def test_base_command_initialization(self):
        """Testa inicialização de comando base com dados reais."""
        # Dados baseados no modelo real de Blog
        test_data = {
            'nome': 'Blog de Tecnologia',
            'desc': 'Blog sobre tecnologia e inovação'
        }
        
        # Mock da classe abstrata para teste
        class TestCommand(BaseCommand):
            def _validate_command_data(self, data):
                if not data.get('nome'):
                    raise ValueError("Nome é obrigatório")
            
            def execute(self, session):
                return self._create_success_result({'nome': data['nome']})
        
        command = TestCommand(**test_data)
        
        assert command.command_id is not None
        assert isinstance(command.timestamp, datetime)
        assert command._data == test_data
    
    def test_base_command_validation_error(self):
        """Testa validação de erro em comando base."""
        class TestCommand(BaseCommand):
            def _validate_command_data(self, data):
                raise ValueError("Dados inválidos")
            
            def execute(self, session):
                pass
        
        with pytest.raises(ValueError, match="Dados inválidos"):
            TestCommand(nome="")
    
    def test_command_result_creation(self):
        """Testa criação de resultado de comando baseado no código real."""
        result = CommandResult(
            success=True,
            data={'id': 1, 'nome': 'Blog Teste'},
            command_id='test-123',
            timestamp=datetime.utcnow()
        )
        
        assert result.success is True
        assert result.data['id'] == 1
        assert result.data['nome'] == 'Blog Teste'
        assert result.command_id == 'test-123'
        assert isinstance(result.to_dict(), dict)

class TestBlogCommands:
    """Testes para comandos de Blog baseados no código real."""
    
    def test_create_blog_command_validation(self):
        """Testa validação de criação de blog baseada no modelo real."""
        # Dados válidos baseados no modelo Blog real
        valid_data = {
            'nome': 'Blog de Marketing Digital',
            'desc': 'Blog sobre estratégias de marketing digital'
        }
        
        command = CreateBlogCommand(**valid_data)
        assert command._data == valid_data
    
    def test_create_blog_command_validation_error(self):
        """Testa erro de validação em criação de blog."""
        # Dados inválidos baseados nas validações reais
        invalid_data = {
            'nome': '',  # Nome vazio viola validação real
            'desc': 'Descrição válida'
        }
        
        with pytest.raises(ValueError, match="Nome do blog é obrigatório"):
            CreateBlogCommand(**invalid_data)
    
    def test_create_blog_command_execution(self):
        """Testa execução de criação de blog baseada no código real."""
        session = Mock()
        session.query.return_value.count.return_value = 5  # Abaixo do limite de 15
        session.query.return_value.filter.return_value.first.return_value = None  # Nome único
        
        mock_blog = Mock()
        mock_blog.id = 1
        mock_blog.nome = 'Blog de Tecnologia'
        mock_blog.desc = 'Blog sobre tecnologia'
        mock_blog.created_at = '2025-01-27 15:30:00'
        mock_blog.updated_at = '2025-01-27 15:30:00'
        
        session.add.return_value = None
        session.commit.return_value = None
        
        command = CreateBlogCommand(
            nome='Blog de Tecnologia',
            desc='Blog sobre tecnologia'
        )
        
        result = command.execute(session)
        
        assert result.success is True
        assert result.data['nome'] == 'Blog de Tecnologia'
        session.add.assert_called_once()
        session.commit.assert_called_once()
    
    def test_create_blog_command_limit_exceeded(self):
        """Testa limite de 15 blogs baseado no constraint real."""
        session = Mock()
        session.query.return_value.count.return_value = 15  # Limite atingido
        
        command = CreateBlogCommand(
            nome='Blog Excedente',
            desc='Blog que excede o limite'
        )
        
        result = command.execute(session)
        
        assert result.success is False
        assert "Limite máximo de 15 blogs" in result.error
    
    def test_update_blog_command_execution(self):
        """Testa execução de atualização de blog baseada no código real."""
        session = Mock()
        
        mock_blog = Mock()
        mock_blog.id = 1
        mock_blog.nome = 'Blog Original'
        mock_blog.desc = 'Descrição original'
        mock_blog.created_at = '2025-01-27 15:30:00'
        mock_blog.updated_at = '2025-01-27 15:30:00'
        
        session.query.return_value.get.return_value = mock_blog
        session.query.return_value.filter.return_value.first.return_value = None  # Nome único
        session.commit.return_value = None
        
        command = UpdateBlogCommand(
            blog_id=1,
            nome='Blog Atualizado',
            desc='Descrição atualizada'
        )
        
        result = command.execute(session)
        
        assert result.success is True
        assert result.data['nome'] == 'Blog Atualizado'
        session.commit.assert_called_once()
    
    def test_delete_blog_command_execution(self):
        """Testa execução de deleção de blog baseada no código real."""
        session = Mock()
        
        mock_blog = Mock()
        mock_blog.id = 1
        mock_blog.nome = 'Blog para Deletar'
        
        session.query.return_value.get.return_value = mock_blog
        session.delete.return_value = None
        session.commit.return_value = None
        
        command = DeleteBlogCommand(blog_id=1)
        
        result = command.execute(session)
        
        assert result.success is True
        assert result.data['deleted_id'] == 1
        assert result.data['deleted_nome'] == 'Blog para Deletar'
        session.delete.assert_called_once_with(mock_blog)
        session.commit.assert_called_once()

class TestArticleCommands:
    """Testes para comandos de geração de artigos baseados no código real."""
    
    @patch('omni_writer.domain.commands.article_commands.PromptBaseArtigosParser')
    @patch('omni_writer.domain.commands.article_commands.OpenAIProvider')
    def test_generate_article_command_execution(self, mock_provider_class, mock_parser_class):
        """Testa execução de geração de artigo baseada no código real."""
        session = Mock()
        
        # Mock da categoria baseada no modelo real
        mock_categoria = Mock()
        mock_categoria.id = 1
        mock_categoria.prompt_path = '/path/to/prompt.txt'
        mock_categoria.ia_provider = 'openai'
        
        mock_blog = Mock()
        mock_blog.nome = 'Blog de Tecnologia'
        
        mock_categoria.blog = mock_blog
        mock_categoria.clusters = []
        
        session.query.return_value.get.return_value = mock_categoria
        
        # Mock do parser real
        mock_parser = Mock()
        mock_parser.parse.return_value = {'tema': 'Tecnologia', 'tone': 'profissional'}
        mock_parser_class.return_value = mock_parser
        
        # Mock do provider real
        mock_provider = Mock()
        mock_provider.generate_article.return_value = 'Conteúdo do artigo gerado'
        mock_provider_class.return_value = mock_provider
        
        command = GenerateArticleCommand(
            categoria_id=1,
            artigo_idx=1,
            semana='2025-W01',
            output_dir='output'
        )
        
        result = command.execute(session)
        
        assert result.success is True
        assert result.data['artigo_idx'] == 1
        assert result.data['categoria_id'] == 1
        assert result.data['blog_nome'] == 'Blog de Tecnologia'
        assert result.data['content_length'] > 0
    
    def test_generate_article_command_categoria_not_found(self):
        """Testa erro quando categoria não é encontrada baseado no código real."""
        session = Mock()
        session.query.return_value.get.return_value = None
        
        command = GenerateArticleCommand(
            categoria_id=999,
            artigo_idx=1
        )
        
        result = command.execute(session)
        
        assert result.success is False
        assert "não encontrada" in result.error
    
    def test_generate_article_command_validation(self):
        """Testa validação de parâmetros baseada no código real."""
        # Dados válidos baseados no modelo real
        valid_data = {
            'categoria_id': 1,
            'artigo_idx': 3,  # Entre 1 e 6
            'semana': '2025-W01',
            'output_dir': 'output'
        }
        
        command = GenerateArticleCommand(**valid_data)
        assert command._data == valid_data
    
    def test_generate_article_command_validation_error(self):
        """Testa erro de validação baseado nas regras reais."""
        # Dados inválidos baseados nas validações reais
        invalid_data = {
            'categoria_id': 0,  # ID inválido
            'artigo_idx': 7,    # Fora do range 1-6
            'output_dir': ''    # Diretório vazio
        }
        
        with pytest.raises(ValueError):
            GenerateArticleCommand(**invalid_data)

class TestCommandHandler:
    """Testes para command handler baseados no código real."""
    
    def test_command_handler_initialization(self):
        """Testa inicialização do command handler."""
        handler = CommandHandler()
        
        # Verificar se todos os comandos reais estão registrados
        expected_commands = [
            'CreateBlogCommand',
            'UpdateBlogCommand', 
            'DeleteBlogCommand',
            'CreateCategoriaCommand',
            'UpdateCategoriaCommand',
            'DeleteCategoriaCommand',
            'CreatePromptCommand',
            'UpdatePromptCommand',
            'DeletePromptCommand',
            'CreateClusterCommand',
            'UpdateClusterCommand',
            'DeleteClusterCommand',
            'GenerateArticleCommand',
            'GenerateArticlesForCategoriaCommand',
            'GenerateZipEntregaCommand'
        ]
        
        for command_name in expected_commands:
            assert command_name in handler._handlers
    
    def test_command_handler_get_handler(self):
        """Testa obtenção de handler para comando específico."""
        handler = CommandHandler()
        
        command_class = handler.get_handler('CreateBlogCommand')
        assert command_class == CreateBlogCommand
    
    def test_command_handler_get_handler_not_found(self):
        """Testa erro quando handler não é encontrado."""
        handler = CommandHandler()
        
        with pytest.raises(ValueError, match="Handler não encontrado"):
            handler.get_handler('ComandoInexistente')
    
    def test_command_handler_execute_command(self):
        """Testa execução de comando através do handler."""
        handler = CommandHandler()
        session = Mock()
        
        # Mock da execução do comando
        with patch.object(CreateBlogCommand, 'execute') as mock_execute:
            mock_result = CommandResult(
                success=True,
                data={'id': 1, 'nome': 'Blog Teste'}
            )
            mock_execute.return_value = mock_result
            
            result = handler.execute_command(
                'CreateBlogCommand',
                session,
                nome='Blog Teste',
                desc='Descrição do blog'
            )
            
            assert result.success is True
            assert result.data['nome'] == 'Blog Teste'
            mock_execute.assert_called_once()
    
    def test_command_handler_list_commands(self):
        """Testa listagem de comandos disponíveis."""
        handler = CommandHandler()
        commands = handler.list_available_commands()
        
        assert isinstance(commands, list)
        assert len(commands) > 0
        assert 'CreateBlogCommand' in commands
    
    def test_command_handler_validate_parameters(self):
        """Testa validação de parâmetros sem execução."""
        handler = CommandHandler()
        
        # Parâmetros válidos baseados no modelo real
        valid_params = {
            'nome': 'Blog Válido',
            'desc': 'Descrição válida'
        }
        
        is_valid = handler.validate_command_parameters('CreateBlogCommand', **valid_params)
        assert is_valid is True
    
    def test_command_handler_validate_parameters_invalid(self):
        """Testa validação de parâmetros inválidos."""
        handler = CommandHandler()
        
        # Parâmetros inválidos baseados nas validações reais
        invalid_params = {
            'nome': '',  # Nome vazio viola validação
            'desc': 'Descrição válida'
        }
        
        is_valid = handler.validate_command_parameters('CreateBlogCommand', **invalid_params)
        assert is_valid is False

class TestCQRSIntegration:
    """Testes de integração CQRS baseados no código real."""
    
    def test_command_result_serialization(self):
        """Testa serialização de resultado de comando baseada no código real."""
        result = CommandResult(
            success=True,
            data={
                'id': 1,
                'nome': 'Blog de Tecnologia',
                'desc': 'Blog sobre tecnologia',
                'created_at': '2025-01-27 15:30:00',
                'updated_at': '2025-01-27 15:30:00'
            },
            command_id='test-123',
            timestamp=datetime.utcnow(),
            execution_time_ms=150.5
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['success'] is True
        assert result_dict['data']['id'] == 1
        assert result_dict['data']['nome'] == 'Blog de Tecnologia'
        assert result_dict['command_id'] == 'test-123'
        assert 'execution_time_ms' in result_dict
    
    def test_command_validation_integration(self):
        """Testa integração de validação baseada no código real."""
        # Dados baseados no modelo Blog real
        valid_blog_data = {
            'nome': 'Blog de Marketing',
            'desc': 'Blog sobre estratégias de marketing digital'
        }
        
        command = CreateBlogCommand(**valid_blog_data)
        
        # Verificar se validação passou
        assert command._data == valid_blog_data
        assert command.command_id is not None
        assert isinstance(command.timestamp, datetime)
    
    def test_command_error_handling_integration(self):
        """Testa tratamento de erros integrado baseado no código real."""
        session = Mock()
        session.query.return_value.get.return_value = None  # Blog não encontrado
        
        command = UpdateBlogCommand(
            blog_id=999,
            nome='Blog Inexistente'
        )
        
        result = command.execute(session)
        
        assert result.success is False
        assert "não encontrado" in result.error
        assert result.command_id is not None
        assert isinstance(result.timestamp, datetime) 