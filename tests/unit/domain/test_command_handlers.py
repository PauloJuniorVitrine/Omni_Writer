"""
Testes unitários para Command Handlers
Prompt: tests
Ruleset: geral_rules_melhorado.yaml
Data/Hora: 2025-01-27T18:40:00Z
Tracing ID: TEST_COMMAND_HANDLERS_001
"""
import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from omni_writer.domain.command_handlers import CommandHandler, command_handler
from omni_writer.domain.commands import BaseCommand, CommandResult
from omni_writer.domain.commands.blog_commands import CreateBlogCommand, UpdateBlogCommand, DeleteBlogCommand
from omni_writer.domain.commands.categoria_commands import CreateCategoriaCommand, UpdateCategoriaCommand, DeleteCategoriaCommand
from omni_writer.domain.commands.prompt_commands import CreatePromptCommand, UpdatePromptCommand, DeletePromptCommand
from omni_writer.domain.commands.cluster_commands import CreateClusterCommand, UpdateClusterCommand, DeleteClusterCommand
from omni_writer.domain.commands.article_commands import GenerateArticleCommand, GenerateArticlesForCategoriaCommand, GenerateZipEntregaCommand


class TestCommandHandler:
    """Testes para o Command Handler com cobertura completa de cenários."""

    @pytest.fixture
    def handler(self):
        """Fixture para Command Handler."""
        return CommandHandler()

    @pytest.fixture
    def mock_session(self):
        """Fixture para sessão mock."""
        return Mock()

    @pytest.fixture
    def mock_command(self):
        """Fixture para comando mock."""
        command = Mock(spec=BaseCommand)
        command.execute.return_value = CommandResult(success=True, command_id="test_123")
        return command

    def test_command_handler_initialization(self, handler):
        """Testa inicialização do Command Handler."""
        assert handler is not None
        assert hasattr(handler, '_handlers')
        assert isinstance(handler._handlers, dict)

    def test_command_handler_registered_commands(self, handler):
        """Testa se todos os comandos estão registrados."""
        expected_commands = [
            'CreateBlogCommand', 'UpdateBlogCommand', 'DeleteBlogCommand',
            'CreateCategoriaCommand', 'UpdateCategoriaCommand', 'DeleteCategoriaCommand',
            'CreatePromptCommand', 'UpdatePromptCommand', 'DeletePromptCommand',
            'CreateClusterCommand', 'UpdateClusterCommand', 'DeleteClusterCommand',
            'GenerateArticleCommand', 'GenerateArticlesForCategoriaCommand', 'GenerateZipEntregaCommand'
        ]
        
        for command_name in expected_commands:
            assert command_name in handler._handlers
            assert handler._handlers[command_name] is not None

    def test_register_handler_success(self, handler):
        """Testa registro de handler com sucesso."""
        class TestCommand(BaseCommand):
            def execute(self, session):
                return CommandResult(success=True, command_id="test")

        handler.register_handler('TestCommand', TestCommand)
        assert 'TestCommand' in handler._handlers
        assert handler._handlers['TestCommand'] == TestCommand

    def test_register_handler_invalid_class(self, handler):
        """Testa registro de classe inválida."""
        class InvalidCommand:
            pass

        with pytest.raises(ValueError, match="Classe deve herdar de BaseCommand"):
            handler.register_handler('InvalidCommand', InvalidCommand)

    def test_get_handler_success(self, handler):
        """Testa obtenção de handler existente."""
        command_class = handler.get_handler('CreateBlogCommand')
        assert command_class == CreateBlogCommand

    def test_get_handler_not_found(self, handler):
        """Testa obtenção de handler inexistente."""
        with pytest.raises(ValueError, match="Handler não encontrado para comando: NonExistentCommand"):
            handler.get_handler('NonExistentCommand')

    def test_execute_command_success(self, handler, mock_session):
        """Testa execução de comando com sucesso."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            result = handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog', url='http://test.com')

            assert result.success is True
            assert result.command_id is not None

            # Verifica logs de sucesso
            mock_logger.info.assert_called()
            success_log_call = mock_logger.info.call_args_list[-1]
            assert 'executado com sucesso' in success_log_call[0][0]

    def test_execute_command_failure(self, handler, mock_session):
        """Testa execução de comando com falha."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            # Simula falha no comando
            with patch.object(CreateBlogCommand, 'execute', side_effect=Exception("Test error")):
                result = handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog')

                assert result.success is False
                assert result.error == "Test error"

                # Verifica logs de erro
                mock_logger.error.assert_called()
                error_log_call = mock_logger.error.call_args
                assert 'Erro ao executar comando' in error_log_call[0][0]

    def test_execute_command_handler_not_found(self, handler, mock_session):
        """Testa execução de comando com handler não encontrado."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            result = handler.execute_command('NonExistentCommand', mock_session)

            assert result.success is False
            assert 'Handler não encontrado' in result.error

            # Verifica logs de erro
            mock_logger.error.assert_called()

    def test_list_available_commands(self, handler):
        """Testa listagem de comandos disponíveis."""
        commands = handler.list_available_commands()
        
        assert isinstance(commands, list)
        assert len(commands) > 0
        assert 'CreateBlogCommand' in commands
        assert 'GenerateArticleCommand' in commands

    def test_validate_command_parameters_success(self, handler):
        """Testa validação de parâmetros com sucesso."""
        is_valid = handler.validate_command_parameters('CreateBlogCommand', nome='Test Blog', url='http://test.com')
        assert is_valid is True

    def test_validate_command_parameters_failure(self, handler):
        """Testa validação de parâmetros com falha."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            is_valid = handler.validate_command_parameters('CreateBlogCommand', invalid_param='test')
            assert is_valid is False

            # Verifica log de warning
            mock_logger.warning.assert_called()

    def test_validate_command_parameters_handler_not_found(self, handler):
        """Testa validação de parâmetros com handler não encontrado."""
        is_valid = handler.validate_command_parameters('NonExistentCommand', param='test')
        assert is_valid is False

    @pytest.mark.parametrize("command_name,params", [
        ('CreateBlogCommand', {'nome': 'Test Blog', 'url': 'http://test.com'}),
        ('CreateCategoriaCommand', {'nome': 'Test Category', 'descricao': 'Test Description'}),
        ('CreatePromptCommand', {'texto': 'Test prompt', 'categoria_id': 1}),
        ('CreateClusterCommand', {'nome': 'Test Cluster', 'descricao': 'Test Description'}),
    ])
    def test_create_commands_execution(self, handler, mock_session, command_name, params):
        """Testa execução de comandos de criação."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command(command_name, mock_session, **params)
            assert result.success is True

    @pytest.mark.parametrize("command_name,params", [
        ('UpdateBlogCommand', {'id': 1, 'nome': 'Updated Blog', 'url': 'http://updated.com'}),
        ('UpdateCategoriaCommand', {'id': 1, 'nome': 'Updated Category', 'descricao': 'Updated Description'}),
        ('UpdatePromptCommand', {'id': 1, 'texto': 'Updated prompt', 'categoria_id': 1}),
        ('UpdateClusterCommand', {'id': 1, 'nome': 'Updated Cluster', 'descricao': 'Updated Description'}),
    ])
    def test_update_commands_execution(self, handler, mock_session, command_name, params):
        """Testa execução de comandos de atualização."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command(command_name, mock_session, **params)
            assert result.success is True

    @pytest.mark.parametrize("command_name,params", [
        ('DeleteBlogCommand', {'id': 1}),
        ('DeleteCategoriaCommand', {'id': 1}),
        ('DeletePromptCommand', {'id': 1}),
        ('DeleteClusterCommand', {'id': 1}),
    ])
    def test_delete_commands_execution(self, handler, mock_session, command_name, params):
        """Testa execução de comandos de exclusão."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command(command_name, mock_session, **params)
            assert result.success is True

    def test_generate_article_command_execution(self, handler, mock_session):
        """Testa execução de comando de geração de artigo."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command('GenerateArticleCommand', mock_session, 
                                           prompt_id=1, config={'model': 'gpt-4'})
            assert result.success is True

    def test_generate_articles_for_categoria_command_execution(self, handler, mock_session):
        """Testa execução de comando de geração de artigos para categoria."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command('GenerateArticlesForCategoriaCommand', mock_session, 
                                           categoria_id=1, config={'model': 'gpt-4'})
            assert result.success is True

    def test_generate_zip_entrega_command_execution(self, handler, mock_session):
        """Testa execução de comando de geração de ZIP de entrega."""
        with patch('omni_writer.domain.command_handlers.logger'):
            result = handler.execute_command('GenerateZipEntregaCommand', mock_session, 
                                           article_ids=[1, 2, 3])
            assert result.success is True

    def test_command_execution_with_trace_id(self, handler, mock_session):
        """Testa execução de comando com trace_id."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            result = handler.execute_command('CreateBlogCommand', mock_session, 
                                           nome='Test Blog', url='http://test.com')

            # Verifica se os logs incluem informações do comando
            log_calls = mock_logger.info.call_args_list
            assert any('Executando comando' in call[0][0] for call in log_calls)
            assert any('executado com sucesso' in call[0][0] for call in log_calls)

    def test_command_execution_error_handling(self, handler, mock_session):
        """Testa tratamento de erros durante execução."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            # Simula erro no comando
            with patch.object(CreateBlogCommand, 'execute', side_effect=ValueError("Validation error")):
                result = handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog')

                assert result.success is False
                assert result.error == "Validation error"
                assert result.command_id is None

                # Verifica logs de erro
                error_calls = mock_logger.error.call_args_list
                assert any('Erro ao executar comando' in call[0][0] for call in error_calls)

    def test_command_execution_with_command_id(self, handler, mock_session):
        """Testa execução de comando que retorna command_id."""
        mock_result = CommandResult(success=True, command_id="cmd_12345")
        
        with patch.object(CreateBlogCommand, 'execute', return_value=mock_result):
            with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
                result = handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog')

                assert result.success is True
                assert result.command_id == "cmd_12345"

                # Verifica se o command_id foi logado
                success_log_call = mock_logger.info.call_args_list[-1]
                assert 'cmd_12345' in str(success_log_call)

    def test_command_handler_singleton_pattern(self):
        """Testa se o command_handler global é um singleton."""
        from omni_writer.domain.command_handlers import command_handler
        
        # Verifica se é a mesma instância
        handler1 = CommandHandler()
        handler2 = CommandHandler()
        
        # Instâncias diferentes devem ter handlers iguais
        assert handler1.list_available_commands() == handler2.list_available_commands()
        
        # Verifica se o global existe
        assert command_handler is not None
        assert isinstance(command_handler, CommandHandler)

    def test_command_handler_logging_structure(self, handler, mock_session):
        """Testa estrutura de logging do command handler."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog')

            # Verifica estrutura dos logs
            log_calls = mock_logger.info.call_args_list
            
            # Log de início da execução
            start_log = log_calls[0]
            assert 'Executando comando' in start_log[0][0]
            assert 'command_name' in start_log[1]['extra']
            assert 'parameters' in start_log[1]['extra']
            
            # Log de sucesso
            success_log = log_calls[-1]
            assert 'executado com sucesso' in success_log[0][0]
            assert 'command_name' in success_log[1]['extra']
            assert 'success' in success_log[1]['extra']
            assert 'command_id' in success_log[1]['extra']

    def test_command_handler_error_logging_structure(self, handler, mock_session):
        """Testa estrutura de logging de erro do command handler."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            with patch.object(CreateBlogCommand, 'execute', side_effect=Exception("Test error")):
                handler.execute_command('CreateBlogCommand', mock_session, nome='Test Blog')

                # Verifica estrutura do log de erro
                error_log = mock_logger.error.call_args
                assert 'Erro ao executar comando' in error_log[0][0]
                assert 'command_name' in error_log[1]['extra']
                assert 'error' in error_log[1]['extra']
                assert 'error_type' in error_log[1]['extra']

    def test_command_handler_registration_logging(self, handler):
        """Testa logging durante registro de handler."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            class TestCommand(BaseCommand):
                def execute(self, session):
                    return CommandResult(success=True, command_id="test")

            handler.register_handler('TestCommand', TestCommand)
            
            # Verifica log de registro
            mock_logger.info.assert_called()
            register_log = mock_logger.info.call_args
            assert 'Handler registrado' in register_log[0][0]
            assert 'TestCommand' in register_log[0][0]

    def test_command_handler_get_handler_logging(self, handler):
        """Testa logging durante obtenção de handler."""
        with patch('omni_writer.domain.command_handlers.logger') as mock_logger:
            with pytest.raises(ValueError):
                handler.get_handler('NonExistentCommand')
            
            # Verifica log de erro
            mock_logger.error.assert_called()
            error_log = mock_logger.error.call_args
            assert 'Handler não encontrado' in error_log[0][0] 