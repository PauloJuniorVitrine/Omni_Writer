"""
Handlers de comandos CQRS para o domínio Omni Writer.

Baseados no código real existente e implementam o padrão Command Handler.
Centraliza a execução de comandos com logging e tratamento de erros.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from typing import Dict, Type, Any
from .commands import BaseCommand, CommandResult
from .commands.blog_commands import CreateBlogCommand, UpdateBlogCommand, DeleteBlogCommand
from .commands.categoria_commands import CreateCategoriaCommand, UpdateCategoriaCommand, DeleteCategoriaCommand
from .commands.prompt_commands import CreatePromptCommand, UpdatePromptCommand, DeletePromptCommand
from .commands.cluster_commands import CreateClusterCommand, UpdateClusterCommand, DeleteClusterCommand
from .commands.article_commands import GenerateArticleCommand, GenerateArticlesForCategoriaCommand, GenerateZipEntregaCommand

logger = logging.getLogger("domain.command_handlers")

class CommandHandler:
    """
    Handler centralizado para execução de comandos CQRS.
    
    Baseado nos padrões de logging e tratamento de erros do código real:
    - Logging estruturado como em generate_articles.py
    - Tratamento de erros como em validation_service.py
    - Validação como em data_models.py
    """
    
    def __init__(self):
        self._handlers: Dict[str, Type[BaseCommand]] = {
            # Blog commands
            'CreateBlogCommand': CreateBlogCommand,
            'UpdateBlogCommand': UpdateBlogCommand,
            'DeleteBlogCommand': DeleteBlogCommand,
            
            # Categoria commands
            'CreateCategoriaCommand': CreateCategoriaCommand,
            'UpdateCategoriaCommand': UpdateCategoriaCommand,
            'DeleteCategoriaCommand': DeleteCategoriaCommand,
            
            # Prompt commands
            'CreatePromptCommand': CreatePromptCommand,
            'UpdatePromptCommand': UpdatePromptCommand,
            'DeletePromptCommand': DeletePromptCommand,
            
            # Cluster commands
            'CreateClusterCommand': CreateClusterCommand,
            'UpdateClusterCommand': UpdateClusterCommand,
            'DeleteClusterCommand': DeleteClusterCommand,
            
            # Article commands
            'GenerateArticleCommand': GenerateArticleCommand,
            'GenerateArticlesForCategoriaCommand': GenerateArticlesForCategoriaCommand,
            'GenerateZipEntregaCommand': GenerateZipEntregaCommand,
        }
    
    def register_handler(self, command_name: str, command_class: Type[BaseCommand]) -> None:
        """
        Registra um novo handler de comando.
        
        Args:
            command_name: Nome do comando
            command_class: Classe do comando
        """
        if not issubclass(command_class, BaseCommand):
            logger.error(f"Tentativa de registrar classe inválida como handler: {command_class}")
            raise ValueError("Classe deve herdar de BaseCommand")
        
        self._handlers[command_name] = command_class
        logger.info(f"Handler registrado: {command_name} -> {command_class.__name__}")
    
    def get_handler(self, command_name: str) -> Type[BaseCommand]:
        """
        Obtém o handler para um comando específico.
        
        Args:
            command_name: Nome do comando
            
        Returns:
            Classe do comando
            
        Raises:
            ValueError: Se o comando não for encontrado
        """
        if command_name not in self._handlers:
            logger.error(f"Handler não encontrado para comando: {command_name}")
            raise ValueError(f"Handler não encontrado para comando: {command_name}")
        
        return self._handlers[command_name]
    
    def execute_command(self, command_name: str, session, **kwargs) -> CommandResult:
        """
        Executa um comando específico.
        
        Args:
            command_name: Nome do comando
            session: Sessão do banco de dados
            **kwargs: Parâmetros do comando
            
        Returns:
            CommandResult: Resultado da execução
        """
        try:
            logger.info(f"Executando comando: {command_name}", extra={
                'command_name': command_name,
                'parameters': kwargs
            })
            
            # Obter handler
            command_class = self.get_handler(command_name)
            
            # Criar instância do comando
            command = command_class(**kwargs)
            
            # Executar comando
            result = command.execute(session)
            
            logger.info(f"Comando {command_name} executado com sucesso", extra={
                'command_name': command_name,
                'success': result.success,
                'command_id': result.command_id
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Erro ao executar comando {command_name}: {e}", extra={
                'command_name': command_name,
                'error': str(e),
                'error_type': type(e).__name__
            })
            
            # Retornar resultado de erro
            return CommandResult(
                success=False,
                error=str(e),
                command_id=getattr(command, 'command_id', None) if 'command' in locals() else None
            )
    
    def list_available_commands(self) -> list:
        """
        Lista todos os comandos disponíveis.
        
        Returns:
            Lista de nomes de comandos
        """
        return list(self._handlers.keys())
    
    def validate_command_parameters(self, command_name: str, **kwargs) -> bool:
        """
        Valida parâmetros de um comando sem executá-lo.
        
        Args:
            command_name: Nome do comando
            **kwargs: Parâmetros a validar
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            command_class = self.get_handler(command_name)
            command = command_class(**kwargs)
            return True
        except Exception as e:
            logger.warning(f"Validação de parâmetros falhou para {command_name}: {e}")
            return False

# Instância global do command handler
command_handler = CommandHandler() 