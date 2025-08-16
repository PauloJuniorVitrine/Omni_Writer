"""
Comandos CQRS para operações de Categoria.

Baseados no código real de orm_models.py e validações existentes.
Implementa operações Create, Update, Delete para entidade Categoria.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .base_command import BaseCommand, CommandResult
from omni_writer.domain.orm_models import Blog, Categoria

logger = logging.getLogger("domain.commands.categoria")

class CreateCategoriaCommand(BaseCommand):
    """
    Comando para criar uma nova Categoria.
    Baseado no modelo Categoria de orm_models.py com validações reais.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para criação de Categoria baseado no código real."""
        nome = data.get('nome')
        blog_id = data.get('blog_id')
        desc = data.get('desc')
        prompt_path = data.get('prompt_path')
        ia_provider = data.get('ia_provider')
        
        if not isinstance(nome, str) or not nome.strip():
            logger.error(f"Validação falhou: nome inválido em CreateCategoriaCommand: '{nome}'")
            raise ValueError("Nome da categoria é obrigatório e deve ser uma string não vazia")
        
        if len(nome) > 100:
            logger.error(f"Validação falhou: nome muito longo em CreateCategoriaCommand: {len(nome)} caracteres")
            raise ValueError("Nome da categoria deve ter no máximo 100 caracteres")
        
        if not isinstance(blog_id, int) or blog_id <= 0:
            logger.error(f"Validação falhou: blog_id inválido em CreateCategoriaCommand: {blog_id}")
            raise ValueError("ID do blog deve ser um inteiro positivo")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em CreateCategoriaCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
        
        if prompt_path is not None and not isinstance(prompt_path, str):
            logger.error(f"Validação falhou: prompt_path inválido em CreateCategoriaCommand: {type(prompt_path)}")
            raise ValueError("Caminho do prompt deve ser uma string ou None")
        
        if ia_provider is not None and not isinstance(ia_provider, str):
            logger.error(f"Validação falhou: ia_provider inválido em CreateCategoriaCommand: {type(ia_provider)}")
            raise ValueError("Provedor de IA deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa criação de Categoria baseado no código real."""
        try:
            self._log_execution_start()
            
            # Verificar se blog existe
            blog = session.query(Blog).get(self._data['blog_id'])
            if not blog:
                error_msg = f"Blog com ID {self._data['blog_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Verificar limite de 7 categorias por blog (constraint real do modelo)
            categoria_count = session.query(Categoria).filter(
                Categoria.blog_id == self._data['blog_id']
            ).count()
            if categoria_count >= 7:
                error_msg = f"Limite máximo de 7 categorias por blog atingido para blog ID {self._data['blog_id']}"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Criar categoria baseado no modelo real
            categoria = Categoria(
                nome=self._data['nome'],
                blog_id=self._data['blog_id'],
                desc=self._data.get('desc'),
                prompt_path=self._data.get('prompt_path'),
                ia_provider=self._data.get('ia_provider')
            )
            
            session.add(categoria)
            session.commit()
            
            result = self._create_success_result({
                'id': categoria.id,
                'nome': categoria.nome,
                'blog_id': categoria.blog_id,
                'desc': categoria.desc,
                'prompt_path': categoria.prompt_path,
                'ia_provider': categoria.ia_provider,
                'created_at': categoria.created_at,
                'updated_at': categoria.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class UpdateCategoriaCommand(BaseCommand):
    """
    Comando para atualizar uma Categoria existente.
    Baseado no modelo Categoria de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para atualização de Categoria."""
        categoria_id = data.get('categoria_id')
        nome = data.get('nome')
        desc = data.get('desc')
        prompt_path = data.get('prompt_path')
        ia_provider = data.get('ia_provider')
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em UpdateCategoriaCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
        
        if nome is not None:
            if not isinstance(nome, str) or not nome.strip():
                logger.error(f"Validação falhou: nome inválido em UpdateCategoriaCommand: '{nome}'")
                raise ValueError("Nome da categoria deve ser uma string não vazia")
            
            if len(nome) > 100:
                logger.error(f"Validação falhou: nome muito longo em UpdateCategoriaCommand: {len(nome)} caracteres")
                raise ValueError("Nome da categoria deve ter no máximo 100 caracteres")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em UpdateCategoriaCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
        
        if prompt_path is not None and not isinstance(prompt_path, str):
            logger.error(f"Validação falhou: prompt_path inválido em UpdateCategoriaCommand: {type(prompt_path)}")
            raise ValueError("Caminho do prompt deve ser uma string ou None")
        
        if ia_provider is not None and not isinstance(ia_provider, str):
            logger.error(f"Validação falhou: ia_provider inválido em UpdateCategoriaCommand: {type(ia_provider)}")
            raise ValueError("Provedor de IA deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa atualização de Categoria."""
        try:
            self._log_execution_start()
            
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria:
                error_msg = f"Categoria com ID {self._data['categoria_id']} não encontrada"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Atualizar campos
            if 'nome' in self._data:
                categoria.nome = self._data['nome']
            if 'desc' in self._data:
                categoria.desc = self._data['desc']
            if 'prompt_path' in self._data:
                categoria.prompt_path = self._data['prompt_path']
            if 'ia_provider' in self._data:
                categoria.ia_provider = self._data['ia_provider']
            
            categoria.updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            
            session.commit()
            
            result = self._create_success_result({
                'id': categoria.id,
                'nome': categoria.nome,
                'blog_id': categoria.blog_id,
                'desc': categoria.desc,
                'prompt_path': categoria.prompt_path,
                'ia_provider': categoria.ia_provider,
                'created_at': categoria.created_at,
                'updated_at': categoria.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class DeleteCategoriaCommand(BaseCommand):
    """
    Comando para deletar uma Categoria.
    Baseado no modelo Categoria de orm_models.py com cascade delete.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para deleção de Categoria."""
        categoria_id = data.get('categoria_id')
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em DeleteCategoriaCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
    
    def execute(self, session) -> CommandResult:
        """Executa deleção de Categoria com cascade delete."""
        try:
            self._log_execution_start()
            
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria:
                error_msg = f"Categoria com ID {self._data['categoria_id']} não encontrada"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Cascade delete automático (definido no modelo real)
            session.delete(categoria)
            session.commit()
            
            result = self._create_success_result({
                'deleted_id': self._data['categoria_id'],
                'deleted_nome': categoria.nome,
                'blog_id': categoria.blog_id
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e) 