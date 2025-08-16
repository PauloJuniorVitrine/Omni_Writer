"""
Comandos CQRS para operações de Blog.

Baseados no código real de orm_models.py e validações existentes.
Implementa operações Create, Update, Delete para entidade Blog.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .base_command import BaseCommand, CommandResult
from omni_writer.domain.orm_models import Blog

logger = logging.getLogger("domain.commands.blog")

class CreateBlogCommand(BaseCommand):
    """
    Comando para criar um novo Blog.
    Baseado no modelo Blog de orm_models.py com validações reais.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para criação de Blog baseado no código real."""
        nome = data.get('nome')
        desc = data.get('desc')
        
        if not isinstance(nome, str) or not nome.strip():
            logger.error(f"Validação falhou: nome inválido em CreateBlogCommand: '{nome}'")
            raise ValueError("Nome do blog é obrigatório e deve ser uma string não vazia")
        
        if len(nome) > 100:
            logger.error(f"Validação falhou: nome muito longo em CreateBlogCommand: {len(nome)} caracteres")
            raise ValueError("Nome do blog deve ter no máximo 100 caracteres")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em CreateBlogCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa criação de Blog baseado no código real."""
        try:
            self._log_execution_start()
            
            # Verificar limite de 15 blogs (constraint real do modelo)
            blog_count = session.query(Blog).count()
            if blog_count >= 15:
                error_msg = "Limite máximo de 15 blogs atingido"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Verificar se nome já existe (unique constraint real)
            existing_blog = session.query(Blog).filter(Blog.nome == self._data['nome']).first()
            if existing_blog:
                error_msg = f"Blog com nome '{self._data['nome']}' já existe"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Criar blog baseado no modelo real
            blog = Blog(
                nome=self._data['nome'],
                desc=self._data.get('desc')
            )
            
            session.add(blog)
            session.commit()
            
            result = self._create_success_result({
                'id': blog.id,
                'nome': blog.nome,
                'desc': blog.desc,
                'created_at': blog.created_at,
                'updated_at': blog.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class UpdateBlogCommand(BaseCommand):
    """
    Comando para atualizar um Blog existente.
    Baseado no modelo Blog de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para atualização de Blog."""
        blog_id = data.get('blog_id')
        nome = data.get('nome')
        desc = data.get('desc')
        
        if not isinstance(blog_id, int) or blog_id <= 0:
            logger.error(f"Validação falhou: blog_id inválido em UpdateBlogCommand: {blog_id}")
            raise ValueError("ID do blog deve ser um inteiro positivo")
        
        if nome is not None:
            if not isinstance(nome, str) or not nome.strip():
                logger.error(f"Validação falhou: nome inválido em UpdateBlogCommand: '{nome}'")
                raise ValueError("Nome do blog deve ser uma string não vazia")
            
            if len(nome) > 100:
                logger.error(f"Validação falhou: nome muito longo em UpdateBlogCommand: {len(nome)} caracteres")
                raise ValueError("Nome do blog deve ter no máximo 100 caracteres")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em UpdateBlogCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa atualização de Blog."""
        try:
            self._log_execution_start()
            
            blog = session.query(Blog).get(self._data['blog_id'])
            if not blog:
                error_msg = f"Blog com ID {self._data['blog_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Verificar se novo nome já existe (se for alterado)
            if 'nome' in self._data and self._data['nome'] != blog.nome:
                existing_blog = session.query(Blog).filter(
                    Blog.nome == self._data['nome'],
                    Blog.id != self._data['blog_id']
                ).first()
                if existing_blog:
                    error_msg = f"Blog com nome '{self._data['nome']}' já existe"
                    logger.error(f"Validação falhou: {error_msg}")
                    return self._create_error_result(ValueError(error_msg))
            
            # Atualizar campos
            if 'nome' in self._data:
                blog.nome = self._data['nome']
            if 'desc' in self._data:
                blog.desc = self._data['desc']
            
            blog.updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            
            session.commit()
            
            result = self._create_success_result({
                'id': blog.id,
                'nome': blog.nome,
                'desc': blog.desc,
                'created_at': blog.created_at,
                'updated_at': blog.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class DeleteBlogCommand(BaseCommand):
    """
    Comando para deletar um Blog.
    Baseado no modelo Blog de orm_models.py com cascade delete.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para deleção de Blog."""
        blog_id = data.get('blog_id')
        
        if not isinstance(blog_id, int) or blog_id <= 0:
            logger.error(f"Validação falhou: blog_id inválido em DeleteBlogCommand: {blog_id}")
            raise ValueError("ID do blog deve ser um inteiro positivo")
    
    def execute(self, session) -> CommandResult:
        """Executa deleção de Blog com cascade delete."""
        try:
            self._log_execution_start()
            
            blog = session.query(Blog).get(self._data['blog_id'])
            if not blog:
                error_msg = f"Blog com ID {self._data['blog_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Cascade delete automático (definido no modelo real)
            session.delete(blog)
            session.commit()
            
            result = self._create_success_result({
                'deleted_id': self._data['blog_id'],
                'deleted_nome': blog.nome
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e) 