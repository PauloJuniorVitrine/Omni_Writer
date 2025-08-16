"""
Comandos CQRS para operações de Prompt.

Baseados no código real de orm_models.py e validações existentes.
Implementa operações Create, Update, Delete para entidade Prompt.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .base_command import BaseCommand, CommandResult
from omni_writer.domain.orm_models import Blog, Categoria, Prompt

logger = logging.getLogger("domain.commands.prompt")

class CreatePromptCommand(BaseCommand):
    """
    Comando para criar um novo Prompt.
    Baseado no modelo Prompt de orm_models.py com validações reais.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para criação de Prompt baseado no código real."""
        text = data.get('text')
        categoria_id = data.get('categoria_id')
        blog_id = data.get('blog_id')
        nome = data.get('nome')
        file_path = data.get('file_path')
        
        if not isinstance(text, str) or not text.strip():
            logger.error(f"Validação falhou: text inválido em CreatePromptCommand: '{text}'")
            raise ValueError("Texto do prompt é obrigatório e deve ser uma string não vazia")
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em CreatePromptCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
        
        if not isinstance(blog_id, int) or blog_id <= 0:
            logger.error(f"Validação falhou: blog_id inválido em CreatePromptCommand: {blog_id}")
            raise ValueError("ID do blog deve ser um inteiro positivo")
        
        if nome is not None and not isinstance(nome, str):
            logger.error(f"Validação falhou: nome inválido em CreatePromptCommand: {type(nome)}")
            raise ValueError("Nome deve ser uma string ou None")
        
        if nome is not None and len(nome) > 100:
            logger.error(f"Validação falhou: nome muito longo em CreatePromptCommand: {len(nome)} caracteres")
            raise ValueError("Nome deve ter no máximo 100 caracteres")
        
        if file_path is not None and not isinstance(file_path, str):
            logger.error(f"Validação falhou: file_path inválido em CreatePromptCommand: {type(file_path)}")
            raise ValueError("Caminho do arquivo deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa criação de Prompt baseado no código real."""
        try:
            self._log_execution_start()
            
            # Verificar se categoria existe
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria:
                error_msg = f"Categoria com ID {self._data['categoria_id']} não encontrada"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Verificar se blog existe
            blog = session.query(Blog).get(self._data['blog_id'])
            if not blog:
                error_msg = f"Blog com ID {self._data['blog_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Verificar limite de 3 prompts por categoria (constraint real do modelo)
            prompt_count = session.query(Prompt).filter(
                Prompt.categoria_id == self._data['categoria_id']
            ).count()
            if prompt_count >= 3:
                error_msg = f"Limite máximo de 3 prompts por categoria atingido para categoria ID {self._data['categoria_id']}"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Criar prompt baseado no modelo real
            prompt = Prompt(
                text=self._data['text'],
                categoria_id=self._data['categoria_id'],
                blog_id=self._data['blog_id'],
                nome=self._data.get('nome'),
                file_path=self._data.get('file_path')
            )
            
            session.add(prompt)
            session.commit()
            
            result = self._create_success_result({
                'id': prompt.id,
                'text': prompt.text,
                'nome': prompt.nome,
                'categoria_id': prompt.categoria_id,
                'blog_id': prompt.blog_id,
                'file_path': prompt.file_path,
                'created_at': prompt.created_at,
                'updated_at': prompt.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class UpdatePromptCommand(BaseCommand):
    """
    Comando para atualizar um Prompt existente.
    Baseado no modelo Prompt de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para atualização de Prompt."""
        prompt_id = data.get('prompt_id')
        text = data.get('text')
        nome = data.get('nome')
        file_path = data.get('file_path')
        
        if not isinstance(prompt_id, int) or prompt_id <= 0:
            logger.error(f"Validação falhou: prompt_id inválido em UpdatePromptCommand: {prompt_id}")
            raise ValueError("ID do prompt deve ser um inteiro positivo")
        
        if text is not None:
            if not isinstance(text, str) or not text.strip():
                logger.error(f"Validação falhou: text inválido em UpdatePromptCommand: '{text}'")
                raise ValueError("Texto do prompt deve ser uma string não vazia")
        
        if nome is not None:
            if not isinstance(nome, str):
                logger.error(f"Validação falhou: nome inválido em UpdatePromptCommand: {type(nome)}")
                raise ValueError("Nome deve ser uma string ou None")
            
            if len(nome) > 100:
                logger.error(f"Validação falhou: nome muito longo em UpdatePromptCommand: {len(nome)} caracteres")
                raise ValueError("Nome deve ter no máximo 100 caracteres")
        
        if file_path is not None and not isinstance(file_path, str):
            logger.error(f"Validação falhou: file_path inválido em UpdatePromptCommand: {type(file_path)}")
            raise ValueError("Caminho do arquivo deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa atualização de Prompt."""
        try:
            self._log_execution_start()
            
            prompt = session.query(Prompt).get(self._data['prompt_id'])
            if not prompt:
                error_msg = f"Prompt com ID {self._data['prompt_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Atualizar campos
            if 'text' in self._data:
                prompt.text = self._data['text']
            if 'nome' in self._data:
                prompt.nome = self._data['nome']
            if 'file_path' in self._data:
                prompt.file_path = self._data['file_path']
            
            prompt.updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            
            session.commit()
            
            result = self._create_success_result({
                'id': prompt.id,
                'text': prompt.text,
                'nome': prompt.nome,
                'categoria_id': prompt.categoria_id,
                'blog_id': prompt.blog_id,
                'file_path': prompt.file_path,
                'created_at': prompt.created_at,
                'updated_at': prompt.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class DeletePromptCommand(BaseCommand):
    """
    Comando para deletar um Prompt.
    Baseado no modelo Prompt de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para deleção de Prompt."""
        prompt_id = data.get('prompt_id')
        
        if not isinstance(prompt_id, int) or prompt_id <= 0:
            logger.error(f"Validação falhou: prompt_id inválido em DeletePromptCommand: {prompt_id}")
            raise ValueError("ID do prompt deve ser um inteiro positivo")
    
    def execute(self, session) -> CommandResult:
        """Executa deleção de Prompt."""
        try:
            self._log_execution_start()
            
            prompt = session.query(Prompt).get(self._data['prompt_id'])
            if not prompt:
                error_msg = f"Prompt com ID {self._data['prompt_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            session.delete(prompt)
            session.commit()
            
            result = self._create_success_result({
                'deleted_id': self._data['prompt_id'],
                'deleted_text': prompt.text[:50] + "..." if len(prompt.text) > 50 else prompt.text,
                'categoria_id': prompt.categoria_id,
                'blog_id': prompt.blog_id
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e) 