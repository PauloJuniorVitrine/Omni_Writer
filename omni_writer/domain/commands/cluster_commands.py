"""
Comandos CQRS para operações de Cluster.

Baseados no código real de orm_models.py e validações existentes.
Implementa operações Create, Update, Delete para entidade Cluster.

Autor: Cursor Enterprise+ Agent
Data: 2025-01-27
Tracing ID: ENTERPRISE_20250127_001
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .base_command import BaseCommand, CommandResult
from omni_writer.domain.orm_models import Categoria, Cluster

logger = logging.getLogger("domain.commands.cluster")

class CreateClusterCommand(BaseCommand):
    """
    Comando para criar um novo Cluster.
    Baseado no modelo Cluster de orm_models.py com validações reais.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para criação de Cluster baseado no código real."""
        nome = data.get('nome')
        palavra_chave = data.get('palavra_chave')
        categoria_id = data.get('categoria_id')
        desc = data.get('desc')
        
        if not isinstance(nome, str) or not nome.strip():
            logger.error(f"Validação falhou: nome inválido em CreateClusterCommand: '{nome}'")
            raise ValueError("Nome do cluster é obrigatório e deve ser uma string não vazia")
        
        if len(nome) > 200:
            logger.error(f"Validação falhou: nome muito longo em CreateClusterCommand: {len(nome)} caracteres")
            raise ValueError("Nome do cluster deve ter no máximo 200 caracteres")
        
        if not isinstance(palavra_chave, str) or not palavra_chave.strip():
            logger.error(f"Validação falhou: palavra_chave inválida em CreateClusterCommand: '{palavra_chave}'")
            raise ValueError("Palavra-chave é obrigatória e deve ser uma string não vazia")
        
        if len(palavra_chave) > 200:
            logger.error(f"Validação falhou: palavra_chave muito longa em CreateClusterCommand: {len(palavra_chave)} caracteres")
            raise ValueError("Palavra-chave deve ter no máximo 200 caracteres")
        
        if not isinstance(categoria_id, int) or categoria_id <= 0:
            logger.error(f"Validação falhou: categoria_id inválido em CreateClusterCommand: {categoria_id}")
            raise ValueError("ID da categoria deve ser um inteiro positivo")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em CreateClusterCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa criação de Cluster baseado no código real."""
        try:
            self._log_execution_start()
            
            # Verificar se categoria existe
            categoria = session.query(Categoria).get(self._data['categoria_id'])
            if not categoria:
                error_msg = f"Categoria com ID {self._data['categoria_id']} não encontrada"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Criar cluster baseado no modelo real
            cluster = Cluster(
                nome=self._data['nome'],
                palavra_chave=self._data['palavra_chave'],
                categoria_id=self._data['categoria_id'],
                desc=self._data.get('desc')
            )
            
            session.add(cluster)
            session.commit()
            
            result = self._create_success_result({
                'id': cluster.id,
                'nome': cluster.nome,
                'palavra_chave': cluster.palavra_chave,
                'categoria_id': cluster.categoria_id,
                'desc': cluster.desc,
                'created_at': cluster.created_at,
                'updated_at': cluster.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class UpdateClusterCommand(BaseCommand):
    """
    Comando para atualizar um Cluster existente.
    Baseado no modelo Cluster de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para atualização de Cluster."""
        cluster_id = data.get('cluster_id')
        nome = data.get('nome')
        palavra_chave = data.get('palavra_chave')
        desc = data.get('desc')
        
        if not isinstance(cluster_id, int) or cluster_id <= 0:
            logger.error(f"Validação falhou: cluster_id inválido em UpdateClusterCommand: {cluster_id}")
            raise ValueError("ID do cluster deve ser um inteiro positivo")
        
        if nome is not None:
            if not isinstance(nome, str) or not nome.strip():
                logger.error(f"Validação falhou: nome inválido em UpdateClusterCommand: '{nome}'")
                raise ValueError("Nome do cluster deve ser uma string não vazia")
            
            if len(nome) > 200:
                logger.error(f"Validação falhou: nome muito longo em UpdateClusterCommand: {len(nome)} caracteres")
                raise ValueError("Nome do cluster deve ter no máximo 200 caracteres")
        
        if palavra_chave is not None:
            if not isinstance(palavra_chave, str) or not palavra_chave.strip():
                logger.error(f"Validação falhou: palavra_chave inválida em UpdateClusterCommand: '{palavra_chave}'")
                raise ValueError("Palavra-chave deve ser uma string não vazia")
            
            if len(palavra_chave) > 200:
                logger.error(f"Validação falhou: palavra_chave muito longa em UpdateClusterCommand: {len(palavra_chave)} caracteres")
                raise ValueError("Palavra-chave deve ter no máximo 200 caracteres")
        
        if desc is not None and not isinstance(desc, str):
            logger.error(f"Validação falhou: desc inválida em UpdateClusterCommand: {type(desc)}")
            raise ValueError("Descrição deve ser uma string ou None")
    
    def execute(self, session) -> CommandResult:
        """Executa atualização de Cluster."""
        try:
            self._log_execution_start()
            
            cluster = session.query(Cluster).get(self._data['cluster_id'])
            if not cluster:
                error_msg = f"Cluster com ID {self._data['cluster_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            # Atualizar campos
            if 'nome' in self._data:
                cluster.nome = self._data['nome']
            if 'palavra_chave' in self._data:
                cluster.palavra_chave = self._data['palavra_chave']
            if 'desc' in self._data:
                cluster.desc = self._data['desc']
            
            cluster.updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            
            session.commit()
            
            result = self._create_success_result({
                'id': cluster.id,
                'nome': cluster.nome,
                'palavra_chave': cluster.palavra_chave,
                'categoria_id': cluster.categoria_id,
                'desc': cluster.desc,
                'created_at': cluster.created_at,
                'updated_at': cluster.updated_at
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e)

class DeleteClusterCommand(BaseCommand):
    """
    Comando para deletar um Cluster.
    Baseado no modelo Cluster de orm_models.py.
    """
    
    def _validate_command_data(self, data: Dict[str, Any]) -> None:
        """Valida dados para deleção de Cluster."""
        cluster_id = data.get('cluster_id')
        
        if not isinstance(cluster_id, int) or cluster_id <= 0:
            logger.error(f"Validação falhou: cluster_id inválido em DeleteClusterCommand: {cluster_id}")
            raise ValueError("ID do cluster deve ser um inteiro positivo")
    
    def execute(self, session) -> CommandResult:
        """Executa deleção de Cluster."""
        try:
            self._log_execution_start()
            
            cluster = session.query(Cluster).get(self._data['cluster_id'])
            if not cluster:
                error_msg = f"Cluster com ID {self._data['cluster_id']} não encontrado"
                logger.error(f"Validação falhou: {error_msg}")
                return self._create_error_result(ValueError(error_msg))
            
            session.delete(cluster)
            session.commit()
            
            result = self._create_success_result({
                'deleted_id': self._data['cluster_id'],
                'deleted_nome': cluster.nome,
                'deleted_palavra_chave': cluster.palavra_chave,
                'categoria_id': cluster.categoria_id
            })
            
            self._log_execution_success(result)
            return result
            
        except Exception as e:
            session.rollback()
            self._log_execution_error(e)
            return self._create_error_result(e) 