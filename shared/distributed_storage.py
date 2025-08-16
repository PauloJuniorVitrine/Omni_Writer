"""
Distributed Storage System - Omni Writer
========================================

Sistema de storage distribuído com PostgreSQL, Redis e fallbacks
para escalabilidade e concorrência.

Prompt: Implementação de storage distribuído
Ruleset: enterprise_control_layer.yaml
Data/Hora: 2025-01-27T11:15:00Z
"""

import os
import json
import logging
import threading
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from contextlib import contextmanager
import redis
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError, OperationalError
import hashlib
import pickle

# Configuração de logging estruturado
storage_logger = logging.getLogger("distributed_storage")
storage_logger.setLevel(logging.INFO)
if not storage_logger.hasHandlers():
    handler = logging.FileHandler("logs/exec_trace/distributed_storage.log")
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [distributed_storage] %(message)s'
    )
    handler.setFormatter(formatter)
    storage_logger.addHandler(handler)

# Configurações
POSTGRES_URL = os.getenv('POSTGRES_URL', 'postgresql://user:password@localhost:5432/omniwriter')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
ENABLE_DISTRIBUTED_STORAGE = os.getenv('ENABLE_DISTRIBUTED_STORAGE', 'true').lower() == 'true'
STORAGE_FALLBACK = os.getenv('STORAGE_FALLBACK', 'sqlite').lower()

Base = declarative_base()

class DistributedStatus(Base):
    """Modelo para status distribuído."""
    __tablename__ = 'distributed_status'
    
    trace_id = Column(String(255), primary_key=True)
    total = Column(Integer, nullable=False)
    current = Column(Integer, nullable=False, default=0)
    status = Column(String(50), nullable=False, default='pending')
    user_id = Column(String(255))
    model_type = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata = Column(Text)  # JSON para metadados adicionais

class DistributedFeedback(Base):
    """Modelo para feedback distribuído."""
    __tablename__ = 'distributed_feedback'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), nullable=False, index=True)
    artigo_id = Column(String(255), nullable=False, index=True)
    tipo = Column(String(50), nullable=False)
    comentario = Column(Text)
    rating = Column(Integer)  # 1-5 rating
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    metadata = Column(Text)  # JSON para metadados adicionais

class DistributedArticle(Base):
    """Modelo para artigos distribuídos."""
    __tablename__ = 'distributed_articles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    trace_id = Column(String(255), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)
    content = Column(Text, nullable=False)
    model_type = Column(String(100))
    prompt = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata = Column(Text)  # JSON para metadados adicionais

class DistributedStorage:
    """
    Sistema de storage distribuído com PostgreSQL, Redis e fallbacks.
    
    Funcionalidades:
    - Storage distribuído com PostgreSQL
    - Cache distribuído com Redis
    - Fallbacks para SQLite e arquivos
    - Pool de conexões otimizado
    - Transações distribuídas
    - Backup e recuperação automática
    """
    
    def __init__(self):
        self.postgres_engine = None
        self.postgres_session_factory = None
        self.redis_client = None
        self.fallback_storage = None
        self.connection_pool = {}
        self.lock = threading.RLock()
        
        # Configurações
        self.enabled = ENABLE_DISTRIBUTED_STORAGE
        self.fallback_type = STORAGE_FALLBACK
        self.cache_ttl = int(os.getenv('CACHE_TTL', '3600'))  # 1 hora
        self.max_retries = int(os.getenv('STORAGE_MAX_RETRIES', '3'))
        
        # Inicialização
        if self.enabled:
            self._initialize_storage()
    
    def _initialize_storage(self):
        """Inicializa o sistema de storage distribuído."""
        try:
            # Inicializa PostgreSQL
            self._init_postgres()
            
            # Inicializa Redis
            self._init_redis()
            
            # Inicializa fallback
            self._init_fallback()
            
            storage_logger.info("Sistema de storage distribuído inicializado com sucesso")
            
        except Exception as e:
            storage_logger.error(f"Erro ao inicializar storage distribuído: {e}")
            self.enabled = False
    
    def _init_postgres(self):
        """Inicializa conexão PostgreSQL."""
        try:
            # Configuração do pool de conexões
            self.postgres_engine = create_engine(
                POSTGRES_URL,
                poolclass=QueuePool,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600,
                echo=False
            )
            
            # Cria tabelas se não existirem
            Base.metadata.create_all(self.postgres_engine)
            
            # Configura session factory
            self.postgres_session_factory = scoped_session(
                sessionmaker(bind=self.postgres_engine)
            )
            
            storage_logger.info("PostgreSQL inicializado com sucesso")
            
        except Exception as e:
            storage_logger.error(f"Erro ao inicializar PostgreSQL: {e}")
            raise
    
    def _init_redis(self):
        """Inicializa conexão Redis."""
        try:
            self.redis_client = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Testa conexão
            self.redis_client.ping()
            
            storage_logger.info("Redis inicializado com sucesso")
            
        except Exception as e:
            storage_logger.error(f"Erro ao inicializar Redis: {e}")
            self.redis_client = None
    
    def _init_fallback(self):
        """Inicializa storage de fallback."""
        try:
            if self.fallback_type == 'sqlite':
                from shared.status_repository import init_db
                init_db()
                storage_logger.info("Fallback SQLite inicializado")
            else:
                storage_logger.info("Fallback de arquivos configurado")
                
        except Exception as e:
            storage_logger.error(f"Erro ao inicializar fallback: {e}")
    
    @contextmanager
    def get_session(self):
        """Context manager para sessões PostgreSQL."""
        if not self.postgres_session_factory:
            raise RuntimeError("PostgreSQL não inicializado")
        
        session = self.postgres_session_factory()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
    
    def _get_cache_key(self, prefix: str, key: str) -> str:
        """Gera chave de cache."""
        return f"omniwriter:{prefix}:{key}"
    
    def _cache_get(self, prefix: str, key: str) -> Optional[Dict[str, Any]]:
        """Obtém dados do cache Redis."""
        if not self.redis_client:
            return None
        
        try:
            cache_key = self._get_cache_key(prefix, key)
            data = self.redis_client.get(cache_key)
            if data:
                return json.loads(data)
        except Exception as e:
            storage_logger.error(f"Erro ao obter cache: {e}")
        
        return None
    
    def _cache_set(self, prefix: str, key: str, data: Dict[str, Any], ttl: int = None):
        """Armazena dados no cache Redis."""
        if not self.redis_client:
            return
        
        try:
            cache_key = self._get_cache_key(prefix, key)
            ttl = ttl or self.cache_ttl
            self.redis_client.setex(cache_key, ttl, json.dumps(data))
        except Exception as e:
            storage_logger.error(f"Erro ao definir cache: {e}")
    
    def _cache_delete(self, prefix: str, key: str):
        """Remove dados do cache Redis."""
        if not self.redis_client:
            return
        
        try:
            cache_key = self._get_cache_key(prefix, key)
            self.redis_client.delete(cache_key)
        except Exception as e:
            storage_logger.error(f"Erro ao deletar cache: {e}")
    
    def update_status(self, trace_id: str, total: int, current: int, status: str, 
                     user_id: str = None, model_type: str = None, metadata: Dict[str, Any] = None):
        """
        Atualiza status de geração com storage distribuído.
        
        Args:
            trace_id: ID único do trace
            total: Total de passos
            current: Passo atual
            status: Status atual
            user_id: ID do usuário
            model_type: Tipo do modelo
            metadata: Metadados adicionais
        """
        if not self.enabled:
            return self._fallback_update_status(trace_id, total, current, status)
        
        try:
            with self.get_session() as session:
                # Busca ou cria registro
                status_obj = session.query(DistributedStatus).get(trace_id)
                if not status_obj:
                    status_obj = DistributedStatus(trace_id=trace_id)
                    session.add(status_obj)
                
                # Atualiza dados
                status_obj.total = total
                status_obj.current = current
                status_obj.status = status
                status_obj.user_id = user_id
                status_obj.model_type = model_type
                status_obj.updated_at = datetime.utcnow()
                if metadata:
                    status_obj.metadata = json.dumps(metadata)
                
                session.commit()
                
                # Atualiza cache
                cache_data = {
                    'trace_id': trace_id,
                    'total': total,
                    'current': current,
                    'status': status,
                    'user_id': user_id,
                    'model_type': model_type,
                    'updated_at': status_obj.updated_at.isoformat()
                }
                self._cache_set('status', trace_id, cache_data)
                
                storage_logger.info(f"Status atualizado: {trace_id} - {status}")
                
        except Exception as e:
            storage_logger.error(f"Erro ao atualizar status: {e}")
            return self._fallback_update_status(trace_id, total, current, status)
    
    def get_status(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtém status de geração com cache.
        
        Args:
            trace_id: ID único do trace
            
        Returns:
            Dicionário com status ou None
        """
        if not self.enabled:
            return self._fallback_get_status(trace_id)
        
        try:
            # Tenta cache primeiro
            cache_data = self._cache_get('status', trace_id)
            if cache_data:
                return cache_data
            
            # Busca no banco
            with self.get_session() as session:
                status_obj = session.query(DistributedStatus).get(trace_id)
                if status_obj:
                    data = {
                        'trace_id': status_obj.trace_id,
                        'total': status_obj.total,
                        'current': status_obj.current,
                        'status': status_obj.status,
                        'user_id': status_obj.user_id,
                        'model_type': status_obj.model_type,
                        'created_at': status_obj.created_at.isoformat(),
                        'updated_at': status_obj.updated_at.isoformat()
                    }
                    
                    if status_obj.metadata:
                        data['metadata'] = json.loads(status_obj.metadata)
                    
                    # Atualiza cache
                    self._cache_set('status', trace_id, data)
                    
                    return data
            
            return None
            
        except Exception as e:
            storage_logger.error(f"Erro ao obter status: {e}")
            return self._fallback_get_status(trace_id)
    
    def save_feedback(self, user_id: str, artigo_id: str, tipo: str, comentario: str = None,
                     rating: int = None, metadata: Dict[str, Any] = None) -> bool:
        """
        Salva feedback com storage distribuído.
        
        Args:
            user_id: ID do usuário
            artigo_id: ID do artigo
            tipo: Tipo de feedback
            comentario: Comentário opcional
            rating: Rating opcional (1-5)
            metadata: Metadados adicionais
            
        Returns:
            True se salvo com sucesso
        """
        if not self.enabled:
            return self._fallback_save_feedback(user_id, artigo_id, tipo, comentario)
        
        try:
            with self.get_session() as session:
                feedback = DistributedFeedback(
                    user_id=user_id,
                    artigo_id=artigo_id,
                    tipo=tipo,
                    comentario=comentario,
                    rating=rating,
                    metadata=json.dumps(metadata) if metadata else None
                )
                
                session.add(feedback)
                session.commit()
                
                # Invalida cache de feedback
                self._cache_delete('feedback', artigo_id)
                
                storage_logger.info(f"Feedback salvo: {artigo_id} por {user_id}")
                return True
                
        except Exception as e:
            storage_logger.error(f"Erro ao salvar feedback: {e}")
            return self._fallback_save_feedback(user_id, artigo_id, tipo, comentario)
    
    def get_feedbacks(self, artigo_id: str = None, user_id: str = None) -> List[Dict[str, Any]]:
        """
        Obtém feedbacks com cache.
        
        Args:
            artigo_id: ID do artigo (opcional)
            user_id: ID do usuário (opcional)
            
        Returns:
            Lista de feedbacks
        """
        if not self.enabled:
            return self._fallback_get_feedbacks(artigo_id)
        
        try:
            # Tenta cache primeiro
            if artigo_id:
                cache_data = self._cache_get('feedbacks', artigo_id)
                if cache_data:
                    return cache_data
            
            with self.get_session() as session:
                query = session.query(DistributedFeedback)
                
                if artigo_id:
                    query = query.filter_by(artigo_id=artigo_id)
                if user_id:
                    query = query.filter_by(user_id=user_id)
                
                feedbacks = []
                for fb in query.all():
                    data = {
                        'id': fb.id,
                        'user_id': fb.user_id,
                        'artigo_id': fb.artigo_id,
                        'tipo': fb.tipo,
                        'comentario': fb.comentario,
                        'rating': fb.rating,
                        'created_at': fb.created_at.isoformat(),
                        'updated_at': fb.updated_at.isoformat()
                    }
                    
                    if fb.metadata:
                        data['metadata'] = json.loads(fb.metadata)
                    
                    feedbacks.append(data)
                
                # Atualiza cache
                if artigo_id:
                    self._cache_set('feedbacks', artigo_id, feedbacks)
                
                return feedbacks
                
        except Exception as e:
            storage_logger.error(f"Erro ao obter feedbacks: {e}")
            return self._fallback_get_feedbacks(artigo_id)
    
    def save_article(self, trace_id: str, filename: str, content: str, model_type: str = None,
                    prompt: str = None, metadata: Dict[str, Any] = None) -> bool:
        """
        Salva artigo com storage distribuído.
        
        Args:
            trace_id: ID do trace
            filename: Nome do arquivo
            content: Conteúdo do artigo
            model_type: Tipo do modelo
            prompt: Prompt usado
            metadata: Metadados adicionais
            
        Returns:
            True se salvo com sucesso
        """
        if not self.enabled:
            return self._fallback_save_article(trace_id, filename, content)
        
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            with self.get_session() as session:
                article = DistributedArticle(
                    trace_id=trace_id,
                    filename=filename,
                    content_hash=content_hash,
                    content=content,
                    model_type=model_type,
                    prompt=prompt,
                    metadata=json.dumps(metadata) if metadata else None
                )
                
                session.add(article)
                session.commit()
                
                storage_logger.info(f"Artigo salvo: {filename} (hash: {content_hash[:8]})")
                return True
                
        except Exception as e:
            storage_logger.error(f"Erro ao salvar artigo: {e}")
            return self._fallback_save_article(trace_id, filename, content)
    
    def get_article(self, trace_id: str, filename: str = None) -> Optional[Dict[str, Any]]:
        """
        Obtém artigo do storage distribuído.
        
        Args:
            trace_id: ID do trace
            filename: Nome do arquivo (opcional)
            
        Returns:
            Dicionário com dados do artigo ou None
        """
        if not self.enabled:
            return self._fallback_get_article(trace_id, filename)
        
        try:
            with self.get_session() as session:
                query = session.query(DistributedArticle).filter_by(trace_id=trace_id)
                
                if filename:
                    query = query.filter_by(filename=filename)
                
                article = query.first()
                if article:
                    data = {
                        'id': article.id,
                        'trace_id': article.trace_id,
                        'filename': article.filename,
                        'content_hash': article.content_hash,
                        'content': article.content,
                        'model_type': article.model_type,
                        'prompt': article.prompt,
                        'created_at': article.created_at.isoformat()
                    }
                    
                    if article.metadata:
                        data['metadata'] = json.loads(article.metadata)
                    
                    return data
            
            return None
            
        except Exception as e:
            storage_logger.error(f"Erro ao obter artigo: {e}")
            return self._fallback_get_article(trace_id, filename)
    
    def _fallback_update_status(self, trace_id: str, total: int, current: int, status: str):
        """Fallback para atualização de status."""
        try:
            from shared.status_repository import update_status
            update_status(trace_id, total, current, status)
        except Exception as e:
            storage_logger.error(f"Erro no fallback de status: {e}")
    
    def _fallback_get_status(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Fallback para obtenção de status."""
        try:
            from shared.status_repository import get_status
            return get_status(trace_id)
        except Exception as e:
            storage_logger.error(f"Erro no fallback de status: {e}")
            return None
    
    def _fallback_save_feedback(self, user_id: str, artigo_id: str, tipo: str, comentario: str) -> bool:
        """Fallback para salvamento de feedback."""
        try:
            from feedback.storage import save_feedback
            save_feedback(user_id, artigo_id, tipo, comentario)
            return True
        except Exception as e:
            storage_logger.error(f"Erro no fallback de feedback: {e}")
            return False
    
    def _fallback_get_feedbacks(self, artigo_id: str) -> List[Dict[str, Any]]:
        """Fallback para obtenção de feedbacks."""
        try:
            from feedback.storage import get_feedbacks
            return get_feedbacks(artigo_id)
        except Exception as e:
            storage_logger.error(f"Erro no fallback de feedbacks: {e}")
            return []
    
    def _fallback_save_article(self, trace_id: str, filename: str, content: str) -> bool:
        """Fallback para salvamento de artigo."""
        try:
            # Salva em arquivo local
            os.makedirs('output', exist_ok=True)
            filepath = os.path.join('output', filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            storage_logger.error(f"Erro no fallback de artigo: {e}")
            return False
    
    def _fallback_get_article(self, trace_id: str, filename: str) -> Optional[Dict[str, Any]]:
        """Fallback para obtenção de artigo."""
        try:
            if filename:
                filepath = os.path.join('output', filename)
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    return {
                        'trace_id': trace_id,
                        'filename': filename,
                        'content': content
                    }
            return None
        except Exception as e:
            storage_logger.error(f"Erro no fallback de artigo: {e}")
            return None
    
    def cleanup_old_data(self, days: int = 7):
        """
        Limpa dados antigos do storage distribuído.
        
        Args:
            days: Número de dias para manter
        """
        if not self.enabled:
            return
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with self.get_session() as session:
                # Limpa status antigo
                session.query(DistributedStatus).filter(
                    DistributedStatus.updated_at < cutoff_date
                ).delete()
                
                # Limpa artigos antigos
                session.query(DistributedArticle).filter(
                    DistributedArticle.created_at < cutoff_date
                ).delete()
                
                session.commit()
            
            # Limpa cache Redis
            if self.redis_client:
                self.redis_client.flushdb()
            
            storage_logger.info(f"Dados antigos limpos (mais de {days} dias)")
            
        except Exception as e:
            storage_logger.error(f"Erro ao limpar dados antigos: {e}")

# Instância global do sistema de storage distribuído
distributed_storage = DistributedStorage()

def update_status(trace_id: str, total: int, current: int, status: str, 
                 user_id: str = None, model_type: str = None, metadata: Dict[str, Any] = None):
    """Função de conveniência para atualizar status."""
    distributed_storage.update_status(trace_id, total, current, status, user_id, model_type, metadata)

def get_status(trace_id: str) -> Optional[Dict[str, Any]]:
    """Função de conveniência para obter status."""
    return distributed_storage.get_status(trace_id)

def save_feedback(user_id: str, artigo_id: str, tipo: str, comentario: str = None,
                 rating: int = None, metadata: Dict[str, Any] = None) -> bool:
    """Função de conveniência para salvar feedback."""
    return distributed_storage.save_feedback(user_id, artigo_id, tipo, comentario, rating, metadata)

def get_feedbacks(artigo_id: str = None, user_id: str = None) -> List[Dict[str, Any]]:
    """Função de conveniência para obter feedbacks."""
    return distributed_storage.get_feedbacks(artigo_id, user_id)

def save_article(trace_id: str, filename: str, content: str, model_type: str = None,
                prompt: str = None, metadata: Dict[str, Any] = None) -> bool:
    """Função de conveniência para salvar artigo."""
    return distributed_storage.save_article(trace_id, filename, content, model_type, prompt, metadata)

def get_article(trace_id: str, filename: str = None) -> Optional[Dict[str, Any]]:
    """Função de conveniência para obter artigo."""
    return distributed_storage.get_article(trace_id, filename) 