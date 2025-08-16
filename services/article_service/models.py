"""
Modelos para Article Service

Baseados no código real de domain/models.py e domain/data_models.py
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json
import os

@dataclass
class Article:
    """
    Modelo de artigo baseado no código real de domain/data_models.py
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    content: str = ""
    prompt: str = ""
    model_type: str = "openai"
    api_key: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "generated"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validação baseada no código real"""
        if not self.prompt:
            raise ValueError("Prompt é obrigatório")
        if not self.content:
            raise ValueError("Conteúdo é obrigatório")
        if self.model_type not in ["openai", "deepseek"]:
            raise ValueError("Modelo deve ser 'openai' ou 'deepseek'")
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'prompt': self.prompt,
            'model_type': self.model_type,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'status': self.status,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Article':
        """Cria instância a partir de dicionário"""
        return cls(
            id=data.get('id', str(uuid.uuid4())),
            title=data.get('title', ''),
            content=data.get('content', ''),
            prompt=data.get('prompt', ''),
            model_type=data.get('model_type', 'openai'),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow(),
            status=data.get('status', 'generated'),
            metadata=data.get('metadata', {})
        )

@dataclass
class Prompt:
    """
    Modelo de prompt baseado no código real
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    text: str = ""
    category: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        if not self.text:
            raise ValueError("Texto do prompt é obrigatório")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'text': self.text,
            'category': self.category,
            'tags': self.tags,
            'created_at': self.created_at.isoformat()
        }

@dataclass
class GenerationConfig:
    """
    Configuração de geração baseada no código real
    """
    model_type: str = "openai"
    api_key: Optional[str] = None
    max_tokens: int = 2000
    temperature: float = 0.7
    timeout: int = 30
    retries: int = 3
    
    def __post_init__(self):
        if self.model_type not in ["openai", "deepseek"]:
            raise ValueError("Modelo deve ser 'openai' ou 'deepseek'")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens deve ser positivo")
        if not 0 <= self.temperature <= 2:
            raise ValueError("temperature deve estar entre 0 e 2")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'model_type': self.model_type,
            'max_tokens': self.max_tokens,
            'temperature': self.temperature,
            'timeout': self.timeout,
            'retries': self.retries
        }

@dataclass
class BatchResult:
    """
    Resultado de geração em lote
    """
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    total_prompts: int = 0
    completed: int = 0
    failed: int = 0
    articles: List[Article] = field(default_factory=list)
    status: str = "processing"
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    trace_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'batch_id': self.batch_id,
            'total_prompts': self.total_prompts,
            'completed': self.completed,
            'failed': self.failed,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'trace_id': self.trace_id,
            'articles': [article.to_dict() for article in self.articles]
        }

@dataclass
class GenerationResult:
    """
    Resultado de geração de artigo
    """
    success: bool = False
    article_id: Optional[str] = None
    content: Optional[str] = None
    title: Optional[str] = None
    error_message: Optional[str] = None
    trace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'article_id': self.article_id,
            'content': self.content,
            'title': self.title,
            'error_message': self.error_message,
            'trace_id': self.trace_id,
            'metadata': self.metadata
        } 