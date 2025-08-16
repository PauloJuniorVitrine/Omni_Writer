import logging
from sqlalchemy import Column, Integer, String, ForeignKey, Text, CheckConstraint
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()
logger = logging.getLogger("domain.orm_models")

class Blog(Base):
    """
    Modelo de Blog para persistência.
    Limite máximo: 15 blogs
    """
    __tablename__ = 'blogs'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False, unique=True)
    desc = Column(Text, nullable=True)
    created_at = Column(String(50), default=func.now())
    updated_at = Column(String(50), default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    prompts = relationship('Prompt', back_populates='blog', cascade='all, delete-orphan')
    categorias = relationship('Categoria', back_populates='blog', cascade='all, delete-orphan')
    
    # Constraint para limitar a 15 blogs
    __table_args__ = (
        CheckConstraint('id <= 15', name='max_blogs_limit'),
    )

    def __init__(self, *args, **kwargs):
        logger.info(f"Criando Blog: nome={kwargs.get('nome')}")
        super().__init__(*args, **kwargs)

    def __del__(self):
        logger.info(f"Deletando Blog: id={self.id}, nome={self.nome}")

class Categoria(Base):
    """
    Modelo de Categoria vinculada a Blog.
    Limite máximo: 7 categorias por blog
    """
    __tablename__ = 'categorias'
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    desc = Column(Text, nullable=True)
    blog_id = Column(Integer, ForeignKey('blogs.id'), nullable=False)
    prompt_path = Column(String(255), nullable=True)  # Caminho do prompt .txt
    ia_provider = Column(String(32), nullable=True)  # Provedor de IA: 'openai', 'gemini', 'claude', etc.
    created_at = Column(String(50), default=func.now())
    updated_at = Column(String(50), default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    blog = relationship('Blog', back_populates='categorias')
    clusters = relationship('Cluster', back_populates='categoria', cascade='all, delete-orphan')
    prompts = relationship('Prompt', back_populates='categoria', cascade='all, delete-orphan')
    
    # Constraint para limitar a 7 categorias por blog
    __table_args__ = (
        CheckConstraint('id <= (SELECT MAX(id) FROM blogs) * 7', name='max_categorias_per_blog'),
    )

    def __init__(self, *args, **kwargs):
        logger.info(f"Criando Categoria: nome={kwargs.get('nome')}, blog_id={kwargs.get('blog_id')}, prompt_path={kwargs.get('prompt_path')}, ia_provider={kwargs.get('ia_provider')}")
        super().__init__(*args, **kwargs)

    def __del__(self):
        logger.info(f"Deletando Categoria: id={self.id}, nome={self.nome}")

class Prompt(Base):
    """
    Modelo de Prompt vinculado a Categoria.
    Limite máximo: 3 prompts por categoria
    """
    __tablename__ = 'prompts'
    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)
    nome = Column(String(100), nullable=True)  # Nome do prompt para identificação
    categoria_id = Column(Integer, ForeignKey('categorias.id'), nullable=False)
    blog_id = Column(Integer, ForeignKey('blogs.id'), nullable=False)  # Para facilitar consultas
    file_path = Column(String(255), nullable=True)  # Caminho do arquivo .txt se foi upload
    created_at = Column(String(50), default=func.now())
    updated_at = Column(String(50), default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    categoria = relationship('Categoria', back_populates='prompts')
    blog = relationship('Blog', back_populates='prompts')
    
    # Constraint para limitar a 3 prompts por categoria
    __table_args__ = (
        CheckConstraint('id <= (SELECT MAX(id) FROM categorias) * 3', name='max_prompts_per_categoria'),
    )

    def __init__(self, *args, **kwargs):
        logger.info(f"Criando Prompt: text={kwargs.get('text')}, categoria_id={kwargs.get('categoria_id')}")
        super().__init__(*args, **kwargs)

    def __del__(self):
        logger.info(f"Deletando Prompt: id={self.id}, text={self.text}")

class Cluster(Base):
    """
    Modelo de Cluster vinculado a Categoria.
    """
    __tablename__ = 'clusters'
    id = Column(Integer, primary_key=True)
    nome = Column(String(200), nullable=False)
    palavra_chave = Column(String(200), nullable=False)
    desc = Column(Text, nullable=True)
    categoria_id = Column(Integer, ForeignKey('categorias.id'), nullable=False)
    created_at = Column(String(50), default=func.now())
    updated_at = Column(String(50), default=func.now(), onupdate=func.now())
    
    # Relacionamentos
    categoria = relationship('Categoria', back_populates='clusters')

    def __init__(self, *args, **kwargs):
        logger.info(f"Criando Cluster: nome={kwargs.get('nome')}, categoria_id={kwargs.get('categoria_id')}")
        super().__init__(*args, **kwargs)

    def __del__(self):
        logger.info(f"Deletando Cluster: id={self.id}, nome={self.nome}")

# Adicionar relacionamento reverso em Blog
Blog.categorias = relationship('Categoria', back_populates='blog', cascade='all, delete-orphan') 