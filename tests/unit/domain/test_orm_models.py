"""
Testes unitários para modelos ORM.

Prompt: Separação de Modelos - IMP-004
Ruleset: Enterprise+ Standards
Data/Hora: 2025-01-27T18:00:00Z
Tracing ID: ENTERPRISE_20250127_004
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from omni_writer.domain.orm_models import Base, Blog, Categoria, Prompt, Cluster


class TestORMModels:
    """Testes unitários para modelos ORM."""
    
    def setup_method(self):
        """Setup para cada teste."""
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def teardown_method(self):
        """Cleanup após cada teste."""
        self.session.close()
        self.engine.dispose()
    
    def test_create_blog(self):
        """Testa criação de blog."""
        blog = Blog(nome="Blog Teste", desc="Descrição do blog teste")
        self.session.add(blog)
        self.session.commit()
        
        assert blog.id is not None
        assert blog.nome == "Blog Teste"
        assert blog.desc == "Descrição do blog teste"
    
    def test_create_categoria(self):
        """Testa criação de categoria."""
        # Criar blog primeiro
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(
            nome="Categoria Teste",
            desc="Descrição da categoria",
            blog_id=blog.id,
            prompt_path="/path/to/prompt.txt",
            ia_provider="openai"
        )
        self.session.add(categoria)
        self.session.commit()
        
        assert categoria.id is not None
        assert categoria.nome == "Categoria Teste"
        assert categoria.blog_id == blog.id
        assert categoria.ia_provider == "openai"
    
    def test_create_prompt(self):
        """Testa criação de prompt."""
        # Criar blog e categoria primeiro
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text="Como criar um blog profissional",
            nome="Prompt Blog",
            categoria_id=categoria.id,
            blog_id=blog.id,
            file_path="/path/to/file.txt"
        )
        self.session.add(prompt)
        self.session.commit()
        
        assert prompt.id is not None
        assert prompt.text == "Como criar um blog profissional"
        assert prompt.categoria_id == categoria.id
        assert prompt.blog_id == blog.id
    
    def test_create_cluster(self):
        """Testa criação de cluster."""
        # Criar blog e categoria primeiro
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        cluster = Cluster(
            nome="Cluster Teste",
            palavra_chave="blog profissional",
            desc="Descrição do cluster",
            categoria_id=categoria.id
        )
        self.session.add(cluster)
        self.session.commit()
        
        assert cluster.id is not None
        assert cluster.nome == "Cluster Teste"
        assert cluster.palavra_chave == "blog profissional"
        assert cluster.categoria_id == categoria.id
    
    def test_blog_categoria_relationship(self):
        """Testa relacionamento entre blog e categoria."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        # Verificar relacionamento
        assert categoria.blog == blog
        assert categoria in blog.categorias
    
    def test_categoria_prompt_relationship(self):
        """Testa relacionamento entre categoria e prompt."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text="Prompt teste",
            categoria_id=categoria.id,
            blog_id=blog.id
        )
        self.session.add(prompt)
        self.session.commit()
        
        # Verificar relacionamento
        assert prompt.categoria == categoria
        assert prompt in categoria.prompts
    
    def test_categoria_cluster_relationship(self):
        """Testa relacionamento entre categoria e cluster."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        cluster = Cluster(
            nome="Cluster Teste",
            palavra_chave="teste",
            categoria_id=categoria.id
        )
        self.session.add(cluster)
        self.session.commit()
        
        # Verificar relacionamento
        assert cluster.categoria == categoria
        assert cluster in categoria.clusters
    
    def test_blog_prompt_relationship(self):
        """Testa relacionamento entre blog e prompt."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text="Prompt teste",
            categoria_id=categoria.id,
            blog_id=blog.id
        )
        self.session.add(prompt)
        self.session.commit()
        
        # Verificar relacionamento
        assert prompt.blog == blog
        assert prompt in blog.prompts
    
    def test_cascade_delete_blog(self):
        """Testa cascade delete ao deletar blog."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text="Prompt teste",
            categoria_id=categoria.id,
            blog_id=blog.id
        )
        self.session.add(prompt)
        self.session.commit()
        
        # Deletar blog
        self.session.delete(blog)
        self.session.commit()
        
        # Verificar se categoria e prompt foram deletados
        assert self.session.query(Categoria).count() == 0
        assert self.session.query(Prompt).count() == 0
    
    def test_cascade_delete_categoria(self):
        """Testa cascade delete ao deletar categoria."""
        blog = Blog(nome="Blog Teste")
        self.session.add(blog)
        self.session.commit()
        
        categoria = Categoria(nome="Categoria Teste", blog_id=blog.id)
        self.session.add(categoria)
        self.session.commit()
        
        prompt = Prompt(
            text="Prompt teste",
            categoria_id=categoria.id,
            blog_id=blog.id
        )
        self.session.add(prompt)
        self.session.commit()
        
        cluster = Cluster(
            nome="Cluster Teste",
            palavra_chave="teste",
            categoria_id=categoria.id
        )
        self.session.add(cluster)
        self.session.commit()
        
        # Deletar categoria
        self.session.delete(categoria)
        self.session.commit()
        
        # Verificar se prompt e cluster foram deletados
        assert self.session.query(Prompt).count() == 0
        assert self.session.query(Cluster).count() == 0
        # Blog deve permanecer
        assert self.session.query(Blog).count() == 1 